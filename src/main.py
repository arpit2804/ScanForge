import asyncio
import json
import re
import time
import urllib.parse
from typing import Dict, List, Any, Optional, Union
from dataclasses import dataclass, asdict
from enum import Enum
import aiohttp
import logging
from abc import ABC, abstractmethod
from contextlib import asynccontextmanager
import hashlib
import os
from src.AIInterface import AIInterface

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# =============================================================================
# Data Models and Enums
# =============================================================================

class Severity(Enum):
    """Vulnerability severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class VulnType(Enum):
    """Supported vulnerability types"""
    XSS = "xss"
    SQLI = "sqli"
    SSRF = "ssrf"
    LFI = "lfi"
    RCE = "rce"
    XXE = "xxe"

@dataclass
class InjectionPoint:
    """Represents where to inject payloads"""
    type: str  # query_param, form_field, header, path, body
    name: str
    position: Optional[int] = None

@dataclass
class HttpRequest:
    """HTTP request representation"""
    method: str
    url: str
    headers: Dict[str, str]
    body: str = ""
    timeout: int = 10

@dataclass
class HttpResponse:
    """HTTP response representation"""
    status_code: int
    headers: Dict[str, str]
    body: str
    response_time: float
    size_bytes: int
    redirect_chain: List[str]

@dataclass
class Vulnerability:
    """Vulnerability finding data structure"""
    type: str
    severity: str
    title: str
    description: str
    location: Dict[str, Any]
    evidence: Dict[str, Any]
    remediation: str
    confidence: float
    timestamp: float = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = time.time()

# =============================================================================
# Safety and Rate Limiting Components
# =============================================================================

class RateLimiter:
    """Rate limiting to prevent overwhelming target servers"""
    
    def __init__(self, requests_per_minute: int = 30):
        self.requests_per_minute = requests_per_minute
        self.requests = []
        self.lock = asyncio.Lock()
    
    async def acquire(self):
        """Acquire permission to make a request"""
        async with self.lock:
            now = time.time()
            # Remove requests older than 1 minute
            self.requests = [req_time for req_time in self.requests if now - req_time < 60]
            
            if len(self.requests) >= self.requests_per_minute:
                # Wait until we can make another request
                sleep_time = 60 - (now - self.requests[0])
                if sleep_time > 0:
                    logger.info(f"Rate limit reached, sleeping for {sleep_time:.2f} seconds")
                    await asyncio.sleep(sleep_time)
            
            self.requests.append(now)

class ScopeValidator:
    """Validates that targets are within allowed testing scope"""
    
    def __init__(self, allowed_domains: List[str] = None, blocked_paths: List[str] = None):
        self.allowed_domains = allowed_domains or []
        self.blocked_paths = blocked_paths or ['/admin', '/system', '/dev']
        
        # Dangerous patterns that should never be in payloads
        self.dangerous_patterns = [
            r'rm\s+-rf',          # File deletion commands
            r'format\s+c:',       # Disk formatting
            r'del\s+/[qsf]',      # Windows delete commands
            r'DROP\s+DATABASE',   # Database destruction
            r'TRUNCATE\s+TABLE',  # Table destruction
        ]
    
    async def is_allowed(self, url: str) -> bool:
        """Check if URL is within allowed scope"""
        parsed = urllib.parse.urlparse(url)
        domain = parsed.netloc.lower()
        path = parsed.path
        
        # Check domain whitelist
        if self.allowed_domains:
            if not any(domain.endswith(allowed.lower()) for allowed in self.allowed_domains):
                logger.warning(f"Domain {domain} not in allowed list")
                return False
        
        # Check blocked paths
        for blocked_path in self.blocked_paths:
            if path.startswith(blocked_path):
                logger.warning(f"Path {path} is blocked")
                return False
        
        return True
    
    def is_payload_safe(self, payload: str) -> bool:
        """Check if payload is safe to use"""
        for pattern in self.dangerous_patterns:
            if re.search(pattern, payload, re.IGNORECASE):
                logger.warning(f"Dangerous payload pattern detected: {pattern}")
                return False
        return True

class SecurityError(Exception):
    """Raised when security constraints are violated"""
    pass

# =============================================================================
# MCP Server Implementation
# =============================================================================

class VulnerabilityDatabase:
    """File-based storage for vulnerability findings.

    Findings are saved as individual JSON files named by a short
    SHA256-derived id in the configured output directory.
    """

    def __init__(self, output_dir: str = "output"):
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)

    async def save_finding(self, vulnerability: Vulnerability, target_url: str):
        """Save vulnerability finding to `output_dir` as a JSON file."""
        vuln_id = hashlib.sha256(
            f"{vulnerability.type}_{vulnerability.location}_{target_url}".encode()
        ).hexdigest()[:16]

        file_path = os.path.join(self.output_dir, f"{vuln_id}.json")

        data = asdict(vulnerability)
        data['target_url'] = target_url

        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            logger.info(f"Saved vulnerability finding to {file_path}")
        except Exception as e:
            logger.error(f"Failed to save finding {vuln_id} to {file_path}: {e}")
            raise

        return vuln_id

class PayloadDatabase:
    """In-memory payload database with context-aware payload generation"""
    
    def __init__(self):
        # Curated payloads for different vulnerability types
        self.payloads = {
            VulnType.XSS.value: [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
                "javascript:alert('XSS')",
                "';alert('XSS');//",
                "\"><script>alert('XSS')</script>",
                "<svg onload=alert('XSS')>",
                "<%2Fscript%3E%3Cscript%3Ealert(%27XSS%27)%3C%2Fscript%3E",
            ],
            VulnType.SQLI.value: [
                "' OR '1'='1",
                "'; DROP TABLE users;--",
                "1' UNION SELECT null,null,null--",
                "admin'--",
                "' OR 1=1#",
                "1' AND (SELECT SUBSTRING(@@version,1,1))='5'--",
                "' WAITFOR DELAY '00:00:05'--",
            ],
            VulnType.SSRF.value: [
                "http://169.254.169.254/latest/meta-data/",
                "file:///etc/passwd",
                "http://localhost:22",
                "http://127.0.0.1:8080",
                "gopher://127.0.0.1:3306/",
                "dict://127.0.0.1:11211/",
            ],
            VulnType.LFI.value: [
                "../../../etc/passwd",
                "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
                "/etc/passwd%00",
                "....//....//....//etc/passwd",
                "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            ]
        }
    
    def get_payloads(self, vuln_type: str, context: Dict[str, Any] = None, count: int = 10) -> List[str]:
        """Get payloads for specific vulnerability type with context awareness"""
        base_payloads = self.payloads.get(vuln_type, [])
        
        if not context:
            return base_payloads[:count]
        
        # Context-aware payload modification
        filtered_payloads = []
        technology = context.get('technology', '').lower()
        input_type = context.get('input_type', '').lower()
        
        for payload in base_payloads:
            # Modify payloads based on detected technology
            if vuln_type == VulnType.SQLI.value:
                if 'mysql' in technology:
                    payload = payload.replace('#', '-- ')
                elif 'oracle' in technology:
                    payload = payload.replace('--', '/**/').replace('#', '/**/')
            
            # Modify based on input type
            if input_type == 'json' and vuln_type == VulnType.XSS.value:
                payload = payload.replace('"', '\\"')
            
            filtered_payloads.append(payload)
        
        return filtered_payloads[:count]

class WebCrawler:
    """Web crawler for discovering attack surface"""
    
    def __init__(self, session: aiohttp.ClientSession):
        self.session = session
        self.visited_urls = set()
        self.discovered_endpoints = []
        self.discovered_forms = []
    
    async def crawl_site(self, seed_url: str, depth: int = 2, scope_domains: List[str] = None) -> Dict[str, Any]:
        """Crawl website to discover endpoints and attack surface"""
        logger.info(f"Starting crawl of {seed_url} with depth {depth}")
        
        self.visited_urls.clear()
        self.discovered_endpoints.clear()
        self.discovered_forms.clear()
        
        await self._crawl_recursive(seed_url, depth, scope_domains or [])
        
        return {
            "endpoints": self.discovered_endpoints,
            "forms": self.discovered_forms,
            "static_analysis": {
                "js_endpoints": [],  # Would extract from JavaScript files
                "comments": [],      # Would extract HTML comments
                "technologies": self._detect_technologies()
            }
        }
    
    async def _crawl_recursive(self, url: str, depth: int, scope_domains: List[str]):
        """Recursive crawling with depth limiting"""
        if depth <= 0 or url in self.visited_urls:
            return
        
        parsed_url = urllib.parse.urlparse(url)
        if scope_domains and not any(parsed_url.netloc.endswith(domain) for domain in scope_domains):
            return
        
        self.visited_urls.add(url)
        
        try:
            async with self.session.get(url, timeout=10) as response:
                if response.status == 200:
                    content = await response.text()
                    
                    # Extract endpoint information
                    endpoint_info = {
                        "url": url,
                        "method": "GET",
                        "parameters": self._extract_parameters(url),
                        "headers_observed": dict(response.headers),
                        "forms": [],
                        "technology_stack": []
                    }
                    self.discovered_endpoints.append(endpoint_info)
                    
                    # Extract forms
                    forms = self._extract_forms(content, url)
                    self.discovered_forms.extend(forms)
                    
                    # Extract links for further crawling
                    if depth > 1:
                        links = self._extract_links(content, url)
                        for link in links[:10]:  # Limit to prevent infinite crawling
                            await self._crawl_recursive(link, depth - 1, scope_domains)
        
        except Exception as e:
            logger.warning(f"Error crawling {url}: {e}")
    
    def _extract_parameters(self, url: str) -> List[str]:
        """Extract query parameters from URL"""
        parsed = urllib.parse.urlparse(url)
        return list(urllib.parse.parse_qs(parsed.query).keys())
    
    def _extract_forms(self, html: str, base_url: str) -> List[Dict[str, Any]]:
        """Extract forms from HTML content"""
        # Simplified form extraction - in practice, use BeautifulSoup
        forms = []
        
        # Basic regex-based form extraction (use proper HTML parser in production)
        form_pattern = r'<form[^>]*action=["\']?([^"\'>\s]+)[^>]*>(.*?)</form>'
        input_pattern = r'<input[^>]*name=["\']([^"\']+)["\'][^>]*type=["\']([^"\']+)["\'][^>]*>'
        
        for match in re.finditer(form_pattern, html, re.DOTALL | re.IGNORECASE):
            action = match.group(1)
            form_content = match.group(2)
            
            # Resolve relative URLs
            if not action.startswith('http'):
                action = urllib.parse.urljoin(base_url, action)
            
            inputs = []
            for input_match in re.finditer(input_pattern, form_content, re.IGNORECASE):
                inputs.append({
                    "name": input_match.group(1),
                    "type": input_match.group(2)
                })
            
            forms.append({
                "action": action,
                "method": "POST",  # Default assumption
                "inputs": inputs
            })
        
        return forms
    
    def _extract_links(self, html: str, base_url: str) -> List[str]:
        """Extract links from HTML content"""
        links = []
        link_pattern = r'<a[^>]*href=["\']([^"\']+)["\'][^>]*>'
        
        for match in re.finditer(link_pattern, html, re.IGNORECASE):
            href = match.group(1)
            if href.startswith('http'):
                links.append(href)
            elif not href.startswith('#') and not href.startswith('javascript:'):
                links.append(urllib.parse.urljoin(base_url, href))
        
        return links
    
    def _detect_technologies(self) -> List[str]:
        """Detect technologies from headers and content"""
        # In practice, integrate with Wappalyzer or similar
        return ["nginx", "php"]  # Placeholder

class MCPServer:
    """Main MCP Server handling all vulnerability scanning operations"""
    
    def __init__(self,ai_interface: AIInterface):
        self.rate_limiter = RateLimiter(requests_per_minute=30)
        self.scope_validator = ScopeValidator()
        self.payload_db = PayloadDatabase()
        self.vuln_db = VulnerabilityDatabase()
        
        # HTTP session for making requests
        self.session = None
        
        # Available MCP tools
        self.tools = {
            "crawl_site": self.crawl_site,
            "send_request": self.send_request,
            "inject_payload": self.inject_payload,
            "analyze_response": self.analyze_response,
            "save_finding": self.save_finding,
            "get_payloads": self.get_payloads,
            "validate_target": self.validate_target,
        }
    
    async def __aenter__(self):
        """Async context manager entry"""
        self.session = aiohttp.ClientSession()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.session:
            await self.session.close()
    
    async def call_tool(self, tool_name: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Main entry point for calling MCP tools"""
        if tool_name not in self.tools:
            raise ValueError(f"Unknown tool: {tool_name}")
        
        # Apply safety checks for dangerous operations
        await self._validate_request(tool_name, params)
        
        # Call the appropriate tool
        tool_func = self.tools[tool_name]
        result = await tool_func(**params)
        
        logger.info(f"Tool {tool_name} executed successfully")
        return result
    
    async def _validate_request(self, tool_name: str, params: Dict[str, Any]):
        """Validate request for safety and scope compliance"""
        if tool_name in ['inject_payload', 'send_request']:
            # Validate URL scope
            url = params.get('url')
            if url and not await self.scope_validator.is_allowed(url):
                raise SecurityError("Target outside allowed scope")
            
            # Check dangerous payloads
            payload = params.get('payload')
            if payload and not self.scope_validator.is_payload_safe(payload):
                raise SecurityError("Dangerous payload detected")
            
            # Apply rate limiting
            await self.rate_limiter.acquire()
    
    async def crawl_site(self, seed_url: str, depth: int = 2, scope_domains: List[str] = None, 
                        follow_forms: bool = True, extract_js_urls: bool = True) -> Dict[str, Any]:
        """Crawl website to discover attack surface"""
        crawler = WebCrawler(self.session)
        return await crawler.crawl_site(seed_url, depth, scope_domains)
    
    async def send_request(self, method: str, url: str, headers: Dict[str, str] = None, 
                          body: str = "", follow_redirects: bool = True, timeout: int = 10) -> Dict[str, Any]:
        """Send HTTP request and capture response"""
        start_time = time.time()
        redirect_chain = []
        
        try:
            async with self.session.request(
                method=method,
                url=url,
                headers=headers or {},
                data=body,
                allow_redirects=follow_redirects,
                timeout=timeout
            ) as response:
                response_body = await response.text()
                response_time = time.time() - start_time
                
                # Track redirects
                if hasattr(response, 'history'):
                    redirect_chain = [str(r.url) for r in response.history]
                
                return {
                    "status_code": response.status,
                    "headers": dict(response.headers),
                    "body": response_body,
                    "response_time": response_time,
                    "redirect_chain": redirect_chain,
                    "size_bytes": len(response_body.encode('utf-8')),
                    "tls_info": {"version": "TLSv1.3", "cipher": "AES256-GCM"}  # Placeholder
                }
        
        except asyncio.TimeoutError:
            return {"error": "Request timeout", "response_time": time.time() - start_time}
        except Exception as e:
            return {"error": str(e), "response_time": time.time() - start_time}
    
    async def inject_payload(self, url: str, injection_point: Dict[str, Any], payload: str, 
                           method: str = "GET", encode: bool = False) -> Dict[str, Any]:
        """Inject payload into specific parameter or location"""
        if encode:
            payload = urllib.parse.quote(payload)
        
        # Prepare request based on injection point type
        headers = {}
        body = ""
        modified_url = url
        
        injection_type = injection_point.get('type')
        param_name = injection_point.get('name')
        
        if injection_type == 'query_param':
            # Inject into URL query parameter
            parsed = urllib.parse.urlparse(url)
            params = urllib.parse.parse_qs(parsed.query)
            params[param_name] = [payload]
            new_query = urllib.parse.urlencode(params, doseq=True)
            modified_url = urllib.parse.urlunparse(
                (parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment)
            )
        
        elif injection_type == 'header':
            headers[param_name] = payload
        
        elif injection_type == 'form_field':
            # Inject into form data
            body = urllib.parse.urlencode({param_name: payload})
            headers['Content-Type'] = 'application/x-www-form-urlencoded'
            method = 'POST'
        
        # Send the crafted request
        return await self.send_request(method, modified_url, headers, body)
    
    async def analyze_response(self, request: Dict[str, Any], response: Dict[str, Any], 
                             vulnerability_types: List[str] = None, context: Dict[str, Any] = None) -> Dict[str, Any]:
        """Analyze HTTP response for vulnerability indicators"""
        indicators = {}
        payload = request.get('payload', '')
        response_body = response.get('body', '')
        response_headers = response.get('headers', {})
        status_code = response.get('status_code', 0)
        response_time = response.get('response_time', 0)
        
        # Check for payload reflection
        indicators['payload_reflection'] = {
            "found": payload in response_body or payload in str(response_headers),
            "locations": [],
            "context": "",
            "encoded": False
        }
        
        if indicators['payload_reflection']['found']:
            if payload in response_body:
                indicators['payload_reflection']['locations'].append('body')
            if payload in str(response_headers):
                indicators['payload_reflection']['locations'].append('headers')
        
        # Check for error disclosure
        error_patterns = {
            'sql_error': [
                r'SQL syntax.*MySQL',
                r'Warning.*mysql_.*',
                r'valid MySQL result',
                r'PostgreSQL.*ERROR',
                r'Warning.*pg_.*',
                r'valid PostgreSQL result'
            ],
            'php_error': [
                r'<b>Fatal error</b>:.*in <b>',
                r'<b>Warning</b>:.*in <b>',
                r'<b>Parse error</b>:.*in <b>'
            ],
            'asp_error': [
                r'Microsoft VBScript runtime error',
                r'Microsoft JET Database Engine error'
            ]
        }
        
        indicators['error_disclosure'] = {"found": False, "type": "", "message": ""}
        
        for error_type, patterns in error_patterns.items():
            for pattern in patterns:
                if re.search(pattern, response_body, re.IGNORECASE):
                    indicators['error_disclosure'] = {
                        "found": True,
                        "type": error_type,
                        "message": re.search(pattern, response_body, re.IGNORECASE).group(0)[:100],
                        "stack_trace": False
                    }
                    break
        
        # Check for timing anomalies (basic implementation)
        baseline_time = context.get('baseline_response_time', 0.5) if context else 0.5
        indicators['timing_anomaly'] = {
            "baseline_ms": baseline_time * 1000,
            "current_ms": response_time * 1000,
            "significant": response_time > baseline_time * 3
        }
        
        # Status code changes
        baseline_status = context.get('baseline_status_code', 200) if context else 200
        indicators['status_changes'] = {
            "baseline": baseline_status,
            "current": status_code
        }
        
        return {"indicators": indicators}
    
    async def get_payloads(self, vulnerability_type: str, context: Dict[str, Any] = None, count: int = 10) -> Dict[str, Any]:
        """Get payloads for specific vulnerability types"""
        payloads = self.payload_db.get_payloads(vulnerability_type, context, count)
        return {"payloads": payloads, "total": len(payloads)}
    
    async def save_finding(self, vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        """Save vulnerability finding to database"""
        vuln = Vulnerability(**vulnerability)
        target_url = vulnerability.get('location', {}).get('url', 'unknown')
        vuln_id = await self.vuln_db.save_finding(vuln, target_url)
        return {"id": vuln_id, "status": "saved"}
    
    async def validate_target(self, url: str, scope_rules: Dict[str, Any] = None) -> Dict[str, Any]:
        """Validate if target is in scope and safe to test"""
        if scope_rules:
            # Update scope validator with custom rules
            allowed_domains = scope_rules.get('allowed_domains', [])
            if allowed_domains:
                self.scope_validator.allowed_domains = allowed_domains
        
        is_valid = await self.scope_validator.is_allowed(url)
        return {"valid": is_valid, "url": url}

# =============================================================================
# LLM Agent Implementation
# =============================================================================

class VulnScanAgent:
    """
    A 'smart' agent that uses an AI 'brain' (AIInterface)
    to call tools on a remote 'body' (MCPServer).
    """
    
    def __init__(self, mcp_server_url: str, ai_interface: AIInterface):
        self.ai_interface = ai_interface
        self.mcp_server_url = mcp_server_url
        self.mcp_session = None
        self.history = []
        self.max_steps = 25  # Safety brake to prevent infinite loops
        # Directory to persist agent steps and outputs
        self.output_dir = "output"
        os.makedirs(self.output_dir, exist_ok=True)

    async def __aenter__(self):
        """Create the session for the agent."""
        self.mcp_session = aiohttp.ClientSession()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Close the session for the agent."""
        if self.mcp_session:
            await self.mcp_session.close()

    async def _call_mcp_tool(self, tool_name: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Helper method to call the remote MCP server tool."""
        if not self.mcp_session:
            raise RuntimeError("Agent session not initialized.")
            
        url = f"{self.mcp_server_url}/call_tool"
        request_body = {"tool_name": tool_name, "params": params}
        
        try:
            # Give tools up to 5 minutes (300s) to run (e.g., for crawling)
            async with self.mcp_session.post(url, json=request_body, timeout=300.0) as response:
                if response.status == 200:
                    return await response.json()
                else:
                    error_detail = await response.text()
                    logger.error(f"MCP server error ({response.status}): {error_detail}")
                    return {"error": f"MCP Server Error: {response.status}", "detail": error_detail}
        except Exception as e:
            logger.error(f"Error calling MCP tool {tool_name}: {e}")
            return {"error": str(e)}

    async def run_goal(self, goal: str):
        """
        Runs the main agent loop to achieve a user-defined goal.
        """
        logger.info(f"Agent starting with goal: {goal}")
        self.history = []  # Reset history for each run
        
        for step in range(self.max_steps):
            logger.info(f"--- Agent Step {step + 1} ---")
            
            # 1. Ask the "brain" (LLM) what to do
            next_step = await self.ai_interface.decide_next_step(goal, self.history)
            
            if "final_answer" in next_step:
                # 4. Goal is complete
                logger.info("Agent has completed the goal.")
                # Persist final answer to output directory
                try:
                    final_record = {
                        "step": "final",
                        "final_answer": next_step["final_answer"],
                        "timestamp": time.time()
                    }
                    final_filename = f"agent_final_{int(final_record['timestamp'] * 1000)}.json"
                    final_path = os.path.join(self.output_dir, final_filename)
                    with open(final_path, 'w', encoding='utf-8') as ff:
                        json.dump(final_record, ff, indent=2, ensure_ascii=False)
                    logger.info(f"Saved agent final answer to {final_path}")
                except Exception as e:
                    logger.error(f"Failed to save final answer to output: {e}")

                print("\n" + "="*80)
                print("AGENT FINAL REPORT")
                print("="*80)
                print(next_step["final_answer"])
                break
                
            if "tool_name" in next_step:
                # 2. Brain decided to call a tool
                action = next_step
                tool_name = action["tool_name"]
                params = action["params"]

                # Log the agent's thought process
                if "thought" in action:
                    logger.info(f"Agent Thought: {action['thought']}")
                
                logger.info(f"Agent Action: Calling tool {tool_name} with params: {params}")
                
                # 3. Execute the tool call on the "body" (MCP Server)
                tool_result = await self._call_mcp_tool(tool_name, params)
                
                # Truncate large results (like crawl data) for history
                result_for_history = self._truncate_result(tool_result)
                
                logger.info(f"Tool Result (truncated): {json.dumps(result_for_history, indent=2)}")
                
                # Add the action and result to history for the next loop
                self.history.append({"action": action, "result": result_for_history})
                # Persist the full step (action + full result) to the output directory
                try:
                    step_record = {
                        "step": step + 1,
                        "action": action,
                        "result": tool_result,
                        "timestamp": time.time()
                    }
                    step_filename = f"agent_step_{step + 1}_{int(step_record['timestamp'] * 1000)}.json"
                    step_path = os.path.join(self.output_dir, step_filename)
                    with open(step_path, 'w', encoding='utf-8') as sf:
                        json.dump(step_record, sf, indent=2, ensure_ascii=False)
                    logger.info(f"Saved agent step to {step_path}")
                except Exception as e:
                    logger.error(f"Failed to save agent step to output: {e}")
            else:
                logger.warning(f"Invalid response from AI: {next_step}")
                print("Agent reasoning error, stopping.")
                break
        
        if step == self.max_steps - 1:
            logger.warning("Agent reached maximum steps, stopping.")
            print("Agent reached maximum steps, stopping.")

    def _truncate_result(self, result: Any, max_length: int = 2000) -> Any:
        """Truncates large tool results to avoid huge LLM context."""
        if isinstance(result, dict) and "body" in result:
             # Truncate response bodies
             result["body"] = result["body"][:max_length] + "... (truncated)"
        
        result_str = json.dumps(result)
        if len(result_str) > max_length:
            return {
                "summary": "Result is too large",
                "keys": list(result.keys()) if isinstance(result, dict) else "N/A",
                "note": "Original result truncated to fit context."
            }
        return result
    
# =============================================================================
# Main Execution and Usage Example
# =============================================================================

async def main():
    mcp_server_url = "http://127.0.0.1:8000"
    
    # === DEFINE YOUR GOAL HERE ===
    
    # Example 1: A full, comprehensive scan
    goal = "Validate and perform a comprehensive scan for XSS and SQLi on 'https://httpbin.org/forms/post'. Be thorough. Start by crawling, then test forms and endpoints you find. Report all findings."
    
    # Example 2: The intelligent, context-aware request you described
    # (To run this, run Example 1 first, then restart and run this)
    #goal = "I've already crawled 'https://httpbin.org/forms/post' and found a form. Just generate 3 good XSS payloads for an input named 'custname' and 'custemail'."

    # Example 3: A simple, single-tool request
    # goal = "Just get me 2 SQLi payloads for a 'username' parameter."

    try:
        logger.info("Initializing AI agent...")
        ai_interface = AIInterface()
        
        async with VulnScanAgent(mcp_server_url, ai_interface) as agent:
            await agent.run_goal(goal)
            
    except aiohttp.ClientConnectorError:
        logger.error(f"Failed to connect to MCP server at {mcp_server_url}. Is it running?")
        print(f"\nError: Cannot connect to MCP Server at {mcp_server_url}")
        print("Please ensure the server is running: uvicorn mcp_server_app:app --port 8000")
    except Exception as e:
        logger.error(f"Unexpected error in main: {e}", exc_info=True)

# =============================================================================
# Plugin System Example
# =============================================================================

class VulnScannerPlugin:
    """Base class for vulnerability scanner plugins"""
    
    def __init__(self):
        self.name = "base_plugin"
        self.tools = {}
    
    def register_tools(self) -> Dict[str, callable]:
        """Register additional MCP tools"""
        return self.tools
    
    def process_finding(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Post-process vulnerability findings"""
        return finding

class ZAPIntegrationPlugin(VulnScannerPlugin):
    """Example plugin for integrating OWASP ZAP scanner"""
    
    def __init__(self, zap_proxy_url: str = "http://localhost:8080"):
        super().__init__()
        self.name = "zap_integration"
        self.zap_proxy_url = zap_proxy_url
        self.tools = {
            "zap_active_scan": self.zap_active_scan,
            "zap_spider": self.zap_spider,
            "zap_get_alerts": self.zap_get_alerts
        }
    
    async def zap_active_scan(self, target_url: str) -> Dict[str, Any]:
        """Trigger ZAP active scan"""
        # Implementation would integrate with ZAP API
        return {"status": "scan_started", "target": target_url}
    
    async def zap_spider(self, target_url: str) -> Dict[str, Any]:
        """Trigger ZAP spider scan"""
        # Implementation would integrate with ZAP API
        return {"status": "spider_started", "target": target_url}
    
    async def zap_get_alerts(self, target_url: str) -> Dict[str, Any]:
        """Retrieve ZAP alerts"""
        # Implementation would retrieve ZAP findings
        return {"alerts": [], "count": 0}

# Entry point
if __name__ == "__main__":
    # Run the vulnerability scanner
    asyncio.run(main())