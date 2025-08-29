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
import sqlite3
from contextlib import asynccontextmanager
import hashlib

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
    """SQLite database for storing vulnerability findings"""
    
    def __init__(self, db_path: str = "vulnerabilities.db"):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """Initialize database schema"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS vulnerabilities (
                    id TEXT PRIMARY KEY,
                    type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT,
                    location TEXT,
                    evidence TEXT,
                    remediation TEXT,
                    confidence REAL,
                    timestamp REAL,
                    target_url TEXT
                )
            """)
            conn.commit()
    
    async def save_finding(self, vulnerability: Vulnerability, target_url: str):
        """Save vulnerability finding to database"""
        vuln_id = hashlib.sha256(
            f"{vulnerability.type}_{vulnerability.location}_{target_url}".encode()
        ).hexdigest()[:16]
        
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT OR REPLACE INTO vulnerabilities 
                (id, type, severity, title, description, location, evidence, 
                 remediation, confidence, timestamp, target_url)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                vuln_id, vulnerability.type, vulnerability.severity,
                vulnerability.title, vulnerability.description,
                json.dumps(vulnerability.location), json.dumps(vulnerability.evidence),
                vulnerability.remediation, vulnerability.confidence,
                vulnerability.timestamp, target_url
            ))
            conn.commit()
        
        logger.info(f"Saved vulnerability finding: {vuln_id}")
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
    
    def __init__(self):
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
    """AI agent that orchestrates vulnerability scanning using MCP tools"""
    
    def __init__(self, mcp_server: MCPServer):
        self.mcp_server = mcp_server
        self.context = {}
        self.attack_plan = {}
        self.findings = []
    
    async def reconnaissance_phase(self, target_url: str) -> Dict[str, Any]:
        """Phase 1: Discover attack surface and plan testing strategy"""
        logger.info(f"Starting reconnaissance phase for {target_url}")
        
        # Validate target is in scope
        validation = await self.mcp_server.call_tool("validate_target", {"url": target_url})
        if not validation.get("valid"):
            raise SecurityError("Target validation failed")
        
        # Crawl target to discover attack surface
        crawl_result = await self.mcp_server.call_tool("crawl_site", {
            "seed_url": target_url,
            "depth": 2
        })
        
        # Analyze discovered information to build context
        self.context = self._analyze_stack(crawl_result)
        
        # Generate attack plan based on discovered attack surface
        self.attack_plan = self._generate_attack_plan(crawl_result)
        
        logger.info(f"Discovered {len(crawl_result['endpoints'])} endpoints and {len(crawl_result['forms'])} forms")
        
        return self.attack_plan
    
    def _analyze_stack(self, crawl_result: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze crawled data to understand technology stack and context"""
        context = {
            "technologies": crawl_result.get("static_analysis", {}).get("technologies", []),
            "endpoints": crawl_result.get("endpoints", []),
            "forms": crawl_result.get("forms", []),
            "parameters": set()
        }
        
        # Extract all parameters for testing
        for endpoint in crawl_result.get("endpoints", []):
            context["parameters"].update(endpoint.get("parameters", []))
        
        # Determine likely technologies based on headers and content
        for endpoint in crawl_result.get("endpoints", []):
            headers = endpoint.get("headers_observed", {})
            if "x-powered-by" in headers:
                context["technologies"].append(headers["x-powered-by"])
        
        context["parameters"] = list(context["parameters"])
        return context
    
    def _generate_attack_plan(self, crawl_result: Dict[str, Any]) -> Dict[str, Any]:
        """Generate comprehensive attack plan based on discovered attack surface"""
        plan = {
            "targets": [],
            "vulnerability_types": [],
            "priority_order": []
        }
        
        # Generate targets from endpoints
        for endpoint in crawl_result.get("endpoints", []):
            for param in endpoint.get("parameters", []):
                plan["targets"].append({
                    "url": endpoint["url"],
                    "injection_point": {
                        "type": "query_param",
                        "name": param
                    },
                    "method": endpoint.get("method", "GET")
                })
        
        # Generate targets from forms
        for form in crawl_result.get("forms", []):
            for input_field in form.get("inputs", []):
                plan["targets"].append({
                    "url": form["action"],
                    "injection_point": {
                        "type": "form_field",
                        "name": input_field["name"]
                    },
                    "method": form.get("method", "POST")
                })
        
        # Determine which vulnerability types to test based on context
        detected_techs = [tech.lower() for tech in self.context.get("technologies", [])]
        
        # Always test for these common vulnerabilities
        plan["vulnerability_types"] = [VulnType.XSS.value]
        
        # Add SQL injection if database technologies detected
        if any(tech in detected_techs for tech in ['mysql', 'postgresql', 'php', 'asp']):
            plan["vulnerability_types"].append(VulnType.SQLI.value)
        
        # Add SSRF for all targets (common attack vector)
        plan["vulnerability_types"].append(VulnType.SSRF.value)
        
        # Add LFI for PHP applications
        if any(tech in detected_techs for tech in ['php', 'apache']):
            plan["vulnerability_types"].append(VulnType.LFI.value)
        
        # Prioritize testing order
        plan["priority_order"] = self._prioritize_tests(plan["targets"])
        
        return plan
    
    def _prioritize_tests(self, targets: List[Dict[str, Any]]) -> List[int]:
        """Prioritize testing order based on likelihood of success"""
        # Simple prioritization - in practice, use ML models or heuristics
        priority_scores = []
        
        for i, target in enumerate(targets):
            score = 0
            
            # Higher priority for form inputs (more likely to be vulnerable)
            if target["injection_point"]["type"] == "form_field":
                score += 3
            
            # Higher priority for parameters with suspicious names
            param_name = target["injection_point"]["name"].lower()
            if any(keyword in param_name for keyword in ['id', 'user', 'file', 'url', 'path']):
                score += 2
            
            # Higher priority for POST requests
            if target.get("method", "GET").upper() == "POST":
                score += 1
            
            priority_scores.append((score, i))
        
        # Return indices sorted by priority score (highest first)
        return [idx for _, idx in sorted(priority_scores, reverse=True)]
    
    async def test_vulnerability_type(self, vuln_type: str, targets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Test specific vulnerability type against discovered targets"""
        logger.info(f"Testing {vuln_type} against {len(targets)} targets")
        
        # Get contextual payloads for this vulnerability type
        payload_result = await self.mcp_server.call_tool("get_payloads", {
            "vulnerability_type": vuln_type,
            "context": self.context,
            "count": 15
        })
        
        payloads = payload_result["payloads"]
        findings = []
        
        # Test each target with each payload
        for target in targets:
            # First, get baseline response for comparison
            baseline_response = await self._get_baseline_response(target)
            
            for payload in payloads:
                try:
                    # Inject payload and capture response
                    response = await self.mcp_server.call_tool("inject_payload", {
                        "url": target["url"],
                        "injection_point": target["injection_point"],
                        "payload": payload,
                        "method": target.get("method", "GET")
                    })
                    
                    # Analyze response for vulnerability indicators
                    analysis = await self.mcp_server.call_tool("analyze_response", {
                        "request": {"payload": payload, "target": target},
                        "response": response,
                        "vulnerability_types": [vuln_type],
                        "context": {
                            "baseline_response_time": baseline_response.get("response_time", 0.5),
                            "baseline_status_code": baseline_response.get("status_code", 200)
                        }
                    })
                    
                    # Use AI reasoning to determine if this indicates a vulnerability
                    if self._is_vulnerable(analysis, vuln_type, payload, response):
                        finding = self._classify_vulnerability(target, payload, analysis, vuln_type)
                        findings.append(finding)
                        logger.info(f"Potential {vuln_type} vulnerability found in {target['url']}")
                
                except Exception as e:
                    logger.warning(f"Error testing payload {payload} on {target['url']}: {e}")
                    continue
        
        return findings
    
    async def _get_baseline_response(self, target: Dict[str, Any]) -> Dict[str, Any]:
        """Get baseline response for comparison purposes"""
        try:
            return await self.mcp_server.call_tool("send_request", {
                "method": target.get("method", "GET"),
                "url": target["url"]
            })
        except Exception:
            return {"response_time": 0.5, "status_code": 200}
    
    def _is_vulnerable(self, analysis: Dict[str, Any], vuln_type: str, payload: str, response: Dict[str, Any]) -> bool:
        """AI reasoning to determine if response indicates vulnerability"""
        indicators = analysis.get("indicators", {})
        
        # XSS Detection Logic
        if vuln_type == VulnType.XSS.value:
            reflection = indicators.get("payload_reflection", {})
            if reflection.get("found") and not reflection.get("encoded"):
                # Payload reflected without encoding - likely XSS
                return True
            
            # Check for successful script execution indicators
            if "<script>" in payload and reflection.get("found"):
                return True
        
        # SQL Injection Detection Logic
        elif vuln_type == VulnType.SQLI.value:
            error_disclosure = indicators.get("error_disclosure", {})
            if error_disclosure.get("found") and error_disclosure.get("type") == "sql_error":
                return True
            
            # Check for timing-based SQL injection
            timing = indicators.get("timing_anomaly", {})
            if "WAITFOR" in payload or "SLEEP" in payload:
                if timing.get("significant"):
                    return True
            
            # Check for boolean-based SQL injection
            status_changes = indicators.get("status_changes", {})
            if "'1'='1" in payload and status_changes.get("baseline") != status_changes.get("current"):
                return True
        
        # SSRF Detection Logic
        elif vuln_type == VulnType.SSRF.value:
            # Check if response indicates successful connection to internal services
            response_body = response.get("body", "")
            if any(indicator in response_body.lower() for indicator in [
                "connection refused", "timeout", "internal server", "metadata"
            ]):
                return True
        
        # LFI Detection Logic
        elif vuln_type == VulnType.LFI.value:
            response_body = response.get("body", "")
            # Check for file inclusion indicators
            if any(indicator in response_body for indicator in [
                "root:x:", "daemon:x:", "[boot loader]", "windows\\system32"
            ]):
                return True
        
        return False
    
    def _classify_vulnerability(self, target: Dict[str, Any], payload: str, analysis: Dict[str, Any], vuln_type: str) -> Dict[str, Any]:
        """Classify and score vulnerability finding using AI reasoning"""
        indicators = analysis.get("indicators", {})
        
        # Calculate confidence score based on evidence strength
        confidence = self._calculate_confidence(indicators, vuln_type, payload)
        
        # Assess severity based on vulnerability type and context
        severity = self._assess_severity(target, vuln_type, indicators)
        
        # Generate human-readable title and description
        title = self._generate_title(target, vuln_type, payload)
        description = self._generate_description(vuln_type, payload, indicators)
        remediation = self._generate_remediation(vuln_type, target)
        
        vulnerability = {
            "type": vuln_type,
            "severity": severity.value,
            "title": title,
            "description": description,
            "location": {
                "url": target["url"],
                "parameter": target["injection_point"]["name"],
                "injection_type": target["injection_point"]["type"],
                "method": target.get("method", "GET")
            },
            "evidence": {
                "payload": payload,
                "indicators": indicators,
                "response_excerpt": ""  # Would include relevant response portions
            },
            "remediation": remediation,
            "confidence": confidence
        }
        
        return vulnerability
    
    def _calculate_confidence(self, indicators: Dict[str, Any], vuln_type: str, payload: str) -> float:
        """Calculate confidence score for vulnerability finding"""
        confidence = 0.0
        
        # Base confidence on evidence strength
        if indicators.get("payload_reflection", {}).get("found"):
            confidence += 0.4
        
        if indicators.get("error_disclosure", {}).get("found"):
            confidence += 0.5
        
        if indicators.get("timing_anomaly", {}).get("significant"):
            confidence += 0.3
        
        # Adjust based on vulnerability type specifics
        if vuln_type == VulnType.XSS.value:
            reflection = indicators.get("payload_reflection", {})
            if reflection.get("found") and not reflection.get("encoded"):
                confidence += 0.3
        
        elif vuln_type == VulnType.SQLI.value:
            error = indicators.get("error_disclosure", {})
            if error.get("type") == "sql_error":
                confidence += 0.4
        
        return min(confidence, 1.0)  # Cap at 1.0
    
    def _assess_severity(self, target: Dict[str, Any], vuln_type: str, indicators: Dict[str, Any]) -> Severity:
        """Assess vulnerability severity based on type and context"""
        # Base severity mappings
        base_severity = {
            VulnType.XSS.value: Severity.MEDIUM,
            VulnType.SQLI.value: Severity.HIGH,
            VulnType.SSRF.value: Severity.HIGH,
            VulnType.LFI.value: Severity.MEDIUM,
            VulnType.RCE.value: Severity.CRITICAL,
            VulnType.XXE.value: Severity.HIGH
        }
        
        severity = base_severity.get(vuln_type, Severity.MEDIUM)
        
        # Adjust severity based on context
        url = target.get("url", "").lower()
        
        # Admin interfaces are more critical
        if any(admin_path in url for admin_path in ["/admin", "/dashboard", "/panel"]):
            if severity == Severity.MEDIUM:
                severity = Severity.HIGH
            elif severity == Severity.HIGH:
                severity = Severity.CRITICAL
        
        # Authentication forms are critical
        param_name = target.get("injection_point", {}).get("name", "").lower()
        if any(auth_param in param_name for auth_param in ["password", "username", "login"]):
            if severity == Severity.MEDIUM:
                severity = Severity.HIGH
        
        return severity
    
    def _generate_title(self, target: Dict[str, Any], vuln_type: str, payload: str) -> str:
        """Generate human-readable vulnerability title"""
        vuln_names = {
            VulnType.XSS.value: "Cross-Site Scripting (XSS)",
            VulnType.SQLI.value: "SQL Injection",
            VulnType.SSRF.value: "Server-Side Request Forgery (SSRF)",
            VulnType.LFI.value: "Local File Inclusion (LFI)",
            VulnType.RCE.value: "Remote Code Execution (RCE)",
            VulnType.XXE.value: "XML External Entity (XXE)"
        }
        
        vuln_name = vuln_names.get(vuln_type, vuln_type.upper())
        param_name = target.get("injection_point", {}).get("name", "parameter")
        
        return f"{vuln_name} in '{param_name}' parameter"
    
    def _generate_description(self, vuln_type: str, payload: str, indicators: Dict[str, Any]) -> str:
        """Generate detailed vulnerability description"""
        descriptions = {
            VulnType.XSS.value: f"The application reflects user input without proper encoding, allowing JavaScript execution. The payload '{payload}' was successfully reflected in the response.",
            VulnType.SQLI.value: f"The application appears vulnerable to SQL injection. The payload '{payload}' triggered database errors or unusual behavior.",
            VulnType.SSRF.value: f"The application may be vulnerable to Server-Side Request Forgery, allowing requests to internal services. The payload '{payload}' indicated potential SSRF behavior.",
            VulnType.LFI.value: f"The application may allow reading of arbitrary files on the server. The payload '{payload}' showed signs of file inclusion vulnerability."
        }
        
        base_desc = descriptions.get(vuln_type, f"Potential {vuln_type} vulnerability detected with payload: {payload}")
        
        # Add evidence details
        evidence_details = []
        if indicators.get("payload_reflection", {}).get("found"):
            evidence_details.append("Payload was reflected in the response")
        if indicators.get("error_disclosure", {}).get("found"):
            error_type = indicators["error_disclosure"].get("type", "unknown")
            evidence_details.append(f"Application disclosed {error_type} errors")
        if indicators.get("timing_anomaly", {}).get("significant"):
            evidence_details.append("Response timing anomalies detected")
        
        if evidence_details:
            base_desc += " Evidence includes: " + ", ".join(evidence_details) + "."
        
        return base_desc
    
    def _generate_remediation(self, vuln_type: str, target: Dict[str, Any]) -> str:
        """Generate remediation guidance"""
        remediation_guides = {
            VulnType.XSS.value: "Implement proper input validation and output encoding. Use Content Security Policy (CSP) headers to prevent script execution.",
            VulnType.SQLI.value: "Use parameterized queries or prepared statements. Implement proper input validation and avoid dynamic SQL construction.",
            VulnType.SSRF.value: "Implement URL validation and whitelist allowed destinations. Disable unused protocols and block internal network ranges.",
            VulnType.LFI.value: "Implement proper input validation and use absolute paths. Avoid user-controlled file inclusion and use secure file handling functions."
        }
        
        return remediation_guides.get(vuln_type, "Implement proper input validation and security controls.")
    
    async def comprehensive_scan(self, target_url: str) -> Dict[str, Any]:
        """Run complete vulnerability scan against target"""
        logger.info(f"Starting comprehensive scan of {target_url}")
        
        # Phase 1: Reconnaissance
        attack_plan = await self.reconnaissance_phase(target_url)
        
        # Phase 2: Vulnerability Testing
        all_findings = []
        
        for vuln_type in attack_plan["vulnerability_types"]:
            logger.info(f"Testing for {vuln_type} vulnerabilities")
            
            # Get prioritized targets for this vulnerability type
            prioritized_indices = attack_plan["priority_order"]
            prioritized_targets = [attack_plan["targets"][i] for i in prioritized_indices[:10]]  # Limit to top 10
            
            findings = await self.test_vulnerability_type(vuln_type, prioritized_targets)
            all_findings.extend(findings)
            
            # Save findings as we discover them
            for finding in findings:
                await self.mcp_server.call_tool("save_finding", {"vulnerability": finding})
        
        # Phase 3: Generate comprehensive report
        report = self._generate_report(target_url, all_findings, attack_plan)
        
        logger.info(f"Scan complete. Found {len(all_findings)} potential vulnerabilities")
        return report
    
    def _generate_report(self, target_url: str, findings: List[Dict[str, Any]], attack_plan: Dict[str, Any]) -> Dict[str, Any]:
        """Generate comprehensive scan report"""
        # Categorize findings by severity
        severity_counts = {severity.value: 0 for severity in Severity}
        for finding in findings:
            severity_counts[finding["severity"]] += 1
        
        # Calculate risk score
        risk_score = self._calculate_risk_score(findings)
        
        report = {
            "scan_summary": {
                "target": target_url,
                "timestamp": time.time(),
                "total_findings": len(findings),
                "severity_breakdown": severity_counts,
                "risk_score": risk_score,
                "targets_tested": len(attack_plan.get("targets", [])),
                "vulnerability_types_tested": attack_plan.get("vulnerability_types", [])
            },
            "findings": findings,
            "recommendations": self._generate_recommendations(findings),
            "attack_surface": {
                "endpoints_discovered": len(self.context.get("endpoints", [])),
                "forms_discovered": len(self.context.get("forms", [])),
                "parameters_discovered": len(self.context.get("parameters", [])),
                "technologies_detected": self.context.get("technologies", [])
            }
        }
        
        return report
    
    def _calculate_risk_score(self, findings: List[Dict[str, Any]]) -> float:
        """Calculate overall risk score for the application"""
        if not findings:
            return 0.0
        
        severity_weights = {
            Severity.CRITICAL.value: 10.0,
            Severity.HIGH.value: 7.5,
            Severity.MEDIUM.value: 5.0,
            Severity.LOW.value: 2.5,
            Severity.INFO.value: 1.0
        }
        
        total_score = 0.0
        for finding in findings:
            severity = finding.get("severity", "info")
            confidence = finding.get("confidence", 0.5)
            weight = severity_weights.get(severity, 1.0)
            total_score += weight * confidence
        
        # Normalize to 0-10 scale
        max_possible = len(findings) * 10.0
        return min((total_score / max_possible) * 10, 10.0) if max_possible > 0 else 0.0
    
    def _generate_recommendations(self, findings: List[Dict[str, Any]]) -> List[str]:
        """Generate high-level security recommendations"""
        recommendations = []
        
        # Count vulnerability types
        vuln_counts = {}
        for finding in findings:
            vuln_type = finding.get("type", "unknown")
            vuln_counts[vuln_type] = vuln_counts.get(vuln_type, 0) + 1
        
        # Generate recommendations based on findings
        if VulnType.XSS.value in vuln_counts:
            recommendations.append("Implement comprehensive input validation and output encoding throughout the application")
            recommendations.append("Deploy Content Security Policy (CSP) headers to mitigate XSS attacks")
        
        if VulnType.SQLI.value in vuln_counts:
            recommendations.append("Migrate to parameterized queries and prepared statements for all database interactions")
            recommendations.append("Implement database-level access controls and principle of least privilege")
        
        if VulnType.SSRF.value in vuln_counts:
            recommendations.append("Implement strict URL validation and whitelist allowed external services")
            recommendations.append("Deploy network segmentation to limit server-side request capabilities")
        
        # General recommendations
        if findings:
            recommendations.extend([
                "Conduct regular security code reviews and penetration testing",
                "Implement a Web Application Firewall (WAF) as an additional layer of protection",
                "Establish a vulnerability management program with regular security assessments"
            ])
        
        return recommendations

# =============================================================================
# Main Execution and Usage Example
# =============================================================================

async def main():
    """Main function demonstrating usage of the MCP vulnerability scanner"""
    
    # Configure the scanner with scope restrictions
    target_url = "https://juice-shop.herokuapp.com/#/"  # Replace with actual target
    
    # Initialize MCP server and agent
    async with MCPServer() as mcp_server:
        # Configure scope (important for safety!)
        mcp_server.scope_validator.allowed_domains = ["juice-shop.herokuapp.com"]
        mcp_server.scope_validator.blocked_paths = ["/admin", "/system", "/private"]
        
        # Initialize AI agent
        agent = VulnScanAgent(mcp_server)
        
        try:
            # Run comprehensive vulnerability scan
            logger.info("Starting comprehensive vulnerability scan...")
            report = await agent.comprehensive_scan(target_url)
            
            # Display results
            print("\n" + "="*80)
            print("VULNERABILITY SCAN REPORT")
            print("="*80)
            print(f"Target: {report['scan_summary']['target']}")
            print(f"Total Findings: {report['scan_summary']['total_findings']}")
            print(f"Risk Score: {report['scan_summary']['risk_score']:.1f}/10.0")
            
            print("\nSeverity Breakdown:")
            for severity, count in report['scan_summary']['severity_breakdown'].items():
                if count > 0:
                    print(f"  {severity.upper()}: {count}")
            
            print(f"\nAttack Surface:")
            attack_surface = report['attack_surface']
            print(f"  Endpoints: {attack_surface['endpoints_discovered']}")
            print(f"  Forms: {attack_surface['forms_discovered']}")
            print(f"  Parameters: {attack_surface['parameters_discovered']}")
            print(f"  Technologies: {', '.join(attack_surface['technologies_detected'])}")
            
            if report['findings']:
                print(f"\nTop Vulnerabilities:")
                for i, finding in enumerate(report['findings'][:5], 1):
                    print(f"  {i}. {finding['title']} - {finding['severity'].upper()} ({finding['confidence']:.1%} confidence)")
            
            print(f"\nKey Recommendations:")
            for i, rec in enumerate(report['recommendations'][:3], 1):
                print(f"  {i}. {rec}")
            
        except SecurityError as e:
            logger.error(f"Security constraint violation: {e}")
        except Exception as e:
            logger.error(f"Scan failed: {e}")

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