import asyncio
import json
import re
import time
import urllib.parse
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from enum import Enum
import aiohttp
import logging
from abc import ABC, abstractmethod
from contextlib import asynccontextmanager
import hashlib
import os
from bs4 import BeautifulSoup
from src.AIInterface import AIInterface

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# =============================================================================
# Data Models and Enums (Unchanged)
# =============================================================================

class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class VulnType(Enum):
    XSS = "xss"
    SQLI = "sqli"
    SSRF = "ssrf"
    LFI = "lfi"
    RCE = "rce"
    XXE = "xxe"

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
# Safety and Core Components (Enhanced with limits)
# =============================================================================

class RateLimiter:
    """Rate limiting to prevent overwhelming target servers"""
    def __init__(self, requests_per_minute: int = 30):
        self.requests_per_minute = requests_per_minute
        self.requests = []
        self.lock = asyncio.Lock()

    async def acquire(self):
        async with self.lock:
            now = time.time()
            self.requests = [req_time for req_time in self.requests if now - req_time < 60]
            if len(self.requests) >= self.requests_per_minute:
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
        self.dangerous_patterns = [r'rm\s+-rf', r'format\s+c:', r'del\s+/[qsf]', r'DROP\s+DATABASE', r'TRUNCATE\s+TABLE']

    async def is_allowed(self, url: str) -> bool:
        try:
            parsed = urllib.parse.urlparse(url)
            domain = parsed.netloc.lower()
            path = parsed.path
            
            if self.allowed_domains and not any(domain.endswith(allowed.lower()) for allowed in self.allowed_domains):
                logger.warning(f"Domain {domain} not in allowed list")
                return False
            if any(path.startswith(blocked_path) for blocked_path in self.blocked_paths):
                logger.warning(f"Path {path} is blocked")
                return False
            return True
        except Exception as e:
            logger.error(f"Error validating URL {url}: {e}")
            return False

    def is_payload_safe(self, payload: str) -> bool:
        if any(re.search(pattern, payload, re.IGNORECASE) for pattern in self.dangerous_patterns):
            logger.warning(f"Dangerous payload pattern detected in: {payload}")
            return False
        return True

class SecurityError(Exception):
    """Raised when security constraints are violated"""
    pass

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

        # Ensure nested fields are JSON-serializable (location, evidence)
        try:
            data['location'] = json.loads(json.dumps(data.get('location', {}), default=str))
        except Exception:
            data['location'] = str(data.get('location'))
        try:
            data['evidence'] = json.loads(json.dumps(data.get('evidence', {}), default=str))
        except Exception:
            data['evidence'] = str(data.get('evidence'))

        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            logger.info(f"Saved vulnerability finding to {file_path}")
        except Exception as e:
            logger.error(f"Failed to save finding {vuln_id} to {file_path}: {e}")
            raise

        return vuln_id

# =============================================================================
# PayloadDatabase to use AI
# =============================================================================
class PayloadDatabase:
    """Payload database that uses an LLM for context-aware payload generation"""
    def __init__(self, ai_interface: AIInterface):
        self.ai_interface = ai_interface
        self.fallback_payloads = {
            VulnType.XSS.value: ["<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>"],
            VulnType.SQLI.value: ["' OR '1'='1", "'; DROP TABLE users;--"],
        }

    async def get_payloads(self, vuln_type: str, context: Dict[str, Any] = None, count: int = 10) -> List[str]:
        if not context:
            return self.fallback_payloads.get(vuln_type, [])[:count]
        try:
            # Add timeout for AI payload generation
            payloads = await asyncio.wait_for(
                self.ai_interface.generate_payloads(vuln_type, context, count),
                timeout=30.0  # 30 second timeout
            )
            if payloads:
                return payloads
        except asyncio.TimeoutError:
            logger.warning("AI payload generation timed out. Using fallback payloads.")
        except Exception as e:
            logger.warning(f"AI payload generation failed: {e}. Using fallback payloads.")
        return self.fallback_payloads.get(vuln_type, [])[:count]


class WebCrawler:
    """Web crawler using BeautifulSoup for robust parsing with limits."""
    def __init__(self, session: aiohttp.ClientSession, max_pages: int = 50, max_depth: int = 3):
        self.session = session
        self.visited_urls = set()
        self.discovered_endpoints = []
        self.discovered_forms = []
        self.page_bodies = {}
        self.max_pages = max_pages  # Limit total pages crawled
        self.max_depth = max_depth  # Limit crawl depth
        self.pages_crawled = 0

    async def crawl_site(self, seed_url: str, depth: int = 2, scope_domains: List[str] = None):
        # Enforce maximum depth limit
        depth = min(depth, self.max_depth)
        logger.info(f"Starting crawl of {seed_url} with depth {depth} (max pages: {self.max_pages})")
        
        base_domain = urllib.parse.urlparse(seed_url).netloc
        await self._crawl_recursive(seed_url, depth, scope_domains or [base_domain])
        
        logger.info(f"Crawl completed. Visited {len(self.visited_urls)} pages, found {len(self.discovered_endpoints)} endpoints, {len(self.discovered_forms)} forms")
        return {
            "endpoints": self.discovered_endpoints,
            "forms": self.discovered_forms,
        }

    def _extract_forms(self, soup: BeautifulSoup, base_url: str):
        forms = soup.find_all('form')
        logger.debug(f"Found {len(forms)} forms on {base_url}")
        for form in forms:
            try:
                action = form.get('action', '')
                method = form.get('method', 'GET').upper()
                action_url = urllib.parse.urljoin(base_url, action)
                inputs = []
                for input_tag in form.find_all(['input', 'textarea', 'select']):
                    name = input_tag.get('name')
                    if name:
                        inputs.append({"name": name, "type": input_tag.get('type', 'text')})
                form_data = {"action": action_url, "method": method, "inputs": inputs}
                if form_data not in self.discovered_forms:
                    self.discovered_forms.append(form_data)
            except Exception as e:
                logger.warning(f"Error extracting form from {base_url}: {e}")

    def _extract_links(self, soup: BeautifulSoup, base_url: str):
        urls = set()
        try:
            # Limit link extraction to avoid excessive processing
            max_links = 100  # Limit number of links per page
            link_count = 0
            
            # <a href>
            for tag in soup.find_all('a', href=True):
                if link_count >= max_links:
                    break
                urls.add(urllib.parse.urljoin(base_url, tag['href']))
                link_count += 1
            
            # <form action> (already limited by form extraction)
            for tag in soup.find_all('form', action=True):
                urls.add(urllib.parse.urljoin(base_url, tag['action']))
                
        except Exception as e:
            logger.warning(f"Error extracting links from {base_url}: {e}")
        
        return urls

    async def _crawl_recursive(self, url: str, depth: int, scope_domains: List[str]):
        # Check limits first
        if (depth <= 0 or 
            url in self.visited_urls or 
            self.pages_crawled >= self.max_pages):
            return
            
        try:
            parsed_url = urllib.parse.urlparse(url)
            if not any(domain in parsed_url.netloc for domain in scope_domains):
                return
                
            self.visited_urls.add(url)
            self.pages_crawled += 1
            
            logger.debug(f"Crawling {url} (depth: {depth}, pages crawled: {self.pages_crawled})")
            
            async with self.session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as response:
                if response.status == 200 and 'text/html' in response.headers.get('Content-Type', ''):
                    content = await response.text()
                    # Limit content size to prevent memory issues
                    if len(content) > 1024 * 1024:  # 1MB limit
                        content = content[:1024 * 1024]
                        
                    self.page_bodies[url] = content
                    soup = BeautifulSoup(content, 'html.parser')
                    
                    # Discover endpoints from URL parameters
                    query_params = list(urllib.parse.parse_qs(parsed_url.query).keys())
                    if query_params:  # Only add if there are parameters
                        endpoint_info = {
                            "url": url, 
                            "method": "GET",
                            "parameters": query_params
                        }
                        if endpoint_info not in self.discovered_endpoints:
                            self.discovered_endpoints.append(endpoint_info)
                    
                    # Discover forms on the page
                    self._extract_forms(soup, url)
                    
                    # Continue crawling if we haven't hit limits
                    if depth > 1 and self.pages_crawled < self.max_pages:
                        links = self._extract_links(soup, url)
                        # Limit concurrent crawling to prevent overwhelming
                        semaphore = asyncio.Semaphore(5)  # Max 5 concurrent requests
                        
                        async def crawl_with_semaphore(link):
                            async with semaphore:
                                await self._crawl_recursive(link, depth - 1, scope_domains)
                        
                        # Process links in batches to avoid creating too many tasks
                        links_list = list(links)[:20]  # Limit to 20 links per page
                        await asyncio.gather(*[crawl_with_semaphore(link) for link in links_list], return_exceptions=True)
                        
        except asyncio.TimeoutError:
            logger.warning(f"Timeout crawling {url}")
        except Exception as e:
            logger.warning(f"Error crawling {url}: {e}")

# =============================================================================
# MCPServer with enhanced limits
# =============================================================================
class MCPServer:
    """Main MCP Server handling all vulnerability scanning operations"""
    
    def __init__(self,ai_interface: AIInterface):
        self.rate_limiter = RateLimiter(requests_per_minute=30)
        self.scope_validator = ScopeValidator()
        self.payload_db = PayloadDatabase(ai_interface)
        self.vuln_db = VulnerabilityDatabase()
        self.session = None
        self.tools = {
            "crawl_site": self.crawl_site, "send_request": self.send_request,
            "inject_payload": self.inject_payload, "analyze_response": self.analyze_response,
            "save_finding": self.save_finding, "get_payloads": self.get_payloads,
            "validate_target": self.validate_target,
        }

    async def __aenter__(self):
        # Configure session with timeouts
        timeout = aiohttp.ClientTimeout(total=30, connect=10)
        self.session = aiohttp.ClientSession(timeout=timeout)
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session: 
            await self.session.close()

    async def call_tool(self, tool_name: str, params: Dict[str, Any]) -> Dict[str, Any]:
        if tool_name not in self.tools: 
            raise ValueError(f"Unknown tool: {tool_name}")
        await self._validate_request(tool_name, params)
        tool_func = self.tools[tool_name]
        try:
            # Add timeout for tool execution
            result = await asyncio.wait_for(tool_func(**params), timeout=60.0)
            logger.info(f"Tool {tool_name} executed successfully")
            return result
        except asyncio.TimeoutError:
            logger.error(f"Tool {tool_name} timed out")
            return {"error": "Tool execution timed out"}

    async def _validate_request(self, tool_name: str, params: Dict[str, Any]):
        if tool_name in ['inject_payload', 'send_request']:
            url = params.get('url')
            if url and not await self.scope_validator.is_allowed(url):
                raise SecurityError("Target outside allowed scope")
            payload = params.get('payload')
            if payload and not self.scope_validator.is_payload_safe(payload):
                raise SecurityError("Dangerous payload detected")
            await self.rate_limiter.acquire()

    async def crawl_site(self, seed_url: str, depth: int = 2, scope_domains: List[str] = None):
        # Limit crawl parameters
        depth = min(depth, 3)  # Max depth of 3
        crawler = WebCrawler(self.session, max_pages=50, max_depth=depth)
        return await crawler.crawl_site(seed_url, depth, scope_domains)
    
    async def send_request(self, method: str, url: str, headers: Dict[str, str] = None, body: Any = None, **kwargs):
        start_time = time.time()
        try:
            # For form submissions, body might be a dict
            if isinstance(body, dict):
                headers = headers or {}
                headers.setdefault('Content-Type', 'application/x-www-form-urlencoded')
                body = urllib.parse.urlencode(body)

            # Add timeout to individual requests
            timeout = aiohttp.ClientTimeout(total=15)
            async with self.session.request(method=method, url=url, headers=headers or {}, 
                                          data=body, timeout=timeout, **kwargs) as response:
                response_body = await response.text()
                return {
                    "status_code": response.status, 
                    "headers": dict(response.headers), 
                    "body": response_body,
                    "response_time": time.time() - start_time,
                }
        except Exception as e:
            logger.warning(f"Request failed for {url}: {e}")
            return {"error": str(e), "response_time": time.time() - start_time}
    
    async def inject_payload(self, url: str, injection_point: Dict[str, Any], payload: str, method: str = "GET", **kwargs):
        try:
            modified_url = url
            headers = kwargs.get('headers', {})
            body = kwargs.get('data', None)

            if injection_point['type'] == 'query_param':
                parsed = urllib.parse.urlparse(url)
                params = urllib.parse.parse_qs(parsed.query)
                params[injection_point['name']] = [payload]
                new_query = urllib.parse.urlencode(params, doseq=True)
                modified_url = parsed._replace(query=new_query).geturl()
                return await self.send_request(method, modified_url, headers, body)
            
            elif injection_point['type'] == 'form_field':
                body = {injection_point['name']: payload}
                return await self.send_request(method, modified_url, headers, body)

            return await self.send_request(method, modified_url, headers, body)
        except Exception as e:
            logger.error(f"Payload injection failed: {e}")
            return {"error": str(e)}

    async def analyze_response(self, request: Dict[str, Any], response: Dict[str, Any], **kwargs) -> Dict[str, Any]:
        try:
            indicators = {}
            payload = request.get('payload', '')
            response_body = response.get('body', '')
            
            # Basic analysis
            indicators['payload_reflection'] = {"found": payload in response_body}
            sql_error_patterns = [r'SQL syntax.*MySQL', r'Warning.*mysql_', r'ORA-\d+', r'Microsoft.*ODBC.*SQL']
            indicators['error_disclosure'] = {"found": any(re.search(p, response_body, re.I) for p in sql_error_patterns)}
            
            return {"indicators": indicators}
        except Exception as e:
            logger.error(f"Response analysis failed: {e}")
            return {"indicators": {}}

    async def get_payloads(self, vulnerability_type: str, context: Dict[str, Any] = None, count: int = 10):
        # Limit payload count
        count = min(count, 5)  # Max 5 payloads per request
        payloads = await self.payload_db.get_payloads(vulnerability_type, context, count)
        return {"payloads": payloads}

    async def save_finding(self, vulnerability: Dict[str, Any]):
        try:
            target_url = vulnerability.get('location', {}).get('url', 'unknown')
            vuln_id = await self.vuln_db.save_finding(vulnerability, target_url)
            return {"id": vuln_id, "status": "saved"}
        except Exception as e:
            logger.error(f"Failed to save finding: {e}")
            return {"error": str(e)}

    async def validate_target(self, url: str, scope_rules: Dict[str, Any] = None):
        try:
            if scope_rules and 'allowed_domains' in scope_rules:
                self.scope_validator.allowed_domains = scope_rules['allowed_domains']
            is_valid = await self.scope_validator.is_allowed(url)
            return {"valid": is_valid, "url": url}
        except Exception as e:
            logger.error(f"Target validation failed: {e}")
            return {"valid": False, "url": url}

# =============================================================================
# Enhanced VulnScanAgent with limits and timeouts
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
# Enhanced Main Execution with better error handling and limits
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
# main entry point
# =============================================================================

if __name__ == "__main__":
    asyncio.run(main())