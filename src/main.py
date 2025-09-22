import asyncio
import json
import re
import time
import urllib.parse
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from enum import Enum
import aiohttp
import logging
import hashlib
import sqlite3
from bs4 import BeautifulSoup

# Import the new AI Interface
from AIInterface import AIInterface

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
    """SQLite database for storing vulnerability findings"""
    def __init__(self, db_path: str = "vulnerabilities.db"):
        self.db_path = db_path
        self.init_database()

    def init_database(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS vulnerabilities (
                    id TEXT PRIMARY KEY, type TEXT NOT NULL, severity TEXT NOT NULL,
                    title TEXT NOT NULL, description TEXT, location TEXT, evidence TEXT,
                    remediation TEXT, confidence REAL, timestamp REAL, target_url TEXT
                )
            """)
            conn.commit()

    async def save_finding(self, vulnerability: Vulnerability, target_url: str):
        # The vulnerability object from the AI might not have all keys
        vuln_data = {
            "type": vulnerability.get('type', 'unknown'),
            "severity": vulnerability.get('severity', 'info'),
            "title": vulnerability.get('title', 'Untitled Finding'),
            "description": vulnerability.get('description', ''),
            "location": vulnerability.get('location', {}),
            "evidence": vulnerability.get('evidence', {}),
            "remediation": vulnerability.get('remediation', ''),
            "confidence": vulnerability.get('confidence', 0.0),
            "timestamp": time.time()
        }
        vuln_id = hashlib.sha256(f"{vuln_data['type']}_{json.dumps(vuln_data['location'])}_{target_url}".encode()).hexdigest()[:16]
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT OR REPLACE INTO vulnerabilities
                (id, type, severity, title, description, location, evidence,
                 remediation, confidence, timestamp, target_url)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                vuln_id, vuln_data['type'], vuln_data['severity'],
                vuln_data['title'], vuln_data['description'],
                json.dumps(vuln_data['location']), json.dumps(vuln_data['evidence']),
                vuln_data['remediation'], vuln_data['confidence'],
                vuln_data['timestamp'], target_url
            ))
            conn.commit()
        logger.info(f"Saved vulnerability finding: {vuln_id}")
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
    def __init__(self, ai_interface: AIInterface):
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
    """AI agent that orchestrates vulnerability scanning using MCP tools and AI reasoning"""
    def __init__(self, mcp_server: MCPServer, ai_interface: AIInterface, max_targets_per_vuln: int = 10):
        self.mcp_server = mcp_server
        self.ai_interface = ai_interface
        self.context = {}
        self.attack_plan = {}
        self.max_targets_per_vuln = max_targets_per_vuln  # Limit targets per vulnerability type
        self.scan_start_time = None
        self.max_scan_duration = 300  # 5 minutes maximum scan time

    async def reconnaissance_phase(self, target_url: str):
        logger.info(f"Starting reconnaissance phase for {target_url}")
        self.scan_start_time = time.time()
        
        validation = await self.mcp_server.call_tool("validate_target", {"url": target_url})
        if not validation.get("valid"): 
            raise SecurityError("Target validation failed")
            
        domain = urllib.parse.urlparse(target_url).netloc
        crawl_result = await self.mcp_server.call_tool(
            "crawl_site",
            {"seed_url": target_url, "scope_domains": [domain], "depth": 2}  # Limit depth
        )
        
        logger.info(f"Crawl completed: {len(crawl_result.get('endpoints', []))} endpoints, {len(crawl_result.get('forms', []))} forms")
        
        self.context = self._analyze_stack(crawl_result)
        self.attack_plan = self._generate_attack_plan(crawl_result)
        
        # Limit total targets
        total_targets = len(self.attack_plan.get('targets', []))
        if total_targets > 50:  # Limit total targets
            self.attack_plan['targets'] = self.attack_plan['targets'][:50]
            logger.warning(f"Limited targets from {total_targets} to 50 for performance")
        
        logger.info(f"Discovered {len(self.attack_plan.get('targets', []))} potential injection points.")
        return self.attack_plan

    def _analyze_stack(self, crawl_result: Dict[str, Any]):
        return {
            "technologies": ["generic"], 
            "endpoints": crawl_result.get("endpoints", []),
            "forms": crawl_result.get("forms", [])
        }

    def _generate_attack_plan(self, crawl_result: Dict[str, Any]):
        plan = {"targets": [], "vulnerability_types": [v.value for v in VulnType]}
        
        # Targets from URL parameters
        for endpoint in crawl_result.get("endpoints", []):
            for param in endpoint.get("parameters", []):
                plan["targets"].append({
                    "url": endpoint["url"],
                    "injection_point": {"type": "query_param", "name": param},
                    "method": endpoint.get("method", "GET")
                })
        
        # Targets from form inputs
        for form in crawl_result.get("forms", []):
            for input_field in form.get("inputs", []):
                plan["targets"].append({
                    "url": form["action"],
                    "injection_point": {"type": "form_field", "name": input_field["name"]},
                    "method": form.get("method", "POST")
                })    
        
        return plan
    
    def _check_scan_timeout(self):
        """Check if scan has exceeded maximum duration"""
        if self.scan_start_time and time.time() - self.scan_start_time > self.max_scan_duration:
            raise TimeoutError("Scan exceeded maximum duration")
    
    async def test_vulnerability_type(self, vuln_type: str, targets: List[Dict[str, Any]]):
        logger.info(f"Testing {vuln_type} against {len(targets)} targets")
        
        # Limit targets per vulnerability type
        limited_targets = targets[:self.max_targets_per_vuln]
        if len(limited_targets) < len(targets):
            logger.warning(f"Limited {vuln_type} testing from {len(targets)} to {len(limited_targets)} targets")
        
        findings = []
        
        for i, target in enumerate(limited_targets):
            try:
                # Check timeout before each target
                self._check_scan_timeout()
                
                logger.debug(f"Testing {vuln_type} on target {i+1}/{len(limited_targets)}: {target['url']}")
                
                target_context = self.context.copy()
                target_context.update({
                    "url": target["url"],
                    "parameter": target["injection_point"]["name"],
                    "injection_point_type": target["injection_point"]["type"]
                })
                
                payload_result = await self.mcp_server.call_tool("get_payloads", {
                    "vulnerability_type": vuln_type, 
                    "context": target_context, 
                    "count": 3  # Limit payloads per target
                })

                for payload in payload_result.get("payloads", []):
                    try:
                        # Check timeout before each payload
                        self._check_scan_timeout()
                        
                        response = await self.mcp_server.call_tool("inject_payload", {
                            **target, "payload": payload
                        })
                        
                        if "error" in response:
                            logger.warning(f"Payload injection failed: {response['error']}")
                            continue
                            
                        analysis = await self.mcp_server.call_tool("analyze_response", {
                            "request": {"payload": payload}, 
                            "response": response
                        })

                        # Add timeout for AI analysis
                        is_vuln = await asyncio.wait_for(
                            self.ai_interface.analyze_vulnerability(
                                {"payload": payload, "target": target}, 
                                response, 
                                vuln_type
                            ),
                            timeout=30.0
                        )
                        
                        if is_vuln:
                            finding = await asyncio.wait_for(
                                self.ai_interface.classify_vulnerability(
                                    target, payload, analysis, vuln_type
                                ),
                                timeout=30.0
                            )
                            if finding:
                                findings.append(finding)
                                logger.info(f"Potential {vuln_type} vulnerability found in {target['url']}")
                                
                    except asyncio.TimeoutError:
                        logger.warning(f"AI analysis timed out for payload {payload}")
                        continue
                    except Exception as e:
                        logger.warning(f"Error testing payload {payload} on {target['url']}: {e}")
                        continue

            except TimeoutError:
                logger.warning("Scan timeout reached, stopping vulnerability testing")
                break
            except Exception as e:
                logger.warning(f"Error testing target {target['url']}: {e}")
                continue

        logger.info(f"Found {len(findings)} potential {vuln_type} vulnerabilities")
        return findings

    async def comprehensive_scan(self, target_url: str):
        logger.info(f"Starting comprehensive scan of {target_url}")
        
        try:
            attack_plan = await self.reconnaissance_phase(target_url)
            all_findings = []
            
            # Limit vulnerability types tested (for demo, test only first 3)
            vuln_types_to_test = attack_plan["vulnerability_types"][:3]
            logger.info(f"Testing {len(vuln_types_to_test)} vulnerability types: {vuln_types_to_test}")
            
            for vuln_type in vuln_types_to_test:
                try:
                    self._check_scan_timeout()
                    findings = await self.test_vulnerability_type(vuln_type, attack_plan["targets"])
                    all_findings.extend(findings)
                    
                    for finding in findings:
                        await self.mcp_server.call_tool("save_finding", {"vulnerability": finding})
                        
                except TimeoutError:
                    logger.warning("Scan timeout reached, stopping comprehensive scan")
                    break
                except Exception as e:
                    logger.error(f"Error testing {vuln_type}: {e}")
                    continue
            
            report = self._generate_report(target_url, all_findings, attack_plan)
            scan_duration = time.time() - self.scan_start_time
            logger.info(f"Scan complete in {scan_duration:.1f} seconds. Found {len(all_findings)} potential vulnerabilities")
            return report
            
        except Exception as e:
            logger.error(f"Comprehensive scan failed: {e}")
            return self._generate_error_report(target_url, str(e))

    def _generate_report(self, target_url: str, findings: List[Dict[str, Any]], attack_plan: Dict[str, Any]):
        severity_counts = {s.value: 0 for s in Severity}
        for f in findings:
            severity = f.get("severity", "info")
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        scan_duration = time.time() - self.scan_start_time if self.scan_start_time else 0
        
        return {
            "scan_summary": {
                "target": target_url, 
                "timestamp": time.time(),
                "scan_duration": scan_duration,
                "total_findings": len(findings), 
                "severity_breakdown": severity_counts,
                "risk_score": self._calculate_risk_score(findings),
                "targets_tested": len(attack_plan.get("targets", [])),
            },
            "findings": findings,
            "attack_surface": {
                "endpoints_discovered": len(self.context.get("endpoints", [])),
                "forms_discovered": len(self.context.get("forms", [])),
                "technologies": self.context.get("technologies", [])
            }
        }

    def _generate_error_report(self, target_url: str, error_message: str):
        """Generate a report when scan fails"""
        return {
            "scan_summary": {
                "target": target_url,
                "timestamp": time.time(),
                "scan_duration": time.time() - self.scan_start_time if self.scan_start_time else 0,
                "total_findings": 0,
                "severity_breakdown": {s.value: 0 for s in Severity},
                "risk_score": 0.0,
                "error": error_message
            },
            "findings": [],
            "attack_surface": {}
        }

    def _calculate_risk_score(self, findings: List[Dict[str, Any]]):
        if not findings: 
            return 0.0
        weights = {
            Severity.CRITICAL.value: 10, 
            Severity.HIGH.value: 7, 
            Severity.MEDIUM.value: 4, 
            Severity.LOW.value: 1, 
            Severity.INFO.value: 0
        }
        score = sum(weights.get(f.get("severity"), 0) * f.get("confidence", 0.5) for f in findings)
        return min(round(score / (len(findings) * 10) * 10, 1), 10.0) if findings else 0.0

# =============================================================================
# Enhanced Main Execution with better error handling and limits
# =============================================================================

async def main():
    target_url = "https://httpbin.org/forms/post"
    
    # Set overall timeout for the entire operation
    overall_timeout = 60  # 10 minutes maximum
    
    try:
        logger.info("Initializing vulnerability scanner...")
        ai_interface = AIInterface()
        
        async with MCPServer(ai_interface) as mcp_server:
            # Configure scope validation
            domain = urllib.parse.urlparse(target_url).netloc
            mcp_server.scope_validator.allowed_domains = [domain]
            
            # Create agent with limits
            agent = VulnScanAgent(
                mcp_server, 
                ai_interface, 
                max_targets_per_vuln=5  # Limit targets per vulnerability type
            )
            
            logger.info("Starting vulnerability scan using AI interface...")
            
            # Run scan with overall timeout
            report = await asyncio.wait_for(
                agent.comprehensive_scan(target_url),
                timeout=overall_timeout
            )
            
            logger.info("Scan completed. Processing results...")

            # Display results
            print("\n" + "="*80)
            print("VULNERABILITY SCAN REPORT")
            print("="*80)
            
            summary = report['scan_summary']
            print(f"Target: {summary['target']}")
            print(f"Scan Duration: {summary.get('scan_duration', 0):.1f} seconds")
            print(f"Total Findings: {summary['total_findings']}")
            print(f"Targets Tested: {summary.get('targets_tested', 0)}")
            print(f"Risk Score: {summary['risk_score']:.1f}/10.0")
            
            if summary.get('error'):
                print(f"Scan Error: {summary['error']}")
            
            print("\nSeverity Breakdown:")
            for severity, count in summary['severity_breakdown'].items():
                if count > 0: 
                    print(f"  {severity.upper()}: {count}")
            
            attack_surface = report.get('attack_surface', {})
            print(f"\nAttack Surface:")
            print(f"  Endpoints Discovered: {attack_surface.get('endpoints_discovered', 0)}")
            print(f"  Forms Discovered: {attack_surface.get('forms_discovered', 0)}")
            print(f"  Technologies: {', '.join(attack_surface.get('technologies', ['Unknown']))}")
            
            if report['findings']:
                print("\nTop Vulnerabilities:")
                for i, finding in enumerate(report['findings'][:5], 1):
                    title = finding.get('title', 'Untitled Finding')
                    severity = finding.get('severity', 'unknown').upper()
                    confidence = finding.get('confidence', 0.0)
                    confidence_str = f"({confidence:.1%} confidence)" if confidence > 0 else ""
                    print(f"  {i}. {title} - {severity} {confidence_str}")
            else:
                print("\nNo vulnerabilities found.")
                print("This could be due to:")
                print("  - Target is well-secured")
                print("  - Limited scan scope/depth")
                print("  - AI interface connectivity issues")
                print("  - Scan timeouts or rate limiting")

    except asyncio.TimeoutError:
        logger.error(f"Scan exceeded maximum time limit of {overall_timeout} seconds")
        print(f"\nScan timed out after {overall_timeout} seconds. Consider:")
        print("  - Reducing scan scope")
        print("  - Increasing timeout limits")
        print("  - Checking target responsiveness")
        
    except SecurityError as e:
        logger.error(f"Security constraint violation: {e}")
        print(f"\nSecurity Error: {e}")
        print("Check your target URL and scope configuration.")
        
    except ValueError as e:
        logger.error(f"Configuration error: {e}")
        print(f"\nConfiguration Error: {e}")
        print("Check your AI interface setup and parameters.")
        
    except Exception as e:
        logger.error(f"Unexpected error during scan: {e}", exc_info=True)
        print(f"\nUnexpected Error: {e}")
        print("Check logs for detailed error information.")
        print("Common issues:")
        print("  - AI interface not properly configured")
        print("  - Network connectivity problems")
        print("  - Target server blocking requests")
        print("  - Missing dependencies")

if __name__ == "__main__":
    asyncio.run(main())