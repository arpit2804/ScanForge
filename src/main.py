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

# New feature modules
from src.adaptive_budgeting import AdaptivePayloadBudget
from src.crawler_enhanced import EnhancedWebCrawler
from src.waf_detector import WAFDetector
from src.attack_surface_graph import AttackSurfaceGraph
from src.anomaly_detector import AnomalyDetector

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# =============================================================================
# Data Models and Enums
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
# Safety and Core Components
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
        self.dangerous_patterns = [
            r'rm\s+-rf', r'format\s+c:', r'del\s+/[qsf]',
            r'DROP\s+DATABASE', r'TRUNCATE\s+TABLE'
        ]

    async def is_allowed(self, url: str) -> bool:
        try:
            parsed = urllib.parse.urlparse(url)
            domain = parsed.netloc.lower()
            path = parsed.path
            if self.allowed_domains and not any(domain.endswith(a.lower()) for a in self.allowed_domains):
                logger.warning(f"Domain {domain} not in allowed list")
                return False
            if any(path.startswith(bp) for bp in self.blocked_paths):
                logger.warning(f"Path {path} is blocked")
                return False
            return True
        except Exception as e:
            logger.error(f"Error validating URL {url}: {e}")
            return False

    def is_payload_safe(self, payload: str) -> bool:
        if any(re.search(p, payload, re.IGNORECASE) for p in self.dangerous_patterns):
            logger.warning(f"Dangerous payload pattern detected in: {payload}")
            return False
        return True

class SecurityError(Exception):
    """Raised when security constraints are violated"""
    pass

class VulnerabilityDatabase:
    """File-based storage for vulnerability findings."""

    def __init__(self, output_dir: str = "output"):
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)

    async def save_finding(self, vulnerability: Any, target_url: str):
        # Accept both Vulnerability dataclass and plain dict
        if isinstance(vulnerability, dict):
            data = vulnerability.copy()
            loc = data.get('location', {})
        else:
            data = asdict(vulnerability)
            loc = data.get('location', {})

        vuln_id = hashlib.sha256(
            f"{data.get('type','unknown')}_{loc}_{target_url}".encode()
        ).hexdigest()[:16]

        file_path = os.path.join(self.output_dir, f"{vuln_id}.json")
        data['target_url'] = target_url

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
# PayloadDatabase
# =============================================================================

class PayloadDatabase:
    """AI-powered payload database"""
    def __init__(self, ai_interface: AIInterface):
        self.ai_interface = ai_interface
        self.emergency_fallbacks = {
            'xss':  ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"],
            'sqli': ["' OR '1'='1", "1' UNION SELECT NULL--"],
            'ssrf': ["http://localhost", "http://169.254.169.254"],
            'lfi':  ["../../etc/passwd", "../../../etc/passwd"],
            'rce':  ["; whoami", "| id"],
        }

    async def get_payloads(
        self,
        vuln_type: str,
        context: Dict[str, Any] = None,
        count: int = 10,
    ) -> List[str]:
        try:
            payloads = await asyncio.wait_for(
                self.ai_interface.generate_payloads(vuln_type, context, count),
                timeout=45.0,
            )
            if payloads:
                logger.info(f"AI generated {len(payloads)} payloads for {vuln_type}")
                return payloads
        except asyncio.TimeoutError:
            logger.warning(f"AI payload generation timed out for {vuln_type}")
        except Exception as e:
            logger.warning(f"AI payload generation failed: {e}")

        fallback = self.emergency_fallbacks.get(vuln_type.lower(), [])
        logger.info(f"Using {len(fallback)} emergency fallback payloads for {vuln_type}")
        return fallback[:count]

# =============================================================================
# MCPServer — all original methods + new feature integrations
# =============================================================================

class MCPServer:
    """Main MCP Server handling all vulnerability scanning operations."""

    def __init__(self, ai_interface: AIInterface):
        self.ai_interface = ai_interface
        self.rate_limiter = RateLimiter(requests_per_minute=30)
        self.scope_validator = ScopeValidator()
        self.payload_db = PayloadDatabase(ai_interface)
        self.vuln_db = VulnerabilityDatabase()
        self.session = None

        # ── Feature modules ────────────────────────────────────────────
        self.waf_detector = WAFDetector()
        self.anomaly_detector = AnomalyDetector()
        self.attack_surface_graph = AttackSurfaceGraph()
        self.adaptive_budget = AdaptivePayloadBudget()
        # ──────────────────────────────────────────────────────────────

        self.tools = {
            # original tools
            "crawl_site":         self.crawl_site,
            "send_request":       self.send_request,
            "inject_payload":     self.inject_payload,
            "analyze_response":   self.analyze_response,
            "save_finding":       self.save_finding,
            "get_payloads":       self.get_payloads,
            "validate_target":    self.validate_target,
            # new tools
            "adaptive_scan":      self.adaptive_scan,
            "get_attack_graph":   self.get_attack_graph,
            "get_anomaly_report": self.get_anomaly_report,
            "detect_waf":         self.detect_waf,
        }

    async def __aenter__(self):
        timeout = aiohttp.ClientTimeout(total=30, connect=10)
        self.session = aiohttp.ClientSession(timeout=timeout)
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()

    # ------------------------------------------------------------------
    # Core dispatcher
    # ------------------------------------------------------------------

    async def call_tool(self, tool_name: str, params: Dict[str, Any]) -> Dict[str, Any]:
        if tool_name not in self.tools:
            raise ValueError(f"Unknown tool: {tool_name}")
        await self._validate_request(tool_name, params)
        tool_func = self.tools[tool_name]
        try:
            result = await asyncio.wait_for(tool_func(**params), timeout=120.0)
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

    # ------------------------------------------------------------------
    # crawl_site — now uses EnhancedWebCrawler + builds attack graph
    # ------------------------------------------------------------------

    async def crawl_site(
        self,
        seed_url: str,
        depth: int = 2,
        scope_domains: List[str] = None,
    ):
        depth = min(depth, 3)
        crawler = EnhancedWebCrawler(self.session, max_pages=60, max_depth=depth)
        result = await crawler.crawl_site(seed_url, depth, scope_domains)

        # Build risk graph from crawl output
        self.attack_surface_graph = AttackSurfaceGraph()
        self.attack_surface_graph.build_from_crawl(result)

        # Establish WAF baseline on the seed URL
        await self.waf_detector.measure_baseline(self.session, seed_url)

        result["graph_summary"] = self.attack_surface_graph.summary()
        result["prioritized_endpoints"] = self.attack_surface_graph.get_prioritized_endpoints(10)
        return result

    # ------------------------------------------------------------------
    # send_request — feeds WAF detector + optional anomaly baseline
    # ------------------------------------------------------------------

    async def send_request(
        self,
        method: str,
        url: str,
        headers: Dict[str, str] = None,
        body: Any = None,
        record_baseline: bool = False,
        **kwargs,
    ):
        start_time = time.time()
        try:
            if isinstance(body, dict):
                headers = headers or {}
                headers.setdefault('Content-Type', 'application/x-www-form-urlencoded')
                body = urllib.parse.urlencode(body)

            timeout = aiohttp.ClientTimeout(total=15)
            async with self.session.request(
                method=method,
                url=url,
                headers=headers or {},
                data=body,
                timeout=timeout,
                **kwargs,
            ) as response:
                response_body = await response.text()
                resp_dict = {
                    "status_code": response.status,
                    "headers": dict(response.headers),
                    "body": response_body,
                    "response_time": time.time() - start_time,
                }

                # WAF detection signal
                waf_info = self.waf_detector.record_response(resp_dict)
                resp_dict["waf_info"] = waf_info

                # Record as anomaly baseline if requested
                if record_baseline:
                    self.anomaly_detector.record_baseline(url, resp_dict)

                return resp_dict
        except Exception as e:
            logger.warning(f"Request failed for {url}: {e}")
            return {"error": str(e), "response_time": time.time() - start_time}

    # ------------------------------------------------------------------
    # inject_payload — WAF evasion + anomaly detection on every injection
    # ------------------------------------------------------------------

    async def inject_payload(
        self,
        url: str,
        injection_point: Dict[str, Any],
        payload: str,
        method: str = "GET",
        **kwargs,
    ):
        try:
            # If WAF is active, try evasion variants first
            if self.waf_detector.waf_detected:
                logger.info("[WAF] WAF active — attempting evasion variants")
                for evaded_payload, transform_name in self.waf_detector.get_evasion_payloads(payload):
                    response = await self._do_inject(url, injection_point, evaded_payload, method, **kwargs)
                    waf_check = self.waf_detector.record_response(response)
                    if not waf_check.get("blocked"):
                        logger.info(f"[WAF] Evasion succeeded with transform: {transform_name}")
                        response["evasion_used"] = transform_name
                        response["original_payload"] = payload
                        response["anomaly"] = self.anomaly_detector.analyze(url, response, evaded_payload)
                        return response
                logger.warning("[WAF] All evasion transforms were blocked.")

            response = await self._do_inject(url, injection_point, payload, method, **kwargs)
            response["anomaly"] = self.anomaly_detector.analyze(url, response, payload)
            return response

        except Exception as e:
            logger.error(f"Payload injection failed: {e}")
            return {"error": str(e)}

    async def _do_inject(
        self,
        url: str,
        injection_point: Dict[str, Any],
        payload: str,
        method: str,
        **kwargs,
    ) -> Dict[str, Any]:
        """Raw injection — no WAF/anomaly logic (internal helper)."""
        modified_url = url
        headers = kwargs.get('headers', {})
        body = kwargs.get('data', None)

        inj_type = injection_point.get('type', '')

        if inj_type == 'query_param':
            parsed = urllib.parse.urlparse(url)
            params = urllib.parse.parse_qs(parsed.query)
            params[injection_point['name']] = [payload]
            new_query = urllib.parse.urlencode(params, doseq=True)
            modified_url = parsed._replace(query=new_query).geturl()
            return await self.send_request(method, modified_url, headers, body)

        elif inj_type == 'form_field':
            body = {injection_point['name']: payload}
            return await self.send_request(method, modified_url, headers, body)

        return await self.send_request(method, modified_url, headers, body)

    # ------------------------------------------------------------------
    # analyze_response — AI-powered (unchanged from original)
    # ------------------------------------------------------------------

    async def analyze_response(
        self,
        request: Dict[str, Any],
        response: Dict[str, Any],
        **kwargs,
    ) -> Dict[str, Any]:
        try:
            analysis = await asyncio.wait_for(
                self.ai_interface.analyze_response_with_ai(request, response),
                timeout=30.0,
            )
            logger.info(f"AI analysis complete: {analysis.get('vulnerability_type', 'none detected')}")
            return analysis
        except asyncio.TimeoutError:
            logger.warning("AI analysis timed out, using basic fallback")
            return self._basic_analysis_fallback(request, response)
        except Exception as e:
            logger.error(f"AI analysis failed: {e}")
            return self._basic_analysis_fallback(request, response)

    def _basic_analysis_fallback(
        self, request: Dict[str, Any], response: Dict[str, Any]
    ) -> Dict[str, Any]:
        payload = request.get('payload', '')
        response_body = response.get('body', '')
        return {
            "vulnerability_detected": False,
            "confidence": 0.1,
            "indicators": {
                "payload_reflected": payload in response_body if payload else False,
                "status_code": response.get('status_code', 0),
            },
            "reasoning": "AI analysis unavailable, basic reflection check only",
            "fallback_mode": True,
        }

    # ------------------------------------------------------------------
    # get_payloads — unchanged from original
    # ------------------------------------------------------------------

    async def get_payloads(
        self,
        vulnerability_type: str,
        context: Dict[str, Any] = None,
        count: int = 10,
        **kwargs,
    ):
        count = min(count, 50)
        payloads = await self.payload_db.get_payloads(vulnerability_type, context, count)
        return {"payloads": payloads}

    # ------------------------------------------------------------------
    # save_finding — unchanged from original
    # ------------------------------------------------------------------

    async def save_finding(self, vulnerability: Dict[str, Any], **kwargs):
        try:
            target_url = vulnerability.get('location', {}).get('url', 'unknown')
            vuln_id = await self.vuln_db.save_finding(vulnerability, target_url)
            return {"id": vuln_id, "status": "saved"}
        except Exception as e:
            logger.error(f"Failed to save finding: {e}")
            return {"error": str(e)}

    # ------------------------------------------------------------------
    # validate_target — unchanged from original
    # ------------------------------------------------------------------

    async def validate_target(
        self, url: str, scope_rules: Dict[str, Any] = None, **kwargs
    ):
        try:
            if scope_rules and 'allowed_domains' in scope_rules:
                self.scope_validator.allowed_domains = scope_rules['allowed_domains']
            is_valid = await self.scope_validator.is_allowed(url)
            return {"valid": is_valid, "url": url}
        except Exception as e:
            logger.error(f"Target validation failed: {e}")
            return {"valid": False, "url": url}

    # ------------------------------------------------------------------
    # NEW: adaptive_scan
    # ------------------------------------------------------------------

    async def adaptive_scan(
        self,
        endpoint: Dict[str, Any],
        vulnerability_type: str,
        **kwargs,
    ) -> Dict[str, Any]:
        """
        Adaptive payload-budget scan for a single endpoint.
        Collects a baseline first, then runs the adaptive loop.
        """
        url = endpoint.get("url", "")
        if url:
            baseline_resp = await self.send_request("GET", url, record_baseline=True)
            if "error" in baseline_resp:
                logger.warning(f"Could not establish baseline for {url}")

        result = await self.adaptive_budget.run_adaptive_scan(
            endpoint=endpoint,
            vuln_type=vulnerability_type,
            payload_getter=self._get_payloads_raw,
            injector=self._do_inject,
            analyzer=self._analyze_raw,
        )
        result["anomaly_summary"] = self.anomaly_detector.summary()
        return result

    async def _get_payloads_raw(
        self, vuln_type: str, context: Dict[str, Any], count: int
    ) -> List[str]:
        result = await self.get_payloads(vuln_type, context, count)
        return result.get("payloads", [])

    async def _analyze_raw(
        self, request: Dict[str, Any], response: Dict[str, Any]
    ) -> Dict[str, Any]:
        return await self.analyze_response(request, response)

    # ------------------------------------------------------------------
    # NEW: get_attack_graph
    # ------------------------------------------------------------------

    async def get_attack_graph(
        self,
        top_n: int = 20,
        min_risk: float = 0.0,
        **kwargs,
    ) -> Dict[str, Any]:
        """Returns the risk-scored attack surface graph from the last crawl."""
        return {
            "summary": self.attack_surface_graph.summary(),
            "prioritized_endpoints": self.attack_surface_graph.get_prioritized_endpoints(top_n),
            "high_risk_endpoints": self.attack_surface_graph.get_high_risk_endpoints(
                min_risk if min_risk else 0.5
            ),
        }

    # ------------------------------------------------------------------
    # NEW: get_anomaly_report
    # ------------------------------------------------------------------

    async def get_anomaly_report(self, **kwargs) -> Dict[str, Any]:
        """Returns all behavioral anomalies detected in this session."""
        return self.anomaly_detector.summary()

    # ------------------------------------------------------------------
    # NEW: detect_waf
    # ------------------------------------------------------------------

    async def detect_waf(self, url: str, **kwargs) -> Dict[str, Any]:
        """
        Probes the target with WAF-triggering strings to identify
        firewall presence and vendor.
        """
        probes = [
            "' OR 1=1--",
            "<script>alert(1)</script>",
            "../../../../etc/passwd",
        ]
        results = []
        for probe in probes:
            probe_url = f"{url}?test={urllib.parse.quote(probe)}"
            resp = await self.send_request("GET", probe_url)
            waf_check = self.waf_detector.record_response(resp)
            results.append({"probe": probe, **waf_check})

        return {
            "waf_detected": self.waf_detector.waf_detected,
            "waf_vendor": self.waf_detector.waf_vendor,
            "probe_results": results,
        }


# =============================================================================
# VulnScanAgent — unchanged from original
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
        self.max_steps = 100
        self.output_dir = "output"
        os.makedirs(self.output_dir, exist_ok=True)

    async def __aenter__(self):
        self.mcp_session = aiohttp.ClientSession()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.mcp_session:
            await self.mcp_session.close()

    async def _call_mcp_tool(self, tool_name: str, params: Dict[str, Any]) -> Dict[str, Any]:
        if not self.mcp_session:
            raise RuntimeError("Agent session not initialized.")
        url = f"{self.mcp_server_url}/call_tool"
        request_body = {"tool_name": tool_name, "params": params}
        try:
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
        logger.info(f"Agent starting with goal: {goal}")
        self.history = []

        for step in range(self.max_steps):
            logger.info(f"--- Agent Step {step + 1} ---")
            next_step = await self.ai_interface.decide_next_step(goal, self.history)

            if "final_answer" in next_step:
                logger.info("Agent has completed the goal.")
                try:
                    final_record = {
                        "step": "final",
                        "final_answer": next_step["final_answer"],
                        "timestamp": time.time(),
                    }
                    final_filename = f"agent_final_{int(final_record['timestamp'] * 1000)}.json"
                    final_path = os.path.join(self.output_dir, final_filename)
                    with open(final_path, 'w', encoding='utf-8') as ff:
                        json.dump(final_record, ff, indent=2, ensure_ascii=False)
                    logger.info(f"Saved agent final answer to {final_path}")
                except Exception as e:
                    logger.error(f"Failed to save final answer to output: {e}")

                print("\n" + "=" * 80)
                print("AGENT FINAL REPORT")
                print("=" * 80)
                print(next_step["final_answer"])
                break

            if "tool_name" in next_step:
                action = next_step
                tool_name = action["tool_name"]
                params = action["params"]

                if "thought" in action:
                    logger.info(f"Agent Thought: {action['thought']}")
                logger.info(f"Agent Action: Calling tool {tool_name} with params: {params}")

                tool_result = await self._call_mcp_tool(tool_name, params)
                result_for_history = self._truncate_result(tool_result)
                logger.info(f"Tool Result (truncated): {json.dumps(result_for_history, indent=2)}")

                self.history.append({"action": action, "result": result_for_history})

                try:
                    step_record = {
                        "step": step + 1,
                        "action": action,
                        "result": tool_result,
                        "timestamp": time.time(),
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
        if isinstance(result, dict) and "body" in result:
            result["body"] = result["body"][:max_length] + "... (truncated)"
        result_str = json.dumps(result)
        if len(result_str) > max_length:
            return {
                "summary": "Result is too large",
                "keys": list(result.keys()) if isinstance(result, dict) else "N/A",
                "note": "Original result truncated to fit context.",
            }
        return result


# =============================================================================
# Main entry point
# =============================================================================

async def main():
    mcp_server_url = "http://127.0.0.1:8000"

    goal = (
        "Validate and perform a comprehensive scan for XSS and SQLi on "
        "'https://httpbin.org/forms/post'. Be thorough. Start by crawling, "
        "then test forms and endpoints you find. Report all findings."
    )

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


if __name__ == "__main__":
    asyncio.run(main())