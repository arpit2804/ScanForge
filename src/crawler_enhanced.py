import asyncio
import json
import logging
import re
import urllib.parse
from typing import Dict, Any, List, Optional, Set
from dataclasses import dataclass, field, asdict

import aiohttp
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Attack Surface Object — the structured output of the enhanced crawler
# ---------------------------------------------------------------------------

@dataclass
class AttackSurfaceNode:
    url: str
    method: str = "GET"
    parameters: List[str] = field(default_factory=list)
    inputs: List[Dict[str, str]] = field(default_factory=list)
    input_type: str = "html_form"   # html_form | query_param | json_body | graphql | rest_api
    context: str = ""
    technology_stack: List[str] = field(default_factory=list)
    estimated_risk_score: float = 0.0
    headers_seen: Dict[str, str] = field(default_factory=dict)
    is_authenticated: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# Technology fingerprinting helpers
# ---------------------------------------------------------------------------

TECH_SIGNATURES = {
    "Django": [r"csrfmiddlewaretoken", r"django", r"__django"],
    "Express": [r"x-powered-by:\s*express", r"express"],
    "PHP": [r"\.php", r"phpsessid", r"x-powered-by:\s*php"],
    "Laravel": [r"laravel_session", r"x-powered-by:\s*php", r"laravel"],
    "Rails": [r"_rails_session", r"x-powered-by:\s*phusion passenger"],
    "ASP.NET": [r"__viewstate", r"aspnetcore", r"x-aspnet-version"],
    "React": [r"react", r"_next", r"__next"],
    "Vue": [r"vue", r"__vue"],
    "Angular": [r"ng-version", r"angular"],
    "WordPress": [r"wp-content", r"wp-login", r"wordpress"],
    "GraphQL": [r"graphql", r"/graphql", r"__schema", r"application/graphql"],
}


def detect_technologies(
    response_headers: Dict[str, str],
    response_body: str,
    url: str,
) -> List[str]:
    detected = []
    combined = (
        json.dumps(response_headers).lower()
        + response_body[:5000].lower()
        + url.lower()
    )
    for tech, patterns in TECH_SIGNATURES.items():
        if any(re.search(p, combined, re.IGNORECASE) for p in patterns):
            detected.append(tech)
    return detected


# ---------------------------------------------------------------------------
# Enhanced crawler
# ---------------------------------------------------------------------------

class EnhancedWebCrawler:
    """
    Comprehensive attack-surface crawler supporting:
    - HTML forms (original)
    - URL query parameters
    - REST API endpoints
    - JSON request body discovery
    - GraphQL endpoint discovery
    - Hidden / dynamically generated parameters
    - Basic JS route extraction
    - Technology fingerprinting
    """

    # REST-like path patterns
    REST_PATH_RE = re.compile(
        r"(/api/[^\s\"'<>]+|/v\d+/[^\s\"'<>]+|/rest/[^\s\"'<>]+)",
        re.IGNORECASE,
    )
    # GraphQL indicators
    GRAPHQL_PATH_RE = re.compile(r"/graphql|/gql", re.IGNORECASE)
    # JSON fetch / axios call patterns in JS
    JS_FETCH_RE = re.compile(
        r"""(?:fetch|axios\.(?:get|post|put|patch|delete))\s*\(\s*['"`]([^'"`]+)['"`]""",
        re.IGNORECASE,
    )
    JS_ROUTE_RE = re.compile(
        r"""(?:path|route|url)\s*:\s*['"`]([/][^'"`\s]+)['"`]""",
        re.IGNORECASE,
    )

    def __init__(
        self,
        session: aiohttp.ClientSession,
        max_pages: int = 60,
        max_depth: int = 3,
    ):
        self.session = session
        self.max_pages = max_pages
        self.max_depth = max_depth

        self.visited_urls: Set[str] = set()
        self.pages_crawled: int = 0
        self.attack_surface: List[AttackSurfaceNode] = []
        self._seen_endpoints: Set[str] = set()   # dedup key

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    async def crawl_site(
        self,
        seed_url: str,
        depth: int = 2,
        scope_domains: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        depth = min(depth, self.max_depth)
        base_domain = urllib.parse.urlparse(seed_url).netloc
        scope = scope_domains or [base_domain]

        logger.info(
            f"[EnhancedCrawler] Starting crawl: {seed_url} | depth={depth} | scope={scope}"
        )
        await self._crawl_recursive(seed_url, depth, scope)

        logger.info(
            f"[EnhancedCrawler] Done. pages={self.pages_crawled} | "
            f"surface_nodes={len(self.attack_surface)}"
        )
        return {
            "endpoints": [n.to_dict() for n in self.attack_surface],
            "forms": [
                n.to_dict()
                for n in self.attack_surface
                if n.input_type == "html_form"
            ],
            "api_endpoints": [
                n.to_dict()
                for n in self.attack_surface
                if n.input_type in ("rest_api", "graphql", "json_body")
            ],
            "technology_stack": self._aggregate_tech(),
            "total_nodes": len(self.attack_surface),
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _dedup_key(self, url: str, method: str, input_type: str) -> str:
        parsed = urllib.parse.urlparse(url)
        return f"{method.upper()}:{parsed.scheme}://{parsed.netloc}{parsed.path}:{input_type}"

    def _add_node(self, node: AttackSurfaceNode):
        key = self._dedup_key(node.url, node.method, node.input_type)
        if key not in self._seen_endpoints:
            self._seen_endpoints.add(key)
            self.attack_surface.append(node)

    def _aggregate_tech(self) -> List[str]:
        all_tech: Set[str] = set()
        for node in self.attack_surface:
            all_tech.update(node.technology_stack)
        return list(all_tech)

    # ------------------------------------------------------------------
    # HTML form extraction (enhanced with hidden inputs + risk hints)
    # ------------------------------------------------------------------

    def _extract_forms(
        self,
        soup: BeautifulSoup,
        base_url: str,
        tech_stack: List[str],
    ):
        for form in soup.find_all("form"):
            try:
                action = urllib.parse.urljoin(base_url, form.get("action", ""))
                method = form.get("method", "GET").upper()
                inputs = []
                has_file = False

                for tag in form.find_all(["input", "textarea", "select"]):
                    name = tag.get("name")
                    if not name:
                        continue
                    t = tag.get("type", "text").lower()
                    inputs.append({"name": name, "type": t})
                    if t == "file":
                        has_file = True

                risk = self._score_form_risk(inputs, method, has_file, action)
                node = AttackSurfaceNode(
                    url=action,
                    method=method,
                    parameters=[i["name"] for i in inputs],
                    inputs=inputs,
                    input_type="html_form",
                    context=f"Form on {base_url}",
                    technology_stack=tech_stack,
                    estimated_risk_score=risk,
                )
                self._add_node(node)
            except Exception as e:
                logger.debug(f"Form extraction error on {base_url}: {e}")

    def _score_form_risk(
        self, inputs: List[Dict], method: str, has_file: bool, action: str
    ) -> float:
        score = 0.0
        HIGH_VALUE_NAMES = {
            "username", "user", "email", "password", "pass", "token",
            "id", "admin", "key", "secret", "auth", "search", "query",
            "q", "file", "path", "url", "redirect", "cmd", "exec",
        }
        for inp in inputs:
            if inp.get("name", "").lower() in HIGH_VALUE_NAMES:
                score += 0.2
        if method in ("POST", "PUT", "PATCH"):
            score += 0.2
        if has_file:
            score += 0.3
        if any(kw in action.lower() for kw in ("login", "admin", "upload", "exec", "run")):
            score += 0.3
        return min(round(score, 2), 1.0)

    # ------------------------------------------------------------------
    # URL query-parameter endpoints
    # ------------------------------------------------------------------

    def _extract_url_params(
        self, url: str, tech_stack: List[str]
    ):
        parsed = urllib.parse.urlparse(url)
        params = list(urllib.parse.parse_qs(parsed.query).keys())
        if params:
            node = AttackSurfaceNode(
                url=url,
                method="GET",
                parameters=params,
                inputs=[{"name": p, "type": "query"} for p in params],
                input_type="query_param",
                context="URL query parameters",
                technology_stack=tech_stack,
                estimated_risk_score=round(min(len(params) * 0.1, 0.7), 2),
            )
            self._add_node(node)

    # ------------------------------------------------------------------
    # REST API endpoint detection
    # ------------------------------------------------------------------

    def _extract_rest_endpoints(
        self, soup: BeautifulSoup, body: str, base_url: str, tech_stack: List[str]
    ):
        # From anchor hrefs / form actions in HTML
        candidates = set()
        for match in self.REST_PATH_RE.finditer(body):
            candidates.add(match.group(1))

        # From inline <script> tags
        for script in soup.find_all("script"):
            src = script.string or ""
            for m in self.JS_FETCH_RE.finditer(src):
                path = m.group(1)
                if path.startswith("/") or path.startswith("http"):
                    candidates.add(path)
            for m in self.JS_ROUTE_RE.finditer(src):
                candidates.add(m.group(1))

        for path in candidates:
            if path.startswith("http"):
                full_url = path
            else:
                full_url = urllib.parse.urljoin(base_url, path)

            node = AttackSurfaceNode(
                url=full_url,
                method="GET",
                parameters=[],
                inputs=[],
                input_type="rest_api",
                context=f"REST endpoint discovered via {base_url}",
                technology_stack=tech_stack,
                estimated_risk_score=0.5,
            )
            self._add_node(node)

    # ------------------------------------------------------------------
    # GraphQL endpoint detection
    # ------------------------------------------------------------------

    def _extract_graphql_endpoints(
        self, body: str, base_url: str, tech_stack: List[str]
    ):
        if self.GRAPHQL_PATH_RE.search(base_url) or self.GRAPHQL_PATH_RE.search(body[:3000]):
            node = AttackSurfaceNode(
                url=base_url if self.GRAPHQL_PATH_RE.search(base_url)
                    else urllib.parse.urljoin(base_url, "/graphql"),
                method="POST",
                parameters=["query", "variables", "operationName"],
                inputs=[
                    {"name": "query", "type": "graphql"},
                    {"name": "variables", "type": "json"},
                ],
                input_type="graphql",
                context="GraphQL endpoint",
                technology_stack=tech_stack + ["GraphQL"],
                estimated_risk_score=0.8,
            )
            self._add_node(node)

    # ------------------------------------------------------------------
    # Link extraction (reused from original, slightly extended)
    # ------------------------------------------------------------------

    def _extract_links(self, soup: BeautifulSoup, base_url: str) -> Set[str]:
        urls: Set[str] = set()
        for tag in soup.find_all("a", href=True):
            urls.add(urllib.parse.urljoin(base_url, tag["href"]))
        for tag in soup.find_all("form", action=True):
            urls.add(urllib.parse.urljoin(base_url, tag["action"]))
        return urls

    # ------------------------------------------------------------------
    # Recursive crawl
    # ------------------------------------------------------------------

    async def _crawl_recursive(
        self, url: str, depth: int, scope_domains: List[str]
    ):
        if (
            depth <= 0
            or url in self.visited_urls
            or self.pages_crawled >= self.max_pages
        ):
            return

        parsed = urllib.parse.urlparse(url)
        if not any(d in parsed.netloc for d in scope_domains):
            return

        self.visited_urls.add(url)
        self.pages_crawled += 1

        try:
            timeout = aiohttp.ClientTimeout(total=12)
            async with self.session.get(url, timeout=timeout, allow_redirects=True) as resp:
                content_type = resp.headers.get("Content-Type", "")
                body = ""

                if "text/html" in content_type:
                    body = await resp.text()
                    if len(body) > 1_048_576:
                        body = body[:1_048_576]

                    # Technology detection
                    tech_stack = detect_technologies(
                        dict(resp.headers), body, url
                    )

                    soup = BeautifulSoup(body, "html.parser")

                    # --- collect attack surface ---
                    self._extract_url_params(url, tech_stack)
                    self._extract_forms(soup, url, tech_stack)
                    self._extract_rest_endpoints(soup, body, url, tech_stack)
                    self._extract_graphql_endpoints(body, url, tech_stack)

                    # --- recurse ---
                    if depth > 1 and self.pages_crawled < self.max_pages:
                        links = self._extract_links(soup, url)
                        sem = asyncio.Semaphore(5)

                        async def _go(link):
                            async with sem:
                                await self._crawl_recursive(link, depth - 1, scope_domains)

                        await asyncio.gather(
                            *[_go(lnk) for lnk in list(links)[:25]],
                            return_exceptions=True,
                        )

                elif "application/json" in content_type:
                    # JSON API response → register as REST endpoint
                    tech_stack = detect_technologies(dict(resp.headers), "", url)
                    node = AttackSurfaceNode(
                        url=url,
                        method="GET",
                        parameters=list(urllib.parse.parse_qs(parsed.query).keys()),
                        inputs=[],
                        input_type="json_body",
                        context="JSON API endpoint",
                        technology_stack=tech_stack,
                        estimated_risk_score=0.6,
                    )
                    self._add_node(node)

        except asyncio.TimeoutError:
            logger.warning(f"[EnhancedCrawler] Timeout: {url}")
        except Exception as e:
            logger.debug(f"[EnhancedCrawler] Error crawling {url}: {e}")