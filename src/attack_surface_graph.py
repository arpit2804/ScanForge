import logging
import urllib.parse
from typing import Dict, Any, List, Set

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Scoring constants
# ---------------------------------------------------------------------------

HIGH_VALUE_PARAM_NAMES: Set[str] = {
    "id", "user_id", "uid", "admin", "token", "key", "secret", "password",
    "passwd", "auth", "session", "redirect", "url", "path", "file", "cmd",
    "exec", "query", "q", "search", "username", "email", "role",
}

HIGH_RISK_PATHS: List[str] = [
    "/admin", "/login", "/logout", "/register", "/upload", "/exec",
    "/run", "/api/", "/v1/", "/v2/", "/graphql", "/gql", "/auth",
    "/oauth", "/reset", "/delete", "/remove",
]

SENSITIVE_METHODS: Set[str] = {"POST", "PUT", "PATCH", "DELETE"}


# ---------------------------------------------------------------------------
# Graph node and edge
# ---------------------------------------------------------------------------

class SurfaceNode:
    def __init__(self, node_id: str, endpoint: Dict[str, Any]):
        self.node_id = node_id
        self.url = endpoint.get("url", "")
        self.method = endpoint.get("method", "GET").upper()
        self.parameters = endpoint.get("parameters", [])
        self.inputs = endpoint.get("inputs", [])
        self.input_type = endpoint.get("input_type", "html_form")
        self.technology_stack = endpoint.get("technology_stack", [])
        self.risk_score: float = 0.0
        self.metadata = endpoint

    def __repr__(self):
        return f"SurfaceNode({self.method} {self.url} risk={self.risk_score:.2f})"


class SurfaceEdge:
    def __init__(self, src_id: str, dst_id: str, relation: str = "link"):
        self.src_id = src_id
        self.dst_id = dst_id
        self.relation = relation   # "link" | "api_call" | "form_submit" | "data_flow"


# ---------------------------------------------------------------------------
# Main graph class
# ---------------------------------------------------------------------------

class AttackSurfaceGraph:
    """
    Constructs a risk-scored graph from crawled attack surface data.

    Nodes  → application components (pages, API endpoints, forms, parameters)
    Edges  → relationships (navigation links, API calls, data flow)

    Risk scoring factors:
    - Parameter semantics (id, token, admin …)
    - Authentication relevance
    - Number of input fields
    - HTTP method sensitivity
    - File uploads
    - Path-level risk keywords
    - Input type (GraphQL, REST → higher)
    """

    def __init__(self):
        self.nodes: Dict[str, SurfaceNode] = {}
        self.edges: List[SurfaceEdge] = []

    # ------------------------------------------------------------------
    # Build
    # ------------------------------------------------------------------

    def build_from_crawl(self, crawl_result: Dict[str, Any]):
        """Populate the graph from the output of EnhancedWebCrawler.crawl_site()."""
        endpoints = crawl_result.get("endpoints", [])
        for ep in endpoints:
            node_id = self._make_node_id(ep)
            node = SurfaceNode(node_id, ep)
            node.risk_score = self._calculate_risk(ep)
            self.nodes[node_id] = node

        self._infer_edges()
        logger.info(
            f"[Graph] Built graph: {len(self.nodes)} nodes, {len(self.edges)} edges"
        )

    def _make_node_id(self, endpoint: Dict[str, Any]) -> str:
        method = endpoint.get("method", "GET").upper()
        url = endpoint.get("url", "")
        parsed = urllib.parse.urlparse(url)
        return f"{method}:{parsed.scheme}://{parsed.netloc}{parsed.path}"

    def _infer_edges(self):
        """
        Create edges between nodes that share the same base path
        (likely same component) or have a parent-child URL relationship.
        """
        node_list = list(self.nodes.values())
        for i, node_a in enumerate(node_list):
            base_a = urllib.parse.urlparse(node_a.url)
            path_a = base_a.path.rstrip("/")

            for node_b in node_list[i + 1:]:
                base_b = urllib.parse.urlparse(node_b.url)
                path_b = base_b.path.rstrip("/")

                # Parent-child path relationship
                if path_b.startswith(path_a + "/") or path_a.startswith(path_b + "/"):
                    relation = "navigation"
                    if node_a.input_type in ("rest_api", "json_body", "graphql"):
                        relation = "api_call"
                    self.edges.append(SurfaceEdge(node_a.node_id, node_b.node_id, relation))

    # ------------------------------------------------------------------
    # Risk scoring
    # ------------------------------------------------------------------

    def _calculate_risk(self, endpoint: Dict[str, Any]) -> float:
        score = 0.0
        url = endpoint.get("url", "").lower()
        method = endpoint.get("method", "GET").upper()
        parameters = endpoint.get("parameters", [])
        inputs = endpoint.get("inputs", [])
        input_type = endpoint.get("input_type", "html_form")

        # 1. HTTP method sensitivity
        if method in SENSITIVE_METHODS:
            score += 0.25

        # 2. High-risk path keywords
        for kw in HIGH_RISK_PATHS:
            if kw in url:
                score += 0.2
                break

        # 3. Parameter semantics
        all_param_names = set()
        for p in parameters:
            if isinstance(p, str):
                all_param_names.add(p.lower())
        for inp in inputs:
            if isinstance(inp, dict):
                all_param_names.add(inp.get("name", "").lower())

        for name in all_param_names:
            if name in HIGH_VALUE_PARAM_NAMES:
                score += 0.15

        # 4. Number of inputs
        num_inputs = len(inputs) or len(parameters)
        score += min(num_inputs * 0.05, 0.2)

        # 5. File upload
        if any(
            isinstance(inp, dict) and inp.get("type") == "file"
            for inp in inputs
        ):
            score += 0.3

        # 6. Input type bonuses
        if input_type == "graphql":
            score += 0.3
        elif input_type in ("rest_api", "json_body"):
            score += 0.2
        elif input_type == "query_param":
            score += 0.05

        # 7. Authentication-related paths
        if any(kw in url for kw in ("auth", "login", "token", "oauth", "session")):
            score += 0.2

        return min(round(score, 3), 1.0)

    # ------------------------------------------------------------------
    # Query helpers
    # ------------------------------------------------------------------

    def get_prioritized_endpoints(self, top_n: int = 20) -> List[Dict[str, Any]]:
        """Return endpoints sorted by risk score, highest first."""
        sorted_nodes = sorted(
            self.nodes.values(), key=lambda n: n.risk_score, reverse=True
        )
        result = []
        for node in sorted_nodes[:top_n]:
            d = node.metadata.copy()
            d["risk_score"] = node.risk_score
            d["node_id"] = node.node_id
            result.append(d)
        return result

    def get_high_risk_endpoints(self, threshold: float = 0.5) -> List[Dict[str, Any]]:
        return [
            ep for ep in self.get_prioritized_endpoints(len(self.nodes))
            if ep["risk_score"] >= threshold
        ]

    def summary(self) -> Dict[str, Any]:
        scores = [n.risk_score for n in self.nodes.values()]
        return {
            "total_nodes": len(self.nodes),
            "total_edges": len(self.edges),
            "high_risk_nodes": sum(1 for s in scores if s >= 0.5),
            "medium_risk_nodes": sum(1 for s in scores if 0.25 <= s < 0.5),
            "low_risk_nodes": sum(1 for s in scores if s < 0.25),
            "average_risk": round(sum(scores) / len(scores), 3) if scores else 0,
            "top_5": self.get_prioritized_endpoints(5),
        }