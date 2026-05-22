import logging
from typing import Dict, Any, List, Tuple

logger = logging.getLogger(__name__)

class AdaptivePayloadBudget:
    """
    Dynamically determines how many payloads to test per endpoint
    based on confidence score progression.
    """

    def __init__(self, min_payloads: int = 3, max_payloads: int = 20, confidence_threshold: float = 0.85):
        self.min_payloads = min_payloads
        self.max_payloads = max_payloads
        self.confidence_threshold = confidence_threshold
        self.marginal_improvement_threshold = 0.05  # Stop if improvement < 5%

    def estimate_initial_budget(self, endpoint: Dict[str, Any]) -> int:
        """
        Estimate initial payload budget based on endpoint complexity.
        More parameters, diverse types → larger budget.
        """
        score = self.min_payloads

        # Factor 1: Number of parameters
        params = endpoint.get("parameters", [])
        if isinstance(params, list):
            score += len(params)
        elif isinstance(params, dict):
            score += len(params)

        # Factor 2: HTTP method sensitivity
        method = endpoint.get("method", "GET").upper()
        if method in ("POST", "PUT", "PATCH"):
            score += 3

        # Factor 3: Input type diversity
        inputs = endpoint.get("inputs", [])
        input_types = {inp.get("type", "text") for inp in inputs if isinstance(inp, dict)}
        score += len(input_types)

        # Factor 4: Risk score if pre-calculated
        risk = endpoint.get("risk_score", 0)
        score += int(risk * 5)

        # Factor 5: File upload present
        if any(inp.get("type") == "file" for inp in inputs if isinstance(inp, dict)):
            score += 4

        return min(max(score, self.min_payloads), self.max_payloads)

    def should_continue(
        self,
        confidence_history: List[float],
        payloads_used: int,
        initial_budget: int,
    ) -> Tuple[bool, str]:
        """
        Decide whether to generate and test another payload.

        Returns (continue: bool, reason: str)
        """
        # Always run minimum payloads
        if payloads_used < self.min_payloads:
            return True, "below_minimum"

        # Hard stop at max
        if payloads_used >= self.max_payloads:
            return False, "max_reached"

        # Vulnerability confirmed with high confidence → stop
        if confidence_history and confidence_history[-1] >= self.confidence_threshold:
            return False, "high_confidence_vuln_found"

        # Check marginal improvement over last 3 payloads
        if len(confidence_history) >= 3:
            recent = confidence_history[-3:]
            improvement = recent[-1] - recent[0]
            if abs(improvement) < self.marginal_improvement_threshold:
                return False, "negligible_improvement"

        # Haven't exhausted initial budget
        if payloads_used < initial_budget:
            return True, "within_budget"

        # Beyond initial budget but confidence is growing → keep going
        if len(confidence_history) >= 2:
            if confidence_history[-1] > confidence_history[-2]:
                return True, "confidence_growing"

        return False, "budget_exhausted"

    async def run_adaptive_scan(
        self,
        endpoint: Dict[str, Any],
        vuln_type: str,
        payload_getter,      # async callable: (vuln_type, context, count) -> List[str]
        injector,            # async callable: (url, injection_point, payload) -> response dict
        analyzer,            # async callable: (request, response) -> analysis dict
    ) -> Dict[str, Any]:
        """
        Full adaptive scanning loop for a single endpoint.
        """
        initial_budget = self.estimate_initial_budget(endpoint)
        logger.info(
            f"Adaptive scan: {endpoint.get('url')} | type={vuln_type} | "
            f"initial_budget={initial_budget}"
        )

        url = endpoint.get("url", "")
        inputs = endpoint.get("inputs", [])
        method = endpoint.get("method", "GET")
        parameters = endpoint.get("parameters", [])

        # Build context for the payload generator
        context = {
            "url": url,
            "method": method,
            "parameters": parameters,
            "inputs": inputs,
            "vulnerability_type": vuln_type,
        }

        confidence_history: List[float] = []
        payloads_tested: List[str] = []
        findings: List[Dict[str, Any]] = []
        payloads_used = 0

        # Determine injection points
        injection_points = self._get_injection_points(endpoint)
        if not injection_points:
            return {"tested": 0, "findings": [], "reason": "no_injection_points"}

        while True:
            should_go, reason = self.should_continue(
                confidence_history, payloads_used, initial_budget
            )
            if not should_go:
                logger.info(f"Stopping adaptive scan: {reason}")
                break

            # Generate one payload at a time for adaptive decisions
            new_payloads = await payload_getter(vuln_type, context, 1)
            if not new_payloads:
                break

            payload = new_payloads[0]
            # Skip duplicates
            if payload in payloads_tested:
                payloads_used += 1
                continue

            payloads_tested.append(payload)

            # Test against each injection point
            best_confidence = 0.0
            for inj_point in injection_points:
                response = await injector(url, inj_point, payload, method)
                if "error" in response:
                    continue

                request_ctx = {
                    "payload": payload,
                    "url": url,
                    "method": method,
                    "vulnerability_type": vuln_type,
                    "injection_point": inj_point,
                }
                analysis = await analyzer(request_ctx, response)

                conf = analysis.get("confidence", 0.0)
                if conf > best_confidence:
                    best_confidence = conf

                if analysis.get("vulnerability_detected"):
                    findings.append({
                        "payload": payload,
                        "injection_point": inj_point,
                        "analysis": analysis,
                        "confidence": conf,
                    })

            confidence_history.append(best_confidence)
            payloads_used += 1

            logger.info(
                f"Payload {payloads_used}: confidence={best_confidence:.2f} | "
                f"history={[round(c, 2) for c in confidence_history]}"
            )

        return {
            "tested": payloads_used,
            "findings": findings,
            "confidence_history": confidence_history,
            "initial_budget": initial_budget,
            "reason": reason,
        }

    def _get_injection_points(self, endpoint: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract testable injection points from an endpoint."""
        points = []

        # Form inputs
        for inp in endpoint.get("inputs", []):
            if isinstance(inp, dict) and inp.get("name"):
                points.append({"type": "form_field", "name": inp["name"]})

        # Query parameters
        for param in endpoint.get("parameters", []):
            if isinstance(param, str):
                points.append({"type": "query_param", "name": param})

        return points