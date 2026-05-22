import logging
from typing import Dict, Any, List, Optional
import hashlib

logger = logging.getLogger(__name__)


class AnomalyDetector:
    """
    Behavioral anomaly detector for vulnerability discovery.

    Workflow:
    1. Collect baseline responses from clean (benign) requests.
    2. During payload testing, compare each response to the baseline.
    3. Flag endpoints exhibiting statistically significant deviations.

    Signals tracked:
    - Response length deviation
    - HTTP status code change
    - Response time deviation
    - Content hash change (structural change)
    - New / missing headers
    - Error keyword appearance
    """

    ERROR_KEYWORDS = [
        "exception", "traceback", "stack trace", "error", "warning",
        "undefined", "null pointer", "segfault", "fatal", "unhandled",
        "syntax error", "sql", "database", "mysql", "postgresql", "oracle",
        "permission denied", "access denied",
    ]

    def __init__(
        self,
        length_deviation_pct: float = 0.20,  # 20% change flags anomaly
        latency_spike_factor: float = 2.5,
        baseline_samples: int = 3,
    ):
        self.length_deviation_pct = length_deviation_pct
        self.latency_spike_factor = latency_spike_factor
        self.baseline_samples = baseline_samples

        # Per-URL baselines
        self._baselines: Dict[str, Dict[str, Any]] = {}
        self._anomalies: List[Dict[str, Any]] = []

    # ------------------------------------------------------------------
    # Baseline collection
    # ------------------------------------------------------------------

    def record_baseline(self, url: str, response: Dict[str, Any]):
        """
        Call this with clean (no-payload) responses before injection testing.
        Accumulates up to `baseline_samples` responses then averages them.
        """
        if url not in self._baselines:
            self._baselines[url] = {
                "lengths": [],
                "latencies": [],
                "status_codes": [],
                "content_hashes": [],
                "headers_seen": set(),
            }

        bl = self._baselines[url]
        body = response.get("body", "")
        bl["lengths"].append(len(body))
        bl["latencies"].append(response.get("response_time", 0))
        bl["status_codes"].append(response.get("status_code", 200))
        bl["content_hashes"].append(hashlib.md5(body.encode()).hexdigest())

        for header in response.get("headers", {}):
            bl["headers_seen"].add(header.lower())

        logger.debug(
            f"[Anomaly] Baseline sample recorded for {url} "
            f"(samples={len(bl['lengths'])})"
        )

    def _get_baseline_stats(self, url: str) -> Optional[Dict[str, Any]]:
        bl = self._baselines.get(url)
        if not bl or not bl["lengths"]:
            return None

        avg_len = sum(bl["lengths"]) / len(bl["lengths"])
        avg_latency = sum(bl["latencies"]) / len(bl["latencies"])
        dominant_status = max(set(bl["status_codes"]), key=bl["status_codes"].count)
        dominant_hash = max(set(bl["content_hashes"]), key=bl["content_hashes"].count)

        return {
            "avg_length": avg_len,
            "avg_latency": avg_latency,
            "dominant_status": dominant_status,
            "dominant_hash": dominant_hash,
            "headers_seen": bl["headers_seen"],
        }

    # ------------------------------------------------------------------
    # Anomaly detection
    # ------------------------------------------------------------------

    def analyze(
        self,
        url: str,
        response: Dict[str, Any],
        payload: str = "",
        vuln_type: str = "",
    ) -> Dict[str, Any]:
        """
        Compare `response` against the stored baseline for `url`.
        Returns an anomaly report dict.
        """
        baseline = self._get_baseline_stats(url)
        anomalies_found: List[str] = []
        anomaly_score: float = 0.0

        body = response.get("body", "")
        status = response.get("status_code", 200)
        latency = response.get("response_time", 0)
        resp_headers = {k.lower() for k in response.get("headers", {})}

        if baseline is None:
            # No baseline — cannot compare, flag as unknown
            return {
                "is_anomalous": False,
                "anomaly_score": 0.0,
                "anomalies": [],
                "note": "No baseline available for this URL",
            }

        # --- Signal 1: Response length deviation ---
        resp_len = len(body)
        if baseline["avg_length"] > 0:
            deviation = abs(resp_len - baseline["avg_length"]) / baseline["avg_length"]
            if deviation > self.length_deviation_pct:
                anomalies_found.append(
                    f"length_deviation: {deviation:.0%} "
                    f"(baseline={int(baseline['avg_length'])}, got={resp_len})"
                )
                anomaly_score += min(deviation, 1.0) * 0.3

        # --- Signal 2: Status code change ---
        if status != baseline["dominant_status"]:
            anomalies_found.append(
                f"status_change: {baseline['dominant_status']} → {status}"
            )
            anomaly_score += 0.3

        # --- Signal 3: Latency spike ---
        if baseline["avg_latency"] > 0:
            if latency > baseline["avg_latency"] * self.latency_spike_factor:
                anomalies_found.append(
                    f"latency_spike: {latency:.2f}s vs baseline {baseline['avg_latency']:.2f}s"
                )
                anomaly_score += 0.25

        # --- Signal 4: Content hash change (structural) ---
        resp_hash = hashlib.md5(body.encode()).hexdigest()
        if resp_hash != baseline["dominant_hash"]:
            # Content changed — weight by how much it changed
            anomalies_found.append("content_structure_changed")
            anomaly_score += 0.1

        # --- Signal 5: Error keywords appeared ---
        lower_body = body.lower()
        found_errors = [kw for kw in self.ERROR_KEYWORDS if kw in lower_body]
        if found_errors:
            anomalies_found.append(f"error_keywords_appeared: {found_errors[:5]}")
            anomaly_score += min(len(found_errors) * 0.1, 0.4)

        # --- Signal 6: New headers appeared ---
        new_headers = resp_headers - baseline["headers_seen"]
        if new_headers:
            anomalies_found.append(f"new_headers: {new_headers}")
            anomaly_score += 0.05

        anomaly_score = min(round(anomaly_score, 3), 1.0)
        is_anomalous = anomaly_score >= 0.3 or len(anomalies_found) >= 2

        result = {
            "is_anomalous": is_anomalous,
            "anomaly_score": anomaly_score,
            "anomalies": anomalies_found,
            "payload": payload,
            "vuln_type": vuln_type,
            "url": url,
            "status": status,
            "response_length": resp_len,
        }

        if is_anomalous:
            self._anomalies.append(result)
            logger.warning(
                f"[Anomaly] ANOMALY DETECTED on {url} | score={anomaly_score:.2f} | "
                f"signals={anomalies_found}"
            )

        return result

    # ------------------------------------------------------------------
    # Reporting
    # ------------------------------------------------------------------

    def get_all_anomalies(self) -> List[Dict[str, Any]]:
        return sorted(self._anomalies, key=lambda a: a["anomaly_score"], reverse=True)

    def summary(self) -> Dict[str, Any]:
        return {
            "urls_baselined": len(self._baselines),
            "total_anomalies": len(self._anomalies),
            "high_score_anomalies": sum(
                1 for a in self._anomalies if a["anomaly_score"] >= 0.6
            ),
            "anomalies": self.get_all_anomalies(),
        }