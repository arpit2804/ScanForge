import asyncio
import logging
import re
import time
import urllib.parse
from typing import Dict, Any, List, Optional, Tuple

import aiohttp

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Known WAF signatures in response bodies / headers
# ---------------------------------------------------------------------------
WAF_BODY_SIGNATURES = [
    (r"Access Denied",               "Generic"),
    (r"Forbidden.*firewall",         "Generic"),
    (r"mod_security",                "ModSecurity"),
    (r"NAXSI",                       "NAXSI"),
    (r"Cloudflare",                  "Cloudflare"),
    (r"__cfduid|cf-ray",             "Cloudflare"),
    (r"Incapsula",                   "Imperva Incapsula"),
    (r"X-Sucuri-ID",                 "Sucuri"),
    (r"Barracuda",                   "Barracuda"),
    (r"F5 BIG-IP",                   "F5 BIG-IP ASM"),
    (r"akamai",                      "Akamai"),
    (r"detected as a security risk", "Generic"),
    (r"blocked by.*security",        "Generic"),
    (r"Your IP has been blocked",    "Generic"),
]

WAF_HEADER_SIGNATURES = [
    ("x-sucuri-id",             "Sucuri"),
    ("x-protected-by",          "Generic WAF"),
    ("x-waf-event-info",        "Generic WAF"),
    ("cf-ray",                  "Cloudflare"),
    ("x-fw-protection",         "Firewall"),
    ("x-cdn",                   "CDN/WAF"),
    ("x-incapsula-session",     "Imperva Incapsula"),
    ("x-iinfo",                 "Imperva Incapsula"),
    ("server: cloudflare",      "Cloudflare"),
    ("server: awselb",          "AWS WAF"),
]

# HTTP status codes that typically mean WAF blocked
WAF_STATUS_CODES = {403, 406, 429, 503, 999}

# Payload evasion transformations
EVASION_TRANSFORMS = [
    "url_encode",
    "double_url_encode",
    "html_entity",
    "case_swap",
    "unicode_escape",
    "payload_split",
    "comment_insertion",
    "whitespace_variation",
]


class WAFDetector:
    """
    Detects WAF presence and switches to adaptive evasion mode when needed.
    """

    def __init__(
        self,
        block_threshold: int = 3,         # consecutive blocks before declaring WAF
        latency_spike_factor: float = 3.0, # 3× baseline = anomalous
    ):
        self.block_threshold = block_threshold
        self.latency_spike_factor = latency_spike_factor

        self._block_count: int = 0
        self._baseline_latency: Optional[float] = None
        self._waf_detected: bool = False
        self._waf_vendor: str = "Unknown"
        self._blocked_responses: List[Dict[str, Any]] = []

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @property
    def waf_detected(self) -> bool:
        return self._waf_detected

    @property
    def waf_vendor(self) -> str:
        return self._waf_vendor

    def set_baseline_latency(self, latency: float):
        self._baseline_latency = latency
        logger.info(f"[WAF] Baseline latency set to {latency:.3f}s")

    def record_response(self, response: Dict[str, Any]) -> Dict[str, Any]:
        """
        Feed a raw response dict into the detector.
        Returns a dict with 'blocked', 'waf_vendor', 'signals'.
        """
        signals = []
        blocked = False
        vendor = "Unknown"

        status = response.get("status_code", 200)
        headers = {k.lower(): v.lower() for k, v in response.get("headers", {}).items()}
        body = response.get("body", "")
        latency = response.get("response_time", 0)

        # --- Signal 1: Status code ---
        if status in WAF_STATUS_CODES:
            signals.append(f"status_code={status}")
            blocked = True

        # --- Signal 2: Body patterns ---
        for pattern, waf_name in WAF_BODY_SIGNATURES:
            if re.search(pattern, body, re.IGNORECASE):
                signals.append(f"body_pattern='{pattern}' ({waf_name})")
                vendor = waf_name
                blocked = True
                break

        # --- Signal 3: Header signatures ---
        header_str = " ".join(f"{k}:{v}" for k, v in headers.items())
        for header_sig, waf_name in WAF_HEADER_SIGNATURES:
            if header_sig in header_str:
                signals.append(f"header='{header_sig}' ({waf_name})")
                vendor = waf_name
                blocked = True
                break

        # --- Signal 4: Latency spike ---
        if self._baseline_latency and latency > self._baseline_latency * self.latency_spike_factor:
            signals.append(
                f"latency_spike: {latency:.2f}s vs baseline {self._baseline_latency:.2f}s"
            )

        # --- Update WAF state ---
        if blocked:
            self._block_count += 1
            self._blocked_responses.append(response)
            if self._block_count >= self.block_threshold and not self._waf_detected:
                self._waf_detected = True
                self._waf_vendor = vendor
                logger.warning(
                    f"[WAF] WAF DETECTED after {self._block_count} blocks! "
                    f"Vendor: {vendor}"
                )
        else:
            # Reset consecutive block count on clean response
            self._block_count = max(0, self._block_count - 1)

        return {
            "blocked": blocked,
            "waf_vendor": vendor,
            "signals": signals,
            "waf_active": self._waf_detected,
        }

    def transform_payload(self, payload: str, transform: str) -> str:
        """Apply a single evasion transformation to a payload."""
        if transform == "url_encode":
            return urllib.parse.quote(payload, safe="")
        if transform == "double_url_encode":
            return urllib.parse.quote(urllib.parse.quote(payload, safe=""), safe="")
        if transform == "html_entity":
            return "".join(f"&#{ord(c)};" for c in payload)
        if transform == "case_swap":
            return "".join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(payload))
        if transform == "unicode_escape":
            return "".join(f"\\u{ord(c):04x}" if c.isalpha() else c for c in payload)
        if transform == "payload_split":
            mid = len(payload) // 2
            return payload[:mid] + "/**/" + payload[mid:]
        if transform == "comment_insertion":
            # Insert SQL/JS comments inside keywords
            return re.sub(r"([a-zA-Z]{3,})", lambda m: m.group(0)[:2] + "/**/" + m.group(0)[2:], payload, count=3)
        if transform == "whitespace_variation":
            return re.sub(r"\s+", "\t", payload)
        return payload

    def get_evasion_payloads(self, original_payload: str) -> List[Tuple[str, str]]:
        """
        Return a list of (transformed_payload, transform_name) tuples
        for WAF bypass attempts.
        """
        variants: List[Tuple[str, str]] = []
        for transform in EVASION_TRANSFORMS:
            try:
                transformed = self.transform_payload(original_payload, transform)
                if transformed != original_payload:
                    variants.append((transformed, transform))
            except Exception as e:
                logger.debug(f"Transform {transform} failed: {e}")
        return variants

    async def measure_baseline(
        self, session: aiohttp.ClientSession, url: str, samples: int = 3
    ):
        """Measure baseline latency from benign requests."""
        latencies = []
        for _ in range(samples):
            try:
                start = time.time()
                async with session.get(
                    url, timeout=aiohttp.ClientTimeout(total=10)
                ) as resp:
                    await resp.read()
                latencies.append(time.time() - start)
                await asyncio.sleep(0.5)
            except Exception:
                pass
        if latencies:
            self.set_baseline_latency(sum(latencies) / len(latencies))