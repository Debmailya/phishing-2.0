import hashlib
import re
import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse

import dns.resolver
import whois

from app.core.config import settings

COMMON_BLACKLIST = {"phishingsite.example", "malicious-paypa1.com"}
HOMOGLYPHS = {"а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x"}


class DetectionService:
    def __init__(self) -> None:
        self.trusted_brands = [brand.strip() for brand in settings.trusted_brands.split(",")]

    def hash_url(self, url: str) -> str:
        return hashlib.sha256(url.encode("utf-8")).hexdigest()

    def scan(self, url: str) -> dict:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        reasons: list[str] = []
        score = 0.0
        brand = self._detect_brand_impersonation(domain)

        if self._is_blacklisted(domain):
            reasons.append("domain_matches_blacklist")
            score += 45
        if self._is_new_domain(domain):
            reasons.append("young_domain")
            score += 15
        if self._has_suspicious_dns(domain):
            reasons.append("suspicious_dns_configuration")
            score += 10
        if not self._has_valid_ssl(domain):
            reasons.append("invalid_or_missing_ssl")
            score += 20
        if brand:
            reasons.append("brand_impersonation_detected")
            score += 25
        if self._is_homograph(domain):
            reasons.append("homograph_attack_pattern")
            score += 20
        if self._looks_like_phishing_content(url):
            reasons.append("html_content_login_harvest_pattern")
            score += 20

        verdict = "malicious" if score >= 60 else "suspicious" if score >= 30 else "benign"
        return {
            "risk_score": min(score, 100),
            "verdict": verdict,
            "reasons": reasons,
            "detected_brand": brand,
            "created_at": datetime.now(timezone.utc),
        }

    def _is_blacklisted(self, domain: str) -> bool:
        return domain in COMMON_BLACKLIST

    def _is_new_domain(self, domain: str) -> bool:
        try:
            info = whois.whois(domain)
            creation = info.creation_date
            if isinstance(creation, list):
                creation = creation[0]
            return (datetime.now() - creation).days < 30
        except Exception:
            return False

    def _has_suspicious_dns(self, domain: str) -> bool:
        try:
            mx_records = dns.resolver.resolve(domain, "MX")
            return len(mx_records) == 0
        except Exception:
            return True

    def _has_valid_ssl(self, domain: str) -> bool:
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=2) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as secure_sock:
                    secure_sock.getpeercert()
                    return True
        except Exception:
            return False

    def _detect_brand_impersonation(self, domain: str) -> str | None:
        stripped = re.sub(r"[^a-z0-9]", "", domain)
        for brand in self.trusted_brands:
            if brand in stripped and brand not in domain:
                return brand
            if self._levenshtein(domain.split(".")[0], brand) <= 1:
                return brand
        return None

    def _is_homograph(self, domain: str) -> bool:
        return any(char in HOMOGLYPHS for char in domain)

    def _looks_like_phishing_content(self, url: str) -> bool:
        lowered = url.lower()
        risky = ["verify-account", "secure-login", "update-payment", "wallet-unlock"]
        return any(token in lowered for token in risky)

    def _levenshtein(self, a: str, b: str) -> int:
        if len(a) < len(b):
            return self._levenshtein(b, a)
        if len(b) == 0:
            return len(a)
        previous_row = list(range(len(b) + 1))
        for i, c1 in enumerate(a):
            current_row = [i + 1]
            for j, c2 in enumerate(b):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        return previous_row[-1]
