"""API for auditing URLs for common phishing indicators."""

import csv
import ipaddress
import logging
import re
from collections import defaultdict
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import AsyncGenerator, Dict, List, Optional, Set, Tuple
from urllib.parse import SplitResult, urlsplit

import jellyfish
import requests
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel


LOGGER = logging.getLogger(__name__)
DATASET_PATH = Path(__file__).resolve().with_name("top-1m.csv")
REQUEST_TIMEOUT_SECONDS = 5
MAX_TYPO_DISTANCE = 2

class URLAuditRequest(BaseModel):
    url: str


# The dataset is loaded during application startup. Labels are indexed by length
# so typo checks inspect all dataset candidates in the allowable distance range.
TOP_DOMAINS: Set[str] = set()
TOP_DOMAIN_LABELS_BY_LENGTH: Dict[int, List[str]] = {}
TOP_DOMAIN_EXAMPLES_BY_LABEL: Dict[str, str] = {}

HIGH_RISK_BRANDS = (
    "paypal",
    "google",
    "facebook",
    "amazon",
    "apple",
    "microsoft",
    "netflix",
    "instagram",
    "chase",
    "wellsfargo",
    "bankofamerica",
    "linkedin",
    "whatsapp",
    "dropbox",
    "adobe",
    "coinbase"
)

_LEETSPEAK_TRANSLATION = str.maketrans(
    {
        "1": "l",
        "0": "o",
        "3": "e",
        "@": "a",
        "5": "s",
        "7": "t",
        # Common single-character Greek and Cyrillic lookalikes.
        "\u03b1": "a",
        "\u0430": "a",
        "\u03b5": "e",
        "\u0435": "e",
        "\u03b9": "i",
        "\u0456": "i",
        "\u03bf": "o",
        "\u043e": "o",
        "\u03c1": "p",
        "\u0440": "p",
        "\u03c7": "x",
        "\u0445": "x",
        "\u0441": "c",
        "\u03bd": "v",
        "\u0443": "y",
    }
)


def load_top_domains() -> None:
    """Load the complete Tranco CSV and build a reusable typo-search index."""
    domains: Set[str] = set()
    labels_by_length: Dict[int, List[str]] = defaultdict(list)
    examples_by_label: Dict[str, str] = {}

    try:
        with DATASET_PATH.open("r", encoding="utf-8", newline="") as dataset:
            for row in csv.reader(dataset):
                if len(row) < 2:
                    continue

                domain = row[1].strip().rstrip(".").lower()
                if not domain:
                    continue
                try:
                    domain = domain.encode("idna").decode("ascii")
                except UnicodeError:
                    LOGGER.warning("Skipping invalid domain in dataset: %r", row[1])
                    continue

                domains.add(domain)
                label = normalize_leetspeak(domain.split(".", 1)[0])
                if label and label not in examples_by_label:
                    examples_by_label[label] = domain
                    labels_by_length[len(label)].append(label)
    except OSError as error:
        LOGGER.exception("Unable to load required domain dataset at %s", DATASET_PATH)
        raise RuntimeError(f"Unable to load domain dataset: {DATASET_PATH}") from error

    global TOP_DOMAINS, TOP_DOMAIN_LABELS_BY_LENGTH, TOP_DOMAIN_EXAMPLES_BY_LABEL
    TOP_DOMAINS = domains
    TOP_DOMAIN_LABELS_BY_LENGTH = dict(labels_by_length)
    TOP_DOMAIN_EXAMPLES_BY_LABEL = examples_by_label
    _closest_global_lookalike.cache_clear()
    LOGGER.info("Loaded %d domains from %s", len(TOP_DOMAINS), DATASET_PATH)


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncGenerator[None, None]:
    """Load the domain dataset before serving requests."""
    LOGGER.debug("Starting %s", _app.title)
    load_top_domains()
    yield


app = FastAPI(
    title="AI-Powered Smart Phishing & QR Auditor API",
    version="2.0.0",
    description="Dynamic global link auditing using the Tranco Top 1M dataset.",
    lifespan=lifespan,
)


@app.get("/health", tags=["health"])
def health_check() -> dict:
    """Provide a lightweight endpoint for deployment health checks."""
    return {"status": "ok"}


def normalize_leetspeak(value: str) -> str:
    """Normalize common ASCII leetspeak and visually similar Unicode letters."""
    return value.lower().translate(_LEETSPEAK_TRANSLATION)


def ensure_http_url(url: str) -> str:
    """Add HTTPS when no scheme is supplied and reject unsupported URL schemes."""
    candidate = url.strip()
    if not candidate:
        raise ValueError("URL cannot be empty")

    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", candidate):
        candidate = f"https://{candidate}"

    try:
        parsed = urlsplit(candidate)
        hostname = parsed.hostname
        parsed.port
    except ValueError as error:
        raise ValueError("URL contains an invalid hostname or port") from error
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
        raise ValueError("URL must have an HTTP or HTTPS scheme and a hostname")
    if not hostname:
        raise ValueError("URL must include a hostname")
    return candidate


def extract_domain(url: str) -> str:
    """Extract a lowercase hostname, excluding credentials, ports, and path."""
    parsed = urlsplit(ensure_http_url(url))
    try:
        hostname = parsed.hostname
    except ValueError as error:
        raise ValueError("URL contains an invalid hostname") from error
    if not hostname:
        raise ValueError("URL must include a hostname")
    return hostname.rstrip(".").lower()


def canonicalize_domain(domain: str) -> str:
    """Convert a hostname to its ASCII IDNA form for dataset and RDAP lookups."""
    try:
        return domain.rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError:
        return domain.rstrip(".").lower()


def is_ip_address(hostname: str) -> bool:
    """Return whether a hostname is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def unshorten_url(url: str) -> Tuple[str, List[str], Optional[str]]:
    """Follow redirects and return the final URL, redirect hops, and any error."""
    try:
        candidate = ensure_http_url(url)
        response = requests.get(
            candidate,
            allow_redirects=True,
            timeout=REQUEST_TIMEOUT_SECONDS,
            stream=True,
        )
        try:
            resolved_url = response.url
            redirect_chain = [candidate]
            for hop in response.history:
                hop_url = hop.url
                if hop_url and hop_url != redirect_chain[-1]:
                    redirect_chain.append(hop_url)
            if resolved_url and resolved_url != redirect_chain[-1]:
                redirect_chain.append(resolved_url)
            return (
                resolved_url or candidate,
                redirect_chain if len(redirect_chain) > 1 else [],
                None,
            )
        finally:
            response.close()
    except (requests.RequestException, ValueError) as error:
        LOGGER.warning("Unable to resolve redirects for the submitted URL: %s", error)
        return url, [], str(error)


def check_domain_age(domain: str) -> Tuple[Optional[int], Optional[str]]:
    """Return the domain age in days using its RDAP registration event."""
    if is_ip_address(domain):
        return None, "Host is a direct IP address"

    rdap_domain = canonicalize_domain(domain)
    try:
        response = requests.get(
            f"https://rdap.org/domain/{rdap_domain}",
            timeout=REQUEST_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
        payload = response.json()
        events = payload.get("events", []) if isinstance(payload, dict) else []
    except (requests.RequestException, ValueError) as error:
        LOGGER.warning("RDAP lookup failed for %s: %s", rdap_domain, error)
        return None, str(error)

    for event in events:
        if not isinstance(event, dict):
            continue
        if event.get("eventAction") not in {"registration", "created"}:
            continue

        event_date = event.get("eventDate")
        if not isinstance(event_date, str):
            continue
        try:
            created_at = datetime.fromisoformat(event_date.replace("Z", "+00:00"))
        except ValueError:
            LOGGER.warning("RDAP returned an invalid registration date for %s", rdap_domain)
            continue

        if created_at.tzinfo is None:
            created_at = created_at.replace(tzinfo=timezone.utc)
        age_days = (datetime.now(timezone.utc) - created_at).days
        return max(age_days, 0), None

    LOGGER.info("RDAP registration date was not found for %s", rdap_domain)
    return None, "Domain registration date not found"


def is_verified_popular_domain(domain: str) -> bool:
    """Test an exact hostname against the complete loaded domain dataset."""
    return canonicalize_domain(domain) in TOP_DOMAINS


def is_subdomain_of_popular_domain(domain: str) -> bool:
    """Recognize subdomains of listed sites to avoid false brand alerts."""
    hostname = canonicalize_domain(domain)
    labels = hostname.split(".")
    return any(".".join(labels[index:]) in TOP_DOMAINS for index in range(1, len(labels)))


def is_trusted_brand_host(domain: str, brand: str) -> bool:
    """Only trust a listed host suffix when its registered label matches the brand."""
    labels = canonicalize_domain(domain).split(".")
    for index in range(len(labels)):
        suffix = ".".join(labels[index:])
        suffix_label = normalize_leetspeak(labels[index])
        if suffix in TOP_DOMAINS and brand in suffix_label:
            return True
    return False


def check_brand_impersonation(domain: str) -> List[str]:
    """Flag target brands in untrusted hosts, including leetspeak variants."""
    if is_verified_popular_domain(domain):
        return []

    normalized_labels = [
        normalize_leetspeak(label)
        for label in domain.rstrip(".").lower().split(".")
    ]
    matches = [
        brand
        for brand in HIGH_RISK_BRANDS
        if any(brand in label for label in normalized_labels)
        and not is_trusted_brand_host(domain, brand)
    ]
    return [
        f"Brand impersonation / keyword trick detected targeting '{brand}'"
        for brand in matches
    ]


@lru_cache(maxsize=4096)
def _closest_global_lookalike(label: str) -> Optional[str]:
    """Find a nearby label across all loaded domains, without a rank cutoff."""
    if not TOP_DOMAIN_LABELS_BY_LENGTH:
        return None

    best_distance = MAX_TYPO_DISTANCE + 1
    closest_label: Optional[str] = None
    min_length = max(1, len(label) - MAX_TYPO_DISTANCE)
    max_length = len(label) + MAX_TYPO_DISTANCE

    for candidate_length in range(min_length, max_length + 1):
        for candidate in TOP_DOMAIN_LABELS_BY_LENGTH.get(candidate_length, []):
            distance = jellyfish.levenshtein_distance(label, candidate)
            if 0 < distance < best_distance:
                best_distance = distance
                closest_label = candidate
                if distance == 1:
                    return TOP_DOMAIN_EXAMPLES_BY_LABEL[closest_label]

    if closest_label is None:
        return None
    return TOP_DOMAIN_EXAMPLES_BY_LABEL[closest_label]


def check_global_lookalike(domain: str) -> Optional[str]:
    """Check every hostname label against the dataset's indexed labels."""
    if is_verified_popular_domain(domain) or is_subdomain_of_popular_domain(domain):
        return None

    for label in domain.rstrip(".").lower().split("."):
        normalized_label = normalize_leetspeak(label)
        if len(normalized_label) <= 3:
            continue
        if normalized_label in TOP_DOMAIN_EXAMPLES_BY_LABEL:
            continue
        match = _closest_global_lookalike(normalized_label)
        if match is not None:
            return match
    return None


def analyze_global_domain(domain: str) -> Tuple[int, List[str]]:
    """Combine dataset verification, stacking, brand, and typo heuristics."""
    if is_ip_address(domain):
        return 0, []
    if is_verified_popular_domain(domain):
        return 0, ["Verified in Global Top Popular Sites dataset"]

    risk = 0
    flags: List[str] = []
    labels = canonicalize_domain(domain).split(".")

    if len(labels) > 3:
        flags.append("Excessive subdomain stacking detected")
        risk += 25

    brand_flags = check_brand_impersonation(domain)
    if brand_flags:
        flags.extend(brand_flags)
        risk += 50
        return risk, flags

    lookalike = check_global_lookalike(domain)
    if lookalike:
        flags.append(f"Possible typosquatting targeting global domain '{lookalike}'")
        risk += 45

    return risk, flags


def risk_level_for_score(risk_score: int) -> str:
    """Map a bounded score to the public risk category."""
    if risk_score >= 70:
        return "CRITICAL"
    if risk_score >= 30:
        return "SUSPICIOUS"
    return "SAFE"


def has_redirected(submitted_url: str, resolved_url: str) -> bool:
    """Compare normalized URL components without treating a missing slash as a redirect."""
    submitted = urlsplit(ensure_http_url(submitted_url))
    resolved = urlsplit(ensure_http_url(resolved_url))

    def effective_port(parsed_url: SplitResult) -> int:
        port = parsed_url.port
        if port is not None:
            return port
        return 443 if parsed_url.scheme.lower() == "https" else 80

    submitted_parts = (
        submitted.scheme.lower(),
        (submitted.hostname or "").lower(),
        effective_port(submitted),
        submitted.path or "/",
        submitted.query,
    )
    resolved_parts = (
        resolved.scheme.lower(),
        (resolved.hostname or "").lower(),
        effective_port(resolved),
        resolved.path or "/",
        resolved.query,
    )
    return submitted_parts != resolved_parts


@app.post("/api/v1/audit-url")
def audit_url(request: URLAuditRequest) -> dict:
    """Resolve and score a submitted URL using the configured heuristics."""
    input_url = request.url.strip()
    if not input_url:
        raise HTTPException(status_code=400, detail="URL cannot be empty")

    try:
        ensure_http_url(input_url)
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error

    flags: List[str] = []
    risk_score = 0
    resolved_url, redirect_chain, resolution_error = unshorten_url(input_url)
    if redirect_chain or has_redirected(input_url, resolved_url):
        flags.append(f"Redirected / Shortened URL detected (Target: {resolved_url})")
        risk_score += 10
    elif resolution_error:
        flags.append(
            "Unable to resolve redirects; the shortener domain was analyzed instead"
        )
        risk_score += 10

    try:
        domain = extract_domain(resolved_url)
    except ValueError as error:
        raise HTTPException(status_code=502, detail="Resolved URL has an invalid hostname") from error

    if is_ip_address(domain):
        flags.append("URL uses a raw IP address instead of a domain name")
        risk_score += 35
    else:
        age_days, _ = check_domain_age(domain)
        if age_days is not None:
            if age_days < 30:
                flags.append(f"Domain is newly registered ({age_days} days old)")
                risk_score += 30
            elif age_days < 90:
                flags.append(f"Domain is relatively new ({age_days} days old)")
                risk_score += 15

    domain_risk, domain_flags = analyze_global_domain(domain)
    risk_score += domain_risk
    flags.extend(domain_flags)

    risk_score = max(0, min(risk_score, 100))
    return {
        "original_url": input_url,
        "resolved_url": resolved_url,
        "redirect_chain": redirect_chain,
        "domain": domain,
        "risk_score": risk_score,
        "risk_level": risk_level_for_score(risk_score),
        "flags": flags,
    }
