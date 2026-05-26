"""Scope validation and ownership verification."""

import hashlib
from urllib.parse import urlparse

import httpx

from src.core.config import get_settings
from src.core.exceptions import ScopeViolationError


def _normalize_domain(url_or_domain: str) -> str:
    """Extract netloc and strip www/port."""
    if url_or_domain.startswith("http://") or url_or_domain.startswith("https://"):
        parsed = urlparse(url_or_domain)
        host = parsed.hostname or ""
    else:
        host = url_or_domain.split(":")[0]
    return host.lower().removeprefix("www.")


def _is_in_scope(target: str, allowed_domains: list[str]) -> bool:
    """Check if target domain is in allowed scope list."""
    target_norm = _normalize_domain(target)
    for allowed in allowed_domains:
        allowed_norm = _normalize_domain(allowed)
        if target_norm == allowed_norm or target_norm.endswith(f".{allowed_norm}"):
            return True
    return False


async def verify_ownership_dns(domain: str, expected_token: str) -> bool:
    """Verify ownership via DNS TXT record containing expected token."""
    try:
        import dns.resolver  # optional dependency

        answers = dns.resolver.resolve(domain, "TXT")
        for rdata in answers:
            txt = rdata.to_text().strip('"')
            if expected_token in txt:
                return True
    except Exception:
        return False
    return False


async def verify_ownership_meta_tag(
    domain: str, expected_token: str, client: httpx.AsyncClient
) -> bool:
    """Verify ownership via HTML meta tag."""
    try:
        url = f"https://{domain}" if not domain.startswith("http") else domain
        response = await client.get(url, timeout=15)
        response.raise_for_status()
        if expected_token in response.text:
            return True
    except Exception:
        return False
    return False


def validate_scope(target: str, allowed_domains: list[str]) -> None:
    """Raise ScopeViolationError if target is not in allowed scope."""
    if not allowed_domains:
        return
    if not _is_in_scope(target, allowed_domains):
        raise ScopeViolationError(
            message=f"Target '{target}' is outside the authorized scope.",
            target=target,
        )


async def verify_ownership(
    domain: str,
    method: str = "auto",
    expected_token: str | None = None,
    client: httpx.AsyncClient | None = None,
) -> bool:
    """Verify target ownership by DNS TXT or meta tag."""
    if expected_token is None:
        settings = get_settings()
        expected_token = settings.env  # fallback

    if method in ("auto", "dns") and await verify_ownership_dns(domain, expected_token):
        return True
    return (
        method in ("auto", "meta")
        and client is not None
        and await verify_ownership_meta_tag(domain, expected_token, client)
    )


def generate_scope_token(domain: str) -> str:
    """Generate a deterministic verification token for a domain."""
    return hashlib.sha256(f"assurix:{domain}".encode()).hexdigest()[:16]
