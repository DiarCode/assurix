"""AttackSurfaceRanker: Ranks attack surfaces by exposure, auth, and data sensitivity.

Uses the knowledge graph and parsed code data to produce a prioritized list
of attack surfaces for the ResearchLoop to generate hypotheses from.
"""

import logging
from typing import Any

from src.schemas.surface import AttackSurface, EndpointNode

logger = logging.getLogger(__name__)


class AttackSurfaceRanker:
    """Ranks attack surfaces by risk factors.

    Scoring factors:
    1. Exposure: How publicly accessible is the endpoint? (public > authenticated > admin)
    2. Auth requirements: Endpoints without auth are higher risk
    3. Data sensitivity: Endpoints handling sensitive data are higher risk
    4. Attack vector diversity: Endpoints with more input vectors are higher risk
    5. Technology risk: Known-vulnerable technologies increase risk

    The ranked surface feeds into HypothesisGenerator for hypothesis seeding.
    """

    # Risk scoring weights
    EXPOSURE_WEIGHT = 0.30
    AUTH_WEIGHT = 0.25
    SENSITIVITY_WEIGHT = 0.25
    DIVERSITY_WEIGHT = 0.10
    TECHNOLOGY_WEIGHT = 0.10

    # Known vulnerable technologies and their risk multipliers
    VULNERABILITY_TECH: dict[str, float] = {
        "php": 1.3,
        "wordpress": 1.4,
        "drupal": 1.3,
        "struts": 1.5,
        "old_jquery": 1.2,
        "express": 1.1,
        "flask": 1.0,
        "django": 1.0,
        "fastapi": 1.0,
        "spring": 1.1,
    }

    def rank_surface(
        self,
        surface: dict[str, Any] | AttackSurface,
        graph_data: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        """Rank attack surface entries by risk score.

        Args:
            surface: Attack surface data (dict or AttackSurface model).
            graph_data: Optional knowledge graph data for enhanced ranking.

        Returns:
            List of ranked surface entries sorted by risk score (descending).
            Each entry contains: url, method, risk_score, risk_factors.
        """
        # Normalize surface data
        if isinstance(surface, AttackSurface):
            endpoints = [
                {
                    "url": ep.url,
                    "method": ep.method,
                    "auth_required": ep.auth_required,
                    "data_sensitivity": ep.data_sensitivity,
                    "parameters": ep.parameters,
                    "technologies": ep.technologies,
                }
                for ep in surface.endpoints
            ]
            technologies = surface.technologies
            auth_pages = surface.auth_pages
            forms = surface.forms
        else:
            endpoints = surface.get("endpoints", [])
            if isinstance(endpoints, list) and endpoints and isinstance(endpoints[0], str):
                # Simple string endpoints — convert to dicts
                endpoints = [{"url": ep, "method": "GET"} for ep in endpoints]
            technologies = surface.get("technologies", [])
            auth_pages = surface.get("auth_pages", [])
            forms = surface.get("forms", [])

        ranked_entries = []

        for endpoint in endpoints:
            url = endpoint.get("url", "")
            if not url:
                continue

            # Calculate individual risk scores
            exposure_score = self._calc_exposure(endpoint, auth_pages)
            auth_score = self._calc_auth_risk(endpoint)
            sensitivity_score = self._calc_sensitivity(endpoint, graph_data)
            diversity_score = self._calc_attack_diversity(endpoint, forms)
            tech_score = self._calc_technology_risk(endpoint, technologies)

            # Weighted total risk score
            total_score = (
                self.EXPOSURE_WEIGHT * exposure_score
                + self.AUTH_WEIGHT * auth_score
                + self.SENSITIVITY_WEIGHT * sensitivity_score
                + self.DIVERSITY_WEIGHT * diversity_score
                + self.TECHNOLOGY_WEIGHT * tech_score
            )

            risk_factors = []
            if auth_score > 0.7:
                risk_factors.append("no_auth")
            if sensitivity_score > 0.7:
                risk_factors.append("sensitive_data")
            if exposure_score > 0.7:
                risk_factors.append("publicly_exposed")
            if diversity_score > 0.5:
                risk_factors.append("multiple_vectors")
            if tech_score > 1.1:
                risk_factors.append("vulnerable_tech")

            ranked_entries.append({
                "url": url,
                "method": endpoint.get("method", "GET"),
                "risk_score": round(total_score, 3),
                "risk_factors": risk_factors,
                "auth_required": endpoint.get("auth_required", False),
                "data_sensitivity": endpoint.get("data_sensitivity", "low"),
                "scores": {
                    "exposure": round(exposure_score, 3),
                    "auth": round(auth_score, 3),
                    "sensitivity": round(sensitivity_score, 3),
                    "diversity": round(diversity_score, 3),
                    "technology": round(tech_score, 3),
                },
            })

        # Sort by risk score (descending)
        ranked_entries.sort(key=lambda x: x["risk_score"], reverse=True)
        return ranked_entries

    def _calc_exposure(self, endpoint: dict[str, Any], auth_pages: list) -> float:
        """Calculate exposure risk: how publicly accessible is this endpoint."""
        url = endpoint.get("url", "").lower()
        method = endpoint.get("method", "GET").upper()

        # Admin/internal endpoints are less exposed
        if any(path in url for path in ["/admin", "/internal", "/private", "/manage"]):
            return 0.3

        # API endpoints are moderately exposed
        if "/api/" in url:
            return 0.7

        # Auth pages are highly exposed (login, register)
        if any(auth in url for auth in ["/login", "/register", "/signup", "/auth"]):
            return 0.9

        # POST/PUT/DELETE methods on public endpoints are higher risk
        if method in ("POST", "PUT", "DELETE", "PATCH"):
            return 0.8

        # Default: GET on regular pages
        return 0.5

    def _calc_auth_risk(self, endpoint: dict[str, Any]) -> float:
        """Calculate authentication risk: endpoints without auth are higher risk."""
        auth_required = endpoint.get("auth_required", False)

        # No auth required = high risk
        if not auth_required:
            url = endpoint.get("url", "").lower()
            # But auth pages don't need auth by design
            if any(a in url for a in ["/login", "/register", "/signup"]):
                return 0.5
            return 0.9

        # Auth required but with weak methods
        return 0.3

    def _calc_sensitivity(self, endpoint: dict[str, Any], graph_data: dict[str, Any] | None) -> float:
        """Calculate data sensitivity risk."""
        sensitivity = endpoint.get("data_sensitivity", "low")
        url = endpoint.get("url", "").lower()

        # Explicit sensitivity mapping
        sensitivity_map = {"high": 0.9, "medium": 0.6, "low": 0.3}
        base_score = sensitivity_map.get(sensitivity, 0.3)

        # Boost for known sensitive URL patterns
        sensitive_patterns = [
            "/user", "/account", "/profile", "/password", "/payment",
            "/credit", "/ssn", "/email", "/phone", "/address",
            "/admin", "/config", "/secret", "/key", "/token",
            "/upload", "/download", "/export", "/backup",
        ]
        for pattern in sensitive_patterns:
            if pattern in url:
                base_score = max(base_score, 0.7)
                break

        return min(1.0, base_score)

    def _calc_attack_diversity(self, endpoint: dict[str, Any], forms: list) -> float:
        """Calculate attack vector diversity: more input vectors = more risk."""
        url = endpoint.get("url", "").lower()
        method = endpoint.get("method", "GET").upper()
        params = endpoint.get("parameters", [])
        diversity = 0.2  # Base: any endpoint has some risk

        # POST/PUT endpoints accept body data
        if method in ("POST", "PUT", "PATCH"):
            diversity += 0.2

        # Query parameters increase attack surface
        if params:
            diversity += min(0.3, len(params) * 0.1)

        # Form submissions
        if forms:
            for form in forms:
                if isinstance(form, dict) and url in str(form.get("action", "")):
                    diversity += 0.2
                    break

        # File upload endpoints
        if any(kw in url for kw in ["upload", "file", "attachment", "import"]):
            diversity += 0.2

        # Search/filter endpoints
        if any(kw in url for kw in ["search", "filter", "query", "sort"]):
            diversity += 0.15

        return min(1.0, diversity)

    def _calc_technology_risk(self, endpoint: dict[str, Any], technologies: list[str]) -> float:
        """Calculate technology-specific risk based on known vulnerabilities."""
        tech_list = endpoint.get("technologies", []) + technologies
        if not tech_list:
            return 1.0  # Neutral risk when unknown

        total_risk = 0.0
        for tech in tech_list:
            tech_lower = tech.lower()
            risk = self.VULNERABILITY_TECH.get(tech_lower, 1.0)
            total_risk += risk

        # Average risk across all technologies
        return total_risk / len(tech_list) if tech_list else 1.0