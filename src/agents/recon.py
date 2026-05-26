"""Surface mapper using AI-driven browser agent for deep reconnaissance."""

import logging
import re
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx
from sqlalchemy.ext.asyncio import AsyncSession

from src.agents.base import BaseAgent
from src.agents.browser.ai_operator import AIBrowserOperator
from src.agents.browser.memory import FindingMemory
from src.agents.browser.suspicious_points import SuspiciousPointDetector
from src.core.audit import log_action
from src.core.config import get_settings

logger = logging.getLogger(__name__)

LINK_RE = re.compile(r'href=["\']([^"\']+)["\']', re.IGNORECASE)
FORM_RE = re.compile(r'<form[^>]*>', re.IGNORECASE)
FORM_ACTION_RE = re.compile(r'action=["\']([^"\']+)["\']', re.IGNORECASE)
API_ENDPOINT_RE = re.compile(r'["\'](/api/[^"\']+)["\']')


class ReconAgent(BaseAgent):
    """Maps attack surface using HTTPX fast crawl + AI-driven browser exploration."""

    name = "recon"

    async def execute(self, payload: dict[str, Any], session: AsyncSession) -> dict[str, Any]:
        target_url = payload.get("target_url", "")
        directives = payload.get("previous_result", {}).get("directives", [])

        if not target_url:
            target_url = payload.get("previous_result", {}).get("target_url", "")

        if not target_url:
            return {"findings": [], "artifacts": [], "surface": {}}

        settings = get_settings()
        artifacts: list[dict] = []
        surface: dict[str, Any] = {
            "pages": [], "endpoints": [], "forms": [], "inputs": [],
            "buttons": [], "scripts": [], "headers": {}, "technologies": [],
            "cookies": [], "tls_info": {}, "meta_tags": {},
            "console_errors": [], "auth_pages": [], "text_content": "",
        }

        crawl_depth = 2
        for d in directives:
            if d.get("type") == "crawl":
                crawl_depth = d.get("depth", 2)

        # Phase 1: Fast HTTPX headers + basic crawl
        visited: set[str] = set()
        async with httpx.AsyncClient(
            timeout=30.0, follow_redirects=True, max_redirects=5, http2=True,
        ) as client:
            try:
                resp = await client.get(target_url)
                surface["headers"] = dict(resp.headers)
                surface["cookies"] = [
                    {"name": c.name, "secure": c.secure, "httponly": c.httpOnly,
                     "domain": c.domain, "path": c.path}
                    for c in client.cookies.jar
                ]
            except httpx.RequestError as exc:
                logger.warning("HTTPX initial fetch failed: %s", exc)

            to_visit: list[tuple[str, int]] = [(target_url, 0)]
            while to_visit:
                url, depth = to_visit.pop(0)
                if url in visited or depth > crawl_depth:
                    continue
                visited.add(url)
                try:
                    resp = await client.get(url)
                    surface["pages"].append({
                        "url": url,
                        "status_code": resp.status_code,
                        "content_type": resp.headers.get("content-type", ""),
                        "content_length": int(resp.headers.get("content-length", 0)),
                    })
                    if resp.status_code == 200 and "text/html" in resp.headers.get("content-type", ""):
                        for link in self._extract_links(resp.text, url, target_url):
                            if link not in visited:
                                to_visit.append((link, depth + 1))
                        for ep in self._extract_api_endpoints(resp.text):
                            if ep not in surface["endpoints"]:
                                surface["endpoints"].append(ep)
                except httpx.RequestError:
                    continue

        # Phase 2: AI-driven browser exploration
        engagement_id = payload.get("engagement_id", "default")
        ai_browser = AIBrowserOperator(engagement_id=engagement_id)
        memory = FindingMemory(engagement_id=engagement_id, artifacts_dir=settings.artifacts_dir)
        ai_result: dict[str, Any] = {}

        try:
            await ai_browser.start()
            ai_result = await ai_browser.explore(target_url, directives=directives)

            ai_surface = ai_result.get("surface", {})
            ai_findings = ai_result.get("findings", [])

            if ai_surface.get("extracted_content"):
                surface["text_content"] = ai_surface["extracted_content"][:8000]

            for url in ai_result.get("visited_urls", []):
                if url not in visited:
                    surface["pages"].append({"url": url, "status_code": 200, "content_type": "text/html"})

            for finding in ai_findings:
                content = finding.get("content", "")
                if content:
                    memory.add_finding(
                        title=f"AI recon: {content[:100]}",
                        severity="info",
                        description=content[:500],
                        evidence_ref=f"ai_agent_step_{finding.get('index', 0)}",
                        vuln_type="recon",
                        url=target_url,
                    )

            for tool_result in ai_result.get("security_tool_results", []):
                content = tool_result.get("content", "")
                if content:
                    memory.add_finding(
                        title=f"Security tool: {content[:100]}",
                        severity="info",
                        description=content[:500],
                        evidence_ref=f"tool_{tool_result.get('type', 'unknown')}",
                        vuln_type="recon",
                        url=target_url,
                    )

            surface["ai_visited_urls"] = ai_result.get("visited_urls", [])

        except Exception as exc:
            logger.error("AI browser recon failed: %s", exc)
            artifacts.append({"type": "ai_error", "content": str(exc)})
        finally:
            await ai_browser.stop()

        # Fallback: scripted browser if AI agent didn't find enough
        if not surface.get("text_content") and surface["pages"]:
            from src.agents.browser.operator import BrowserOperator
            browser = BrowserOperator()
            await browser.start()
            try:
                page_data = await browser.browse_page(target_url)
                if "error" not in page_data:
                    surface["text_content"] = page_data.get("text_content", "")
                    surface["meta_tags"] = page_data.get("meta_tags", {})
                    surface["console_errors"] = page_data.get("console_errors", [])
                    for form in page_data.get("forms", []):
                        if not any(f.get("action") == form.get("action") for f in surface["forms"]):
                            surface["forms"].append(form)
                    surface["inputs"] = page_data.get("inputs", [])
                    surface["buttons"] = page_data.get("buttons", [])
                    surface["scripts"] = page_data.get("scripts", [])
                    for bc in page_data.get("cookies", []):
                        if not any(c.get("name") == bc.get("name") for c in surface["cookies"]):
                            surface["cookies"].append(bc)

                auth_data = await browser.test_auth_page(target_url)
                if auth_data.get("has_auth"):
                    surface["auth_pages"].append({
                        "url": target_url,
                        "auth_type": auth_data.get("auth_type"),
                        "login_form": auth_data.get("login_form"),
                        "oauth_buttons": auth_data.get("oauth_buttons", []),
                    })
            finally:
                await browser.stop()

        # Detect technologies from combined data
        surface["technologies"] = self._detect_technologies(
            surface["headers"], surface.get("meta_tags", {}), surface.get("scripts", [])
        )
        surface["tls_info"] = self._check_tls_basic(surface["headers"])

        # Detect suspicious points for targeted investigation
        settings = get_settings()
        sp_detector = SuspiciousPointDetector()
        suspicious_points = sp_detector.detect(surface)
        suspicious_points = [sp for sp in suspicious_points if sp.confidence >= settings.sp_confidence_threshold][:settings.sp_max_points]

        # Deduplicate
        surface["forms"] = self._dedupe_forms(surface["forms"])
        surface["endpoints"] = list(dict.fromkeys(surface["endpoints"]))
        surface["cookies"] = self._dedupe_cookies(surface["cookies"])

        artifacts.append({
            "type": "dom_snapshot",
            "content": {
                "surface_map": {k: v for k, v in surface.items() if k != "text_content"},
                "pages_crawled": len(visited),
                "ai_steps_taken": ai_result.get("steps_taken", 0),
            },
        })

        await log_action(
            session=session, action="recon_completed", actor="recon",
            payload={
                "target_url": target_url,
                "pages_found": len(surface["pages"]),
                "endpoints_found": len(surface["endpoints"]),
                "forms_found": len(surface["forms"]),
                "auth_pages": len(surface["auth_pages"]),
                "console_errors": len(surface["console_errors"]),
            },
        )

        return {
            "findings": [],
            "artifacts": artifacts,
            "surface": surface,
            "target_url": target_url,
            "suspicious_points": [sp.to_dict() for sp in suspicious_points],
        }

    def _extract_links(self, html: str, base_url: str, scope_url: str) -> list[str]:
        scope_domain = urlparse(scope_url).netloc
        links: list[str] = []
        for match in LINK_RE.findall(html):
            full = urljoin(base_url, match)
            parsed = urlparse(full)
            if parsed.netloc == scope_domain and parsed.scheme in ("http", "https"):
                clean = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                if clean not in links:
                    links.append(clean)
        return links[:50]

    def _extract_forms(self, html: str, base_url: str) -> list[dict]:
        forms: list[dict] = []
        for form_match in FORM_RE.finditer(html):
            form_tag = form_match.group(0)
            action_match = FORM_ACTION_RE.search(form_tag)
            action = urljoin(base_url, action_match.group(1)) if action_match else base_url
            method = "POST" if re.search(r'method=["\']post["\']', form_tag, re.IGNORECASE) else "GET"
            forms.append({"action": action, "method": method})
        return forms

    def _extract_api_endpoints(self, html: str) -> list[str]:
        endpoints: list[str] = []
        for match in API_ENDPOINT_RE.findall(html):
            if match not in endpoints:
                endpoints.append(match)
        return endpoints

    def _detect_technologies(
        self, headers: dict, meta_tags: dict, scripts: list[str]
    ) -> list[str]:
        tech: list[str] = []
        server = headers.get("server", "").lower()
        if "nginx" in server:
            tech.append("nginx")
        elif "apache" in server:
            tech.append("apache")
        powered_by = headers.get("x-powered-by", "").lower()
        if "express" in powered_by:
            tech.append("express")
        elif "php" in powered_by:
            tech.append("php")
        render_mode = headers.get("x-render-mode", "").lower()
        if "ssr" in render_mode:
            tech.append("SSR/Node.js")
        served_by = headers.get("x-served-by", "").lower()
        if served_by:
            tech.append(f"frontend:{served_by}")

        # Detect from meta tags
        generator = meta_tags.get("generator", "").lower()
        if "wordpress" in generator:
            tech.append("WordPress")
        elif "next.js" in generator:
            tech.append("Next.js")

        # Detect from scripts
        for src in scripts:
            src_lower = src.lower()
            if "react" in src_lower:
                tech.append("React")
            elif "vue" in src_lower:
                tech.append("Vue.js")
            elif "angular" in src_lower:
                tech.append("Angular")
            elif "jquery" in src_lower:
                tech.append("jQuery")
            elif "bootstrap" in src_lower:
                tech.append("Bootstrap")

        return list(set(tech))

    def _check_tls_basic(self, headers: dict) -> dict[str, Any]:
        hsts = headers.get("strict-transport-security", "")
        return {"enabled": True, "hsts": hsts if hsts else None}

    def _dedupe_forms(self, forms: list[dict]) -> list[dict]:
        seen = set()
        result = []
        for f in forms:
            key = (f.get("action", ""), f.get("method", ""))
            if key not in seen:
                seen.add(key)
                result.append(f)
        return result

    def _dedupe_cookies(self, cookies: list[dict]) -> list[dict]:
        seen = set()
        result = []
        for c in cookies:
            name = c.get("name", "")
            if name not in seen:
                seen.add(name)
                result.append(c)
        return result