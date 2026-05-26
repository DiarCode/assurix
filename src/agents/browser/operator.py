"""Playwright-based browser operator for deep security testing."""

import logging
from typing import Any

from playwright.async_api import BrowserContext, Page, async_playwright

from src.core.config import get_settings

logger = logging.getLogger(__name__)


class BrowserOperator:
    """Async Playwright browser operator for security testing."""

    def __init__(self, headless: bool = True, max_contexts: int = 2) -> None:
        settings = get_settings()
        self._headless = headless if headless is not None else settings.playwright_headless
        self._max_contexts = max_contexts or settings.max_browser_contexts
        self._playwright = None
        self._browser = None
        self._contexts: list[BrowserContext] = []

    async def start(self) -> None:
        self._playwright = await async_playwright().start()
        self._browser = await self._playwright.chromium.launch(headless=self._headless)
        logger.info("Browser launched (headless=%s)", self._headless)

    async def stop(self) -> None:
        for ctx in self._contexts:
            await ctx.close()
        self._contexts.clear()
        if self._browser:
            await self._browser.close()
        if self._playwright:
            await self._playwright.stop()
        logger.info("Browser closed")

    async def new_context(self) -> BrowserContext:
        if not self._browser:
            raise RuntimeError("Browser not started. Call start() first.")
        if len(self._contexts) >= self._max_contexts:
            oldest = self._contexts.pop(0)
            await oldest.close()
        ctx = await self._browser.new_context(
            viewport={"width": 1280, "height": 720},
            user_agent="Assurix/0.1 Security Scanner",
        )
        self._contexts.append(ctx)
        return ctx

    async def _close_context(self, ctx: BrowserContext) -> None:
        await ctx.close()
        if ctx in self._contexts:
            self._contexts.remove(ctx)

    async def browse_page(self, url: str) -> dict[str, Any]:
        """Navigate to URL and extract full page content, links, forms, and metadata."""
        ctx = await self.new_context()
        page = await ctx.new_page()
        result: dict[str, Any] = {
            "url": url, "status": None, "title": "", "html": "",
            "text_content": "", "links": [], "forms": [], "inputs": [],
            "buttons": [], "scripts": [], "meta_tags": {}, "cookies": [],
            "console_errors": [],
        }
        try:
            page.on("console", lambda msg: result["console_errors"].append(msg.text) if msg.type == "error" else None)
            response = await page.goto(url, wait_until="networkidle", timeout=30000)
            result["status"] = response.status if response else None
            await page.wait_for_timeout(2000)

            result["title"] = await page.title()
            result["html"] = await page.content()
            result["url"] = page.url

            result["links"] = await page.evaluate("""() => {
                return Array.from(document.querySelectorAll('a[href]')).map(a => ({
                    href: a.href, text: a.textContent.trim().slice(0, 100), target: a.target
                })).filter(l => l.href && !l.href.startsWith('javascript:'))
            }""")

            result["forms"] = await page.evaluate("""() => {
                return Array.from(document.querySelectorAll('form')).map(f => ({
                    action: f.action, method: f.method, id: f.id,
                    inputs: Array.from(f.querySelectorAll('input,textarea,select')).map(i => ({
                        name: i.name, type: i.type, id: i.id, required: i.required,
                        placeholder: i.placeholder, autocomplete: i.autocomplete
                    }))
                }))
            }""")

            result["inputs"] = await page.evaluate("""() => {
                return Array.from(document.querySelectorAll('input:not([type=hidden])')).map(i => ({
                    name: i.name, type: i.type, id: i.id, required: i.required,
                    placeholder: i.placeholder, autocomplete: i.autocomplete
                }))
            }""")

            result["buttons"] = await page.evaluate("""() => {
                return Array.from(document.querySelectorAll('button,input[type=submit],input[type=button]')).map(b => ({
                    text: b.textContent.trim().slice(0, 100), type: b.type, id: b.id
                }))
            }""")

            result["scripts"] = await page.evaluate("""() => {
                return Array.from(document.querySelectorAll('script[src]')).map(s => s.src)
            }""")

            result["meta_tags"] = await page.evaluate("""() => {
                const tags = {};
                document.querySelectorAll('meta').forEach(m => {
                    const name = m.getAttribute('name') || m.getAttribute('property') || m.getAttribute('http-equiv');
                    if (name) tags[name] = m.getAttribute('content') || '';
                });
                return tags;
            }""")

            cookies_raw = await ctx.cookies()
            result["cookies"] = [
                {
                    "name": c.get("name", "") if isinstance(c, dict) else c.name,
                    "domain": c.get("domain", "") if isinstance(c, dict) else c.domain,
                    "secure": c.get("secure", False) if isinstance(c, dict) else c.secure,
                    "httponly": c.get("httpOnly", False) if isinstance(c, dict) else c.httpOnly,
                    "path": c.get("path", "/") if isinstance(c, dict) else c.path,
                }
                for c in cookies_raw
            ]

            result["text_content"] = await page.evaluate("document.body?.innerText?.slice(0, 8000) || ''")

        except Exception as exc:
            logger.error("Browser error on %s: %s", url, exc)
            result["error"] = str(exc)
        finally:
            await self._close_context(ctx)
        return result

    async def fill_and_submit_form(
        self, url: str, form_index: int = 0, data: dict[str, str] | None = None
    ) -> dict[str, Any]:
        """Navigate, fill form fields, submit, and capture response."""
        ctx = await self.new_context()
        page = await ctx.new_page()
        result: dict[str, Any] = {"url": url, "submitted": False, "response_html": "", "response_text": ""}
        try:
            await page.goto(url, wait_until="networkidle", timeout=30000)
            await page.wait_for_timeout(1000)
            forms = await page.query_selector_all("form")
            if not forms or form_index >= len(forms):
                result["error"] = f"No form at index {form_index}"
                return result
            if data:
                form = forms[form_index]
                for name, value in data.items():
                    el = await form.query_selector(f'[name="{name}"]')
                    if el:
                        await el.fill(value)
            await page.evaluate(f"document.forms[{form_index}].submit()")
            await page.wait_for_load_state("networkidle", timeout=15000)
            result["submitted"] = True
            result["response_html"] = await page.content()
            result["response_text"] = await page.evaluate("document.body?.innerText?.slice(0, 5000) || ''")
            result["response_url"] = page.url
        except Exception as exc:
            logger.error("Form submission error: %s", exc)
            result["error"] = str(exc)
        finally:
            await self._close_context(ctx)
        return result

    async def click_and_observe(self, url: str, selector: str) -> dict[str, Any]:
        """Navigate, click element, observe result."""
        ctx = await self.new_context()
        page = await ctx.new_page()
        result: dict[str, Any] = {"url": url, "selector": selector, "clicked": False}
        try:
            await page.goto(url, wait_until="networkidle", timeout=30000)
            await page.wait_for_timeout(1000)
            element = await page.query_selector(selector)
            if element:
                await element.click()
                result["clicked"] = True
                await page.wait_for_timeout(2000)
                result["result_html"] = await page.content()
                result["result_text"] = await page.evaluate("document.body?.innerText?.slice(0, 5000) || ''")
                result["result_url"] = page.url
            else:
                result["error"] = f"Selector not found: {selector}"
        except Exception as exc:
            logger.error("Click error: %s", exc)
            result["error"] = str(exc)
        finally:
            await self._close_context(ctx)
        return result

    async def test_auth_page(self, url: str) -> dict[str, Any]:
        """Detect and analyze authentication pages."""
        ctx = await self.new_context()
        page = await ctx.new_page()
        result: dict[str, Any] = {"url": url, "has_auth": False, "auth_type": None, "login_form": None}
        try:
            await page.goto(url, wait_until="networkidle", timeout=30000)
            await page.wait_for_timeout(1000)

            login_form = await page.evaluate("""() => {
                const forms = Array.from(document.querySelectorAll('form'));
                for (const form of forms) {
                    const inputs = Array.from(form.querySelectorAll('input'));
                    const hasPassword = inputs.some(i => i.type === 'password');
                    const hasText = inputs.some(i => i.type === 'text' || i.type === 'email');
                    if (hasPassword && hasText) {
                        return {
                            action: form.action, method: form.method,
                            fields: inputs.map(i => ({name: i.name, type: i.type, placeholder: i.placeholder})),
                            hasCaptcha: !!form.querySelector('[class*="captcha"], [id*="captcha"], iframe[src*="captcha"]'),
                            has2FA: !!form.querySelector('[name*="otp"], [name*="totp"], [name*="code"]')
                        };
                    }
                }
                return null;
            }""")

            if login_form:
                result["has_auth"] = True
                result["auth_type"] = "form_login"
                result["login_form"] = login_form
            else:
                oauth = await page.evaluate("""() => {
                    const sels = ['a[href*="oauth"]', 'a[href*="google"]', 'a[href*="github"]',
                        'button[data-provider]', '[class*="social-login"]', '[class*="sso"]'];
                    return sels.map(s => document.querySelector(s)?.outerHTML?.slice(0, 200)).filter(Boolean);
                }""")
                if oauth:
                    result["has_auth"] = True
                    result["auth_type"] = "oauth_sso"
                    result["oauth_buttons"] = oauth

            cookies_raw = await ctx.cookies()
            result["cookies"] = [
                {
                    "name": c.get("name", "") if isinstance(c, dict) else c.name,
                    "secure": c.get("secure", False) if isinstance(c, dict) else c.secure,
                    "httponly": c.get("httpOnly", False) if isinstance(c, dict) else c.httpOnly,
                }
                for c in cookies_raw
            ]
            result["page_text"] = await page.evaluate("document.body?.innerText?.slice(0, 3000) || ''")
        except Exception as exc:
            logger.error("Auth analysis error: %s", exc)
            result["error"] = str(exc)
        finally:
            await self._close_context(ctx)
        return result