"""AI-driven browser operator using browser-use for autonomous security testing.

DEPRECATED: Use AgentBrowserOperator (src.agents.browser.agent_browser_operator)
as the primary browser automation. agent-browser (Vercel) provides a
deterministic snapshot+ref workflow, native Rust CLI performance, and
built-in network introspection. AIBrowserOperator is retained for
backward compatibility but will be removed once ReconAgent and
WebappAgent complete their migration.
"""

import asyncio
import glob
import logging
import os
import sys
from pathlib import Path
from typing import Any

from browser_use import Agent, BrowserSession

from src.agents.browser.acc import AgentCognitiveCompressor
from src.agents.browser.prompts import (
    ADVANCED_AUTH_PROMPT,
    API_DISCOVERY_PROMPT,
    AUTH_TESTER_PROMPT,
    BUSINESS_LOGIC_PROMPT,
    ERROR_PROBE_PROMPT,
    RACE_CONDITION_PROMPT,
    SECURITY_RECON_PROMPT,
    SSRF_HUNTER_PROMPT,
    XSS_HUNTER_PROMPT,
)
from src.agents.browser.security_tools import create_security_tools
from src.core.config import get_settings

logger = logging.getLogger(__name__)

# Map task types to their prompts
TASK_PROMPTS = {
    "recon": SECURITY_RECON_PROMPT,
    "xss_hunt": XSS_HUNTER_PROMPT,
    "auth_test": AUTH_TESTER_PROMPT,
    "api_discover": API_DISCOVERY_PROMPT,
    "error_probe": ERROR_PROBE_PROMPT,
    "ssrf_hunt": SSRF_HUNTER_PROMPT,
    "business_logic": BUSINESS_LOGIC_PROMPT,
    "race_condition": RACE_CONDITION_PROMPT,
    "advanced_auth": ADVANCED_AUTH_PROMPT,
}


class AIBrowserOperator:
    """Wraps browser-use Agent for autonomous security testing.

    Uses ChatOllama (deepseek-v4-flash for reasoning, gemma4:31b for fast tasks)
    to drive browser exploration and vulnerability discovery.
    """

    def __init__(self, engagement_id: str = "default") -> None:
        settings = get_settings()
        self._engagement_id = engagement_id
        self._headless = settings.browser_use_headless
        self._max_steps = settings.browser_use_max_steps
        self._keep_alive = settings.browser_use_keep_alive
        self._ollama_host = settings.ollama_host
        self._ollama_api_key = settings.ollama_api_key
        self._reasoning_model = settings.ollama_reasoning_model
        self._fast_model = settings.ollama_fast_model
        self._artifacts_dir = Path(settings.artifacts_dir) / engagement_id / "evidence"
        self._artifacts_dir.mkdir(parents=True, exist_ok=True)
        self._chrome_path = self._find_chrome()
        self._tools = create_security_tools(self._artifacts_dir)
        self._history: list[dict[str, Any]] = []
        self._evidence: list[dict[str, Any]] = []
        self._acc = AgentCognitiveCompressor(
            token_budget=settings.acc_token_budget,
            max_hypotheses=settings.acc_max_hypotheses,
        )

    def _get_llm(self, task_type: str = "reasoning"):
        """Create OllamaChatLLM instance (handles markdown-fenced JSON from cloud models)."""
        from src.agents.browser.llm_adapter import OllamaChatLLM

        model = self._reasoning_model
        client_params: dict[str, Any] = {}
        if self._ollama_api_key:
            client_params["headers"] = {"Authorization": f"Bearer {self._ollama_api_key}"}

        return OllamaChatLLM(
            model=model,
            host=self._ollama_host,
            client_params=client_params or None,
        )

    def _create_session_kwargs(self) -> dict[str, Any]:
        """Build kwargs for BrowserSession construction."""
        kwargs: dict[str, Any] = {"headless": self._headless}
        if self._chrome_path:
            kwargs["executable_path"] = self._chrome_path
            logger.info("Using Chrome at: %s", self._chrome_path)
        if self._keep_alive:
            kwargs["keep_alive"] = True
        return kwargs

    async def start(self) -> None:
        """Pre-validate browser availability (BrowserSession creates browser lazily)."""
        if self._chrome_path:
            logger.info("AI Browser will use Chrome at: %s", self._chrome_path)
        else:
            logger.warning("No Chrome binary found — browser-use will try its default path")

    @staticmethod
    def _find_chrome() -> str | None:
        """Find installed Playwright/Chrome binary for browser-use.

        Playwright's cache directory differs by platform:
        - Linux:   ``~/.cache/ms-playwright/``
        - macOS:   ``~/Library/Caches/ms-playwright/``
        - Windows: ``%LOCALAPPDATA%/ms-playwright/``

        Each cached Chromium build contains a platform-specific binary tree:
        - Linux:   ``chrome-linux/chrome``
        - macOS:   ``chrome-mac/Chromium.app/Contents/MacOS/Chromium`` (intel)
                   ``chrome-mac-arm64/Chromium.app/Contents/MacOS/Chromium`` (apple silicon)
        - Windows: ``chrome-win/chrome.exe`` or ``chrome-win64/chrome.exe``
        """
        home = os.path.expanduser("~")
        if sys.platform == "win32":
            patterns = [
                f"{home}/AppData/Local/ms-playwright/chromium-*/chrome-win64/chrome.exe",
                f"{home}/AppData/Local/ms-playwright/chromium-*/chrome-win/chrome.exe",
            ]
        elif sys.platform == "darwin":
            patterns = [
                f"{home}/Library/Caches/ms-playwright/chromium-*/chrome-mac-arm64/Chromium.app/Contents/MacOS/Chromium",
                f"{home}/Library/Caches/ms-playwright/chromium-*/chrome-mac/Chromium.app/Contents/MacOS/Chromium",
                f"{home}/Library/Caches/ms-playwright/chromium-*/chrome-mac-arm64/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing",
                f"{home}/Library/Caches/ms-playwright/chromium-*/chrome-mac/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing",
                "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
            ]
        else:
            # Linux / other unix
            patterns = [
                f"{home}/.cache/ms-playwright/chromium-*/chrome-linux/chrome",
                "/usr/bin/google-chrome",
                "/usr/bin/chromium",
                "/usr/bin/chromium-browser",
            ]
        for pattern in patterns:
            matches = sorted(glob.glob(pattern), reverse=True)
            if matches:
                return matches[0]
        return None

    async def stop(self) -> None:
        """Close browser and save evidence."""
        logger.info("AI Browser closed, evidence count: %d", len(self._evidence))

    async def explore(self, target_url: str, directives: list[dict] | None = None) -> dict[str, Any]:
        """Run autonomous security recon on a target URL."""
        directive_text = ""
        if directives:
            directive_text = "\n\nSpecific directives:\n" + "\n".join(
                f"- {d.get('type', 'unknown')}: {d.get('reason', d.get('category', ''))}"
                for d in directives[:10]
            )

        task = SECURITY_RECON_PROMPT.format(
            target_url=target_url,
            directives=directive_text,
        )

        return await self._run_agent(task, target_url, task_type="recon")

    async def investigate(
        self, vulnerability_type: str, target_url: str, context: str = ""
    ) -> dict[str, Any]:
        """Run a focused investigation for a specific vulnerability class."""
        prompt_template = TASK_PROMPTS.get(vulnerability_type, ERROR_PROBE_PROMPT)
        task = prompt_template.format(
            target_url=target_url,
            context=context,
        )
        return await self._run_agent(task, target_url, task_type="reasoning")

    async def _run_agent(
        self, task: str, target_url: str, task_type: str = "reasoning"
    ) -> dict[str, Any]:
        """Execute a browser-use agent with the given task prompt."""
        llm = self._get_llm(task_type)
        session_kwargs = self._create_session_kwargs()

        # Create a fresh BrowserSession per agent run
        browser_session = BrowserSession(**session_kwargs)

        agent = Agent(
            task=task,
            llm=llm,
            browser_session=browser_session,
            directly_open_url=True,
            max_failures=10,
            use_vision=False,
        )

        # Inject ACC compressed context into task prompt
        acc_context = self._acc.get_context()
        if acc_context:
            task = f"{task}\n\n## Previous Investigation Context\n{acc_context}"

        # Step hook for evidence capture and ACC tracking
        step_count = 0
        visited_urls: list[str] = []

        async def on_step(agent_instance: Agent) -> None:
            nonlocal step_count
            step_count += 1
            try:
                state = await agent_instance.browser_session.get_browser_state_summary()
                if state and state.url and state.url not in visited_urls:
                    visited_urls.append(state.url)
                    self._acc.add_step({"url": state.url, "action": "navigate", "step": step_count})
                    logger.info("Step %d: Agent visited %s", step_count, state.url)
            except Exception as exc:
                logger.debug("Step hook error: %s", exc)

        logger.info("Starting AI agent task on %s (type=%s)", target_url, task_type)

        try:
            history = await agent.run(
                max_steps=self._max_steps,
                on_step_start=on_step,
            )
        except Exception as exc:
            logger.error("AI agent task failed: %s", exc)
            return {
                "error": str(exc),
                "target_url": target_url,
                "task_type": task_type,
                "visited_urls": visited_urls,
            }
        finally:
            try:
                await browser_session.close()
            except Exception:
                pass

        # Extract results from agent history
        result: dict[str, Any] = {
            "target_url": target_url,
            "task_type": task_type,
            "steps_taken": step_count,
            "visited_urls": visited_urls,
            "findings": [],
            "surface": {},
            "evidence": list(self._evidence),
        }

        # Extract findings from agent actions and thoughts
        try:
            for thought in history.model_thoughts():
                if thought and hasattr(thought, "content") and thought.content:
                    result["findings"].append({
                        "type": "agent_thought",
                        "content": str(thought.content)[:500],
                    })

            for action in history.model_actions():
                if action and hasattr(action, "action") and action.action:
                    result["findings"].append({
                        "type": "agent_action",
                        "action": str(action.action),
                        "index": getattr(action, "index", None),
                    })

            extracted = history.extracted_content()
            if extracted:
                result["surface"]["extracted_content"] = str(extracted)[:5000]

            urls = history.urls()
            if urls:
                result["surface"]["all_visited_urls"] = list(urls)
        except Exception as exc:
            logger.warning("Error extracting agent history: %s", exc)

        # Process security tool results captured during execution
        result["security_tool_results"] = self._extract_tool_results()

        self._history.append(result)
        logger.info(
            "AI agent completed: %d steps, %d URLs visited, %d findings",
            step_count,
            len(visited_urls),
            len(result["findings"]),
        )

        return result

    def _extract_tool_results(self) -> list[dict[str, Any]]:
        """Extract structured results from security tools called during execution."""
        results: list[dict[str, Any]] = []
        for ev in self._evidence:
            if ev.get("type") == "tool_result":
                results.append(ev)
        return results

    def add_evidence(self, evidence_type: str, content: dict[str, Any]) -> None:
        """Add evidence captured during agent execution."""
        self._evidence.append({
            "type": evidence_type,
            "content": content,
            "engagement_id": self._engagement_id,
        })

    async def run_parallel_investigations(
        self, target_url: str, investigation_types: list[str], context: str = ""
    ) -> list[dict[str, Any]]:
        """Run multiple investigation types in parallel.

        Each investigation gets its own browser session.
        """
        settings = get_settings()
        max_parallel = min(len(investigation_types), settings.parallel_agents)

        async def _run_one(inv_type: str) -> dict[str, Any]:
            try:
                return await self.investigate(inv_type, target_url, context)
            except Exception as exc:
                logger.error("Investigation %s failed: %s", inv_type, exc)
                return {"error": str(exc), "task_type": inv_type, "target_url": target_url}

        tasks = [_run_one(inv_type) for inv_type in investigation_types[:max_parallel]]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        processed = []
        for r in results:
            if isinstance(r, Exception):
                processed.append({"error": str(r)})
            else:
                processed.append(r)
        return processed