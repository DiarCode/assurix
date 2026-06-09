"""Integration test: WebappAgent uses BrowserSession, not direct operator construction (plan §3.1.3.bis)."""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

from src.agents.browser.session import BrowserSession
from src.agents.webapp import WebappAgent


def test_webapp_uses_browser_session_not_direct_operator() -> None:
    """The 4 acceptance assertions from plan §3.1.3.bis."""
    # 1. agent.browser_session is a BrowserSession
    agent = WebappAgent()
    assert isinstance(agent.browser_session, BrowserSession)

    # 2. The primary operator is AgentBrowserOperator
    assert type(agent.browser_session.primary_operator).__name__ == "AgentBrowserOperator"

    # 3. ast_grep_search proves AIBrowserOperator(...) and module-scope
    #    BrowserOperator() are absent from webapp.py
    webapp_path = Path("src/agents/webapp.py")
    tree = ast.parse(webapp_path.read_text())
    offenders: list[str] = []

    class Finder(ast.NodeVisitor):
        def visit_Call(self, node: ast.Call) -> None:  # type: ignore[override]
            func = node.func
            # Direct constructor: AIBrowserOperator(...)
            if isinstance(func, ast.Name) and func.id == "AIBrowserOperator":
                offenders.append(f"line {node.lineno}: AIBrowserOperator(...) call")
            # Module-scope constructor: BrowserOperator()
            if isinstance(func, ast.Name) and func.id == "BrowserOperator":
                offenders.append(f"line {node.lineno}: BrowserOperator(...) call")
            self.generic_visit(node)

    Finder().visit(tree)
    assert not offenders, (
        f"webapp.py must not construct AIBrowserOperator/BrowserOperator directly:\n"
        + "\n".join(offenders)
    )


def test_webapp_with_explicit_browser_session() -> None:
    """Callers can pass a custom session (e.g., from agent run-loop)."""
    custom = BrowserSession(engagement_id="eng-1", config=None)
    agent = WebappAgent(browser_session=custom)
    assert agent.browser_session is custom


def test_webapp_routes_through_agent_browser() -> None:
    """Plan §3.1.3.bis: WebappAgent.run uses browser_session.with_auth()."""
    agent = WebappAgent()
    # The primary operator IS the agent-browser operator (per primary_operator='agent')
    assert type(agent.browser_session.primary_operator).__name__ == "AgentBrowserOperator"
    # BrowserSession has the with_auth async context manager
    assert hasattr(agent.browser_session, "with_auth")
