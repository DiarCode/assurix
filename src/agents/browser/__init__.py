"""Browser agents for security testing.

Primary: AgentBrowserOperator (Vercel agent-browser CLI, Phase 3).
Legacy: AIBrowserOperator and BrowserOperator retained for backward
compatibility — use AgentBrowserOperator for new code.
"""

from src.agents.browser.agent_browser_operator import AgentBrowserOperator
from src.agents.browser.crawl_strategy import CrawlStrategy, SurfaceData
from src.agents.browser.memory import FindingMemory
from src.agents.browser.security_tools import create_security_tools

# Legacy operators: imported lazily and emit a deprecation warning on use
# to avoid surprising side-effects on simple imports. Downstream code can
# still do `from src.agents.browser.ai_operator import AIBrowserOperator`
# directly.
__all__ = [
    "AgentBrowserOperator",
    "CrawlStrategy",
    "SurfaceData",
    "FindingMemory",
    "create_security_tools",
]