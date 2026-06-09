"""Recon subpackage: surface mapping and link graph extraction.

Historical note: this package replaced a single ``recon.py`` module
during Wave 1 (defect 1 — planner BFS graph wiring). The class
``ReconAgent`` is re-exported here so the canonical import paths
``src.agents.recon:ReconAgent`` (used by the agent registry) and
``from src.agents.recon import ReconAgent`` (used by callers) both
continue to work unchanged.
"""
from __future__ import annotations

from src.agents.recon.agent import ReconAgent

__all__ = ["ReconAgent"]
