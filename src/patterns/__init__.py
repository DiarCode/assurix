"""ZCAT — Zero-Shot Cross-Application Transfer pattern library.

Seeded with common vulnerability patterns from OWASP Top 10 and real CVEs.
Enables cross-target learning: patterns discovered on one target can be applied
to new targets without retraining.
"""

from src.patterns.library import VulnerabilityPatternLibrary, VulnerabilityPattern

__all__ = ["VulnerabilityPatternLibrary", "VulnerabilityPattern"]