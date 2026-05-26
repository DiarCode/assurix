# Assurix

Authorized Autonomous Security Validation Platform

## Overview

Assurix is an authorized autonomous security validation platform. It takes an authorized target (web application, API, or codebase), orchestrates specialized AI agents to discover and analyze security issues, correlates findings in a graph-native knowledge model, and produces professional HTML reports with evidence and remediation guidance.

## Quick Start

```bash
# Install dependencies
uv sync

# Run API server
uv run uvicorn src.api.main:app --reload --port 8000

# Run CLI scan
uv run python -m src.cli scan --target example.com

# Run tests
uv run pytest
```

## Architecture

See `docs/CLAUDE.md` for the full development guide and architecture overview.
