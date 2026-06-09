# Assurix — Project Rules

These rules are project-specific and authoritative. Follow them exactly. They
were established when the codebase was collapsed to a single, unified design
(no v1/v2 split, no mode flags, no versioned agent names). Do not re-introduce
the patterns they forbid.

## Architecture

### End-to-end scan pipeline

The default `assurix scan <target>` always runs the same pipeline. There
is no mode that skips a step; full deep mode is the only mode.

```
planner → research_loop → reporter
   │            │             │
   │            │             └─ writes data/reports/<ts>_<target>_<eng8>.md
   │            └─ dispatches pentester / webapp / reasoner sub-investigations
   │               (browser agent with asyncio.wait_for ceiling + cumulative
   │                budget, see `src/core/config.py::browser_use_step_timeout_seconds`
   │                and `research_loop_max_total_seconds`)
   └─ EGATS: BFS recon (30%) + TDI-guided MCTS exploit (70%)
```

Engagement state machine:

- `PENDING → RUNNING` when the engine starts
- `RUNNING → RESEARCHING` when the research_loop takes over
- `RESEARCHING → COMPLETED` after the reporter writes the report
- `* → FAILED` when any agent raises (engine's per-iteration `except` flips
  the engagement to FAILED so the CLI's polling loop exits, see
  `src/orchestrator/engine.py::_run_loop`)

Hard ceilings:

- `browser_use_max_steps * browser_use_step_timeout_seconds + 60s` wall-clock
  ceiling per browser investigation (default 50 × 30s + 60s ≈ 25 min).
- `research_loop_max_total_seconds` cumulative budget (default 1800s = 30 min)
  across all investigations in one engagement.

CLI startup sweeps stale `RUNNING`/`RESEARCHING`/`PAUSED` engagements older
than 1 hour and flips them to `FAILED` (`_cleanup_stale_engagements()` in
`src/cli.py`). This is the crash-recovery invariant — never remove it.

### Planner

- **One planner.** `EGATSPlanner` (in `src/agents/planner_egats.py`) is the
  only planner. It is registered under the canonical name `"planner"`.
- There is no `planner_linear` (v1) and no `planner_egats` (v2 alias).
  The class's `BaseAgent.name` is `"planner"`. Both old names must never
  reappear in the registry, the engine routing, the CLI, the API, the
  benchmark runner, or the test suite.
- The `EGATSPlanner.execute()` method is the planner entry point. It
  runs BFS recon (30% budget) + TDI-guided exploit (70% budget). The
  inner MCTS work is delegated to `MCTSPlannerAgent`, which is also
  registered as `"planner_mcts"` and is callable on its own for
  isolated runs.

### CLI

- **One command.** `assurix scan <target>` plus the default `--help`.
  There are no other subcommands.
- The Typer app is a *group*, not a single-command shell. It uses
  `invoke_without_command=True` and an explicit `@app.callback()`
  (see `src/cli.py`). Without that, Typer collapses a single-command
  app and hoists the `target` argument to the top level, which makes
  `assurix <target>` work and `assurix scan <target>` fail with
  "Got unexpected extra argument." Don't drop the callback.
- There are no flags on `scan`. The user passes the target and that's it.
  No `--mode`, `--orchestrator`, `--no-depth-pass`, `--depth-pass-*`,
  `--iterations`, or `--strict-finding-gate` flags. They are forbidden.
- Full deep mode is always on. The default engagement config
  (`src/cli.py::DEFAULT_ENGAGEMENT_CONFIG`) is the single source of
  truth: `use_depth_pass=True`, `strict_finding_gate=True`,
  `use_research_loop=True`, `use_hypothesis_orchestrator=True`,
  `mode="offensive"`, `max_iterations=200`. The CLI never exposes any
  of these as a flag.
- The same `DEFAULT_ENGAGEMENT_CONFIG` lives in
  `src/api/routers/scans.py::DEFAULT_ENGAGEMENT_CONFIG` for the API.
  The two must stay in sync.

### Reports

- **Reports live in `data/reports/`.** The filename pattern is
  `<YYYYMMDD_HHMMSS>_<sanitized_target>_<engagement8>.md` where
  `engagement8` is the first 8 hex chars of the engagement id
  (UUID without dashes).
- After every write, the file `data/reports/LATEST.md` is updated to
  point at the most recent report (symlink where supported, replaced
  on each write).
- Reports are never written to `data/artifacts/<engagement_id>/`.
  That old path is gone. New code must not introduce it.

### Strict finding gate

- **The strict finding gate is always on.** Findings missing any of
  (PoC, request/response excerpt, `confidence_score >= 0.30`) are
  downgraded to `info` with a `strict_gate_downgraded` marker.
- There is no opt-out. The legacy "warn-only" behavior is gone.

## Code style

### No versioned names

- Don't add `if v2: ... else: ...` style version branches. The code IS
  the v2 code; there is no other code to fall back to.
- Don't add backwards-compat aliases. If something is being removed,
  delete it. Don't add a deprecation warning — just change the call
  site. The only exception is the optional `artifacts_dir` kwarg in
  `generate_report`, which is accepted-and-ignored for callers that
  pre-date the `data/reports/` move.
- Comments should not say "v2" or "legacy" or "Week 4 removal" — the
  code does what it does, and that's the only version that exists.

### Findings

- **Every finding produced by an agent must be persisted to the
  `findings` table.** The agent that produced the finding (or the
  reporter, as a finalization step) is responsible for the INSERT.
- The DB row is the source of truth for any future report
  regeneration. The MD file is a derived view that the reporter
  renders from the same `validated_findings` list.
- The `dedup_key` column is the stable identity used to deduplicate
  findings at report render time. Generate it once at the finding's
  point of origin and carry it forward.

### LLM call conventions

- **Reporter LLM call is best-effort.** If the LLM call fails or
  returns invalid JSON, the report still gets written with a
  deterministic fallback summary derived from the findings. The
  technical template must always render.
- Wrap every LLM call in a try/except that logs the failure and
  falls back to a deterministic template. Never let an LLM error
  bubble out of an agent's `execute()` and kill the engine task.
- The `REPORTER_SYSTEM` prompt instructs the LLM to walk through the
  kill-chain (Recon → Hypotheses → Exploits → Validation) with
  timestamps and what was attempted. For zero-finding scans, the
  prompt explicitly asks for a "no exploitable vulnerabilities
  confirmed" narrative tied to the methodology.

### DB serialization

- Anything written to a SQLAlchemy `JSON` column must be JSON-native
  (`dict`, `list`, `str`, `int`, `float`, `bool`, `None`). Sets and
  tuples are NOT safe — `json.dumps` has no `default=str` fallback in
  the JSON column serializer. See
  `src/db/session.py` and the `egats-set-serialization` memory.
- If an agent's `execute()` returns a dict, run `json.dumps(result)`
  from stdlib (no `default`) before assuming the engine can store it.

### Engine exception handling

- Every phase of `_run_loop` (Phase 1 dequeue, Phase 2 agent
  execute, Phase 3 post-execute bookkeeping) is wrapped in
  try/except. Phase 3's wrapper is critical — the post-execute
  bookkeeping writes to the `Job.result` JSON column, and a
  serialization error there will silently kill the entire engine
  task if uncaught. See `src/orchestrator/engine.py`.

### Iteration counter

- The `engagement.iteration_count` is bumped every time the workflow
  router re-enqueues the planner. The only name in the router that
  triggers this is `"planner"` (single planner). Don't add other
  agents to the increment.

## Don't

- Don't reintroduce `planner_linear` or `planner_egats` as agent
  names. The single planner is `planner`.
- Don't add CLI flags for "modes", "orchestrators", or "depth pass
  budgets". None of those exist. The defaults are the only config.
- Don't add `if v2: ... else: ...` style branches. The code IS the
  only version.
- Don't write reports to `data/artifacts/<engagement_id>/`. Use
  `data/reports/`.
- Don't add a deprecation warning when removing a flag. Just remove
  the flag and update the call sites.
- Don't let an LLM call exception bubble out of an agent. The
  technical template must always render.

## Verification

- `source .venv/bin/activate && python -m pytest tests/unit/ -k
  "planner or engine or report or cli or no_v1 or finding_persistence
  or iteration_counter" --tb=short -q` — all green.
- `assurix --help` shows only `scan`.
- `assurix scan --help` shows only the `target` argument and the
  default help. No flags.
- `grep -rn "'planner_linear'\|'planner_egats'" src/ tests/` returns
  no matches (except in this file).
- `grep -rn "data/artifacts.*report.md" src/ tests/` returns no
  matches.
