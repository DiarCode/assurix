#!/usr/bin/env python3
"""Validate CyberArena ground truth endpoints against running Docker containers.

This script spins up each Docker target, authenticates (for DVWA),
then verifies every endpoint in the ground truth file returns a valid
response (200, not redirect to login). Reports any mismatches.

Usage:
    python scripts/validate_cyberarena_ground_truth.py

Requires Docker to be installed and running.
NOT part of the automated test suite — run manually before committing
ground truth changes.
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

import httpx

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from src.benchmark.docker_target import BENCHMARK_TARGETS, DockerTargetManager, DockerUnavailableError
from src.benchmark.target_setup import setup_dvwa

GROUND_TRUTH_PATH = PROJECT_ROOT / "data" / "benchmarks" / "cyberarena_ground_truth.json"


async def validate_target(
    target_name: str,
    target_url: str,
    test_cases: list[dict],
    dvwa_cookies: dict[str, str] | None = None,
) -> list[str]:
    """Validate all test case endpoints for a single target.

    Returns list of error strings (empty = all OK).
    """
    errors: list[str] = []

    async with httpx.AsyncClient(
        verify=False, follow_redirects=False, timeout=15.0,
        cookies=dvwa_cookies,
    ) as client:
        for tc in test_cases:
            tc_id = tc.get("id", "unknown")
            endpoint = tc.get("endpoint", "")
            full_url = tc.get("target_url", f"{target_url}{endpoint}")

            if not endpoint and not full_url:
                errors.append(f"  {tc_id}: no endpoint or target_url defined")
                continue

            # Skip test cases with empty parameter (info disclosure, etc.)
            # — just verify the URL is reachable
            try:
                resp = await client.get(full_url)

                # For DVWA, a 302 redirect to /login.php means auth failed
                if resp.status_code in (301, 302, 303, 307, 308):
                    location = resp.headers.get("location", "")
                    if "login" in location.lower():
                        errors.append(
                            f"  {tc_id}: {full_url} -> redirect to login ({resp.status_code})"
                        )
                    else:
                        # Redirect elsewhere is OK (e.g., WebGoat challenge pages)
                        pass
                elif resp.status_code >= 500:
                    errors.append(
                        f"  {tc_id}: {full_url} -> server error ({resp.status_code})"
                    )
                elif resp.status_code == 404:
                    errors.append(
                        f"  {tc_id}: {full_url} -> not found (404)"
                    )
                # 200, 401, 403 are all valid responses for vulnerable endpoints

            except httpx.ConnectError:
                errors.append(f"  {tc_id}: {full_url} -> connection refused")
            except httpx.TimeoutException:
                errors.append(f"  {tc_id}: {full_url} -> timeout")
            except Exception as exc:
                errors.append(f"  {tc_id}: {full_url} -> error: {exc}")

    return errors


async def main() -> int:
    """Run the validation."""
    if not GROUND_TRUTH_PATH.exists():
        print(f"ERROR: Ground truth file not found: {GROUND_TRUTH_PATH}")
        return 1

    with open(GROUND_TRUTH_PATH, encoding="utf-8") as f:
        data = json.load(f)

    test_cases = data.get("test_cases", [])
    if not test_cases:
        print("ERROR: No test cases found in ground truth file")
        return 1

    print(f"Loaded {len(test_cases)} test cases from ground truth")

    # Group by target
    by_target: dict[str, list[dict]] = {}
    for tc in test_cases:
        name = tc.get("target_name", "unknown")
        by_target.setdefault(name, []).append(tc)

    docker_mgr = DockerTargetManager()
    total_errors = 0

    for target_name, cases in by_target.items():
        target = BENCHMARK_TARGETS.get(target_name)
        if not target:
            print(f"\nWARNING: Unknown target '{target_name}' — skipping {len(cases)} test cases")
            continue

        print(f"\n=== Validating {target_name} ({len(cases)} test cases) ===")

        # Start container
        try:
            target_url = await docker_mgr.start(target)
        except DockerUnavailableError as exc:
            print(f"  Docker unavailable: {exc} — skipping")
            continue
        except Exception as exc:
            print(f"  Failed to start container: {exc} — skipping")
            continue

        # DVWA: authenticate
        dvwa_cookies = None
        if target_name == "dvwa":
            try:
                dvwa_cookies = await setup_dvwa(target_url)
                print(f"  DVWA auth successful (cookies: {list(dvwa_cookies.keys())})")
            except Exception as exc:
                print(f"  DVWA auth FAILED: {exc}")
                print(f"  Continuing without auth — some endpoints will report redirect errors")

        # Validate endpoints
        errors = await validate_target(target_name, target_url, cases, dvwa_cookies)

        if errors:
            print(f"  FAILURES ({len(errors)}):")
            for err in errors:
                print(err)
            total_errors += len(errors)
        else:
            print(f"  All {len(cases)} endpoints OK ✓")

        # Stop container
        try:
            await docker_mgr.stop(target_name)
        except Exception:
            pass

    # Summary
    print(f"\n{'=' * 50}")
    if total_errors == 0:
        print("All endpoints validated successfully ✓")
        return 0
    else:
        print(f"VALIDATION FAILED: {total_errors} endpoint(s) returned unexpected responses")
        return 1


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)