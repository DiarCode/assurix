"""Manage ephemeral Docker containers for benchmark targets."""

from __future__ import annotations

import asyncio
import logging
import re
import time
from dataclasses import dataclass, field
from typing import Any

import httpx

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Custom exceptions
# ---------------------------------------------------------------------------


class DockerUnavailableError(RuntimeError):
    """Raised when Docker is not installed or not accessible."""


class ContainerStartError(RuntimeError):
    """Raised when a Docker container fails to start."""


class HealthCheckTimeoutError(RuntimeError):
    """Raised when a container does not become healthy within the allowed time."""


# ---------------------------------------------------------------------------
# Target definitions
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DockerTarget:
    """Configuration for a Docker-based benchmark target."""

    name: str
    image: str
    container_name: str
    port: int
    health_check_path: str = "/"
    health_check_timeout: int = 60
    env_vars: dict[str, str] = field(default_factory=dict)
    ready_pattern: str = ""


JUICE_SHOP = DockerTarget(
    name="juice-shop",
    image="bkimminich/juice-shop:v17.1",
    container_name="assurix-bench-juice-shop",
    port=3000,
    health_check_path="/",
    health_check_timeout=90,
    ready_pattern="Juice Shop",
)

DVWA = DockerTarget(
    name="dvwa",
    image="vulnerables/web-dvwa:latest",
    container_name="assurix-bench-dvwa",
    port=80,
    health_check_path="/login.php",
    health_check_timeout=60,
    ready_pattern="Login",
)

WEBGOAT = DockerTarget(
    name="webgoat",
    image="webgoat/webgoat:8.2.0",
    container_name="assurix-bench-webgoat",
    port=8080,
    health_check_path="/WebGoat/login",
    health_check_timeout=90,
    ready_pattern="WebGoat",
)

BENCHMARK_TARGETS: dict[str, DockerTarget] = {
    "juice-shop": JUICE_SHOP,
    "dvwa": DVWA,
    "webgoat": WEBGOAT,
}


# ---------------------------------------------------------------------------
# Manager
# ---------------------------------------------------------------------------


class DockerTargetManager:
    """Manages ephemeral Docker containers for benchmark targets."""

    def __init__(self) -> None:
        self._containers: dict[str, str] = {}  # target_name -> container_id
        self._docker_available: bool | None = None

    async def start(self, target: DockerTarget) -> str:
        """Start a Docker container for the target.

        Returns the base URL (e.g. ``http://localhost:3000``).

        Raises:
            DockerUnavailableError: If Docker is not installed or accessible.
            ContainerStartError: If the container fails to start.
            HealthCheckTimeoutError: If the container does not become healthy.
        """
        await self._check_docker_available()

        # Stop any existing container with the same name first
        if target.name in self._containers:
            await self.stop(target.name)

        logger.info("Starting benchmark target %s (%s)", target.name, target.image)

        env_args: list[str] = []
        for key, value in target.env_vars.items():
            env_args.extend(["-e", f"{key}={value}"])

        cmd: list[str] = [
            "docker", "run",
            "-d",
            "--rm",
            "-p", f"{target.port}:{target.port}",
            "--name", target.container_name,
            *env_args,
            target.image,
        ]

        try:
            container_id = await self._run_docker(*cmd)
        except Exception as exc:
            raise ContainerStartError(
                f"Failed to start container for {target.name}: {exc}"
            ) from exc

        self._containers = {**self._containers, target.name: container_id.strip()}

        base_url = f"http://localhost:{target.port}"
        logger.info(
            "Container %s started (id=%s). Waiting for health check at %s",
            target.name,
            container_id.strip()[:12],
            base_url + target.health_check_path,
        )

        healthy = await self._wait_for_healthy(target)
        if not healthy:
            await self.stop(target.name)
            raise HealthCheckTimeoutError(
                f"Target {target.name} did not become healthy within "
                f"{target.health_check_timeout}s"
            )

        logger.info("Target %s is healthy at %s", target.name, base_url)
        return base_url

    async def stop(self, target_name: str) -> None:
        """Stop and remove a Docker container."""
        if target_name not in self._containers:
            logger.warning("No tracked container for target %s", target_name)
            # Still try to stop by name in case it was left over
            target = BENCHMARK_TARGETS.get(target_name)
            if target:
                try:
                    await self._run_docker("docker", "stop", target.container_name)
                except Exception:
                    pass
            return

        target = BENCHMARK_TARGETS.get(target_name)
        container_name = target.container_name if target else target_name

        logger.info("Stopping benchmark target %s", target_name)
        try:
            await self._run_docker("docker", "stop", container_name)
        except Exception as exc:
            logger.warning("Failed to stop container %s: %s", container_name, exc)

        self._containers = {
            k: v for k, v in self._containers.items() if k != target_name
        }

    async def stop_all(self) -> None:
        """Stop all running benchmark containers."""
        names = list(self._containers.keys())
        for name in names:
            await self.stop(name)

    async def is_healthy(self, target: DockerTarget) -> bool:
        """Check if the target is healthy and ready for scanning."""
        url = f"http://localhost:{target.port}{target.health_check_path}"
        try:
            async with httpx.AsyncClient(verify=False, timeout=10.0) as client:
                response = await client.get(url)
                if response.status_code >= 500:
                    return False
                if target.ready_pattern:
                    return bool(re.search(target.ready_pattern, response.text))
                return response.status_code < 400
        except (httpx.HTTPError, httpx.ConnectError, OSError):
            return False

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    async def _check_docker_available(self) -> None:
        """Verify Docker is installed and accessible."""
        if self._docker_available is True:
            return
        try:
            result = await self._run_docker("docker", "info", "--format", "{{.ID}}")
            self._docker_available = True
            logger.debug("Docker is available (daemon ID: %s)", result.strip()[:12])
        except Exception as exc:
            self._docker_available = False
            raise DockerUnavailableError(
                f"Docker is not available: {exc}"
            ) from exc

    async def _wait_for_healthy(self, target: DockerTarget) -> bool:
        """Poll the health endpoint until the target is ready or times out."""
        deadline = time.monotonic() + target.health_check_timeout
        poll_interval = 2.0
        while time.monotonic() < deadline:
            if await self.is_healthy(target):
                return True
            logger.debug(
                "Target %s not healthy yet, retrying in %.1fs",
                target.name,
                poll_interval,
            )
            await asyncio.sleep(poll_interval)
        return False

    async def _run_docker(self, *args: str) -> str:
        """Run a Docker command and return stdout.

        Uses asyncio.create_subprocess_exec to avoid shell injection.
        All arguments are passed as a list, not through a shell.
        """
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        if proc.returncode != 0:
            error_detail = stderr.decode(errors="replace").strip()
            raise RuntimeError(
                f"Docker command failed (exit {proc.returncode}): {error_detail}"
            )
        return stdout.decode(errors="replace")