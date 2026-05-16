"""Docker sandbox for safe tool execution."""

from __future__ import annotations

import logging
import time

import docker
from docker.errors import ContainerError, ImageNotFound
from requests.exceptions import ReadTimeout

from dixie.core.config import SandboxConfig
from dixie.core.schema import ToolResult

logger = logging.getLogger(__name__)


class Sandbox:
    """Manages Docker containers for isolated tool execution."""

    def __init__(self, config: SandboxConfig) -> None:
        self.config = config
        self.client = docker.from_env()
        self._container = None

    def ensure_image(self) -> bool:
        try:
            self.client.images.get(self.config.image)
            return True
        except ImageNotFound:
            logger.warning("Sandbox image '%s' not found. Build it first.", self.config.image)
            return False

    def run_command(self, command: list[str], tool_name: str) -> ToolResult:
        """Execute a command inside the sandbox container.

        Uses ``detach=True`` + ``container.wait(timeout=...)`` so the same
        :attr:`SandboxConfig.timeout` (seconds) applies as for :meth:`run_local`.

        Returns a ToolResult with raw output and timing information.
        """
        cmd_str = " ".join(command)
        start = time.monotonic()
        container = None
        try:
            container = self.client.containers.run(
                image=self.config.image,
                command=command,
                detach=True,
                remove=False,
                network_mode=self.config.network_mode,
                mem_limit=self.config.memory_limit,
                cpu_quota=int(self.config.cpu_limit * 100_000),
            )
            wait_result = container.wait(timeout=self.config.timeout)
            elapsed = int((time.monotonic() - start) * 1000)
            exit_code = int(wait_result.get("StatusCode", 1))
            raw_bytes = container.logs(stdout=True, stderr=True)
            raw = raw_bytes.decode("utf-8", errors="replace")

            return ToolResult(
                tool=tool_name,
                command=cmd_str,
                raw_output=raw,
                duration_ms=elapsed,
                success=exit_code == 0,
                error=None if exit_code == 0 else f"exit code {exit_code}",
            )

        except ReadTimeout:
            elapsed = int((time.monotonic() - start) * 1000)
            if container is not None:
                try:
                    container.kill()
                except Exception:
                    logger.warning("Failed to kill timed-out container", exc_info=True)
            return ToolResult(
                tool=tool_name,
                command=cmd_str,
                raw_output="",
                duration_ms=elapsed,
                success=False,
                error=f"Timeout after {self.config.timeout}s",
            )

        except ContainerError as e:
            elapsed = int((time.monotonic() - start) * 1000)
            return ToolResult(
                tool=tool_name,
                command=cmd_str,
                raw_output=e.stderr.decode("utf-8", errors="replace") if e.stderr else "",
                duration_ms=elapsed,
                success=False,
                error=str(e),
            )

        except Exception as e:
            elapsed = int((time.monotonic() - start) * 1000)
            return ToolResult(
                tool=tool_name,
                command=cmd_str,
                raw_output="",
                duration_ms=elapsed,
                success=False,
                error=f"{type(e).__name__}: {e}",
            )

        finally:
            if container is not None:
                try:
                    container.remove(force=True)
                except Exception:
                    logger.debug("Sandbox container remove failed", exc_info=True)

    def run_local(self, command: list[str], tool_name: str) -> ToolResult:
        """Execute a command locally (no Docker). For development/testing only."""
        import subprocess

        cmd_str = " ".join(command)
        start = time.monotonic()

        try:
            proc = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=self.config.timeout,
            )
            elapsed = int((time.monotonic() - start) * 1000)

            return ToolResult(
                tool=tool_name,
                command=cmd_str,
                raw_output=proc.stdout + proc.stderr,
                duration_ms=elapsed,
                success=proc.returncode == 0,
                error=None if proc.returncode == 0 else f"exit code {proc.returncode}",
            )
        except subprocess.TimeoutExpired:
            elapsed = int((time.monotonic() - start) * 1000)
            return ToolResult(
                tool=tool_name,
                command=cmd_str,
                raw_output="",
                duration_ms=elapsed,
                success=False,
                error=f"Timeout after {self.config.timeout}s",
            )
