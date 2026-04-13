"""Subprocess helpers for external security tools."""

from __future__ import annotations

import asyncio
import shutil
from typing import AsyncIterator


async def run(
    *cmd: str,
    timeout: int = 300,
    check: bool = False,
) -> tuple[int, str, str]:
    """Run a command, return (returncode, stdout, stderr)."""
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.communicate()
        raise TimeoutError(f"Command timed out after {timeout}s: {' '.join(cmd)}")

    rc = proc.returncode or 0
    if check and rc != 0:
        raise RuntimeError(f"Command failed ({rc}): {' '.join(cmd)}\n{stderr.decode()}")
    return rc, stdout.decode(errors="replace"), stderr.decode(errors="replace")


async def stream_lines(
    *cmd: str,
    timeout: int = 600,
) -> AsyncIterator[str]:
    """Stream stdout lines from a subprocess."""
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
    )
    assert proc.stdout
    try:
        async with asyncio.timeout(timeout):
            async for line in proc.stdout:
                yield line.decode(errors="replace").rstrip()
    finally:
        if proc.returncode is None:
            proc.kill()
            await proc.wait()


def tool_available(name: str) -> bool:
    return shutil.which(name) is not None
