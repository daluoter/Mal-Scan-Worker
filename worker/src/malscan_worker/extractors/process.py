"""Run archive parsers in a process whose entire process group can be stopped.

The Linux worker container is the supported boundary. Native decoders and rar
helper processes are killed on timeout/cancellation; an asyncio thread timeout
cannot provide this guarantee. Expansion accounting happens in the parent,
using IPC before each output reservation/write.
"""
from __future__ import annotations

import asyncio
import multiprocessing
import os
import signal
import time
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, cast

from malscan_worker.budget import BudgetExceeded, RootBudget, reservation_key
from malscan_worker.exceptions import (
    ArchivePasswordRequiredError,
    ArchiveWrongPasswordError,
)
from malscan_worker.extractors.base import (
    ExtractionLimits,
    ExtractionResult,
    FormatHandler,
)


def _extract_child(
    connection: Any,
    handler: FormatHandler,
    file_path: Path,
    extract_dir: Path,
    limits: ExtractionLimits,
    password: str | None,
) -> None:
    try:
        os.setsid()
        high_water: dict[str, tuple[int, int]] = {}

        def reserve(origin: str, files: int, bytes: int) -> None:
            old_files, old_bytes = high_water.get(origin, (0, -1))
            if files <= old_files and bytes <= old_bytes:
                return
            files, bytes = max(files, old_files), max(bytes, old_bytes)
            connection.send(("reserve", origin, files, bytes))
            reply = connection.recv()
            if reply[0] != "accepted":
                raise BudgetExceeded(reply[1])
            high_water[origin] = (files, bytes)

        limits = replace(limits, reserve_output=reserve)
        result = handler.extract(file_path, extract_dir, limits, password)
        connection.send(("result", result))
    except ArchivePasswordRequiredError:
        connection.send(("password_required", handler.name))
    except ArchiveWrongPasswordError:
        connection.send(("wrong_password", handler.name))
    except BudgetExceeded as exc:
        connection.send(("limit", exc.reason))
    except NotImplementedError:
        connection.send(("unsupported", handler.name))
    except Exception as exc:
        # Raw parser exceptions may contain credentials or hostile filenames.
        connection.send(("error", type(exc).__name__))
    finally:
        connection.close()


def _stop_process(process: Any) -> None:
    if process.pid is None:
        return
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except PermissionError:
        if process.is_alive():
            process.kill()
    if process.is_alive():
        process.kill()
    process.join(timeout=0.1)


async def extract_bounded(
    handler: FormatHandler,
    file_path: Path,
    extract_dir: Path,
    limits: ExtractionLimits,
    password: str | None,
    root_budget: RootBudget | None,
    job_id: str,
) -> ExtractionResult:
    if os.name != "posix" or "fork" not in multiprocessing.get_all_start_methods():
        raise RuntimeError("bounded extraction requires the Linux worker process boundary")
    timeout = float(limits.timeout_seconds)
    if root_budget is not None:
        await root_budget.check_deadline()
        snapshot = await root_budget.snapshot()
        timeout = min(timeout, (snapshot.deadline_at - datetime.now(timezone.utc)).total_seconds())
    if timeout <= 0:
        raise BudgetExceeded("analysis_attempt_deadline")
    parent, child = multiprocessing.get_context("fork").Pipe()
    process = multiprocessing.get_context("fork").Process(
        target=_extract_child,
        args=(child, handler, file_path, extract_dir, limits, password),
        daemon=True,
    )
    process.start()
    child.close()
    deadline = time.monotonic() + timeout
    try:
        while True:
            if time.monotonic() >= deadline:
                raise BudgetExceeded("extraction_deadline")
            if parent.poll():
                try:
                    message = parent.recv()
                except EOFError as exc:
                    raise RuntimeError("extractor process exited without a result") from exc
                kind = message[0]
                if kind == "reserve":
                    try:
                        if root_budget is not None:
                            await asyncio.wait_for(
                                root_budget.reserve(
                                    reservation_key(job_id, "archive-extract", message[1]),
                                    message[2],
                                    message[3],
                                ),
                                timeout=max(0.001, deadline - time.monotonic()),
                            )
                        parent.send(("accepted",))
                    except BudgetExceeded as exc:
                        parent.send(("rejected", exc.reason))
                    except asyncio.TimeoutError:
                        raise BudgetExceeded("extraction_deadline") from None
                    except Exception:
                        parent.send(("rejected", "root_budget_unavailable"))
                elif kind == "result":
                    return cast(ExtractionResult, message[1])
                elif kind == "password_required":
                    raise ArchivePasswordRequiredError(message[1])
                elif kind == "wrong_password":
                    raise ArchiveWrongPasswordError(message[1])
                elif kind == "limit":
                    raise BudgetExceeded(message[1])
                elif kind == "unsupported":
                    raise NotImplementedError(f"{message[1]} extraction is not supported")
                else:
                    raise RuntimeError(f"extractor process failed: {message[1]}")
            elif not process.is_alive():
                raise RuntimeError("extractor process exited without a result")
            else:
                await asyncio.sleep(0.01)
    finally:
        _stop_process(process)
        parent.close()


def _parser_child(connection: Any, function: Any) -> None:
    try:
        os.setsid()
        high_water: dict[str, tuple[int, int]] = {}

        def reserve(origin: str, files: int, bytes: int) -> None:
            old_files, old_bytes = high_water.get(origin, (0, -1))
            if files <= old_files and bytes <= old_bytes:
                return
            files, bytes = max(files, old_files), max(bytes, old_bytes)
            connection.send(("reserve", origin, files, bytes))
            reply = connection.recv()
            if reply[0] != "accepted":
                raise BudgetExceeded(reply[1])
            high_water[origin] = (files, bytes)

        connection.send(("result", function(reserve)))
    except BudgetExceeded as exc:
        connection.send(("limit", exc.reason))
    except Exception as exc:
        connection.send(("error", type(exc).__name__))
    finally:
        connection.close()


async def run_parser_bounded(
    function: Any,
    *,
    root_budget: RootBudget | None,
    job_id: str,
    source: str,
    timeout_seconds: float,
) -> Any:
    """Same killable process boundary for embedded-document parsers."""
    if os.name != "posix" or "fork" not in multiprocessing.get_all_start_methods():
        raise RuntimeError("bounded parsing requires the Linux worker process boundary")
    timeout = float(timeout_seconds)
    if root_budget is not None:
        await root_budget.check_deadline()
        snapshot = await root_budget.snapshot()
        timeout = min(timeout, (snapshot.deadline_at - datetime.now(timezone.utc)).total_seconds())
    if timeout <= 0:
        raise BudgetExceeded("analysis_attempt_deadline")
    parent, child = multiprocessing.get_context("fork").Pipe()
    process = multiprocessing.get_context("fork").Process(
        target=_parser_child,
        args=(child, function),
        daemon=True,
    )
    process.start()
    child.close()
    deadline = time.monotonic() + timeout
    try:
        while True:
            if time.monotonic() >= deadline:
                raise BudgetExceeded("parser_deadline")
            if parent.poll():
                try:
                    message = parent.recv()
                except EOFError as exc:
                    raise RuntimeError("parser process exited without a result") from exc
                if message[0] == "reserve":
                    try:
                        if root_budget is not None:
                            await asyncio.wait_for(
                                root_budget.reserve(
                                    reservation_key(job_id, source, message[1]),
                                    message[2],
                                    message[3],
                                ),
                                timeout=max(0.001, deadline - time.monotonic()),
                            )
                        parent.send(("accepted",))
                    except BudgetExceeded as exc:
                        parent.send(("rejected", exc.reason))
                    except asyncio.TimeoutError:
                        raise BudgetExceeded("parser_deadline") from None
                    except Exception:
                        parent.send(("rejected", "root_budget_unavailable"))
                elif message[0] == "result":
                    return message[1]
                elif message[0] == "limit":
                    raise BudgetExceeded(message[1])
                else:
                    raise RuntimeError(f"parser process failed: {message[1]}")
            elif not process.is_alive():
                raise RuntimeError("parser process exited without a result")
            else:
                await asyncio.sleep(0.01)
    finally:
        _stop_process(process)
        parent.close()
