"""Domain exceptions for worker archive handling."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from malscan_worker.stages.base import StageResult


class ArchivePasswordError(Exception):
    """Password blocking carries completed, credential-free analysis evidence."""

    completed_results: list[StageResult] | None = None
    partial_report: dict[str, Any] | None = None


class ArchivePasswordRequiredError(ArchivePasswordError):
    """Raised when an archive requires a password but none was provided."""


class ArchiveWrongPasswordError(ArchivePasswordError):
    """Raised when an archive password was provided but is invalid."""
