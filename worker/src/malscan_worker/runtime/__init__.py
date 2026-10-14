"""Portable root-batch execution of the shared analysis pipeline.

This entry point does not connect to the application database or message queue.
Its artifact and report stores are explicit dependencies, rather than temporary
container disks masquerading as published results.
"""

from malscan_worker.runtime.batch import RootBatchRunner
from malscan_worker.runtime.manifest import AnalysisManifest, SourceReference
from malscan_worker.runtime.store import LocalObjectStore, S3ObjectStore

__all__ = [
    "AnalysisManifest",
    "LocalObjectStore",
    "RootBatchRunner",
    "S3ObjectStore",
    "SourceReference",
]
