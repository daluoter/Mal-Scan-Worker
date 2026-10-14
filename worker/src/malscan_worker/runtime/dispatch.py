"""In-process dispatcher reused for bounded root batches and checkpoint recovery."""

from collections import deque


class BatchDispatcher:
    """Queue identities, without launching one container for every child file."""

    def __init__(self) -> None:
        self._queue: deque[str] = deque()
        self._pending: set[str] = set()

    def dispatch(self, artifact_id: str) -> None:
        if artifact_id not in self._pending:
            self._queue.append(artifact_id)
            self._pending.add(artifact_id)

    def next_artifact(self) -> str | None:
        if not self._queue:
            return None
        artifact_id = self._queue.popleft()
        self._pending.remove(artifact_id)
        return artifact_id
