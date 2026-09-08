"""TaskExecutor contract for the Execution plane (asyncio Task/DAG).

NetworkX may be used internally to represent the DAG; it is not itself
the executor. Execution state is distinct from Investigation/Evidence/
Authorization state — see CLAUDE.md.
"""
from __future__ import annotations

from enum import Enum
from typing import Any, Awaitable, Callable, Protocol


class TaskStatus(str, Enum):
    PENDING = "PENDING"
    READY = "READY"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    RETRYING = "RETRYING"
    BLOCKED = "BLOCKED"
    WAITING_APPROVAL = "WAITING_APPROVAL"
    CANCELLED = "CANCELLED"


class TaskExecutor(Protocol):
    async def submit(
        self,
        task_id: str,
        coro_factory: Callable[[], Awaitable[Any]],
        depends_on: tuple[str, ...] = (),
    ) -> None:
        """Register a task and its dependencies; does not necessarily run it immediately."""
        ...

    def status(self, task_id: str) -> TaskStatus:
        """Return the current lifecycle status of a task."""
        ...

    async def cancel(self, task_id: str) -> None:
        """Request cancellation of a pending or running task."""
        ...
