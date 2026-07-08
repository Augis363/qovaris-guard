"""
Nexus Guard — LangChain Integration
=====================================

Provides :class:`NexusSecureTool`, a drop-in ``BaseTool`` wrapper that routes
every LangChain tool invocation through the Nexus Sentinel gateway for
intent-verification before execution.

Requires ``langchain-core >= 0.3.0``.  Import errors are surfaced clearly so
the core SDK can still be used without LangChain installed.

Example
-------
::

    from nexus_guard import NexusFinOpsGuard
    from nexus_guard.langchain import NexusSecureTool
    from langchain_core.tools import tool

    guard = NexusFinOpsGuard(api_key="nx_key")

    @tool
    def search(query: str) -> str:
        \"\"\"Search the catalog.\"\"\"
        return f"Results for {query}"

    secure = NexusSecureTool(
        wrapped_tool=search,
        guard=guard,
        allowed_intent="Search books under $50",
    )

    with guard.session("Find affordable books"):
        result = secure.invoke({"query": "python"})
"""

from __future__ import annotations

import asyncio
from typing import Any, Dict, Optional, Type

try:
    from langchain_core.tools import BaseTool
    from pydantic import BaseModel, ConfigDict
except ImportError as _exc:
    raise ImportError(
        "langchain-core is required for NexusSecureTool. "
        "Install it with:  pip install 'langchain-core>=0.3.0'"
    ) from _exc

from .guard import NexusFinOpsGuard

__all__ = ["NexusSecureTool"]


class NexusSecureTool(BaseTool):
    """LangChain tool that verifies every invocation through the Nexus gateway.

    The wrapper inherits the original tool's ``name``, ``description``, and
    ``args_schema`` so it is a transparent substitute in any LangChain chain
    or agent.

    Parameters
    ----------
    wrapped_tool : BaseTool
        The original LangChain tool to protect.
    guard : NexusFinOpsGuard
        An initialised Nexus Guard instance.
    allowed_intent : str
        A plain-English constraint describing what this tool is permitted to do.
    """

    # --- Pydantic model fields -------------------------------------------
    wrapped_tool: Any          # BaseTool — typed as Any to avoid fwd-ref issues
    guard: Any                 # NexusFinOpsGuard
    allowed_intent: str = ""

    # Inherited from the wrapped tool during __init__
    name: str = ""
    description: str = ""
    args_schema: Optional[Type[BaseModel]] = None

    model_config = ConfigDict(arbitrary_types_allowed=True)

    def __init__(
        self,
        wrapped_tool: BaseTool,
        guard: NexusFinOpsGuard,
        allowed_intent: str = "",
        **kwargs: Any,
    ) -> None:
        super().__init__(
            wrapped_tool=wrapped_tool,
            guard=guard,
            allowed_intent=allowed_intent,
            name=wrapped_tool.name,
            description=wrapped_tool.description,
            args_schema=getattr(wrapped_tool, "args_schema", None),
            **kwargs,
        )

    # ------------------------------------------------------------------ #
    #  Verification helper
    # ------------------------------------------------------------------ #

    def _verify(self, tool_input: Dict[str, Any]) -> None:
        """Verify this invocation through the shared guard enforcement path.

        Works identically in remote (HTTP ``/verify``) and embedded (in-process)
        modes because it delegates to :meth:`NexusFinOpsGuard._authorize`.
        Raises :class:`SecurityBlockException` if denied, unless
        ``guard.fail_open`` is ``True`` and the gateway is unreachable.
        """
        payload = {
            "original_intent": self.guard.current_intent,
            "tool_name": self.name,
            "arguments": tool_input,
            "allowed_intent": self.allowed_intent,
        }
        self.guard._authorize(payload, self.name)

    # ------------------------------------------------------------------ #
    #  BaseTool interface
    # ------------------------------------------------------------------ #

    @staticmethod
    def _collect_input(args: Any, kwargs: Any) -> Any:
        """Reconstruct the tool input from the BaseTool dispatch call."""
        if kwargs:
            return dict(kwargs)
        if args:
            return args[0]
        return {}

    def _run(self, *args: Any, **kwargs: Any) -> Any:
        """Synchronous execution — verify then delegate to the wrapped tool."""
        tool_input = self._collect_input(args, kwargs)
        verify_args = tool_input if isinstance(tool_input, dict) else {"input": tool_input}
        self._verify(verify_args)
        # Delegate via the public API so LangChain injects config/run-manager
        # correctly for both Tool and StructuredTool implementations.
        return self.wrapped_tool.invoke(tool_input)

    async def _arun(self, *args: Any, **kwargs: Any) -> Any:
        """Asynchronous execution — verify in executor then delegate."""
        tool_input = self._collect_input(args, kwargs)
        verify_args = tool_input if isinstance(tool_input, dict) else {"input": tool_input}

        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, self._verify, verify_args)
        return await self.wrapped_tool.ainvoke(tool_input)
