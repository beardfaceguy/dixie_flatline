"""Base class and registry for pentesting tool plugins."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, ClassVar

from pydantic import BaseModel


class ToolParameter(BaseModel):
    name: str
    type: str = "string"
    description: str
    required: bool = False
    default: Any = None


class Tool(ABC):
    """Base class for all pentesting tool plugins.

    Each plugin wraps a CLI tool and provides:
    - A structured parameter schema for the LLM
    - Output parsing from raw CLI output to structured JSON
    - The actual command construction
    """

    name: str
    description: str
    parameters: list[ToolParameter]
    #: When True, :attr:`name` is denied in recon mode (merged into recon policy).
    recon_blocked: ClassVar[bool] = False

    @abstractmethod
    def build_command(self, **kwargs: Any) -> list[str]:
        """Build the CLI command from parameters."""

    @abstractmethod
    def parse_output(self, raw_output: str) -> dict:
        """Parse raw CLI output into structured JSON."""

    def tool_schema(self) -> dict:
        """Generate the function-calling schema for the LLM."""
        properties = {}
        required = []
        for param in self.parameters:
            properties[param.name] = {
                "type": param.type,
                "description": param.description,
            }
            if param.default is not None:
                properties[param.name]["default"] = param.default
            if param.required:
                required.append(param.name)

        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": {
                    "type": "object",
                    "properties": properties,
                    "required": required,
                },
            },
        }


class ToolRegistry:
    """Registry of available tool plugins."""

    def __init__(self) -> None:
        self._tools: dict[str, Tool] = {}

    def register(self, tool: Tool) -> None:
        self._tools[tool.name] = tool

    def get(self, name: str) -> Tool | None:
        return self._tools.get(name)

    def list_tools(self) -> list[Tool]:
        return list(self._tools.values())

    def tool_schemas(self) -> list[dict]:
        return [t.tool_schema() for t in self._tools.values()]
