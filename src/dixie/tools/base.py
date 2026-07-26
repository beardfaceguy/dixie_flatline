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

    def missing_required_parameters(self, arguments: dict[str, Any]) -> list[str]:
        """Return the names of required parameters absent from ``arguments``.

        A parameter is considered satisfied when a key is present with a
        non-``None`` value. Tools with a schema default for a required
        parameter are treated as satisfied even when the caller omits it,
        since ``build_command`` can fall back to that default.
        """
        missing: list[str] = []
        for param in self.parameters:
            if not param.required:
                continue
            if param.default is not None:
                continue
            value = arguments.get(param.name)
            if value is None:
                missing.append(param.name)
        return missing

    def validate_arguments(self, arguments: dict[str, Any]) -> str | None:
        """Validate ``arguments`` against the schema before building a command.

        Returns an error message when required parameters are missing, or
        ``None`` when the arguments are usable. This guards ``build_command``
        against malformed / empty tool-call payloads (e.g. the model emitting
        ``{}``) which would otherwise raise an uncaught ``KeyError``.
        """
        missing = self.missing_required_parameters(arguments)
        if missing:
            return (
                f"Tool '{self.name}' called without required parameter(s): "
                f"{', '.join(missing)}. Provide them and retry."
            )
        return None

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
