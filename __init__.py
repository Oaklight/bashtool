"""BashTool -- shell command execution with built-in safety validation.

Re-export facade.  When this repo is mounted as a git submodule (e.g. at
``_vendor/bashtool/``), the directory is importable as a Python package::

    from _vendor.bashtool import BashTool
"""

from .bashtool import (
    DANGER_PATTERNS,
    MAX_OUTPUT_BYTES,
    BashTool,
    __version__,
    truncate,
    validate_command,
)

__all__ = [
    "DANGER_PATTERNS",
    "MAX_OUTPUT_BYTES",
    "BashTool",
    "__version__",
    "truncate",
    "validate_command",
]
