"""Shell command execution with built-in safety validation.

Provides ``BashTool.execute()`` to run shell commands via ``subprocess``.
Each command runs in its own session so a timeout kills the whole
process tree, not just the shell.
A static deny list blocks known-dangerous patterns (recursive delete,
privilege escalation, fork bombs, etc.) before the subprocess is spawned.

This module has **zero external dependencies** -- it uses only the Python
standard library (``re``, ``subprocess``, ``pathlib``).

Usage::

    from bashtool import BashTool

    result = BashTool.execute("ls -la")
    print(result["stdout"])

When used as a git submodule mounted at ``_vendor/bashtool/``::

    from _vendor.bashtool import BashTool
"""

from __future__ import annotations

import contextlib
import os
import re
import signal
import subprocess
import sys
import time
from pathlib import Path

__version__ = "0.3.0"

_UNSAFE_WARNED = False


def _is_unsafe_mode() -> bool:
    """Check whether deny-list validation is disabled via environment."""
    global _UNSAFE_WARNED
    enabled = os.environ.get("BASHTOOL_UNSAFE", "") not in ("", "0", "false")
    if enabled and not _UNSAFE_WARNED:
        print("bashtool: BASHTOOL_UNSAFE is set, deny list disabled", file=sys.stderr)
        _UNSAFE_WARNED = True
    return enabled


# Maximum bytes kept for stdout / stderr to prevent memory exhaustion.
MAX_OUTPUT_BYTES = 65_536  # 64 KB

# ---------------------------------------------------------------------------
# Danger-pattern deny list
# ---------------------------------------------------------------------------
# Each entry is (compiled_regex, human-readable reason).
# Patterns are checked against *each segment* of the command after splitting
# on shell operators (&&, ||, ;, |).

DANGER_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # -- Destructive filesystem operations --
    (
        re.compile(
            r"\brm\s+.*-[a-zA-Z]*r[a-zA-Z]*f[a-zA-Z]*\s+[/~*]"
            r"|\brm\s+.*-[a-zA-Z]*f[a-zA-Z]*r[a-zA-Z]*\s+[/~*]"
        ),
        "Recursive forced deletion of root, home, or wildcard paths",
    ),
    (re.compile(r"\bmkfs\b"), "Filesystem formatting"),
    (re.compile(r"\bdd\s+.*\bif="), "Raw disk image write"),
    (re.compile(r">\s*/dev/sd[a-z]"), "Device overwrite"),
    # -- Privilege escalation --
    (re.compile(r"\bsu\s+-"), "User switching via su"),
    (
        re.compile(r"\bchmod\s+.*-[a-zA-Z]*R.*\b777\b.*\s+/"),
        "Recursive world-writable permission on root",
    ),
    (re.compile(r"\bchown\s+.*-[a-zA-Z]*R"), "Recursive ownership change"),
    # -- Code injection --
    (re.compile(r"\beval\b"), "Arbitrary code evaluation"),
    (re.compile(r"\bexec\b"), "Process replacement via exec"),
    # -- Fork bomb --
    (re.compile(r":\(\)\s*\{.*:\|:.*\}"), "Fork bomb"),
    # -- Git destructive operations --
    (re.compile(r"\bgit\s+push\s+.*--force\b"), "Force push"),
    (re.compile(r"\bgit\s+reset\s+--hard\b"), "Hard reset"),
    (re.compile(r"\bgit\s+clean\s+.*-[a-zA-Z]*f"), "Force clean"),
    # -- System control --
    (re.compile(r"\bshutdown\b"), "System shutdown"),
    (re.compile(r"\breboot\b"), "System reboot"),
    (re.compile(r"\bhalt\b"), "System halt"),
    (re.compile(r"\bkill\s+.*-9\s+1\b"), "Killing init process"),
]

# Pipe-to-shell: checked on the full (unsplit) command.
_PIPE_EXEC_RE = re.compile(r"\b(?:curl|wget)\b.*\|\s*(?:bash|sh|zsh|dash)\b")

# Shell operator split (&&, ||, ;, |) -- simplistic but sufficient for the
# deny-list use-case.  We do NOT attempt full AST parsing.
_OPERATOR_SPLIT_RE = re.compile(r"\s*(?:&&|\|\||;)\s*")


def validate_command(command: str) -> None:
    """Raise ``ValueError`` if *command* matches a known-dangerous pattern.

    Skipped entirely when ``BASHTOOL_UNSAFE`` is set in the environment.

    Args:
        command: Raw shell command string.

    Raises:
        ValueError: With a human-readable reason describing why the command
            was rejected.
    """
    if _is_unsafe_mode():
        return

    # 1. Pipe-to-shell check on the full command
    if _PIPE_EXEC_RE.search(command):
        raise ValueError("Dangerous command blocked: pipe-to-shell execution detected")

    # 2. Segment by shell operators and check each part
    segments = _OPERATOR_SPLIT_RE.split(command)
    for segment in segments:
        stripped = segment.strip()
        if not stripped:
            continue
        for pattern, reason in DANGER_PATTERNS:
            if pattern.search(stripped):
                raise ValueError(f"Dangerous command blocked: {reason}")


# Backward-compatible alias
_validate_command = validate_command


def truncate(text: str, max_bytes: int = MAX_OUTPUT_BYTES) -> str:
    """Truncate *text* to at most *max_bytes* UTF-8 bytes.

    If truncation occurs, a marker is appended so the caller knows the
    output was clipped.

    Args:
        text: The string to truncate.
        max_bytes: Maximum number of UTF-8 bytes allowed.

    Returns:
        The (possibly truncated) string.
    """
    encoded = text.encode("utf-8", errors="replace")
    if len(encoded) <= max_bytes:
        return text
    truncated = encoded[:max_bytes].decode("utf-8", errors="ignore")
    return truncated + "\n... [output truncated]"


# Backward-compatible alias
_truncate = truncate


# ---------------------------------------------------------------------------
# Timeout handling
# ---------------------------------------------------------------------------


class CommandTimeoutError(TimeoutError):
    """Raised when a command exceeds its timeout and is killed.

    A timeout is a failure, not a result: callers that key on an exit status
    must not mistake a killed command for one that ran (#188).  The partial
    output is carried on the exception rather than discarded, so a caller
    that wants it can read :attr:`stdout` / :attr:`stderr` or call
    :meth:`to_dict`.

    Attributes:
        command: The command that timed out.
        timeout: The timeout in seconds.
        stdout: Captured standard output (truncated at 64 KB).
        stderr: Captured standard error (truncated at 64 KB).
        exit_code: ``-1``; a killed process has no exit status.
        timed_out: Always ``True``.
    """

    def __init__(
        self,
        command: str,
        timeout: int,
        stdout: str = "",
        stderr: str = "",
        exit_code: int = -1,
    ) -> None:
        self.command = command
        self.timeout = timeout
        self.stdout = truncate(stdout)
        self.stderr = truncate(stderr)
        self.exit_code = exit_code
        self.timed_out = True

        parts = [f"Command timed out after {timeout}s and was killed: {command}"]
        if self.stdout:
            parts.append(f"stdout:\n{self.stdout}")
        if self.stderr:
            parts.append(f"stderr:\n{self.stderr}")
        super().__init__("\n".join(parts))

    def to_dict(self) -> dict:
        """Return the timeout as the dict an ``execute()`` caller would have had."""
        return {
            "stdout": self.stdout,
            "stderr": self.stderr,
            "exit_code": self.exit_code,
            "timed_out": True,
        }


def _kill_process_tree(proc: subprocess.Popen, grace: float = 0.5) -> None:
    """Kill *proc* and everything it started.

    ``shell=True`` makes the immediate child a shell; terminating only that
    PID leaves the command it launched running (#190).  The child is started
    in its own session, so its process group is exactly the command's tree:
    SIGTERM the group, give it a moment, then SIGKILL whatever is left.

    Args:
        proc: The process returned by ``Popen(start_new_session=True)``.
        grace: Seconds between SIGTERM and SIGKILL.
    """
    if os.name != "posix":  # pragma: no cover - Windows has no process groups
        proc.kill()
        return

    try:
        pgid = os.getpgid(proc.pid)
    except ProcessLookupError:
        return

    try:
        os.killpg(pgid, signal.SIGTERM)
    except ProcessLookupError:
        return

    deadline = time.monotonic() + grace
    while time.monotonic() < deadline and proc.poll() is None:
        time.sleep(0.02)

    # The shell may be gone while a grandchild survives; kill the group
    # unconditionally rather than trusting the shell's exit.
    with contextlib.suppress(ProcessLookupError):
        os.killpg(pgid, signal.SIGKILL)


# ---------------------------------------------------------------------------
# BashTool
# ---------------------------------------------------------------------------


class BashTool:
    """Shell command execution with built-in safety validation."""

    @staticmethod
    def execute(
        command: str,
        timeout: int = 120,
        cwd: str | None = None,
    ) -> dict:
        """Execute a shell command and return its output.

        The command is first validated against a built-in deny list of
        known-dangerous patterns.  If the command passes validation it is
        executed via ``subprocess.Popen`` with ``shell=True``, in its own
        session so that a timeout can kill the whole process tree.

        Args:
            command: The shell command to execute.
            timeout: Maximum wall-clock seconds before the process is
                killed.  Defaults to 120.
            cwd: Working directory for the command.  If ``None``, the
                current process working directory is used.

        Returns:
            A dict with keys:

            - ``stdout`` (str): captured standard output (truncated at 64 KB).
            - ``stderr`` (str): captured standard error (truncated at 64 KB).
            - ``exit_code`` (int): process exit code.
            - ``timed_out`` (bool): always ``False`` for a returned result; a
              timeout raises :class:`CommandTimeoutError` instead.

        Raises:
            ValueError: If the command matches a dangerous pattern.
            FileNotFoundError: If *cwd* is specified but does not exist.
            CommandTimeoutError: If the command exceeds *timeout*.  Its
                ``stdout`` / ``stderr`` hold whatever was written before the
                kill.
        """
        # Validate safety
        validate_command(command)

        # Validate cwd
        if cwd is not None:
            cwd_path = Path(cwd)
            if not cwd_path.is_dir():
                raise FileNotFoundError(f"Working directory does not exist: {cwd}")

        proc = subprocess.Popen(
            command,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd=cwd,
            # Own session ⇒ own process group ⇒ the timeout can kill the
            # command's whole tree instead of only the shell (#190).
            start_new_session=os.name == "posix",
        )
        try:
            stdout, stderr = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            _kill_process_tree(proc)
            try:
                # Reap the killed tree and collect what it wrote.
                stdout, stderr = proc.communicate(timeout=5)
            except subprocess.TimeoutExpired:  # pragma: no cover - defensive
                stdout, stderr = "", ""
            raise CommandTimeoutError(command, timeout, stdout or "", stderr or "") from None

        return {
            "stdout": truncate(stdout or ""),
            "stderr": truncate(stderr or ""),
            "exit_code": proc.returncode,
            "timed_out": False,
        }
