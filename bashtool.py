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
import shlex
import signal
import subprocess
import sys
import time
from pathlib import Path

__version__ = "0.3.1"

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
    # Only when eval/exec *is the command*, not a substring of someone
    # else's argument: ``find -exec`` and ``grep eval`` are routine and were
    # refused by the previous unanchored patterns (#191).
    (
        re.compile(
            r"^\s*(?:(?:sudo|command|builtin)\s+)*"
            r"(?:[A-Za-z_][A-Za-z0-9_]*=\S*\s+)*"
            r"eval(?:\s|$)"
        ),
        "Arbitrary code evaluation",
    ),
    (
        re.compile(
            r"^\s*(?:(?:sudo|command|builtin)\s+)*"
            r"(?:[A-Za-z_][A-Za-z0-9_]*=\S*\s+)*"
            r"exec(?:\s|$)"
        ),
        "Process replacement via exec",
    ),
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

# Patterns that must see the *whole* command: splitting on ``|`` would tear
# them apart.  The fork bomb contains pipes of its own, and pipe-to-shell
# needs both sides of the pipe.
_PIPE_EXEC_RE = re.compile(r"\b(?:curl|wget)\b.*\|\s*(?:bash|sh|zsh|dash)\b")
_FORK_BOMB_RE = re.compile(r":\(\)\s*\{.*:\|:.*\}")
_FULL_COMMAND_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (_PIPE_EXEC_RE, "pipe-to-shell execution detected"),
    (_FORK_BOMB_RE, "Fork bomb"),
]

# Shell operator split (&&, ||, ;, |) -- simplistic but sufficient for the
# deny-list use-case.  We do NOT attempt full AST parsing.
_OPERATOR_SPLIT_RE = re.compile(r"\s*(?:&&|\|\||;|\|)\s*")


_WRAPPERS = frozenset(
    {"sudo", "doas", "command", "builtin", "env", "nohup", "time", "nice", "timeout", "xargs"}
)

# Options that consume the following token as their value, per wrapper.
_WRAPPER_VALUE_OPTIONS: dict[str, frozenset[str]] = {
    "sudo": frozenset(
        {
            "-u",
            "--user",
            "-g",
            "--group",
            "-p",
            "--prompt",
            "-C",
            "--chdir",
            "-h",
            "--host",
            "-r",
            "--role",
            "-t",
            "--type",
            "-U",
            "--other-user",
        }
    ),
    "doas": frozenset({"-u", "-C"}),
    "env": frozenset({"-u", "--unset", "-C", "--chdir", "--split-string"}),
    "nice": frozenset({"-n", "--adjustment"}),
    "timeout": frozenset({"-s", "--signal", "-k", "--kill-after"}),
    "xargs": frozenset(
        {
            "-n",
            "--max-args",
            "-I",
            "--replace",
            "-P",
            "--max-procs",
            "-L",
            "--max-lines",
            "-s",
            "--max-chars",
            "-d",
            "--delimiter",
            "-E",
            "-a",
            "--arg-file",
            "-J",
        }
    ),
}

_ASSIGNMENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*=\S*")
_DURATION_RE = re.compile(r"^\d+(?:\.\d+)?[smhd]?$")
_FALSE_VALUES = frozenset({"false", "0", "no", "off"})
_SHELLS = frozenset({"sh", "bash", "zsh", "dash", "ksh", "ash", "fish"})
_PROTECTED_RM_TARGETS = ("/", "~", "*")
_MAX_SHELL_C_DEPTH = 4


def _tokenize(segment: str) -> list[str]:
    """Split a shell segment into words, tolerating unbalanced quotes."""
    try:
        return shlex.split(segment, posix=True)
    except ValueError:
        return segment.split()


def _skip_command_prefix(words: list[str]) -> int:
    """Return the index of the command that actually runs.

    Skips wrapper programs (``sudo``, ``env``, ``nice``, ``timeout``,
    ``xargs``, …), their options and values, and leading ``VAR=value``
    assignments, so ``sudo -u root rm`` and ``timeout 5 rm`` are seen as
    an ``rm`` invocation (#191 review).

    Args:
        words: Tokenised command segment.

    Returns:
        Index of the first token that is not a wrapper, option, or
        assignment.
    """
    index = 0
    while index < len(words):
        word = words[index]
        if _ASSIGNMENT_RE.fullmatch(word):
            index += 1
            continue
        wrapper = os.path.basename(word)
        if wrapper not in _WRAPPERS:
            break
        index += 1
        value_options = _WRAPPER_VALUE_OPTIONS.get(wrapper, frozenset())
        if wrapper == "timeout" and index < len(words) and _DURATION_RE.match(words[index]):
            index += 1
        while index < len(words):
            token = words[index]
            if token == "--":
                index += 1
                break
            if token.startswith("-") and token != "-":
                index += 1
                if token in value_options and index < len(words):
                    index += 1
                continue
            break
        # ``timeout`` accepts its duration after options; ``env`` accepts
        # assignments after its options.
        if wrapper == "timeout" and index < len(words) and _DURATION_RE.match(words[index]):
            index += 1
        while index < len(words) and _ASSIGNMENT_RE.fullmatch(words[index]):
            index += 1
    return index


def _rm_is_dangerous(words: list[str], *, brace_target: bool = False) -> bool:
    """Whether tokens starting at an ``rm`` invocation force-delete protected paths.

    Args:
        words: Tokens beginning with the ``rm`` command word.
        brace_target: Count a ``{}`` target as protected.  True for a
            ``find -exec``/``-execdir`` payload, where ``{}`` expands to the
            matched paths — the tree-deleting idiom (#191 review).

    Returns:
        True when recursive and force flags are combined with a target under
        root, home, a wildcard, or (when enabled) ``{}``.
    """
    recursive = force = False
    targets: list[str] = []
    end_of_options = False
    for token in words[1:]:
        if end_of_options:
            targets.append(token)
        elif token == "--":
            end_of_options = True
        elif token.startswith("--"):
            name, _, value = token[2:].partition("=")
            enabled = value.lower() not in _FALSE_VALUES
            if name == "recursive":
                recursive = recursive or enabled
            elif name == "force":
                force = force or enabled
        elif token.startswith("-") and token != "-":
            recursive = recursive or "r" in token or "R" in token
            force = force or "f" in token
        else:
            targets.append(token)

    if not (recursive and force):
        return False
    protected = _PROTECTED_RM_TARGETS + (("{}",) if brace_target else ())
    return any(target.startswith(protected) for target in targets)


def _find_exec_payloads(words: list[str]) -> list[list[str]]:
    """Return the command payloads of ``find -exec``/``-execdir`` clauses."""
    payloads: list[list[str]] = []
    index = 0
    while index < len(words):
        if words[index] in ("-exec", "-execdir"):
            payload: list[str] = []
            index += 1
            while index < len(words) and words[index] not in (";", "+"):
                payload.append(words[index])
                index += 1
            if payload:
                payloads.append(payload)
        index += 1
    return payloads


def _command_name(segment: str) -> str | None:
    """Return the basename of the command that actually runs, if any."""
    words = _tokenize(segment)
    command = _skip_command_prefix(words)
    if command >= len(words):
        return None
    return os.path.basename(words[command])


def _segment_is_dangerous_rm(segment: str) -> bool:
    """Whether *segment* contains a dangerous ``rm`` at any command position.

    Covers a plain invocation, one behind a wrapper, and the payload of
    ``find -exec``/``-execdir``, whose command the previous unanchored
    pattern used to catch by accident.

    Args:
        segment: One shell segment (already split on operators).

    Returns:
        True when a dangerous ``rm`` is found.
    """
    words = _tokenize(segment)
    command = _skip_command_prefix(words)
    if command >= len(words):
        return False

    name = os.path.basename(words[command])
    if name == "rm":
        return _rm_is_dangerous(words[command:])
    if name == "find":
        return any(
            _rm_is_dangerous(payload, brace_target=True)
            for payload in _find_exec_payloads(words)
            if os.path.basename(payload[0]) == "rm"
        )
    return False


def _shell_c_payload(words: list[str]) -> str | None:
    """Return the command string of ``sh -c …``, if this is that shape."""
    command = _skip_command_prefix(words)
    if command >= len(words):
        return None
    if os.path.basename(words[command]) not in _SHELLS:
        return None
    rest = words[command + 1 :]
    for index, token in enumerate(rest):
        if token == "-c" and index + 1 < len(rest):
            return rest[index + 1]
    return None


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

    _validate(command, 0)


def _validate(command: str, depth: int) -> None:
    """Run the deny-list checks at recursion *depth* (``sh -c`` payloads).

    Args:
        command: The command string to check.
        depth: Current ``sh -c`` nesting depth.
    """
    # 1. Checks that need the unsplit command
    for pattern, reason in _FULL_COMMAND_PATTERNS:
        if pattern.search(command):
            raise ValueError(f"Dangerous command blocked: {reason}")

    # 2. Segment by shell operators and check each part
    segments = _OPERATOR_SPLIT_RE.split(command)
    for segment in segments:
        stripped = segment.strip()
        if not stripped:
            continue
        if _segment_is_dangerous_rm(stripped):
            raise ValueError(
                "Dangerous command blocked: Recursive forced deletion of "
                "root, home, or wildcard paths"
            )
        command_name = _command_name(stripped)
        if command_name == "eval":
            raise ValueError("Dangerous command blocked: Arbitrary code evaluation")
        if command_name == "exec":
            raise ValueError("Dangerous command blocked: Process replacement via exec")
        payload = _shell_c_payload(_tokenize(stripped))
        if payload is not None and depth < _MAX_SHELL_C_DEPTH:
            _validate(payload, depth + 1)
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
