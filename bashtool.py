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
import posixpath
import re
import shlex
import signal
import subprocess
import sys
import time
from pathlib import Path

__version__ = "0.3.3"

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
    # ``rm`` is judged structurally by ``_segment_is_dangerous_rm``: a regex
    # could not merge split flags and matched ``rm -rf /`` inside quoted
    # arguments (#6).
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
    {
        "sudo",
        "doas",
        "command",
        "builtin",
        "env",
        "nohup",
        "time",
        "nice",
        "timeout",
        "xargs",
        "busybox",
        "toybox",
    }
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
#: Directories whose recursive deletion is catastrophic.  Deeper paths are
#: judged separately: home trees are protected in full, other system
#: subtrees are not, so routine cleanup such as ``rm -rf /tmp/build`` works.
_SYSTEM_DIRS = frozenset(
    {
        "/",
        "/bin",
        "/boot",
        "/dev",
        "/etc",
        "/home",
        "/lib",
        "/lib64",
        "/opt",
        "/proc",
        "/root",
        "/run",
        "/sbin",
        "/srv",
        "/sys",
        "/usr",
        "/var",
    }
)
#: Trees that are not recoverable by reinstalling a package, plus the
#: credential stores, protected *recursively*.  Other system subtrees stay
#: deletable because that is routine cleanup: ``/etc/nginx/cache``,
#: ``/srv/app/out``, ``/var/log/app``, ``/var/tmp/cache`` and ``/tmp/build``
#: are all allowed (#6 review).
_PROTECTED_TREES = (
    "/bin",
    "/boot",
    "/dev",
    "/etc/ssh",
    "/etc/sudoers",
    "/etc/systemd",
    "/lib",
    "/lib32",
    "/lib64",
    "/libx32",
    "/proc",
    "/sbin",
    "/sys",
    "/usr/bin",
    "/usr/lib",
    "/usr/lib32",
    "/usr/lib64",
    "/usr/libx32",
    "/usr/libexec",
    "/usr/sbin",
    "/var/lib",
)
_HOME_PREFIXES = ("/home/", "/root/")
_HOME_VARS = frozenset({"$HOME", "${HOME}"})
_HOME_VAR_PREFIXES = ("$HOME/", "${HOME}/")
#: Characters the shell expands in a path: glob (``*?[``) and brace
#: expansion (``{a,b}``).  Any of them means the deleted set is chosen by
#: the shell, not by the caller of this module.
_WILDCARD_CHARS = "*?[{"
#: POSIX keeps exactly two leading slashes through ``normpath``, but the
#: kernel treats ``//etc`` as ``/etc``, so runs are collapsed first.
_SLASH_RUN_RE = re.compile(r"/{2,}")
#: ``../..`` and deeper: a target made only of parent segments has no
#: knowable depth, so it is treated like ``..``.
_DOT_DOT_ONLY_RE = re.compile(r"(?:\.\.)(?:/\.\.)*")
_MAX_SHELL_C_DEPTH = 4


def _as_text(value: str | bytes | None) -> str:
    """Decode a captured stream value, tolerating the bytes form."""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value or ""


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


def _rm_is_dangerous(
    words: list[str],
    *,
    brace_target: bool = False,
    appended_targets: bool = False,
) -> bool:
    """Whether tokens starting at an ``rm`` invocation force-delete protected paths.

    Args:
        words: Tokens beginning with the ``rm`` command word.
        brace_target: Count a ``{}`` target as protected.  True for a
            ``find -exec``/``-execdir`` payload, where ``{}`` expands to the
            matched paths — the tree-deleting idiom (#191 review).
        appended_targets: The operands are supplied by a wrapper rather than
            written here (``xargs``).  ``find / | xargs rm -rf`` then has no
            safe reading, since the caller cannot see what is deleted
            (#6 review).

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
    if appended_targets:
        return True
    return any(_target_is_protected(target, brace_target=brace_target) for target in targets)


def _is_under(path: str, tree: str) -> bool:
    """Whether *path* is *tree* itself or inside it, on a path boundary."""
    return path == tree or path.startswith(tree + "/")


def _wildcard_index(target: str) -> int:
    """Index of the first shell-expanded character in *target*, or ``-1``."""
    positions = [target.find(char) for char in _WILDCARD_CHARS if char in target]
    return min(positions, default=-1)


def _target_is_protected(target: str, *, brace_target: bool = False) -> bool:
    """Whether deleting *target* recursively and forcibly is catastrophic.

    Only the paths whose loss takes a machine or a home directory with it
    are protected — root, the system directory names themselves, the trees
    that cannot be reinstalled (``/usr/bin``, ``/lib*``, ``/boot``, …),
    anything under a home directory, and the shell spellings that expand to
    those (``//etc``, ``./``, ``../..``, ``/et?``, ``/{etc,usr}``).  A
    concrete path elsewhere (``/tmp/build``, ``/srv/app/out``,
    ``/etc/nginx/cache``) is ordinary cleanup and stays allowed (#6).

    Args:
        target: One ``rm`` operand, after shell dequoting.
        brace_target: Treat ``{}`` as protected (a ``find -exec`` payload,
            where it expands to the matched paths).

    Returns:
        True when the target is protected.
    """
    if brace_target and target == "{}":
        return True

    # ``//etc`` is ``/etc`` to the kernel, but POSIX keeps exactly two
    # leading slashes through ``normpath``; collapse runs before comparing.
    target = _SLASH_RUN_RE.sub("/", target)
    if target.startswith("~"):
        return True
    if target in _HOME_VARS or target.startswith(_HOME_VAR_PREFIXES):
        return True

    wildcard_at = _wildcard_index(target)
    if wildcard_at >= 0:
        if target.startswith("/") and any(
            char in target.lstrip("/").split("/", 1)[0] for char in _WILDCARD_CHARS
        ):
            # ``/et?``, ``/tm*`` and ``/{etc,usr}`` glob the root level: the
            # shell chooses the deleted set, so the pattern is refused.
            return True
        raw_prefix = target[:wildcard_at].rstrip("/")
        # Normalise so ``/tmp/../*`` is judged as ``/*``.
        prefix = posixpath.normpath(raw_prefix) if raw_prefix else ""
        if (
            prefix in ("", ".", "..", "/")
            or prefix.startswith("~")
            or prefix in _HOME_VARS
            or prefix in _SYSTEM_DIRS
            or prefix.startswith(_HOME_PREFIXES)
            or any(_is_under(prefix, tree) for tree in _PROTECTED_TREES)
        ):
            return True
        # Judge the literal prefix: ``/var/log/app/*`` deletes a subtree of
        # an application directory, which is cleanup, not catastrophe.
        target = prefix

    normalized = posixpath.normpath(target)
    if normalized in (".", "..") or _DOT_DOT_ONLY_RE.fullmatch(normalized):
        return True
    return (
        normalized in _SYSTEM_DIRS
        or normalized.startswith(_HOME_PREFIXES)
        or any(_is_under(normalized, tree) for tree in _PROTECTED_TREES)
    )


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


def _segment_is_dangerous_rm(segment: str, depth: int = 0) -> bool:
    """Whether *segment* contains a dangerous ``rm`` at any command position.

    Covers a plain invocation, one behind a wrapper, and the payload of
    ``find -exec``/``-execdir`` — including a wrapper around the payload
    command (``find / -exec sudo rm -rf {} +``) and a shell payload
    (``find . -exec sh -c 'rm -rf /' +``).

    Args:
        segment: One shell segment (already split on operators).
        depth: Current ``sh -c`` nesting depth, so a shell payload found
            inside ``-exec`` cannot restart the recursion budget.

    Returns:
        True when a dangerous ``rm`` is found.
    """
    words = _tokenize(segment)
    command = _skip_command_prefix(words)
    if command >= len(words):
        return False

    name = os.path.basename(words[command])
    if name == "rm":
        # ``xargs rm -rf`` has no operands of its own; the wrapper supplies
        # whatever the pipeline produced, so the call cannot be judged safe.
        return _rm_is_dangerous(
            words[command:],
            appended_targets=any(os.path.basename(word) == "xargs" for word in words[:command]),
        )
    if name == "find":
        for payload in _find_exec_payloads(words):
            start = _skip_command_prefix(payload)
            if start >= len(payload):
                continue
            if os.path.basename(payload[start]) == "rm" and _rm_is_dangerous(
                payload[start:], brace_target=True
            ):
                return True
            shell_payload = _shell_c_payload(payload)
            if shell_payload is not None and depth < _MAX_SHELL_C_DEPTH:
                _validate(shell_payload, depth + 1)
    return False


def _read_balanced(command: str, start: int) -> tuple[str, int]:
    """Return the body of a ``$( … )`` starting at *start* and the next index."""
    depth = 1
    index = start
    while index < len(command):
        char = command[index]
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return command[start:index], index + 1
        index += 1
    return command[start:], len(command)


def _command_substitutions(command: str) -> list[str]:
    """Return the bodies of ``$( … )`` and backtick substitutions.

    A substitution body is a command in its own right, so it is validated
    like one; a ``shlex`` tokenizer cannot see it (#6 review).  Quoting is
    tracked the way the shell does it: single quotes disable substitution,
    double quotes allow it, and a quote character inside the other kind of
    quote is literal (so ``echo "it's $(date)"`` still expands).

    Args:
        command: One shell segment.

    Returns:
        The raw command strings of every substitution, in source order.
    """
    bodies: list[str] = []
    index = 0
    in_single_quote = False
    in_double_quote = False
    while index < len(command):
        char = command[index]
        if in_single_quote:
            in_single_quote = char != "'"
            index += 1
            continue
        if char == "'" and not in_double_quote:
            in_single_quote = True
            index += 1
            continue
        if char == '"':
            in_double_quote = not in_double_quote
            index += 1
            continue
        if char == "\\":
            index += 2
            continue
        if char == "$" and command.startswith("$(", index):
            body, index = _read_balanced(command, index + 2)
            bodies.append(body)
            continue
        if char == "`":
            end = command.find("`", index + 1)
            if end == -1:
                break
            bodies.append(command[index + 1 : end])
            index = end + 1
            continue
        index += 1
    return bodies


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
        if _segment_is_dangerous_rm(stripped, depth):
            raise ValueError(
                "Dangerous command blocked: Recursive forced deletion of "
                "root, home, or wildcard paths"
            )
        if depth < _MAX_SHELL_C_DEPTH:
            # ``$(rm -rf /)`` and ``` `rm -rf /` ``` run just as surely as
            # ``sh -c ...``; validate each body as its own command.
            for body in _command_substitutions(stripped):
                _validate(body, depth + 1)
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

    # Wait for the *group*, not the shell: the shell exits on SIGTERM at
    # once, which used to end the grace period after ~20 ms and deny a
    # grandchild the cleanup time the grace exists for (#10).  ``poll()``
    # reaps the shell so its zombie cannot keep the group alive.
    deadline = time.monotonic() + grace
    while time.monotonic() < deadline:
        proc.poll()
        try:
            os.killpg(pgid, 0)
        except ProcessLookupError:
            break
        time.sleep(0.02)

    # Something may ignore SIGTERM; kill the group unconditionally rather
    # than trusting any member's exit.
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
                # Reap the killed tree and collect what it wrote.  A
                # descendant that left the session (setsid) keeps the pipe
                # open and cannot be killed by the group signal, so bound
                # this wait tightly instead of stalling for seconds (#10).
                stdout, stderr = proc.communicate(timeout=1)
            except subprocess.TimeoutExpired as exc:
                # Keep whatever was captured before the deadline instead of
                # discarding output the caller needs (#188).  In text mode
                # the timeout path still hands the captured chunks back as
                # bytes, so decode rather than dropping them (#10).
                stdout = _as_text(exc.stdout)
                stderr = _as_text(exc.stderr)
            raise CommandTimeoutError(command, timeout, stdout or "", stderr or "") from None

        return {
            "stdout": truncate(stdout or ""),
            "stderr": truncate(stderr or ""),
            "exit_code": proc.returncode,
            "timed_out": False,
        }
