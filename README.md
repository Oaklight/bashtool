# bashtool

Shell command execution with built-in safety validation. Zero external dependencies.

## What it does

`BashTool.execute()` runs shell commands via `subprocess.run` with:

- **Safety deny-list** -- 20+ regex patterns block dangerous commands before execution (recursive `rm -rf`, `sudo`, `mkfs`, fork bombs, `git push --force`, etc.)
- **Output truncation** -- stdout/stderr capped at 64 KB to prevent memory exhaustion
- **Timeout** -- configurable wall-clock timeout that kills the whole process tree
  (the shell *and* whatever it started) and raises `CommandTimeoutError`
- **Working directory** -- optional `cwd` parameter with existence validation

## Usage

### Direct import

```python
from bashtool import BashTool

result = BashTool.execute("ls -la")
print(result["stdout"])
# result = {"stdout": "...", "stderr": "", "exit_code": 0, "timed_out": False}
```

### As a git submodule

```bash
git submodule add https://github.com/Oaklight/bashtool.git _vendor/bashtool
```

```python
from _vendor.bashtool import BashTool

result = BashTool.execute("echo hello", timeout=30, cwd="/tmp")
```

### Safety validation standalone

```python
from bashtool import validate_command

validate_command("ls -la")           # OK
validate_command("rm -rf /")         # raises ValueError
validate_command("sudo apt update")  # raises ValueError
```

## API

### `BashTool.execute(command, timeout=120, cwd=None) -> dict`

Execute a shell command and return its output.

- **command** (`str`): Shell command string.
- **timeout** (`int`): Max seconds before kill. Default 120.
- **cwd** (`str | None`): Working directory. Default: current process cwd.

Returns `dict` with keys: `stdout`, `stderr`, `exit_code`, `timed_out` (`timed_out` is
always `False` on a returned dict -- a timeout raises instead).

Raises `ValueError` if the command matches a dangerous pattern, `FileNotFoundError` if
`cwd` doesn't exist, and `CommandTimeoutError` when the timeout expires. The timeout
error carries the partial `stdout` / `stderr` written before the kill, plus
`exit_code == -1` and `to_dict()` for callers that want the old result shape:

```python
try:
    result = BashTool.execute("sleep 10", timeout=1)
except CommandTimeoutError as exc:
    print(exc.stdout, exc.exit_code, exc.to_dict())
```

### `CommandTimeoutError`

Raised when a command exceeds its timeout. Subclasses `TimeoutError`; fields:
`command`, `timeout`, `stdout`, `stderr`, `exit_code` (`-1`), `timed_out` (`True`),
and `to_dict()`.

### `validate_command(command) -> None`

Check a command against the deny list. Raises `ValueError` if blocked.

### `truncate(text, max_bytes=65536) -> str`

Truncate text to at most `max_bytes` UTF-8 bytes. Appends `[output truncated]` marker if clipped.

### `DANGER_PATTERNS`

The deny-list itself, as `list[tuple[re.Pattern[str], str]]`. Importable for extension or inspection.

## Blocked patterns

| Category | Examples |
|----------|----------|
| Destructive filesystem | `rm -rf /`, `mkfs`, `dd if=`, `> /dev/sd*` |
| Privilege escalation | `sudo`, `su -`, `chmod -R 777 /`, `chown -R` |
| Code injection | `eval`, `exec` |
| Fork bomb | `:(){ :\|:& };:` |
| Git destructive | `git push --force`, `git reset --hard`, `git clean -f` |
| System control | `shutdown`, `reboot`, `halt`, `kill -9 1` |
| Pipe-to-shell | `curl ... \| bash`, `wget ... \| sh` |

## License

MIT
