# bashtool

Shell command execution with built-in safety validation. Zero external dependencies.

## What it does

`BashTool.execute()` runs shell commands via `subprocess.run` with:

- **Safety deny-list** -- 20+ regex patterns block dangerous commands before execution (recursive `rm -rf`, `sudo`, `mkfs`, fork bombs, `git push --force`, etc.)
- **Output truncation** -- stdout/stderr capped at 64 KB to prevent memory exhaustion
- **Timeout** -- configurable wall-clock timeout with clean kill
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

Returns `dict` with keys: `stdout`, `stderr`, `exit_code`, `timed_out`.

Raises `ValueError` if the command matches a dangerous pattern, `FileNotFoundError` if `cwd` doesn't exist.

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
