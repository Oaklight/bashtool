# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [0.3.1] - 2026-10-22

### Fixed

- `eval` and `exec` are only blocked when they are the invoked command. The previous unanchored
  patterns refused routine work such as `find . -exec wc -l {} +`, `grep -rn eval src/` and
  `echo done > eval.txt`.
- `rm` flags are normalised before the dangerous-delete check, so separated and long-form
  spellings are treated like the clustered one: `rm -r -f /x`, `rm -f -r /x`,
  `rm --recursive --force /x` and `rm -Rf /x` are now blocked alongside `rm -rf /x`.
  Recursive deletes of local paths (`rm -rf ./build`) remain allowed.
- Command segments are now split on a single `|` as the comment always claimed, so per-segment
  checks also see the right-hand side of a pipe (for example `echo ok | rm -rf /x`).
- The fork bomb check moved to a whole-command pass, so splitting on `|` cannot tear it apart.

## [0.3.0] - 2026-10-22

### Changed

- **Breaking:** `BashTool.execute()` now raises `CommandTimeoutError` on timeout instead of
  returning `{"timed_out": True, "exit_code": -1}` alongside successful results. A killed
  command is a failure, and returning it as data let MCP hosts report `isError: false` so a
  model reasoned from empty output. The exception subclasses `TimeoutError` and carries
  `command`, `timeout`, `stdout`, `stderr`, `exit_code` (`-1`), `timed_out` (`True`) and
  `to_dict()` for callers that want the previous shape.
- Commands now run in their own session (`start_new_session=True`) and a timeout kills the
  whole process group (SIGTERM, then SIGKILL after a grace period). Previously only the
  `shell=True` child was killed, leaving background children such as `sleep 300 &` running.
- Partial output written before the kill is preserved on the exception instead of being
  discarded.

## [0.2.0] - 2026-08-04

### Added

- `BASHTOOL_UNSAFE` environment variable to disable deny-list validation for trusted deployment environments
- `sudo` commands (e.g., `sudo apt update`) now pass validation — `sudo` is a permission mechanism, not a destructive operation. Dangerous commands like `sudo rm -rf /` are still caught by their own patterns

### Changed

- `UNSAFE_MODE` module-level constant replaced with dynamic `_is_unsafe_mode()` check — reads the environment variable on each `validate_command()` call instead of once at import time
- Warn-once semantics preserved: stderr warning printed only on first unsafe-mode invocation

### Removed

- **Breaking:** `UNSAFE_MODE` removed from public API (`__init__.py` re-exports). Use the `BASHTOOL_UNSAFE` environment variable directly

## [0.1.0] - 2026-06-25

### Added

- Initial release: `BashTool.execute()` for shell command execution via `subprocess.run`
- Static deny-list validation with 17 regex patterns covering destructive filesystem ops, privilege escalation, code injection, fork bombs, git destructive operations, and system control commands
- Pipe-to-shell detection (`curl ... | bash`)
- Shell operator splitting (`&&`, `||`, `;`) for per-segment validation
- Output truncation at 64 KB to prevent memory exhaustion
- Zero external dependencies — Python standard library only
- `__init__.py` re-export facade for git submodule usage

[0.2.0]: https://github.com/Oaklight/bashtool/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/Oaklight/bashtool/releases/tag/v0.1.0
