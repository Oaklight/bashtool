# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

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
