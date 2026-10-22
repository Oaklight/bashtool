# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [0.3.3] - 2026-10-22

### Fixed

- `rm` targets are judged structurally instead of by absolute-path shape, so routine cleanup
  such as `rm -rf /tmp/build` or `rm -rf /srv/app/cache` is allowed again (#6). Protected
  targets are the root; the system directory names themselves (`/etc`, `/var`, `/home`, …);
  the trees that cannot be reinstalled (`/bin`, `/sbin`, `/lib*`, `/usr/bin`, `/usr/lib*`,
  `/boot`, `/dev`, `/proc`, `/sys`, `/var/lib`, `/etc/ssh`, `/etc/sudoers`, `/etc/systemd`);
  `$HOME`/`~`/`${HOME}` and anything under `/home/` or `/root/`; `.`, `..` and any target made
  only of parent segments (`../..`); and wildcard sweeps over any of those. Application
  subtrees stay deletable (`/etc/nginx/cache`, `/opt/app/out`, `/var/log/app/*`,
  `/var/tmp/cache`, `/tmp/*`). Only recursive-and-force deletion is refused, as before.
- Spellings the kernel and the shell treat as those paths are normalised before judging:
  `//etc` and `//` (a run of slashes is collapsed), trailing slashes (`./`, `../`, `.//`),
  and glob/brace forms whose first component is expanded by the shell (`/et?`, `/et[c]`,
  `/tm?`, `/{etc,usr}`). All of these were allowed by the first version of this rewrite,
  and `//etc` was additionally blocked by 0.3.2.
- A command substitution body is now validated as a command of its own
  (`$(rm -rf /)`, `` `rm -rf /` ``, `X=$(rm -rf /)`), which the structural `rm` check could
  not see because `shlex` does not tokenise it. Text inside single quotes is still ignored.
- Command separators are recognised only outside quotes: `;`, `&`, `&&`, `||`, `|` and a
  newline now end a command, so `echo hi & rm -rf /` and `echo hi` followed by a newline and
  `rm -rf /` are both caught, while a quoted multi-line commit message containing the same
  text stays allowed. Command-like text after a single `&` and after a newline was previously
  inspected as one segment and missed.
- Clustered shell short flags are unwrapped: `bash -lc 'rm -rf /'` and `sh -ec 'rm -rf /'`
  are now blocked like `bash -c '…'`. Only a token starting with a single `-` that contains
  `c` is treated as the shell's `-c`.
- Compound statements no longer hide the command word: leading group characters (`(`, `{`,
  `!`) are stripped from a segment and the shell keywords that can precede a command
  (`then`, `do`, `else`, `elif`, `if`, `while`, `until`, `fi`, `done`, `esac`, `!`) are
  skipped, so `( rm -rf / )`, `{ rm -rf /; }`, `if …; then rm -rf /; fi`,
  `while …; do rm -rf /; done`, `! rm -rf /`, `echo hi && (rm -rf /)` and
  `sh -c '{ rm -rf /; }'` are blocked. `{}` inside a `find -exec` payload is untouched
  because only edge characters are stripped.
- Case statements and function definitions no longer hide their bodies: a leading
  `name()` header is removed, and a `case <word> in` header plus each arm's `pattern)`
  prefix, so `case x in a) rm -rf /;; esac` and `f() { rm -rf /; }` are blocked.
- Backslash-newline continuations are joined before the command is tokenised, so
  `rm -rf` followed by a continuation and `/` is judged as `rm -rf /`.
- GNU long options are matched by unique prefix, so `rm --rec -f`, `rm --recur -f` and
  `rm --f -r` are treated like `rm --recursive --force`, including with
  `--no-preserve-root`.
- `find -exec` payloads are unwrapped before the `rm` check, so
  `find / -exec sudo -u root rm -rf {} +` and `find / -exec env -i rm -rf {} +` are blocked,
  and a shell payload inside `-exec` (`find . -exec sh -c 'rm -rf /' +`) is validated
  recursively.
- `xargs rm -rf` without operands is blocked: the wrapper supplies whatever the pipeline
  produced (`find / | xargs rm -rf`), so the call has no safe reading.
- Dangerous-looking text inside a quoted argument no longer trips the deny list, because `rm`
  is only inspected in command position. `echo 'rm -rf /'` and commit messages mentioning
  `exec` run normally.

### Changed

- `busybox` and `toybox` joined the wrapper set, so `busybox rm -rf /` is unwrapped and judged
  like `rm -rf /`.

### Known limits

- Relative spellings of a protected tree (`rm -rf usr/lib`, `rm -rf home/user`) are not
  blocked, because the deny list has no working directory to resolve them against. Pass an
  absolute path to have it judged.
- A target whose protected-ness depends on runtime values (`rm -rf "$VAR"`) cannot be
  resolved statically and is allowed; so is `{}` outside a `find -exec` payload.

## [0.3.2] - 2026-10-22

### Fixed

- The SIGTERM grace period now watches the whole process group instead of the shell. With
  `shell=True` the shell exits on SIGTERM immediately, so the old loop ended after ~20 ms and
  SIGKILLed children that were still cleaning up in their TERM handler (#10).
- When a descendant leaves the session (`setsid`, a daemonising server) it keeps the stdout pipe
  open. The recovery wait is now 1 second instead of 5, and output captured before the deadline is
  kept rather than replaced with `""`. In text mode the timeout path hands that output back as
  bytes; it is decoded now. Such a descendant cannot be killed with the process-group signal —
  documented rather than silently waited on.

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
- `find -exec` / `-execdir` payloads are validated as commands of their own, and a `{}` target
  counts as protected when recursive and force are combined. This restores blocking of
  `find / -exec rm -rf {} +`, which the anchored `exec` pattern would otherwise have missed.
- Wrapper chains are parsed before the command word is judged: `sudo -u root rm -r -f /x`,
  `env -i rm …`, `nice -n 5 rm …`, `timeout 5 rm …` and `xargs rm …` are blocked, as are
  `env exec …`, `nohup exec …` and `time exec …`.
- Shell `-c` payloads are validated recursively (bounded to four levels), so
  `sh -c 'rm -r -f /x'` and `bash -c 'exec …'` are blocked; previously only the clustered
  spelling was caught, by the old `rm` regex.
- `--recursive=false` (and other false spellings) no longer counts as recursive.

Known limit, unchanged: an interpreter's `-c` payload (`python -c …`) is not parsed, and
`sh -c` recursion stops at four levels. The deny list is a speed bump, not a sandbox.

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
