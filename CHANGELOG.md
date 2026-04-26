# Changelog

## 1.2.0 - 2026-04-25

- added profile registry and premium Rich banner variants: `matrix`, `stealth`, `shield`, and `enterprise`
- improved CLI UX around `scan`, `modules`, `explain`, `version`, and config-driven runs
- added `python -m secaudit` support
- fixed flat `secaudit.toml` parsing so the generated config is valid and loadable
- tightened config boolean parsing for `banner` / `no_banner` and `color` / `no_color`
- made terminal output respect configured output formats
- improved module listing and explain output for human-friendly documentation
- added CLI/config regression tests and a project `CODE_OF_CONDUCT.md`
- fixed the scheduled GitHub Actions workflow to install the package before invoking `secaudit`
- redesigned interactive mode into a hacker-style Control Deck with `Blitz`, `Ghost`, `Blacksite`, and `Precision Scan`
- cut extra interactive prompts so preset scans can launch with minimal operator input

## 1.1.0 - 2026-04-25

- refactored the original monolithic core into focused modules:
  `context`, `http`, `engine`, `models`, `scoring`, `diff`, `registry`, `config`
- introduced profile-aware CLI with `scan`, `modules`, `explain`, `init`, and `compare`
- added `secaudit.toml` configuration support
- moved packaging to `pyproject.toml`
- added pytest, ruff, mypy, and CI workflows
- improved JavaScript same-origin classification to account for ports
- improved email/DNS lookup reporting so lookup failures are no longer reported as missing records
- added compatibility shims to preserve older `secaudit.core` and `secaudit.reporter` imports
