# Contributing

## Development setup

Use Python 3.11 or newer and the system OpenSSH client for NAS integration checks. The runtime package has no third-party Python dependencies.

```console
python -m pip install -e '.[test]'
python -m unittest discover -s tests -v
adm --help
```

Pull requests and pushes to `main` run unit and Draft 2020-12 JSON Schema validation on Python 3.11–3.14, Ruff, and package-install checks on Windows and macOS using Python 3.11 and 3.14. Install the `test` extra to run schema tests locally. Run `ruff check .` locally before submitting when Ruff is installed.

Do not run mutating platform-module commands on a production NAS as part of ordinary tests. Unit tests should cover their command generation, compatibility gates, backup validation and cancellation behavior with fixtures/mocks. Live module operations require hardware the reference driver explicitly supports, a recovery path, and a local state backup.

## Change expectations

- Keep remote commands fixed and allowlisted; never interpolate arbitrary shell input.
- Preserve the read-only MCP contract.
- Add or update report schemas and `docs/CLI_SPEC.md` when output contracts change.
- Update `docs/COMPATIBILITY.md` only for models/versions actually verified by this CLI.
- Add a dated changelog entry for every user-visible change using `## X.Y.Z — YYYY-MM-DD`; include behavior, safety, and compatibility effects.
- Update the English and Traditional Chinese README files and `docs/TROUBLESHOOTING.md` for user-facing changes.
- Describe risks and recovery behavior for any new hardware mutation.
- Do not commit NAS credentials, SSH keys, serial numbers, private incident reports, or platform backup snapshots.
- Do not add copied code or binaries from reference projects without reviewing their licenses and explicitly documenting the actual reuse.
- List external software or technical sources only when the project actually uses them as a dependency, copied source/binary, workflow action, or implemented integration target. Do not list projects consulted only as design references.
- Redact real NAS addresses and login material from commits, fixtures, documentation, examples, and logs.
- Keep the weekly Dependabot pull requests for GitHub Actions and Python package metadata reviewed; check the official Python support schedule when changing the supported-version floor.

## Pull requests

Include the user-visible behavior, safety impact, compatibility evidence, tests run, and any hardware checks that were not possible. Keep changes focused and update the English and Traditional Chinese README sections when user-facing features change.

Use the [release checklist](docs/RELEASE_CHECKLIST.md) before tagging. A GitHub release tag builds distributions; it does not publish to PyPI by itself.
