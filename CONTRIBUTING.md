# Contributing

## Development setup

Use Python 3.10 or newer and the system OpenSSH client for NAS integration checks. The runtime package has no third-party Python dependencies.

```console
python -m pip install -e .
python -m unittest discover -s tests -v
adm --help
```

Pull requests and pushes to `main` run the same unit suite on Python 3.10–3.13 plus Ruff. Run `ruff check .` locally before submitting when Ruff is installed.

Do not run mutating platform-module commands on a production NAS as part of ordinary tests. Unit tests should cover their command generation, compatibility gates, backup validation and cancellation behavior with fixtures/mocks. Live module operations require hardware the reference driver explicitly supports, a recovery path, and a local state backup.

## Change expectations

- Keep remote commands fixed and allowlisted; never interpolate arbitrary shell input.
- Preserve the read-only MCP contract.
- Add or update report schemas and `docs/CLI_SPEC.md` when output contracts change.
- Update `docs/COMPATIBILITY.md` only for models/versions actually verified by this CLI; label reference-only evidence.
- Describe risks and recovery behavior for any new hardware mutation.
- Do not commit NAS credentials, SSH keys, serial numbers, private incident reports, or platform backup snapshots.
- Do not add copied code or binaries from reference projects without reviewing their licenses and explicitly documenting the actual reuse.

## Pull requests

Include the user-visible behavior, safety impact, compatibility evidence, tests run, and any hardware checks that were not possible. Keep changes focused and update the English and Traditional Chinese README sections when user-facing features change.
