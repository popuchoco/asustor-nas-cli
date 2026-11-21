# Release checklist

## Before a version tag

- [ ] Set `src/asustor_nas_cli/__init__.py` to the release version.
- [ ] Add a dated `CHANGELOG.md` entry using `## X.Y.Z — YYYY-MM-DD`; list user-visible changes, safety impacts, and compatibility limits.
- [ ] Update both README files, `docs/CLI_SPEC.md`, schemas, and compatibility notes for every changed behavior.
- [ ] Run `python -m unittest discover --start-directory tests --verbose` and `ruff check .`.
- [ ] Build and inspect package metadata: `python -m build --sdist --wheel` and `python -m twine check --strict dist/*`.
- [ ] Confirm CI's package-build job installed the wheel and ran `adm --version`; confirm the release tag workflow matched the installed command version to the tag.
- [ ] Review `install.md` commands for Windows, macOS, and Ubuntu and confirm they install the intended tagged version without claiming that an unpublished PyPI package is available.
- [ ] Review the staged diff for real NAS addresses, usernames/passwords, SSH keys, serial numbers, raw incident output, and local backup files.
- [ ] Check that generated report examples validate against every published JSON Schema.
- [ ] Confirm that read-only MCP tools remain annotated read-only and that mutating module operations stay outside MCP.
- [ ] Verify compatibility claims against this CLI's own evidence. Do not turn reference-project reports or code review into live-device claims.
- [ ] Require all GitHub Actions checks on the commit to pass before tagging.
- [ ] Review pending Dependabot pull requests and confirm the supported Python floor and workflow action versions against upstream maintenance status.

## Tag and publish

- [ ] Push the reviewed commit to `main`.
- [ ] Create and push an annotated `vX.Y.Z` tag pointing at that commit.
- [ ] Confirm the release workflow built the sdist and wheel and passed `twine check`.
- [ ] Review the artifact contents and metadata before any package-index publication.
- [ ] PyPI publication is a separate manual workflow dispatch. Confirm the `pypi` GitHub Environment and PyPI Trusted Publisher configuration first.
- [ ] Record which compatibility checks were unavailable, including the absence of a Linux 6.1+ ASUSTOR test unit.

A tag push builds distributions only. It does not publish to PyPI. See [publishing and installation](PUBLISHING.md) for setup and commands.
