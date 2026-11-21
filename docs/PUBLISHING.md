# Building and publishing

## Local build

Use Python 3.10 or newer from a clean checkout:

```console
python -m pip install --upgrade build twine
python -m build --sdist --wheel
python -m twine check --strict dist/*
```

Use the [release checklist](RELEASE_CHECKLIST.md) before tagging a version.

The GitHub Actions workflow at `.github/workflows/release.yml` runs those checks for version tags beginning with `v` and stores the distributions as a workflow artifact. A tag push builds artifacts but does not publish to a package index.

## PyPI Trusted Publisher setup

Publishing is intentionally a separate, manually dispatched workflow step. Before using it:

1. Create or claim the `asustor-nas-cli` project on PyPI.
2. In PyPI's project publishing settings, add a GitHub Actions Trusted Publisher for repository `popuchoco/asustor-nas-cli`, workflow `release.yml`, and GitHub environment `pypi`.
3. In GitHub repository settings, create the `pypi` environment and enable any desired approval rule.
4. Push a reviewed `vX.Y.Z` tag. Confirm the release workflow built and checked both artifacts.
5. Run `Release package` with that tag selected and set `publish` to `true`.

The workflow uses PyPI's OIDC Trusted Publishing permission and does not require a PyPI API token or repository secret. A tag push alone never publishes. Publishing to PyPI makes the package publicly downloadable; review the source and package contents before enabling the publish input.

## Installing after publication

The package requires Python 3.10+ and has no runtime dependencies. Install into an isolated command environment with pipx:

```console
python -m pip install --user pipx
python -m pipx ensurepath
pipx install asustor-nas-cli
adm --help
```

On Windows PowerShell, the package can also be installed into the selected Python environment:

```powershell
py -m pip install asustor-nas-cli
adm --help
```

## Offline wheel installation

On an internet-connected computer with the target Python version:

```console
python -m pip download --only-binary=:all: --no-deps --dest wheelhouse asustor-nas-cli==X.Y.Z
```

Transfer the wheelhouse to the offline computer, then install:

```console
python -m pip install --no-index --find-links ./wheelhouse asustor-nas-cli==X.Y.Z
```

The package is pure Python. The OpenSSH client is supplied by the operating system and is not bundled in the wheel.
