# Release Process

This document outlines how to publish a new release of openrecon.

## Versioning

openrecon follows [Semantic Versioning](https://semver.org/):

- **MAJOR**: breaking changes to CLI, config, or graph schema
- **MINOR**: new collectors, features, or report sections
- **PATCH**: bug fixes, documentation, and minor improvements

## Pre-release Checklist

Before tagging a release, verify:

- [ ] All tests pass: `make test`
- [ ] Lint is clean: `make lint`
- [ ] CHANGELOG.md is updated with the new version's entries
- [ ] Version in `pyproject.toml` is bumped
- [ ] README.md is accurate (install steps, feature list, badges)
- [ ] No secrets or credentials in the codebase
- [ ] `make tools` still works (or documents the change)

## Release Steps

### 1. Update the changelog

Add a new section to `CHANGELOG.md`:

```markdown
## [0.2.0] - YYYY-MM-DD

### Added
- New `cmdi` collector for OS command injection detection
- New `lfi` collector for path traversal detection

### Fixed
- Crawler no longer crashes on progress events
- Port scanner now scans in-scope hostnames, not just IPs

### Changed
- Reduced false positives in command injection detection
```

### 2. Bump the version

Edit `pyproject.toml`:

```toml
version = "0.2.0"
```

### 3. Commit and tag

```bash
git add -A
git commit -m "chore: release 0.2.0"
git tag -a v0.2.0 -m "openrecon 0.2.0"
git push origin main --tags
```

### 4. Build and publish

```bash
python -m build
python -m twine upload dist/*
```

Or let the GitHub Actions workflow handle it automatically when a release is published.

### 5. Create a GitHub Release

1. Go to [Releases](https://github.com/kohryan/openrecon/releases)
2. Click "Draft a new release"
3. Choose the tag `v0.2.0`
4. Title: `openrecon 0.2.0`
5. Paste the changelog section as the description
6. Attach the built `dist/*` files (optional, PyPI has them)
7. Publish

## Automated Publishing

The `.github/workflows/publish.yml` workflow triggers when a release is published on GitHub. It:

1. Builds the package
2. Publishes to PyPI using OIDC trusted publishing (no API token needed)

To enable trusted publishing:

1. Go to [pypi.org/manage/account/publishing](https://pypi.org/manage/account/publishing/)
2. Add a new pending publisher:
   - Project name: `openrecon`
   - Owner: `kohryan`
   - Workflow name: `publish.yml`
   - Environment: `pypi`

## Post-release

- Announce in discussions or social channels if applicable
- Update any external documentation
- Close related issues and milestones
