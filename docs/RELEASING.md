# Releasing agentvuln

The `agentvuln` PyPI name is unclaimed (verified 2026-05-03). The first
release will register it.

## One-time setup
1. Create an account at https://pypi.org/account/register/.
2. Create a project-scoped API token at https://pypi.org/manage/account/token/.
   - Scope: "Entire account" for the very first upload (you can re-scope to
     just `agentvuln` after `0.1.0` lands).
3. Save it locally:
   ```
   pip install --upgrade twine
   ```
   and put the token in `~/.pypirc`:
   ```ini
   [pypi]
   username = __token__
   password = pypi-XXXXXXXX...
   ```
4. (Optional, recommended) Configure **Trusted Publishing** so future
   releases ship from GitHub Actions without a long-lived token:
   https://docs.pypi.org/trusted-publishers/

## Cutting a release
From a clean working tree on `main`:

```bash
# 1. Bump the version in pyproject.toml and agentvuln/__init__.py.
# 2. Update CHANGELOG.md with the new version + date.
# 3. Commit.
git commit -am "Release v0.1.0"

# 4. Tag and push.
git tag -a v0.1.0 -m "v0.1.0"
git push origin main --tags

# 5. Build.
rm -rf dist build
python -m build

# 6. Sanity check the wheel.
twine check dist/*

# 7. Upload.
twine upload dist/*
```

Within a minute, `pip install agentvuln` will work for everyone.

## After the first upload
- Tighten the API token to scope `agentvuln` only.
- Switch to Trusted Publishing and delete the token entirely.
- Add a `release.yml` workflow that runs `python -m build` + `pypa/gh-action-pypi-publish@release/v1` on every `v*` tag.
