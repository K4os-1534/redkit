## Summary

What does this PR change and why?

## Type of change

- [ ] Bug fix (non-breaking)
- [ ] New module or feature (non-breaking)
- [ ] Breaking change (fix or feature that changes existing behaviour/APIs)
- [ ] Documentation only

## Checklist

- [ ] `pytest` passes locally (all tests, not just the new ones)
- [ ] Tests added/updated for the change
- [ ] `ruff check src tests` and `ruff format --check src tests` pass
- [ ] `mypy` passes
- [ ] [CHANGELOG.md](../CHANGELOG.md) updated (under "Unreleased")
- [ ] For new modules: honest severities, `self.http_client()` used (no raw requests), no plaintext secrets in logs, module documented in README table

## Authorized-use statement

- [ ] This change keeps RedKit strictly within authorized security testing use (no DoS, no mass targeting, no unauthorized-access capability).
