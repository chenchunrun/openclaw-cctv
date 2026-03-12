<!-- SPDX-License-Identifier: Apache-2.0 -->
# Contributing to OpenClawCCTV

Thanks for contributing.

## Scope

This repository focuses on defensive monitoring and policy enforcement for OpenClaw on macOS.

- Keep changes aligned with non-root threat mitigation
- Keep fail-closed behavior intact
- Do not introduce hidden persistence or offensive capability

## Development Setup

```bash
git clone <your-fork-or-repo>
cd openclawcctv
bash -n install.sh uninstall.sh harden_openclaw.sh gen_auth_token.sh
python3 -m py_compile cctv.py watchdog.py logger.py
```

## Coding Rules

- Prefer simple Python 3 stdlib and shell scripts
- Keep platform target explicit (macOS)
- Preserve SPDX headers in files
- Keep secret values out of logs and examples

## Pull Request Checklist

- [ ] Threat model impact explained in PR description
- [ ] Backward compatibility impact documented
- [ ] Security behavior tested (dangerous command blocked / token accepted)
- [ ] `bash -n` and `py_compile` checks passed
- [ ] README or SECURITY docs updated when behavior changes

## Commit Style

Use clear, scoped commits, for example:

- `fix(logger): serialize hash-chain writes across processes`
- `feat(policy): enforce env-only auth token transport`
- `docs(readme): add one-click hardening instructions`

## Reporting Security Issues

Do **not** open public issues for exploitable vulnerabilities.

Please follow the process in [`SECURITY.md`](./SECURITY.md#vulnerability-reporting-github-template).
