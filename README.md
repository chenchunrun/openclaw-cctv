<!-- SPDX-License-Identifier: Apache-2.0 -->
# OpenClawCCTV (macOS)

A fail-closed CCTV-style security monitor for OpenClaw on macOS.

- Root-run watchdog + monitor service (`launchd`)
- Tamper-evident audit log (hash-chain + HMAC signature)
- Security policy loaded from `SECURITY.md` at startup
- Dangerous operations blocked unless authorized by short-lived token
- **Token transport is `env-only`** (`OPENCLAW_SEC_AUTH`)
- Secret/token values are redacted (`****`) before any log write

## License

This project is licensed under **Apache License 2.0**.

- SPDX headers are included in project files
- Full license text: [`LICENSE`](./LICENSE)

## Project Policies

- Contribution guide: [`CONTRIBUTING.md`](./CONTRIBUTING.md)
- Security policy and reporting: [`SECURITY.md`](./SECURITY.md)

## Threat Model

### In scope

- OpenClaw process/channel may be compromised
- Attacker tries to execute dangerous commands, disable policy, or access audit logs through OpenClaw

### Accepted boundary

- If attacker already has local macOS admin/root privileges, they can still bypass protections

### Security goal

- If attacker does **not** have admin/root, they cannot bypass CCTV policy via OpenClaw channel

## Architecture

```text
LaunchDaemon(com.openclaw.cctv)
        |
        v
   watchdog.py (root, fail-closed precheck)
        |
        v
      cctv.py (root monitor)
        |
        +--> /var/log/openclaw-cctv/audit.log
        +--> /var/log/openclaw-cctv/alerts.log
        +--> syslog (tag: openclaw-cctv)
```

### Key files

- `install.sh`: install and enable service
- `harden_openclaw.sh`: one-click hardening after OpenClaw deployment
- `cctv.py`: main policy enforcement and auditing
- `watchdog.py`: self-recovery + fail-closed launcher
- `logger.py`: append-only style hash-chain logger
- `SECURITY.md`: human-readable + machine policy block
- `rules.json`: extra monitor/integrity rules
- `gen_auth_token.sh`: root-side token generator

## Requirements

- macOS (Intel/Apple Silicon)
- Python 3 (`/usr/bin/python3`)
- root privileges for install/hardening
- OpenClaw already deployed

## Quick Start

### 1. Deploy OpenClaw first

Install and run your OpenClaw service as **non-root user**.

### 2. One-click hardening

```bash
cd openclawcctv
sudo ./harden_openclaw.sh
```

This will:

- install files to `/Library/Application Support/OpenClawCCTV`
- install policy to `/etc/openclaw/security/SECURITY.md`
- create root-only keys
- bootstrap `launchd` service `com.openclaw.cctv`
- enforce permissions for policy/log directories

### 3. Check status

```bash
sudo launchctl print system/com.openclaw.cctv
sudo tail -f /var/log/openclaw-cctv/audit.log
sudo tail -f /var/log/openclaw-cctv/alerts.log
```

## Dangerous Operation Authorization (`env-only`)

For dangerous commands, policy requires token in environment variable:

- variable name: `OPENCLAW_SEC_AUTH`
- token format: `<timestamp_ms>:<nonce>:<hmac_sha256>`

Generate token:

```bash
eval "$(sudo /Library/Application\ Support/OpenClawCCTV/gen_auth_token.sh)"
```

Then execute dangerous operation (example pattern match):

```bash
OPENCLAW_SEC_AUTH="$OPENCLAW_SEC_AUTH" openclaw ...
```

### Important

- Passing token via command-line `SEC-AUTH:...` is blocked
- Token is short-lived and one-time (anti-replay)

## Logging and Redaction

Audit fields include timestamp, pid, user, command, file/network target, result, chain hash, and signature.

Sensitive values are redacted before write:

- `OPENCLAW_SEC_AUTH=...` -> `OPENCLAW_SEC_AUTH=****`
- `SEC-AUTH:...` -> `SEC-AUTH:****`
- `password/token/secret/api_key` style values -> `****`

## Policy Enforcement

`cctv.py` requires valid machine policy block from:

- `/etc/openclaw/security/SECURITY.md`

If missing/invalid:

- monitor fails closed
- watchdog refuses to relaunch monitor until policy is valid

## Hardening Notes

- Do **not** run OpenClaw as root (script enforces this)
- Keep keys root-only:
  - `/etc/openclaw-cctv.key`
  - `/etc/openclaw-cctv.authkey`
- Protect audit directory permissions:
  - `/var/log/openclaw-cctv`

## Uninstall

```bash
cd openclawcctv
sudo ./uninstall.sh
```

Optional cleanup:

```bash
sudo ./uninstall.sh --purge-logs --purge-policy --purge-key
```

## Development Checks

```bash
bash -n install.sh uninstall.sh harden_openclaw.sh gen_auth_token.sh
python3 -m py_compile cctv.py watchdog.py logger.py
```

## Disclaimer

This project improves non-root channel abuse resistance but is **not** a kernel-level mandatory access control system.
If an attacker has local admin/root, bypass is still possible.
