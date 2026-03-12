<!-- SPDX-License-Identifier: Apache-2.0 -->
# OpenClaw Security Contract

This file is mandatory at startup. If missing, malformed, or if policy validation fails,
OpenClaw CCTV must fail closed and stop monitoring service startup.

## Core Principles

- OpenClaw is untrusted by default.
- Dangerous operations require a short-lived signed token.
- Reconfiguration/reset of security channel from OpenClaw command channel is forbidden.
- Audit logs and security key files are never accessible from OpenClaw channel.
- If policy cannot be enforced, stop service rather than degrade.

## Token Model

- Token format (value only): `<timestamp_ms>:<nonce>:<hmac_sha256>`
- Transport: environment variable only (`OPENCLAW_SEC_AUTH`)
- Command-line token transport like `SEC-AUTH:...` is forbidden and blocked.
- Signature input: `<timestamp_ms>:<nonce>`
- Signature algorithm: `HMAC-SHA256`
- Key storage: root-only file path declared in policy
- Token is short-lived and single-use (anti-replay)

## Machine Policy

<!-- POLICY_BEGIN -->
```json
{
  "policy_id": "openclaw-security-v2",
  "enforce": true,
  "fail_closed": true,
  "kill_on_violation": true,
  "always_block_patterns": [
    "/var/log/openclaw-cctv",
    "/etc/openclaw-cctv.key",
    "/etc/openclaw-cctv.authkey",
    "/etc/openclaw/security/security.md",
    "cat /var/log/openclaw-cctv",
    "tail -f /var/log/openclaw-cctv",
    "less /var/log/openclaw-cctv",
    "vi /var/log/openclaw-cctv",
    "nano /var/log/openclaw-cctv"
  ],
  "dangerous_command_patterns": [
    "rm -rf",
    "chmod 777",
    "chflags",
    "launchctl bootout",
    "launchctl remove",
    "python -c",
    "curl ",
    "scp ",
    "nc "
  ],
  "prohibited_reconfiguration_patterns": [
    "reset security token",
    "rotate security key",
    "disable security contract",
    "edit /etc/openclaw/security/security.md",
    "vi /etc/openclaw/security/security.md",
    "nano /etc/openclaw/security/security.md"
  ],
  "auth": {
    "required_prefix": "SEC-AUTH:",
    "token_transport": "env_only",
    "env_var_name": "OPENCLAW_SEC_AUTH",
    "token_ttl_seconds": 120,
    "hmac_key_file": "/etc/openclaw-cctv.authkey"
  }
}
```
<!-- POLICY_END -->

## Operational Notes

- Admin may update this file offline as root.
- Any update should be reviewed and logged.
- Do not expose auth key through OpenClaw channel.
- CCTV logger redacts secrets before any disk/syslog write.

## Vulnerability Reporting (GitHub Template)

If you find a security vulnerability, report it privately first.

1. Do not post exploitable details in public issues.
2. Open a private security report via GitHub Security Advisories, or email the maintainers.
3. Include:
   - affected version/commit
   - reproduction steps
   - expected vs actual behavior
   - impact and suggested fix (if available)
4. Maintainer target timeline:
   - acknowledge within 72 hours
   - provide triage status within 7 days
   - publish fix/mitigation timeline after confirmation
5. Coordinated disclosure:
   - keep details private until a fix is released
   - publish advisory and patch references after release

### Suggested Report Subject

`[SECURITY] OpenClawCCTV vulnerability report: <short-title>`
