# Juss Protect Me — Model One

**Human-first personal cyber defense.**

Model One is the consumer-facing Protect Me system: device, browser, identity, scam, privacy, family, and recovery protection built around one rule: **security claims must carry proof, and proof never grants itself authority.**

## Why Model One exists

Traditional security suites are strong at malware, web protection, VPN, identity monitoring, and scam detection. Model One is designed to compete there while adding a stricter evidence contract:

- every meaningful alert can be individually addressed;
- evidence is tamper-evident when a server-held signing secret is configured;
- source/model/policy/sensor identity changes make old proof stale;
- raw passwords, tokens, cookies, email addresses, and raw IP fields are rejected from evidence receipts;
- a threat recommendation and permission to take action are separate decisions;
- destructive actions cannot be auto-authorized by the evidence kernel.

## Current implemented slice

`src/model-one.mjs` provides:

- privacy-safe threat-event validation;
- threat evaluation for malware, ransomware, phishing, scams, deepfakes, account takeover, credential exposure, privacy exposure, unsafe networks, and device tampering;
- reversible containment recommendations;
- separate policy authorization for automation;
- HMAC-SHA256 signed receipts when a secret is available;
- SHA-256 integrity-only receipts that remain `inferred`, never `verified`;
- exact identity-bound staleness evaluation.

Run:

```bash
npm test
```

## Model One supremacy target

This repository does **not** claim that Model One already outperforms Norton, McAfee, or any independently tested security suite. Superiority becomes a release claim only after real-path and independent evidence.

The product target is to win on two axes at once:

1. **Consumer protection parity or better** — independently validated malware/ransomware/web protection, low performance cost, low false positives, cross-device coverage, scam/deepfake defense, identity monitoring, recovery, privacy, and family protection.
2. **Evidence-native differentiation** — explainable decisions, identity-bound proof, privacy-preserving telemetry, explicit staleness, rollback/recovery receipts, and no self-authorizing security engine.

### Required proof ladder

A release cannot call itself superior unless the relevant claim has its own current receipt:

- endpoint protection effectiveness;
- ransomware containment + recovery;
- phishing/scam/deepfake protection;
- performance overhead;
- false-positive/usability rate;
- privacy/data-minimization review;
- account and identity takeover protection;
- browser/network protection;
- recovery/rollback success;
- third-party lab or independently reproducible real-world evaluation.

## Relationship to Juss Protect Me 2

Model One protects **people and their devices**.

Protect Me 2 protects **software systems, repositories, AI agents, CI/CD, cloud runtimes, and edge traffic**.

They may exchange evidence through a documented contract, but they do not share authority, deployment identity, or automatic action permissions. Model One should outshine Model Two at human/identity/device protection; Model Two should outshine Model One at infrastructure/agent/software-supply-chain protection.

## Status

`KERNEL_IMPLEMENTED / PRODUCT_NOT_YET_LAB_VALIDATED`
