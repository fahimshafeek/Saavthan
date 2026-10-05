# Vault — Backend Build Guide

> **Audience:** you (the backend owner) and the AI coding harness that will generate the backend from this file.
> **Goal:** a complete, ordered, opinionated blueprint — architecture, data model, APIs, crypto, workflows, tests and acceptance criteria — so that generating the backend from this document is mechanical.
> **Codename:** `Vault` (Python package `vaultkit`). Rename freely; search-and-replace `vaultkit` / `Vault`.

---

## Table of contents

0. [How to use this document (rules for the coding harness)](#0-how-to-use-this-document-rules-for-the-coding-harness)
1. [Product recap and backend scope](#1-product-recap-and-backend-scope)
2. [Glossary](#2-glossary)
3. [Architecture](#3-architecture)
4. [Threat model](#4-threat-model)
5. [Tech stack and why](#5-tech-stack-and-why)
6. [Repository layout](#6-repository-layout)
7. [Cross-cutting conventions](#7-cross-cutting-conventions)
8. [Data model](#8-data-model)
9. [Phase 0 — Foundation](#9-phase-0--foundation)
10. [Phase 1 — Backend with login (hub + agent)](#10-phase-1--backend-with-login-hub--agent)
11. [Phase 2 — Custom endpoint generation (Cloudflare Tunnel)](#11-phase-2--custom-endpoint-generation-cloudflare-tunnel)
12. [Phase 3 — Auto-registration and `manager.py`](#12-phase-3--auto-registration-and-managerpy)
13. [Phase 4 — Secure upload and sync (anti-forgery)](#13-phase-4--secure-upload-and-sync-anti-forgery)
14. [Phase 4.5 — Retention and wipe engine (the core promise)](#14-phase-45--retention-and-wipe-engine-the-core-promise)
15. [Phase 5 — Login hardening](#15-phase-5--login-hardening)
16. [Phase 6 — Automation, signed builds, auto-updates](#16-phase-6--automation-signed-builds-auto-updates)
17. [Testing strategy](#17-testing-strategy)
18. [Deployment](#18-deployment)
19. [Observability and operations](#19-observability-and-operations)
20. [Legal and compliance notes (India)](#20-legal-and-compliance-notes-india)
21. [Security checklist](#21-security-checklist)
22. [Per-phase prompts for the coding harness](#22-per-phase-prompts-for-the-coding-harness)
23. [Milestone plan](#23-milestone-plan)
24. [Open questions to settle with your team](#24-open-questions-to-settle-with-your-team)
25. [Appendix — API reference, env vars, snippets](#25-appendix--api-reference-env-vars-snippets)

---

## 0. How to use this document (rules for the coding harness)

If you are an AI coding agent reading this: follow these rules exactly.

1. **Build phase by phase, in order.** Do not start Phase N+1 until Phase N's *Definition of Done* (DoD) is green. One phase = one branch = one PR.
2. **Tests first or alongside.** Every module ships with tests. A phase is not done if `pytest`, `ruff check`, `ruff format --check` and `mypy --strict` (on `vaultcommon` and new code) are not all green.
3. **Never invent cryptography.** Use only the primitives named in this document (Argon2id, Ed25519, SHA-256, HMAC-SHA256, AES-256-GCM, X25519 sealed boxes) through the named libraries (`argon2-cffi`, `PyNaCl`, `cryptography`). No custom ciphers, no home-made KDFs, no MD5/SHA-1, no `random` module for secrets (use `secrets` / `os.urandom`).
4. **No secrets in the repo.** Config comes from environment variables / secret files. Provide `.env.example` only.
5. **Never trust client input.** Validate with Pydantic v2 models. Never use a client-supplied filename as a filesystem path — store blobs under server-generated UUIDs.
6. **No placeholders.** No `TODO: implement`, no `pass` bodies, no fake responses in non-test code. If something cannot be done in the current phase, raise `NotImplementedError` behind a clearly named feature flag *and* list it in `docs/KNOWN_GAPS.md`.
7. **Small, typed, async-first.** Python 3.12, full type hints, `async def` for I/O, dependency injection via FastAPI `Depends`.
8. **Every security decision gets an ADR.** Add a short markdown file under `docs/adr/NNNN-title.md` (context, decision, consequences) whenever you choose between alternatives.
9. **Do not log sensitive data.** No filenames, file contents, passwords, tokens, or full IPs in logs. See §19.
10. **Commit style:** Conventional Commits (`feat:`, `fix:`, `test:`, `docs:`, `chore:`, `sec:`).
11. **Ask when the spec conflicts with itself**, otherwise pick the safer option and record it in an ADR.
12. **Out of scope for the backend** (do not build): the sandbox/desktop shell UI, the installer's GUI, the customer-facing marketing site. The backend only exposes the contracts listed in §10.6 for those.

---

## 1. Product recap and backend scope

**Product.** A one-click `.exe` that launches an isolated, disposable kiosk environment (no VMware/VirtualBox) on a shared computer — Akshaya centers, internet cafés, print shops. Everything a person downloads, uploads, types into a form or saves during their session is **obliterated** when the session ends. Customers who cannot come in person can also send documents through a **virtual portal** at a per-shop URL such as `vault.laddu.cc/mycafe1`; those files reach the shop's machine, are handled, and are then destroyed too.

**Business model.** Every installed machine is registered with *us* (the makers). We can see which shops/machines run the product, which version, and whether they are healthy. This also lets us push security updates.

**Core promises the backend must make true:**

| Promise | Mechanism |
|---|---|
| "We don't keep your data" | Per-session ephemeral keys, crypto-shredding, TTL-based retention, wipe verification, wipe-on-boot |
| "Nobody forged or altered your file" | Chunk + file hashes, signed receipts, hash-chained transparency log |
| "This shop is who it claims to be" | Slug registry, device identity keys, signed server-to-server requests |
| "The software is current and untampered" | Signed builds, signed update manifests, anti-rollback, staged rollout |

**Your backend responsibilities (in the order you were given):**

1. Small backend with login — a **client-side local service** (the *agent*, on each kiosk machine) plus a **site server** (the *hub*, one per shop) plus server-to-server connectivity.
2. Custom endpoint generation — `vault.laddu.cc/<slug>` through Cloudflare Tunnel.
3. Auto-registration on a central server — `manager.py`.
4. File sync between sender and service provider with forgery/modification protection.
5. Hashed login.
6. Automation: scripts, signed builds, auto-updating images.

I add one more component because it *is* the product's central promise: **§14 the retention and wipe engine.** Treat it as mandatory.

> **A note on ordering.** You listed "hashing login" as step 5, but you cannot ship step 1 (login) without password hashing. So: Phase 1 implements Argon2id password hashing properly; Phase 5 *hardens* the login system (lockout, rate limits, device-bound sessions, optional TOTP, audit trail).

---

## 2. Glossary

| Term | Meaning |
|---|---|
| **Kiosk** | A shop computer running the Vault exe; a disposable session per customer |
| **Agent** | Local backend service on each kiosk machine. Controls sessions, wipe, updates, talks to hub and manager. The "client (server)" in your brief |
| **Hub** | Per-shop server. Receives remote uploads (through the tunnel), stores them encrypted and briefly, serves them to the shop's agents. One hub per shop (can run on the same PC as the agent in single-PC shops) |
| **Manager** | *Our* central server (`manager.py`). Enrolls devices, provisions endpoints, publishes signed releases, keeps the transparency log |
| **Gateway** | A Cloudflare Worker that maps `vault.laddu.cc/<slug>/…` to the right shop's tunnel origin |
| **Portal** | The static web page a remote customer uses to upload (served by the hub through the tunnel) |
| **Slug** | The shop's public path segment, e.g. `mycafe1` |
| **Drop** | A time-limited upload request created by shop staff: "customer X may upload up to N files / M MB until T" |
| **Receipt** | Signed JSON proving "hub H received file with hash X, size S at time T" |
| **Transparency log** | Append-only, hash-chained list of receipts held by the manager (hashes only — never file content) |
| **Crypto-shredding** | Destroying the encryption key so remaining ciphertext is unrecoverable |
| **Release manifest** | Signed JSON listing artifact hashes, version, channel, expiry, severity |
| **Ring** | Staged rollout group (canary → early → general) |

---

## 3. Architecture

### 3.1 Component diagram

```
                                   ┌──────────────────────────────┐
                                   │  MANAGER  (ours, cloud VPS)  │
                                   │  manager.py + PostgreSQL     │
                                   │  • enrollment & fleet        │
                                   │  • Cloudflare API client     │
                                   │  • release signing/publish   │
                                   │  • transparency log          │
                                   └──────▲───────────▲───────────┘
                          signed requests │           │ signed requests
                    (enroll/heartbeat/    │           │ (receipts → log,
                     update check)        │           │  endpoint status)
                                          │           │
┌───────────────┐   HTTPS   ┌─────────────┴───┐   ┌───┴─────────────────────────────┐
│ CUSTOMER      │──────────▶│ CLOUDFLARE EDGE │   │  SHOP (Akshaya / café)          │
│ browser       │ vault.    │  Worker gateway │   │                                 │
│ (Portal)      │ laddu.cc/ │  /slug → origin │   │  ┌──────────────┐  LAN/loopback │
└───────────────┘ mycafe1   └────────┬────────┘   │  │  HUB         │◀────────┐     │
                                      │ Cloudflare │  │  FastAPI +   │         │     │
                                      └──Tunnel────┼─▶│  SQLite      │         │     │
                                       (cloudflared│  │  encrypted   │   ┌─────┴───┐ │
                                        outbound)  │  │  staging     │   │ AGENT   │ │  × N machines
                                                   │  └──────────────┘   │ (local) │ │
                                                   │                     │ sessions│ │
                                                   │                     │ wipe    │ │
                                                   │                     └────┬────┘ │
                                                   │                          │      │
                                                   │            ┌─────────────▼────┐ │
                                                   │            │ Kiosk shell/     │ │
                                                   │            │ sandbox (others' │ │
                                                   │            │ work)            │ │
                                                   │            └──────────────────┘ │
                                                   └─────────────────────────────────┘
```

### 3.2 Trust boundaries (memorize these)

1. **Customer browser ↔ Cloudflare ↔ hub.** Untrusted network. Cloudflare terminates TLS, so it can technically see traffic. Mitigation: optional **end-to-end encryption** (§13.8) so Cloudflare only ever sees ciphertext.
2. **Hub ↔ manager.** Mutually authenticated by device-signed requests (Ed25519) over HTTPS. Manager never receives file content or filenames.
3. **Agent ↔ hub.** Same signed-request scheme, over LAN/loopback. Even on LAN, don't trust the network.
4. **Agent ↔ kiosk user.** The person sitting at the machine is **adversarial** (curious, malicious, or simply careless). The agent runs as a privileged service account; the kiosk user's account must not be able to call privileged endpoints (§10.6).
5. **Our release pipeline ↔ every installed machine.** Machines trust exactly one thing: our **root public key** embedded at build time. Everything else must chain to it.

### 3.3 Data flows (high level)

**A. Remote upload**
1. Staff create a *drop* in the hub (via agent UI or hub dashboard) → get a short code + link.
2. Staff give the link/code to the customer (WhatsApp, verbally, printed).
3. Customer opens `vault.laddu.cc/mycafe1/d/<code>`, selects files. Browser hashes each chunk (SHA-256), uploads chunks (optionally E2E-encrypted).
4. Hub verifies each chunk hash, stores the chunk encrypted, verifies the final tree hash, issues a **signed receipt**, and submits a hash-only entry to the manager's **transparency log**.
5. Customer's browser shows the receipt; customer can download it.
6. Staff open the file on a kiosk: agent pulls from hub, verifies the hash against the receipt, decrypts **into the session workspace only**.
7. Session ends → workspace destroyed; hub copy destroyed after delivery + short grace or TTL.

**B. In-person use**
1. Staff/customer starts a kiosk session → agent creates an ephemeral workspace + session key.
2. Customer works (inside the sandbox layer — not your scope).
3. Session end (button, idle timeout, crash, power loss recovery) → wipe engine runs and verifies → writes a content-free wipe record.

**C. Fleet**
1. Agent/hub enroll with an enrollment token → manager registers the device public key.
2. Heartbeats every N seconds; update checks piggyback on heartbeats.
3. Manager publishes signed release → devices fetch, verify, stage, apply between sessions, roll back on failed health check.

---

## 4. Threat model

Use STRIDE-ish thinking. The harness must write tests for every row marked ★.

| # | Threat | Example | Mitigation |
|---|---|---|---|
| T1★ | Malicious kiosk user tries to keep data | Copies a file to USB, hides it in an unusual folder | Sandbox layer (out of scope) + wipe verification + workspace-only decryption |
| T2★ | Kiosk user calls agent's privileged API | `POST /local/v1/session/end?skip_wipe=1` | No such parameter; privileged endpoints require supervisor credential unreachable to the kiosk account (named pipe ACL / service-only token) |
| T3★ | File tampered in transit or at rest | MITM flips bytes; hub admin edits blob | Chunk hashes, tree hash, signed receipt, AES-GCM tags with AAD binding |
| T4★ | Forged/replayed request to manager | Attacker replays a heartbeat or enrolls a fake device | Ed25519 signed requests with timestamp + nonce; single-use, expiring enrollment tokens |
| T5★ | Fake shop impersonating a trusted shop | Registers slug `akshaya-official` | Reserved/confusable slug rules, manual verification flag, ASCII-only slugs |
| T6★ | Malicious update | Attacker controls CDN and serves a backdoored image | Signed manifests (offline root key), artifact SHA-256, anti-rollback, expiry |
| T7★ | Rollback attack | Attacker serves old vulnerable release | Monotonic version check + manifest `expires_at` + minimum version |
| T8★ | Credential stuffing / brute force on login | Automated guesses on shop owner accounts | Argon2id, per-account + per-IP rate limits, lockout with backoff, optional TOTP |
| T9★ | Path traversal / zip-slip in uploads | Filename `../../Windows/System32/x` | Never use client names for paths; sanitize display names; store by UUID |
| T10 | Abuse of public upload page | Spam, malware, illegal content | Drops require staff-issued code; size/type limits; Turnstile; optional AV scan hook; abuse report endpoint |
| T11 | Data remains in pagefile / hibernation / SSD wear-leveling | Forensic recovery after session | Crypto-shredding (primary), disable hibernation, clear pagefile at shutdown, RAM-first buffers |
| T12 | Manager compromise | Our server is hacked | Manager holds **no** file data; release signing key is offline; device keys are per-device; transparency log is hash-chained and externally checkpointed |
| T13 | Cloudflare account compromise | Attacker repoints tunnels | Scoped API tokens, 2FA, audit logs; E2EE mode makes redirected traffic useless |
| T14 | Hub clock skew breaks signature windows | Wrong system time | Skew tolerance ±120 s; manager returns `Date` header; agent warns when skew exceeds tolerance |
| T15 | Denial of service on a cafe's hub | Flood of upload attempts | Cloudflare rate limiting + Turnstile + per-drop quotas + body-size caps |

**Explicit non-goals (be honest with customers):** protecting against a kiosk with a hardware keylogger, a compromised BIOS, or a person photographing the screen. Say this in your trust page.

---

## 5. Tech stack and why

| Concern | Choice | Reason |
|---|---|---|
| Language | **Python 3.12** | You know it; fast to build; good crypto libs |
| Web framework | **FastAPI** + **Uvicorn** | Typed, async, auto OpenAPI (import into Postman) |
| Validation | **Pydantic v2**, **pydantic-settings** | Strict models; env-based config |
| ORM / migrations | **SQLAlchemy 2.0 (async)** + **Alembic** | Standard, testable |
| Hub/agent DB | **SQLite (WAL mode, `secure_delete=ON`)** | Zero-install on shop PCs |
| Manager DB | **PostgreSQL 16** | Multi-tenant fleet data, transactions |
| Password hashing | **argon2-cffi** (Argon2id) | OWASP-recommended |
| Signatures | **PyNaCl** (Ed25519) | Small, audited, simple API |
| Symmetric crypto | **cryptography** (AESGCM) | Standard AEAD |
| HTTP client | **httpx** (async) | Timeouts, retries, mocking with `respx` |
| Rate limiting | **slowapi** (or custom token bucket in SQLite/Redis) | Per-IP / per-account |
| Tokens | **PyJWT** (EdDSA or HS256) for access; opaque random for refresh | Short-lived access + revocable refresh |
| Logging | **structlog** (JSON) with a redaction processor | Searchable, no PII |
| Windows secrets | **keyring** (Windows Credential Manager / DPAPI) | Store device key without plaintext files |
| CLI | **Typer** | `manager.py` subcommands |
| Packaging | **uv** (workspace), **PyInstaller** or **Nuitka** | Reproducible env; single exe |
| Quality | **ruff**, **mypy**, **pytest**, **pytest-asyncio**, **hypothesis**, **respx**, **coverage** | Fast feedback |
| Security scans | **pip-audit**, **osv-scanner**, **bandit**, **trivy** (images), **CycloneDX SBOM** | Supply-chain hygiene |
| CI/CD | **GitHub Actions** | Free for students; supports OIDC + artifact attestations |
| Edge | **Cloudflare Tunnel (`cloudflared`)**, **Workers** (gateway), **Turnstile** | Your requirement |
| Container | **Docker + Compose** (manager only) | You know Docker |

> Cloudflare plan limits matter: on Free/Pro plans a single request body is capped at about 100 MB. **Design every upload as chunked** (default 8 MiB chunks) so you never depend on that limit. Re-verify current Cloudflare limits before launch.

---

## 6. Repository layout

Monorepo, `uv` workspace.

```
vault/
├── README.md                      # this file
├── pyproject.toml                 # uv workspace root, ruff/mypy/pytest config
├── uv.lock
├── .env.example
├── .github/workflows/
│   ├── ci.yml                     # lint, type-check, test, audit
│   ├── release.yml                # build, sbom, sign, publish
│   └── security-scan.yml          # scheduled dependency/CVE scans
├── packages/
│   └── vaultcommon/
│       ├── pyproject.toml
│       └── src/vaultcommon/
│           ├── __init__.py
│           ├── canonical.py       # canonical JSON
│           ├── crypto.py          # Ed25519, AES-GCM, key utils
│           ├── hashing.py         # chunk/tree hashes
│           ├── passwords.py       # Argon2id + pepper
│           ├── signing.py         # signed-request headers (build/verify)
│           ├── errors.py          # ApiError + problem+json
│           ├── logging.py         # structlog setup + redaction
│           ├── schemas/           # shared Pydantic models (receipts, manifests)
│           └── time.py            # UTC helpers, skew checks
├── apps/
│   ├── manager/
│   │   ├── manager.py             # ENTRYPOINT: `python manager.py serve|…`
│   │   ├── src/vault_manager/
│   │   │   ├── api/               # routers: enroll, devices, endpoints, updates, log, admin
│   │   │   ├── services/          # cloudflare.py, releases.py, transparency.py, enrollment.py
│   │   │   ├── db/                # models.py, session.py, migrations/
│   │   │   ├── security/          # request verification, admin auth
│   │   │   └── settings.py
│   │   └── tests/
│   ├── hub/
│   │   ├── src/vault_hub/
│   │   │   ├── api/               # auth, users, drops, public_upload, inbox, health
│   │   │   ├── services/          # uploads.py, receipts.py, storage.py, retention.py, tunnel.py
│   │   │   ├── db/
│   │   │   ├── security/
│   │   │   └── settings.py
│   │   └── tests/
│   ├── agent/
│   │   ├── src/vault_agent/
│   │   │   ├── api/               # local API (loopback/pipe): sessions, inbox, status
│   │   │   ├── services/          # session.py, wipe.py, workspace.py, enrollment.py, updater.py, heartbeat.py
│   │   │   ├── platform/          # windows.py, linux.py, dev.py (WorkspaceProvider impls)
│   │   │   └── settings.py
│   │   └── tests/
│   └── gateway/                   # Cloudflare Worker (TypeScript)
│       ├── src/index.ts
│       └── wrangler.toml
├── portal/                        # static upload page (vanilla JS + tweetnacl/libsodium)
├── infra/
│   ├── docker-compose.manager.yml
│   ├── cloudflared/config.template.yml
│   └── caddy/Caddyfile            # reverse proxy for manager
├── scripts/
│   ├── gen_release_keys.py        # offline key ceremony helper
│   ├── sign_release.py
│   ├── build_exe.ps1
│   └── dev_up.sh
├── tests/e2e/                     # cross-service tests via docker compose
└── docs/
    ├── adr/
    ├── KNOWN_GAPS.md
    ├── API.md
    └── RUNBOOK.md
```

---

## 7. Cross-cutting conventions

### 7.1 Configuration (pydantic-settings)

Every service has a `Settings` class; env prefix per service (`VAULT_HUB_`, `VAULT_AGENT_`, `VAULT_MGR_`). Secrets can be passed as `*_FILE` paths so Docker secrets work.

```python
from pathlib import Path
from pydantic import Field, HttpUrl
from pydantic_settings import BaseSettings, SettingsConfigDict

class HubSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="VAULT_HUB_", env_file=".env", extra="ignore")

    data_dir: Path = Path("./data")
    db_url: str = "sqlite+aiosqlite:///./data/hub.db"
    manager_url: HttpUrl
    public_base_path: str = ""            # set by gateway via X-Forwarded-Prefix
    chunk_size_bytes: int = 8 * 1024 * 1024
    max_upload_bytes: int = 2 * 1024 * 1024 * 1024
    drop_default_ttl_minutes: int = 60
    upload_retention_hours: int = 24      # hard ceiling; wipe regardless
    access_token_ttl_s: int = 600
    refresh_token_ttl_s: int = 8 * 3600
    password_pepper_file: Path = Field(..., description="32+ random bytes, outside data_dir")
    log_level: str = "INFO"
```

### 7.2 Errors — RFC 9457 `application/problem+json`

```python
class ApiError(Exception):
    def __init__(self, code: str, status: int, detail: str = "", **extra): ...
# Response:
# {"type":"https://vault.laddu.cc/errors/chunk_hash_mismatch","title":"Chunk hash mismatch",
#  "status":422,"detail":"...","code":"chunk_hash_mismatch","request_id":"..."}
```

Error codes are a stable enum in `vaultcommon.errors` (see Appendix B). Never leak stack traces; unknown exceptions → `500 internal_error` with `request_id`.

### 7.3 IDs, time, versions

- IDs: **UUIDv7 if available, else UUIDv4**, stored as text in SQLite, `uuid` in Postgres. Public-facing codes (drop codes) are separate: 10-char Crockford base32 from `secrets`.
- Time: **always UTC**, ISO-8601 with `Z`. Never store naive datetimes. Helper `vaultcommon.time.utcnow()`.
- API versioning: URL prefix `/api/v1`. Breaking changes → `/api/v2` side by side.
- Request IDs: accept `X-Request-ID` (validated), else generate; return it on every response; include in logs.

### 7.4 Canonical JSON (for anything signed)

Both sides must produce identical bytes. Rule: UTF-8, keys sorted, no whitespace, no floats in signed payloads (use integers/strings).

```python
import json
def canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
```

The portal's JS must implement the same canonicalization (sorted keys, no spaces) to verify receipts; also expose a server-side `POST /api/v1/receipts/verify` so users aren't forced to run JS.

### 7.5 Signed-request scheme (device → manager, agent → hub)

Headers:

```
X-Vault-Device:    <device_id>
X-Vault-Timestamp: <unix seconds>
X-Vault-Nonce:     <16 random bytes, base64url>
X-Vault-Signature: <base64url Ed25519 signature>
```

Signature input (newline-joined, exact):

```
VAULT-REQ-V1
<HTTP METHOD upper>
<path + "?" + sorted query string, or just path>
<timestamp>
<nonce>
<hex sha256 of raw request body>   # sha256("") for empty body
```

Verifier rules: device exists and `status == active`; `|now − ts| ≤ 120 s`; nonce not seen in last 5 minutes (store in a small table with TTL or Redis); signature valid; then process. For streaming/chunk uploads where the body is huge, sign `sha256` supplied in `X-Vault-Content-SHA256` and verify it against the actual body while streaming.

```python
def build_signing_string(method: str, path_qs: str, ts: int, nonce: str, body: bytes) -> bytes:
    return "\n".join([
        "VAULT-REQ-V1", method.upper(), path_qs, str(ts), nonce, hashlib.sha256(body).hexdigest(),
    ]).encode()
```

### 7.5.1 Why not mTLS?

mTLS is great but painful with Cloudflare Tunnel on the hub side and with shop PCs behind NAT/ISP middleboxes. Signed requests over HTTPS give equivalent device authentication with fewer moving parts. Record this in `docs/adr/0003-signed-requests-over-mtls.md`.

### 7.6 Code style

- `ruff` (line length 100, rules: `E,F,I,B,UP,S,ASYNC,RUF`), `mypy --strict`.
- Routers thin; business logic in `services/`; DB access only in services/repositories.
- Dependency injection for DB session, settings, current user/device, clock (inject `Clock` so tests can freeze time).
- No global mutable state except explicitly documented singletons (settings, key material cache).

---

## 8. Data model

### 8.1 Manager (PostgreSQL)

| Table | Key columns |
|---|---|
| `admin_users` | `id`, `email` (unique), `password_hash`, `totp_secret_enc`, `role` (`superadmin`,`support`,`readonly`), `created_at`, `disabled_at` |
| `cafes` | `id`, `name`, `slug` (unique, citext), `owner_email`, `verified` (bool), `status` (`pending`,`active`,`suspended`), `plan`, `created_at` |
| `enrollment_tokens` | `id`, `cafe_id`, `token_hash` (sha256), `role_allowed` (`hub`,`agent`,`any`), `max_uses`, `used`, `expires_at`, `revoked_at`, `created_by` |
| `devices` | `id`, `cafe_id`, `role` (`hub`,`agent`), `public_key` (32B b64), `label`, `os`, `app_version`, `image_version`, `ring`, `status` (`active`,`suspended`,`revoked`), `first_seen`, `last_seen`, `last_seen_country` (coarse), `clock_skew_s` |
| `device_nonces` | `device_id`, `nonce`, `seen_at` (TTL cleanup; unique `(device_id, nonce)`) |
| `endpoints` | `cafe_id`, `slug`, `tunnel_id`, `origin_hostname`, `dns_record_id`, `status` (`provisioning`,`active`,`disabled`), `created_at` |
| `releases` | `id`, `version`, `channel` (`stable`,`beta`), `severity` (`normal`,`security`,`critical`), `manifest_json`, `manifest_sig`, `min_supported_version`, `published_at`, `revoked_at` |
| `rollouts` | `release_id`, `ring`, `percent`, `start_at`, `force_by` |
| `device_release_status` | `device_id`, `release_id`, `state` (`offered`,`downloading`,`staged`,`applied`,`failed`,`rolled_back`), `updated_at`, `error_code` |
| `transparency_log` | `seq` (bigserial PK), `cafe_id`, `device_id`, `entry_json`, `entry_hash`, `prev_hash`, `hub_sig`, `manager_sig`, `created_at` |
| `audit_events` | `id`, `actor_type`, `actor_id`, `action`, `target`, `meta_json`, `created_at` |

### 8.2 Hub (SQLite)

| Table | Key columns |
|---|---|
| `users` | `id`, `username` (unique, lowercased), `password_hash`, `role` (`owner`,`operator`), `failed_attempts`, `locked_until`, `totp_secret_enc`, `created_at`, `disabled_at`, `must_change_password` |
| `refresh_tokens` | `id`, `user_id`, `token_hash`, `family_id`, `issued_at`, `expires_at`, `revoked_at`, `replaced_by`, `device_hint` |
| `drops` | `id`, `code_hash`, `pin_hash` (nullable), `created_by`, `label_enc`, `expires_at`, `max_files`, `max_bytes`, `allowed_types_json`, `status` (`open`,`closed`,`expired`), `e2ee_pubkey` (nullable) |
| `uploads` | `id`, `drop_id`, `display_name_enc`, `declared_size`, `received_size`, `chunk_size`, `tree_hash`, `status` (`receiving`,`verified`,`delivered`,`wiped`,`failed`), `dek_wrapped`, `created_at`, `verified_at`, `delivered_at`, `wipe_after` |
| `chunks` | `upload_id`, `idx`, `sha256`, `size`, `blob_path` — PK `(upload_id, idx)` |
| `receipts` | `upload_id` (PK), `receipt_json`, `hub_sig`, `manager_ack_seq` (nullable), `created_at` |
| `kiosk_sessions` | `id`, `agent_device_id`, `started_at`, `ended_at`, `wipe_status` (`pending`,`ok`,`failed`,`recovered_on_boot`) |
| `rate_limits` | `bucket_key`, `window_start`, `count` |
| `audit_events` | `id`, `actor`, `action`, `target`, `at` — **no filenames, no content** |

SQLite pragmas on connect: `journal_mode=WAL`, `synchronous=NORMAL`, `foreign_keys=ON`, **`secure_delete=ON`**, `busy_timeout=5000`.

### 8.3 Agent (local)

Minimal: `agent_state` (device id, enrollment status, versions), `pending_wipes` (session ids with unfinished wipes — drives wipe-on-boot), `queued_heartbeats`. Device private key lives in the OS credential store (`keyring`), **not** in SQLite.

---

## 9. Phase 0 — Foundation

**Goal:** a repo where adding a feature is boring and safe.

### 9.1 Steps

1. `uv init` the workspace; add members `packages/vaultcommon`, `apps/manager`, `apps/hub`, `apps/agent`.
2. Add dev tools: ruff, mypy, pytest, pytest-asyncio, hypothesis, respx, coverage, pip-audit, bandit, pre-commit.
3. `pre-commit`: ruff, ruff-format, mypy (changed files), detect-secrets, check-added-large-files.
4. Implement `vaultcommon`:
   - `canonical.py`, `time.py`, `errors.py`, `logging.py` (with redaction processor that drops/masks keys `password`, `token`, `authorization`, `filename`, `display_name`, `signature`, `private_key`, and masks IPs to /24).
   - `crypto.py`: key generation, Ed25519 sign/verify, AES-GCM seal/open, `constant_time_equal`.
   - `hashing.py`: chunk hashing and tree hash (§13.2).
   - `passwords.py`: Argon2id + pepper (§10.2).
   - `signing.py`: build/verify signed-request headers (§7.5).
5. GitHub Actions `ci.yml`: matrix (ubuntu, windows) → `uv sync` → ruff → mypy → pytest → `pip-audit`.
6. Docs: ADR 0001 (stack), 0002 (monorepo), 0003 (signed requests over mTLS).

### 9.2 Core snippets the harness should implement verbatim in spirit

**Ed25519 (PyNaCl):**

```python
import base64
from nacl.signing import SigningKey, VerifyKey
from nacl.exceptions import BadSignatureError

def b64u(b: bytes) -> str: return base64.urlsafe_b64encode(b).rstrip(b"=").decode()
def unb64u(s: str) -> bytes: return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

def generate_keypair() -> tuple[SigningKey, str]:
    sk = SigningKey.generate()
    return sk, b64u(bytes(sk.verify_key))

def sign_obj(sk: SigningKey, obj) -> str:
    return b64u(sk.sign(canonical(obj)).signature)

def verify_obj(pub_b64u: str, obj, sig_b64u: str) -> bool:
    try:
        VerifyKey(unb64u(pub_b64u)).verify(canonical(obj), unb64u(sig_b64u))
        return True
    except (BadSignatureError, ValueError):
        return False
```

**AES-256-GCM with AAD (at-rest chunks):**

```python
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def seal(key: bytes, aad: bytes, plaintext: bytes) -> bytes:
    nonce = os.urandom(12)
    return nonce + AESGCM(key).encrypt(nonce, plaintext, aad)

def open_(key: bytes, aad: bytes, blob: bytes) -> bytes:
    return AESGCM(key).decrypt(blob[:12], blob[12:], aad)   # raises InvalidTag on tamper
```

AAD for a chunk is `f"{upload_id}:{idx}".encode()` — binding ciphertext to its position so chunks cannot be swapped or reordered undetected.

### 9.3 Definition of Done (Phase 0)

- `uv run pytest` green on Linux and Windows CI.
- `vaultcommon` coverage ≥ 90 %.
- Property tests (hypothesis): `open_(seal(x)) == x`; any single-bit flip in ciphertext raises; canonical JSON is key-order independent; sign/verify round-trips and fails on any mutation.
- ADRs committed.

---

## 10. Phase 1 — Backend with login (hub + agent)

**Goal:** a working hub with users + login, and an agent that talks to it. This is requirement #1 ("small backend with login, client (server) + server").

### 10.1 Roles and identities

Three kinds of principals — keep them separate in code:

| Principal | Authenticates with | Can do |
|---|---|---|
| **Human staff** (owner/operator) | Username + password → JWT access + opaque refresh | Manage drops, view inbox, create operators (owner only) |
| **Device** (agent or hub) | Ed25519 signed requests | Agent ↔ hub sync; hub/agent ↔ manager |
| **Anonymous customer** | Drop code (+ optional PIN) in URL | Upload to exactly one drop; read own receipt |

The kiosk *user* (the person at the machine) is **not a principal at all.** They interact with the sandbox; only the supervisor process talks to the agent.

### 10.2 Password hashing (Argon2id) — implement fully now

```python
import base64, hashlib, hmac
from argon2 import PasswordHasher, Type
from argon2.exceptions import VerificationError, InvalidHashError

_ph = PasswordHasher(time_cost=3, memory_cost=64 * 1024, parallelism=2,
                     hash_len=32, salt_len=16, type=Type.ID)

def _prehash(password: str, pepper: bytes) -> str:
    # HMAC with a server-side pepper, then base64 (no NUL bytes, bounded length).
    return base64.b64encode(hmac.new(pepper, password.encode("utf-8"), hashlib.sha256).digest()).decode()

def hash_password(password: str, pepper: bytes) -> str:
    return _ph.hash(_prehash(password, pepper))

def verify_password(stored: str | None, password: str, pepper: bytes) -> tuple[bool, str | None]:
    """Returns (ok, new_hash_if_rehash_needed). Runs a dummy verify for unknown users (timing)."""
    target = stored or _DUMMY_HASH
    try:
        _ph.verify(target, _prehash(password, pepper))
        ok = stored is not None
    except (VerificationError, InvalidHashError):
        return False, None
    new_hash = _ph.hash(_prehash(password, pepper)) if ok and _ph.check_needs_rehash(stored) else None
    return ok, new_hash
```

Policy:
- Min 12 characters, max 128; no composition rules; reject top-10k common passwords (bundle a list; check case-insensitively).
- Tune Argon2 so one hash takes ~100–250 ms on the **weakest shop PC you support**; expose via settings; `check_needs_rehash` upgrades hashes transparently at login.
- Pepper: 32 random bytes in a file outside `data_dir`, readable only by the service account; on Windows protect with DPAPI via `keyring`. Document pepper rotation (keep `pepper_id` per hash; support two peppers during rotation).
- **Do not hash passwords in the browser as a substitute** for server-side hashing; TLS protects transport. (Client-side pre-hashing only makes the hash the password.)

### 10.3 Token strategy

- **Access token:** JWT (PyJWT), 10 min, claims: `sub`, `role`, `sid` (session id), `iat`, `exp`, `jti`. Algorithm EdDSA with a hub-local Ed25519 key (or HS256 with a 32-byte secret, simpler). Verified on every request; reject `alg=none` and mismatched algorithms.
- **Refresh token:** 256-bit random opaque string, **stored only as SHA-256 hash**, 8 h lifetime, **rotation on every use**; reuse of an already-rotated token revokes the entire family (`family_id`) and forces re-login. Return in an `HttpOnly; Secure; SameSite=Strict` cookie *or* in JSON for the desktop agent client (the agent is not a browser).
- Logout revokes the family.
- Staff sessions on a kiosk machine should be short: idle timeout 15 min (front-end concern; backend enforces by access-token TTL).

### 10.4 Hub endpoints (Phase 1 subset)

| Method | Path | Auth | Notes |
|---|---|---|---|
| POST | `/api/v1/auth/login` | none (rate-limited) | `{username,password}` → `{access_token, refresh_token, expires_in, must_change_password}` |
| POST | `/api/v1/auth/refresh` | refresh token | rotation |
| POST | `/api/v1/auth/logout` | refresh token | revoke family |
| GET | `/api/v1/auth/me` | access | profile |
| POST | `/api/v1/auth/change-password` | access | verifies current password |
| POST | `/api/v1/users` | owner | create operator; sets `must_change_password` |
| GET | `/api/v1/users` | owner | list |
| PATCH | `/api/v1/users/{id}` | owner | disable/enable/reset |
| GET | `/healthz` | none | liveness (no dependency checks) |
| GET | `/readyz` | none | DB reachable, keys loaded |
| GET | `/.well-known/vault-hub.json` | none | hub public key + version (used by portal for receipt verification) |

**First-run bootstrap:** on first start with an empty `users` table, hub prints a **one-time bootstrap code** to the local console/log file (mode 0600). `POST /api/v1/bootstrap {code, username, password}` creates the owner and permanently disables the endpoint. No default passwords, ever.

### 10.5 Agent ↔ hub connection

- On enrollment (§12) the agent learns the hub's `device_id` + public key from the manager, and the hub learns the agent's. After that, agent→hub calls use signed requests (§7.5). The hub's allow-list of agent device IDs is synced from the manager (pull on heartbeat) — a rogue LAN device cannot talk to the hub.
- Single-PC shops: run hub and agent in one process (`vault-node --role both`); the same code paths, loopback transport.
- Hub binds to `127.0.0.1:8443` for the tunnel and `0.0.0.0` (or a chosen LAN interface) *only* for the LAN API on a separate port with a separate router; the public portal router is **only** mounted on the tunnel-facing listener. Never mount the staff API on the public listener.

### 10.6 Agent local API (contract for the sandbox/shell team)

Transport: named pipe (Windows) / Unix socket (Linux) preferred; fall back to `127.0.0.1` with a random per-boot bearer token passed to the shell supervisor at launch. **Two capability tiers:**

| Tier | Caller | Endpoints |
|---|---|---|
| **Shell** (untrusted-ish; runs in/near the kiosk user context) | Kiosk UI | `GET /local/v1/status`, `GET /local/v1/inbox` (names shown only if staff-authorized), `POST /local/v1/inbox/{id}/open` (decrypt into workspace), `POST /local/v1/session/request-end` (asks supervisor to end; cannot influence wipe mode) |
| **Supervisor** (service account; unreachable from kiosk account via ACL) | Agent internals / launcher | `POST /local/v1/session/start`, `POST /local/v1/session/end`, `POST /local/v1/wipe/verify`, `POST /local/v1/update/apply` |

There is **no parameter anywhere** to skip, shorten or weaken a wipe. The shell can only *request* an end.

### 10.7 Steps for the harness

1. DB models + Alembic migration for hub (`users`, `refresh_tokens`, `audit_events`, `rate_limits`).
2. `passwords.py` (above) with tests: wrong password, unknown user (timing within tolerance), rehash upgrade, pepper rotation.
3. Token service (issue/verify/rotate/reuse-detection) with tests, including reuse-detection killing the family.
4. Auth router + dependencies `require_role("owner")`.
5. Bootstrap flow.
6. Rate limiting on login: 5 attempts / 15 min per (username) **and** 20 / 15 min per source IP; progressive lock (1 min → 5 → 15 → 60); return identical error for unknown user and wrong password.
7. Agent skeleton: settings, local API app, status endpoint, signed-request client to hub, health checks.
8. Structured logging + request IDs.
9. OpenAPI export to `docs/openapi-hub.json` and a Postman collection generated from it (`scripts/export_postman.py`).

### 10.8 Definition of Done (Phase 1)

- Fresh install → bootstrap owner → login → create operator → operator logs in → refresh rotates → reuse of old refresh token revokes family. All covered by integration tests (`httpx.AsyncClient` against the ASGI app).
- No plaintext secrets/passwords/tokens in DB, logs or error bodies (test greps log output).
- Login timing for unknown user vs. wrong password within a statistically reasonable tolerance (test with ≥ 50 samples).
- `mypy --strict` clean; coverage ≥ 85 % on new code.

---

## 11. Phase 2 — Custom endpoint generation (Cloudflare Tunnel)

**Goal:** each shop gets a public, trustworthy URL — `vault.laddu.cc/<slug>` — that reaches *its* hub, created automatically. This is requirement #2.

### 11.1 The design decision you must understand first

Cloudflare Tunnels route by **hostname**, not by path. You have two options to get `vault.laddu.cc/mycafe1`:

| Option | How | Pros | Cons |
|---|---|---|---|
| **A (recommended): Worker gateway** | One public hostname `vault.laddu.cc`. A Cloudflare Worker reads the first path segment (`mycafe1`), looks up the shop's tunnel origin hostname (stored in Workers KV, written by the manager), strips the prefix and proxies the request to that origin. Each shop has its own tunnel + origin hostname like `c-7f3a9b.laddu.cc` | Exactly the URL you want; tunnels are isolated per shop | Needs a Worker; one more moving part |
| **B: Subdomain per shop** | `mycafe1-vault.laddu.cc` → tunnel directly | Simplest; no Worker | Doesn't match your URL format |

Use **A** for production, **B** as the fallback/dev mode (feature flag `ENDPOINT_MODE=path|subdomain`). Record in ADR 0004.

> **Certificate gotcha:** Cloudflare's free Universal SSL covers `laddu.cc` and `*.laddu.cc` (one level). A name like `mycafe1.vault.laddu.cc` (two levels) is **not** covered without a paid certificate product. Keep origin hostnames single-level, e.g. `c-7f3a9b.laddu.cc`.

### 11.2 Slug rules (anti-impersonation, T5)

- Regex: `^[a-z0-9](?:[a-z0-9-]{1,28}[a-z0-9])$` (3–30 chars, ASCII only, no leading/trailing hyphen, no `--`).
- Reserved list: `admin, api, www, manager, vault, support, help, status, login, static, assets, d, p, .well-known`, plus anything starting with `akshaya`, `gov`, `csc`, `uidai`, `bank`, `official` unless the cafe is flagged `verified` by an admin.
- Confusable check: normalize (`0→o`, `1→l`, `rn→m`, `vv→w`, strip hyphens) and reject if the normalized form collides with an existing slug's normalized form.
- Slugs are **immutable once active** (changing breaks printed links); admins can disable and re-issue.
- A `verified` badge (shown on the portal page) is set only by a human admin after checking the shop's identity — that is the "credibility" feature of your brief.

### 11.3 Provisioning workflow (manager)

```
Cafe owner/admin requests slug
        │
        ▼
POST /api/v1/endpoints  {cafe_id, slug}
        │  validate slug rules, uniqueness
        ▼
status = provisioning
        │
        ├─ 1. Cloudflare: create tunnel (config_src = cloudflare)         → tunnel_id
        ├─ 2. Cloudflare: GET tunnel token                                → tunnel_token
        ├─ 3. Cloudflare: PUT tunnel configuration (ingress):
        │        hostname = c-<shortid>.laddu.cc  → service http://localhost:8443
        │        final rule → http_status:404
        ├─ 4. Cloudflare: create DNS CNAME (proxied)
        │        c-<shortid>.laddu.cc → <tunnel_id>.cfargotunnel.com
        ├─ 5. Cloudflare: write KV  slug → {origin: "c-<shortid>.laddu.cc", verified: bool}
        └─ 6. Store endpoint row, status = active
        │
        ▼
Hub fetches its tunnel token (signed request) → starts `cloudflared tunnel run --token …`
```

Cloudflare API calls (verify against current docs; the harness must wrap them in `services/cloudflare.py` behind an interface so tests use a fake):

```
POST   /accounts/{account_id}/cfd_tunnel                         {name, config_src:"cloudflare"}
GET    /accounts/{account_id}/cfd_tunnel/{tunnel_id}/token
PUT    /accounts/{account_id}/cfd_tunnel/{tunnel_id}/configurations   {config:{ingress:[…]}}
POST   /zones/{zone_id}/dns_records                              {type:"CNAME", name, content, proxied:true}
PUT    /accounts/{account_id}/storage/kv/namespaces/{ns}/values/{slug}   (Workers KV write)
DELETE …  (for teardown)
```

Rules:
- The Cloudflare API token used by the manager is **scoped** (Tunnel:Edit, DNS:Edit for the one zone, KV:Edit for the one namespace) and stored as a secret — never given to shops.
- The shop only ever receives its own **tunnel token**, which can run only that tunnel.
- Provisioning is **idempotent and resumable**: persist each step; on retry, skip completed steps. A reconciliation job (every 10 min) compares DB ↔ Cloudflare and repairs drift.
- Teardown (`DELETE /endpoints/{slug}`): remove KV key first (stop routing), then DNS, then tunnel; revoke the device's tunnel token by deleting/rotating the tunnel.

### 11.4 Hub side

- `services/tunnel.py` manages `cloudflared`: downloads a **pinned, hash-verified** `cloudflared` binary (version + SHA-256 in the signed release manifest, §16), runs `cloudflared tunnel --no-autoupdate run --token <token>` as a child/service, restarts with backoff, exposes tunnel status on `/readyz`.
- Token stored in OS credential store, never on disk in plaintext.
- Hub honours `X-Forwarded-Prefix: /mycafe1` when building absolute links in API responses; otherwise relative links.

### 11.5 Gateway Worker (TypeScript sketch)

```ts
export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    const url = new URL(req.url);
    const [, slug, ...rest] = url.pathname.split("/");        // "/mycafe1/d/ABC" → ["", "mycafe1","d","ABC"]
    if (!slug) return Response.redirect("https://laddu.cc", 302);
    if (!/^[a-z0-9][a-z0-9-]{1,28}[a-z0-9]$/.test(slug)) return new Response("Not found", { status: 404 });

    const rec = await env.SLUGS.get(slug, "json") as { origin: string; verified: boolean } | null;
    if (!rec) return new Response("Not found", { status: 404 });

    const upstream = new URL(req.url);
    upstream.hostname = rec.origin;
    upstream.pathname = "/" + rest.join("/");

    const headers = new Headers(req.headers);
    headers.set("X-Forwarded-Prefix", `/${slug}`);
    headers.set("X-Vault-Verified", rec.verified ? "1" : "0");
    headers.delete("X-Vault-Device"); headers.delete("X-Vault-Signature");   // public path must never carry device auth

    return fetch(new Request(upstream.toString(), { method: req.method, headers, body: req.body, redirect: "manual" }));
  },
};
```

Gateway rules: only `/p/*`, `/d/*`, `/static/*`, `/.well-known/*` are forwarded; **staff/device API paths are never routed through the public gateway.** Add Cloudflare WAF rate-limiting rules (per IP, per slug) and Turnstile on the portal page.

### 11.6 Endpoints (manager)

| Method | Path | Auth | Notes |
|---|---|---|---|
| POST | `/api/v1/endpoints` | admin or cafe-owner device token | Claim slug, start provisioning |
| GET | `/api/v1/endpoints/{slug}` | admin / owning device | Status |
| GET | `/api/v1/endpoints/{slug}/tunnel-token` | **hub device only, signed** | One-time-ish fetch; audit-logged |
| DELETE | `/api/v1/endpoints/{slug}` | admin | Teardown |
| POST | `/api/v1/endpoints/{slug}/verify` | admin | Set verified badge |

### 11.7 Definition of Done (Phase 2)

- Using a **fake Cloudflare client**, provisioning runs end-to-end, is idempotent when interrupted at every step (parametrized test kills after each step), and teardown leaves nothing behind.
- Slug validator passes a table of good/bad/confusable cases (≥ 40 cases).
- A staging run against a **real** Cloudflare zone (manual, documented in `docs/RUNBOOK.md`) produces a working `https://vault.laddu.cc/<slug>/healthz` through the tunnel.
- Test: staff API paths return 404 through the gateway.

---

## 12. Phase 3 — Auto-registration and `manager.py`

**Goal:** every installed hub/agent registers itself with *our* manager, which gives us the fleet view (and the business model). This is requirement #3.

### 12.1 `manager.py` — what it is

`apps/manager/manager.py` is the **single entrypoint** of the central service and its admin CLI (Typer):

```
python manager.py serve [--host 0.0.0.0 --port 8080]    # run the API (uvicorn)
python manager.py migrate                               # alembic upgrade head
python manager.py create-admin --email ...              # first admin (prompts for password)
python manager.py create-cafe --name "My Cafe" --owner-email ...
python manager.py issue-token --cafe <id> --role any --max-uses 25 --ttl 72h
python manager.py list-devices [--cafe <id>] [--stale 7d]
python manager.py revoke-device <device_id>
python manager.py publish-release <manifest.json> <manifest.sig>     # §16
python manager.py log-checkpoint                                     # print signed log head
```

The CLI and API share the same service layer, so behavior is identical.

### 12.2 Enrollment flow

```
 Owner buys/gets service  ──▶  admin runs: manager.py issue-token --cafe C --max-uses 25
                                          └─ token shown ONCE (only sha256 stored)

 Installer / first run on a machine:
   1. generate Ed25519 keypair locally; private key → OS credential store
   2. POST /api/v1/enroll   (unsigned, but token-gated, rate-limited)
        {
          "enrollment_token": "…",
          "role": "hub" | "agent",
          "public_key": "<b64u>",
          "app_version": "1.4.2", "image_version": "2025.10.1",
          "os": "Windows 11 23H2", "label": "Counter-2"
        }
   3. manager: validate token (hash match, not expired/revoked, uses < max, role allowed)
              → create device (status=active, or pending if admin-approval mode)
              → increment token usage atomically (single SQL UPDATE … WHERE used < max_uses)
              → return { device_id, cafe_id, cafe_slug?, manager_public_key, heartbeat_interval_s,
                         hub_directory:[{device_id, public_key, lan_address?}] }
   4. device stores device_id; from now on ALL requests are signed (§7.5)
```

Design notes:
- **Token = bearer secret.** 32 random bytes, base64url, displayed once, stored as SHA-256. Short TTL (default 72 h), `max_uses` for fleet installs. Revocable.
- **Admin-approval mode** (`pending` → `active`) is a per-cafe flag for higher-assurance deployments.
- **Re-enrollment** of an existing machine requires a new token; the old device record is revoked (prevents cloning a device identity silently).
- **Machine fingerprint:** do *not* collect invasive hardware IDs. Send a salted hash of OS install ID + hostname purely to detect cloned installs (two active devices with the same fingerprint → alert). Document this in the privacy notice.
- **Pin the manager:** the agent ships with the manager's TLS expectations (domain) and its **release root public key**; the enrollment response's `manager_public_key` is used to verify manager-signed messages (log countersignatures).

### 12.3 Heartbeat

`POST /api/v1/devices/{id}/heartbeat` (signed) every 60–300 s (jittered):

```json
{ "app_version":"1.4.2", "image_version":"2025.10.1", "uptime_s":86400,
  "state":"idle|in_session", "last_wipe_ok": true, "pending_wipes": 0,
  "clock_skew_s": 1, "tunnel_status":"up|down|n/a", "disk_free_mb": 20480 }
```

Response: `{ "server_time": "...", "update": null | {…offer…}, "directory_version": 12, "revoked": false, "message": null }`.

Rules:
- **No customer data in heartbeats. Ever.** Add a schema with `extra="forbid"` so adding fields requires a code change and review.
- If the manager is unreachable the machine **keeps working** (grace period, default 30 days, configurable per plan); queue heartbeats (bounded), back off exponentially. Enforcement for lapsed/suspended customers: after grace, show a notice and refuse *new* sessions — but never block wipes.
- `last_seen` > 2× interval → "stale"; > 7 d → "offline" in the fleet dashboard.

### 12.4 Admin/fleet API (manager)

| Method | Path | Auth | Purpose |
|---|---|---|---|
| POST | `/api/v1/admin/login` | none (rate-limited) | admin login (Argon2id + optional TOTP) |
| GET | `/api/v1/admin/cafes` | admin | list/search |
| POST | `/api/v1/admin/cafes` | admin | create |
| POST | `/api/v1/admin/cafes/{id}/tokens` | admin | issue enrollment token |
| GET | `/api/v1/admin/devices` | admin | filter by cafe/status/version/staleness |
| POST | `/api/v1/admin/devices/{id}/suspend` · `/revoke` | admin | |
| GET | `/api/v1/admin/fleet/summary` | admin | counts by version/ring/status; stale devices |
| GET | `/api/v1/admin/audit` | admin | audit trail |

Admin auth reuses the §10 login machinery (shared code in `vaultcommon`), **plus mandatory TOTP** for `superadmin`.

### 12.5 Definition of Done (Phase 3)

- Docker Compose (`infra/docker-compose.manager.yml`) brings up manager + Postgres + Caddy (TLS) locally.
- Enrollment works end-to-end with a real hub and agent; replayed enrollment request with an exhausted token is rejected; concurrent enrollments with `max_uses=1` produce exactly one success (race test).
- Signature verification rejects: bad signature, stale timestamp, reused nonce, revoked device, wrong device ID.
- `manager.py` CLI commands all work and are covered by tests (`typer.testing.CliRunner`).
- Fleet summary endpoint returns correct counts for a seeded dataset.

---

## 13. Phase 4 — Secure upload and sync (anti-forgery)

**Goal:** the customer's file reaches the shop *exactly* as sent, provably, and nobody can quietly swap or modify it later. This is requirement #4 ("sync files … to block attempts to forge a file or modify it").

### 13.1 What "sync" means in this system

Two sync relationships — implement both:

1. **Content sync (sender → hub → agent).** Chunked, resumable, hash-verified transfer of file bytes.
2. **Proof sync (hub → manager).** Only *hashes and metadata* are sent to the manager's transparency log, so neither the shop nor the sender can later dispute what was received. The manager never stores content.

> Why the manager doesn't store files: it would destroy your "we don't keep data" promise and make you a juicy target. The manager is a **notary**, not a warehouse.

### 13.2 Hashing scheme

- **Chunk size** `C` = 8 MiB (hub-configurable; sent to client at upload init). Last chunk may be smaller.
- **Chunk digest** `d_i = SHA-256(chunk_i_plaintext)`.
- **File ID / tree hash:**

```python
def tree_hash(chunk_digests: list[bytes], total_size: int, chunk_size: int) -> str:
    h = hashlib.sha256()
    h.update(b"vault-file-v1\x00")                 # domain separation
    h.update(chunk_size.to_bytes(4, "big"))
    h.update(total_size.to_bytes(8, "big"))
    for d in chunk_digests:                        # order matters → detects reordering
        h.update(d)
    return h.hexdigest()
```

This works in the browser with `crypto.subtle.digest("SHA-256", chunk)` per chunk — no need to stream-hash a 2 GB file in one pass.

### 13.3 Upload protocol (public portal API, mounted only on the tunnel listener)

| Step | Request | Hub behavior |
|---|---|---|
| 0 | `GET /p/{code}` | Return drop metadata: shop name, verified badge, limits, allowed types, whether PIN required, `e2ee_pubkey` if enabled. Constant-time code lookup via hash. 404 for unknown/expired (identical body) |
| 1 | `POST /p/{code}/uploads` `{display_name, size, chunk_count, pin?}` | Check quotas/types; create `uploads` row (`receiving`); generate DEK; return `{upload_id, chunk_size, upload_token}` (short-lived token bound to this upload) |
| 2 | `PUT /p/{code}/uploads/{id}/chunks/{idx}` body=chunk, header `X-Chunk-SHA256` | Recompute SHA-256; mismatch → `422 chunk_hash_mismatch`; encrypt (AES-GCM, AAD=`upload_id:idx`), write `blob_path`, upsert `chunks`. **Idempotent** — resending the same chunk with the same hash is a no-op |
| 3 | `GET /p/{code}/uploads/{id}` | Report which chunk indexes are present (resume support) |
| 4 | `POST /p/{code}/uploads/{id}/complete` `{chunk_digests:[…], tree_hash}` | Verify all chunks present; compare supplied digests with stored; recompute tree hash; mismatch → `409 tree_hash_mismatch` and **discard**. On success: status `verified`, create **signed receipt**, enqueue log submission |
| 5 | `GET /p/{code}/uploads/{id}/receipt` | Return receipt + hub signature |

Limits to enforce **before** reading bodies: `Content-Length` ≤ chunk_size + overhead, per-drop `max_files`/`max_bytes`, per-IP and per-drop request rate, total concurrent uploads per hub. Reject unknown chunk indexes. Use streaming reads with a hard cap — never `await request.body()` on an unbounded body.

```python
@router.put("/p/{code}/uploads/{upload_id}/chunks/{idx}", status_code=204)
async def put_chunk(code: str, upload_id: UUID, idx: int, request: Request,
                    x_chunk_sha256: str = Header(..., min_length=64, max_length=64),
                    ctx: UploadCtx = Depends(upload_context)):
    if not (0 <= idx < ctx.upload.chunk_count):
        raise ApiError("bad_chunk_index", 422)
    data = await read_capped(request, limit=ctx.settings.chunk_size_bytes + 1024)
    digest = hashlib.sha256(data).hexdigest()
    if not hmac.compare_digest(digest, x_chunk_sha256.lower()):
        raise ApiError("chunk_hash_mismatch", 422)
    await ctx.storage.put_chunk(ctx.upload, idx, data, digest)   # encrypts + atomic rename
```

Storage details:
- Write to `staging/<upload_id>/<idx>.part` → fsync → atomic rename to `.chunk`.
- Directory layout uses UUIDs only; permissions restricted to the service account.
- Disk-full and partial-write handling: delete the partial; return `507 insufficient_storage`.

### 13.4 Receipts (signed proof)

```json
{
  "v": 1,
  "receipt_id": "…uuid…",
  "cafe_slug": "mycafe1",
  "hub_device_id": "…",
  "drop_id": "…",
  "upload_id": "…",
  "tree_hash": "<hex>",
  "size": 12345678,
  "chunk_size": 8388608,
  "received_at": "2025-10-05T10:15:30Z",
  "hub_public_key": "<b64u>"
}
```

`hub_sig = Ed25519(canonical(receipt))`. The **filename is deliberately not in the receipt** (privacy; the customer already knows it). Optionally include `name_hash = SHA-256(salt || name)` if customers want to bind the name.

The portal shows the receipt and offers "Download receipt (.json)". A later verification (by customer, shop, or dispute handler) = recompute the file's tree hash → compare with `receipt.tree_hash` → verify `hub_sig` against the hub's public key → check the entry exists in the manager's transparency log.

### 13.5 Transparency log (manager)

Hub submits (signed request) `POST /api/v1/log/entries`:

```json
{ "receipt": {…as above…}, "hub_sig": "…" }
```

Manager:
1. Verifies the request signature and `hub_sig` over the receipt using the registered hub key; ensures `cafe_slug` matches the device's cafe.
2. Builds `entry_json = canonical({receipt, hub_sig})`, `entry_hash = SHA-256(prev_hash || entry_json)` (**hash chain**), inserts with the next `seq` **inside a serializable transaction** (or advisory lock) so the chain cannot fork.
3. Countersigns: `manager_sig = Ed25519(canonical({seq, entry_hash, prev_hash, logged_at}))`.
4. Returns `{seq, entry_hash, manager_sig, logged_at}`; hub stores `manager_ack_seq` and attaches it to the receipt (an "inclusion proof lite").

Extra integrity hooks:
- `GET /api/v1/log/checkpoint` → `{seq, head_hash, signed_by_manager}`; a nightly job **publishes the head hash externally** (e.g., a GitHub Gist/commit in a public repo, or tweet) so even we can't rewrite history quietly.
- `GET /api/v1/log/entries/{seq}` and `/log/verify?receipt_id=…` for dispute checks. Returns hashes/metadata only.
- If the manager is unreachable the hub **queues** submissions (bounded, persisted) and retries with backoff; receipts are still valid immediately, just without `manager_ack_seq` until synced. Show a "pending notarization" state.

### 13.6 Agent ↔ hub content sync (delivery to the kiosk)

1. Agent `GET /api/v1/inbox` (signed device request + staff-authorized flag) → list of `{upload_id, size, tree_hash, received_at, status}` (display names returned only when a staff user is authenticated on that agent).
2. Agent `GET /api/v1/inbox/{id}/manifest` → receipt + `hub_sig` + chunk digests. Agent **verifies the receipt signature** against the hub key it learned during enrollment.
3. Agent downloads chunks (`GET …/chunks/{idx}`), each ciphertext is decrypted by the hub-to-agent transport scheme: hub re-encrypts chunks for transport with a **per-delivery session key** exchanged via X25519 (or simply relies on TLS/LAN + signed requests in v1 — record the choice in an ADR; strongly prefer encrypting even on LAN).
4. Agent verifies every chunk digest, recomputes the tree hash, compares with the receipt's `tree_hash`. **Any mismatch → abort, do not open, alert staff, log an `integrity_failure` audit event.**
5. Decrypt/assemble **only into the session workspace** (§14). Never write plaintext outside the workspace.
6. `POST /inbox/{id}/ack` → hub marks `delivered`, sets `wipe_after = now + grace` (default 10 min), then crypto-shreds.

### 13.7 Anti-abuse on public upload

- Drops require a **staff-issued code** (10-char Crockford base32 ≈ 50 bits) + optional 4–6 digit PIN delivered via a second channel; unlimited anonymous upload to `/mycafe1` itself is **not** allowed.
- Per-drop quotas; per-IP rate limit; Turnstile token verified server-side on `POST /uploads`.
- Allow-list of extensions + **magic-byte sniffing** (e.g., `pdf, jpg, jpeg, png, docx, xlsx, txt` default). Block executables/scripts/archives by default; archive support only behind a flag with zip-bomb and zip-slip protection (cap decompressed size, ratio, entry count; never extract to computed paths).
- Optional hook: `scan_command` setting (ClamAV `clamdscan`) executed on the encrypted-then-decrypted-in-memory chunk stream or on delivery into the workspace; scanner failure = fail closed for risky types.
- Abuse reporting: `POST /p/abuse {code, reason}`; hub owner notified; manager can disable the slug.
- Never render uploaded content in the portal; never serve uploads back from public routes.

### 13.8 Optional hardening: end-to-end encryption (E2EE mode)

Because Cloudflare terminates TLS, enable E2EE for customers who need real assurance:

1. At drop creation, the hub generates an **X25519 keypair per drop**; private key stays in hub memory/secure store; public key goes in `GET /p/{code}`.
2. Portal (libsodium.js `crypto_box_seal` / PyNaCl `SealedBox`-compatible) encrypts each chunk to the drop public key *before* upload; chunk hashes are computed over **ciphertext** in this mode (the tree hash then covers ciphertext; add `plaintext_tree_hash` computed over plaintext inside the sealed metadata so the agent can verify after decryption).
3. Hub stores ciphertext as-is (still wraps with AES-GCM at rest), and the agent decrypts via the hub-provided private key only during delivery.

Mark this "v1.1" if time is short; design the data model now (`drops.e2ee_pubkey`) so it's additive.

### 13.9 Definition of Done (Phase 4)

- **Tamper tests (must all fail safely):** flip one bit in a chunk body, drop a chunk, reorder chunks, replay chunk with different data for the same idx, tamper stored blob (AES-GCM `InvalidTag`), edit receipt JSON (signature fails), swap two uploads' receipts, truncate file, upload > declared size.
- Resume test: kill the client after 40 % and complete from `GET …/uploads/{id}`.
- Property test: `tree_hash` equal for any chunking of identical data **only if** chunk_size is equal; differs when chunk_size differs (it's bound in the hash).
- Hash chain test: manager log verifies end-to-end; modifying any historical row breaks verification (provide `scripts/verify_log.py`).
- Large-file test: 1 GB upload on a laptop with memory usage staying flat (< 150 MB growth) — proves streaming.
- Public listener does not expose staff routes (route-table test).

---

## 14. Phase 4.5 — Retention and wipe engine (the core promise)

This is not in your numbered list, but it is *why the product exists*. It touches hub and agent.

### 14.1 Principles

1. **Crypto-shredding is primary.** Overwriting files on SSDs/flash is unreliable (wear-leveling, journaling, copy-on-write, backups, shadow copies). Make recovery pointless by ensuring plaintext never reaches disk unencrypted and then destroying keys.
2. **Plaintext lives in RAM or an ephemeral encrypted workspace.**
3. **Wipe is mandatory, unconditional, and idempotent.** It runs on session end, idle timeout, crash recovery, **and on every boot before anything else.**
4. **Verify, then record — without recording content.**

### 14.2 Session lifecycle (agent)

```
start_session():
    session_id = uuid
    K_s = os.urandom(32)                      # session key, in memory only (never persisted)
    ws = WorkspaceProvider.create(session_id, K_s)   # ephemeral encrypted volume/dir/tmpfs
    pending_wipes.add(session_id)             # persisted BEFORE the user gets control
    return ws.mount_path

end_session(reason):
    1. lock UI (stop accepting input)
    2. terminate all processes in the session sandbox/job object (platform layer)
    3. flush & unmount workspace
    4. zeroize K_s (best effort: overwrite bytearray; drop references)
    5. destroy workspace: delete container/volume file(s); remove directory tree
    6. purge side-channels: clipboard, browser profile dirs, recent-files lists, temp dirs, thumbnails cache,
       print spool, downloads folder, (platform layer lists them in a manifest)
    7. verify(): walk expected locations; assert empty; assert container gone
    8. record wipe result {session_id, started_at, ended_at, duration, result, bytes_destroyed_count?}   # NO names/content
    9. pending_wipes.remove(session_id) only if verify() passed; else keep + alert + retry loop
```

**Wipe-on-boot:** on agent start, before enabling the kiosk shell, process `pending_wipes` and run the full purge manifest regardless of recorded state. If the machine lost power mid-session, ciphertext remains but `K_s` never touched disk → unrecoverable by construction.

### 14.3 `WorkspaceProvider` interface (implementations are platform-specific)

```python
class WorkspaceProvider(Protocol):
    async def create(self, session_id: str, key: bytes) -> Workspace: ...
    async def destroy(self, ws: Workspace) -> None: ...
    async def verify_empty(self, ws: Workspace) -> VerifyResult: ...
    def purge_manifest(self) -> list[PurgeTarget]: ...      # clipboard, temp, profiles, spool, ...

# implementations
DevDirWorkspace        # dev/test only: temp dir (clearly flagged INSECURE)
LinuxTmpfsWorkspace    # tmpfs mount, size-capped, noexec,nosuid,nodev
WindowsVhdWorkspace    # ephemeral VHDX/encrypted container + restricted ACL (decision in §24)
```

The backend team ships the **interface, the lifecycle, the verification harness and the Dev/Linux implementations**; the sandbox team plugs in the Windows one. Keep the interface stable.

### 14.4 System-level hygiene (documented as installer/OS-hardening tasks the agent *checks* and reports)

- Disable hibernation (`powercfg /h off`); set `ClearPageFileAtShutdown=1` or place the pagefile on the ephemeral/encrypted volume; disable crash dumps; disable Windows Search indexing / thumbnails for the workspace; disable File History / System Restore on the workspace volume; exclude workspace from backup/VSS.
- Agent self-check on start: `hygiene_report()` returns pass/fail per item; failures appear in heartbeat (`hygiene_ok`) and in the staff UI.

### 14.5 Hub retention

- Every `uploads` row has `wipe_after = min(created_at + upload_retention_hours, delivered_at + grace)`.
- `retention.py` runs every minute: for each due upload → **crypto-shred** (delete wrapped DEK row/zero it) → delete chunk files → mark `wiped` → later hard-delete metadata (default: 7 days, then purge rows entirely; receipts are the only long-lived artifact and contain no filename/content).
- `PRAGMA secure_delete=ON` so deleted SQLite pages are zeroed; `VACUUM` weekly.
- DEK handling: DEK is wrapped by a hub KEK stored in the OS credential store. Rotate the KEK monthly (re-wrap live DEKs). Shredding a DEK row is enough to render its ciphertext useless.
- Expired drops: closed immediately; any `receiving` uploads for them are aborted and wiped.
- Manual "Wipe now" for staff, and an emergency **"Wipe everything"** owner action (requires password re-entry).

### 14.6 Wipe evidence (without breaking privacy)

Content-free wipe records: `{session_id_hash, started, ended, result, hygiene_ok, agent_version}` synced to the manager in aggregate (counts and last-result). This supports the credibility claim: *"This shop's machines wiped successfully N/N sessions this month."* The shop can show a verified wipe-stats badge sourced from the manager. Be careful in wording: it proves the *software ran and verified*, not an absolute guarantee.

### 14.7 Definition of Done (Phase 4.5)

- Property/integration tests: after `end_session`, workspace path does not exist; purge manifest locations empty; key bytes zeroized (best effort assertion on the bytearray).
- Crash test: kill the agent process mid-session (SIGKILL / taskkill) → restart → wipe-on-boot clears workspace before shell enable.
- Hub: delivered uploads vanish after grace; DB pages don't contain the display name afterwards (scan the `.db` file for known test strings → none found after `secure_delete` + wipe).
- Forensic-ish test (Linux CI): create session, write known canary string into workspace, end session, scan the entire temp filesystem area for the canary → not found.

---

## 15. Phase 5 — Login hardening

**Goal:** turn "login works" into "login is hard to attack." This completes requirement #5.

### 15.1 Controls to add

1. **Account lockout with backoff** (already started in Phase 1) — make it persistent, auditable, and owner-unlockable.
2. **Layered rate limiting:** per-username, per-IP, per-IP+username; token-bucket stored in SQLite (hub) / Postgres or Redis (manager). Cloudflare WAF rate limits on the public side.
3. **Password policy enforcement:** length, breached/common list, forbid username/shop-name as password, no reuse of last 5.
4. **TOTP 2FA (RFC 6238)** for owner and for all manager admins (`pyotp`); 10 single-use recovery codes stored hashed; TOTP secret encrypted at rest with the KEK. Mandatory for `superadmin`.
5. **Session binding:** access tokens carry `sid`; sessions record coarse device hint + issued-at; optional "bind refresh token to client key" for the agent (agent signs refresh requests with its device key → stolen refresh tokens are useless elsewhere).
6. **Step-up auth** for dangerous actions: wipe-everything, create user, change slug, issue enrollment token → require password (or TOTP) re-entry within the last 5 minutes.
7. **Audit trail:** every login success/failure, lockout, password change, role change, token issue/revoke, with actor + request id (no passwords, no IP beyond /24).
8. **Password reset:** hub has no email by default → owner-assisted reset (generates temp password + `must_change_password`), manager-assisted reset for owners via verified channel. No security questions.
9. **Uniform responses:** same status/body/latency class for unknown user vs wrong password vs locked-out (locked state may be conveyed only after correct password to avoid user enumeration — document the tradeoff in an ADR).
10. **Constant-time comparisons** (`hmac.compare_digest`) everywhere secrets are compared.

### 15.2 Hash upgrade path

Argon2 parameters are stored in the hash string. Implement `needs_rehash` on login (done in §10.2) and a config-driven "target params" so an update can raise cost across the fleet silently over time. Add a CLI/job report: `% of users on target params`.

### 15.3 Definition of Done (Phase 5)

- Brute-force simulation test: 100 rapid wrong guesses → account locked, rate-limit responses, audit events recorded; legitimate login works after unlock.
- TOTP flow tested with time-frozen clock including ±1 step drift and replay of the same code (rejected).
- Step-up required for listed actions (tests assert `403 step_up_required` without recent re-auth).
- Security review checklist (§21) items for auth all ticked.

---

## 16. Phase 6 — Automation, signed builds, auto-updates

**Goal:** when a vulnerability is found, you ship a fix and every machine updates itself — safely. This is requirement #6.

### 16.1 What gets updated ("images")

An **update bundle** is one or more signed artifacts:

| Artifact | Contents |
|---|---|
| `vault-app` | The exe/agent+hub binaries (PyInstaller/Nuitka output) |
| `vault-image` | The kiosk base image/sandbox template (whatever the sandbox team defines: base profile, hardening config, browser/PDF-viewer builds) |
| `cloudflared` | Pinned tunnel binary |
| `policy` | Hygiene/OS hardening policy files |

Each is a compressed archive (`.zst`/`.zip`) addressed by SHA-256.

### 16.2 Release manifest (what devices verify)

```json
{
  "v": 1,
  "release_id": "uuid",
  "version": "1.5.0",
  "channel": "stable",
  "severity": "security",
  "published_at": "2025-10-05T09:00:00Z",
  "expires_at":   "2025-12-05T09:00:00Z",
  "min_supported_version": "1.3.0",
  "notes_url": "https://vault.laddu.cc/releases/1.5.0",
  "artifacts": [
    {"name":"vault-app","url":"https://updates.laddu.cc/vault-app-1.5.0.zip",
     "sha256":"…","size":48211234},
    {"name":"vault-image","url":"…","sha256":"…","size":812345678}
  ],
  "rollout": {"rings":[{"ring":"canary","percent":100},{"ring":"early","percent":100},{"ring":"general","percent":100}],
              "force_by":"2025-10-12T00:00:00Z"}
}
```

Signed with an **Ed25519 release key**: `manifest_sig = sign(canonical(manifest))`.

### 16.3 Key management (the part people get wrong)

- **Root key** (offline; hardware token like a YubiKey, or an air-gapped machine). Its *public* half is compiled into every build. It signs **release keys** (delegation record with `not_before`/`not_after`).
- **Release key** (used to sign manifests; can sit in an HSM/cloud KMS or on a hardened signer). Rotatable: ship a new delegation signed by root.
- **CI never holds the root key.** CI holds *no* signing key at all in v1: CI builds + attests; a **human triggers signing** (a manual-approval GitHub Environment step that calls `scripts/sign_release.py` with the release key from a hardware token/KMS).
- Key ceremony documented in `docs/RUNBOOK.md`; `scripts/gen_release_keys.py` generates keys and prints fingerprints.
- Revocation: manifest field `revoked_release_ids` and `revoked_keys` lists; devices honour them.

> If this is too heavy for your timeline, start with a single offline release key and adopt the delegation layer later, but keep the verification code structured so adding it is non-breaking. When you outgrow it, consider adopting The Update Framework (TUF) via `python-tuf` rather than extending this by hand.

### 16.4 Device-side update flow (agent `updater.py`)

```
heartbeat response contains an "update offer" (or poll GET /api/v1/updates/check?version=…&ring=…)
        │
        ▼
1. fetch manifest + sig  (from manager; also try CDN) 
2. VERIFY, in this order — any failure aborts and reports `update_rejected`:
     a. manifest signature valid under a trusted (root-chained) release key
     b. now < expires_at
     c. release_id not revoked; release key not revoked
     d. version > current_version  (anti-rollback)  AND version ≥ min_supported_version
     e. channel matches device channel
3. download artifacts to a staging dir (resumable, range requests)
4. verify each artifact's SHA-256 + size against the signed manifest
5. WAIT until no active session (never interrupt a customer; for severity=critical past force_by,
   end idle sessions after warning staff)
6. A/B apply: install to inactive slot (versioned dir), keep previous slot
7. health check after restart: process up, local API answers, hub/tunnel up (if hub), self-test passes
8. success → mark slot active, report `applied`; failure/timeout (e.g. 3 min) → automatic rollback to previous slot, report `rolled_back` + error code
9. delete staging data; keep the last known-good slot only
```

```python
def verify_release(manifest: dict, sig: str, trusted_release_keys: list[str],
                   current: Version, now: datetime, revoked: set[str]) -> None:
    if not any(verify_obj(k, manifest, sig) for k in trusted_release_keys):
        raise UpdateRejected("bad_signature")
    if parse_utc(manifest["expires_at"]) <= now:
        raise UpdateRejected("manifest_expired")
    if manifest["release_id"] in revoked:
        raise UpdateRejected("revoked")
    v = Version(manifest["version"])
    if v <= current:
        raise UpdateRejected("rollback_or_same")
    if v < Version(manifest["min_supported_version"]):
        raise UpdateRejected("below_min_supported")
```

### 16.5 Rollout control (manager)

- Rings: `canary` (your own test machines) → `early` (friendly shops) → `general`. Manager assigns each device a ring (default `general`; admin can pin).
- Percentage ramps inside a ring using a **stable hash** of `device_id` (so a device doesn't flap in/out).
- **Kill switch:** `POST /admin/releases/{id}/revoke` stops new offers and tells devices (via heartbeat) to roll back if they're on it and a newer/older safe version exists.
- **Auto-halt:** if > X % of devices in a ring report `failed`/`rolled_back` within Y minutes, the manager pauses the rollout and alerts you.
- Security severity: `critical` sets a `force_by` deadline; devices apply at the first idle moment.

### 16.6 Build pipeline (GitHub Actions)

`ci.yml` on every PR: ruff → mypy → pytest (Linux+Windows) → bandit → `pip-audit` → coverage gate.

`release.yml` on tag `v*`:

1. Checkout; `uv sync --frozen` (lockfile with hashes).
2. Build exe (PyInstaller/Nuitka) on a **Windows runner**; build image artifacts as defined by sandbox team.
3. Generate **SBOM** (CycloneDX) and run vulnerability scans (`pip-audit`, `osv-scanner`, `trivy fs`). Fail on High/Critical unless an ADR-recorded exception exists.
4. **Code-sign the exe** (Windows Authenticode via your certificate/Azure Trusted Signing or an OSS signing service; timestamp the signature). Unsigned exes trigger SmartScreen/antivirus warnings, which will hurt adoption in shops.
5. **Build provenance:** GitHub artifact attestations / Sigstore `cosign` for CI-built artifacts (so you can prove which commit/workflow produced them).
6. Compute SHA-256 + sizes; assemble the unsigned manifest as a workflow artifact.
7. **Manual approval gate** → human runs `scripts/sign_release.py` (release key from hardware token/KMS) → uploads signed manifest → `manager.py publish-release`.
8. Artifacts uploaded to object storage/CDN (e.g., Cloudflare R2) under immutable paths.

`security-scan.yml` (scheduled daily): `pip-audit`, `osv-scanner`, Dependabot/Renovate config → opens PRs; a scheduled job opens a GitHub issue labelled `security` when a *new* advisory affects a pinned dependency.

### 16.7 "Automatically install new images when a vulnerability is found" — the real workflow

```
New CVE / advisory → scheduled scan flags affected dependency or base image
   → bot PR (bump pin) → CI green → you review & merge
   → tag vX.Y.Z (severity=security)
   → release.yml builds, scans, signs (manual gate)
   → manager publishes; canary ring gets it within minutes
   → auto-halt watches failures; ramp to early → general
   → fleet dashboard shows % updated, stragglers highlighted
```

Fully unattended deployment of *code you didn't review* is a supply-chain risk. Automate detection, PR creation, building and scanning; keep **human approval before signing**. Say so in your trust documentation.

### 16.8 Scripts to deliver

| Script | Purpose |
|---|---|
| `scripts/dev_up.sh` / `.ps1` | Start manager+Postgres+hub+agent locally with seed data |
| `scripts/gen_release_keys.py` | Generate root/release keys, print fingerprints, never print private keys unless `--export` |
| `scripts/sign_release.py` | Sign a manifest with a given key source (file/KMS/YubiKey), verify before output |
| `scripts/build_exe.ps1` | PyInstaller/Nuitka build with pinned flags |
| `scripts/verify_log.py` | Verify transparency-log hash chain |
| `scripts/export_postman.py` | OpenAPI → Postman collection |
| `scripts/loadtest_upload.py` | Locust/async stress test of chunk uploads |

### 16.9 Definition of Done (Phase 6)

- End-to-end test (docker compose + fake artifacts): publish release → canary agent updates → health check passes → ring ramp works → forced bad release triggers automatic rollback and auto-halt.
- Negative tests: tampered artifact (hash mismatch), valid-but-expired manifest, downgrade attempt, manifest signed by an unknown key, manifest with a revoked release key — all rejected, all produce `update_rejected` telemetry.
- Release pipeline runs on a test tag and produces: signed exe (test cert OK), SBOM, scan report, unsigned manifest awaiting approval.
- `docs/RUNBOOK.md` contains the key ceremony and "emergency revoke" steps.

---

## 17. Testing strategy

| Layer | Tools | What |
|---|---|---|
| Unit | pytest, hypothesis | crypto, hashing, canonical JSON, slug rules, version logic |
| Service | pytest-asyncio, SQLite/Postgres test containers | repositories, token rotation, retention |
| API | httpx `AsyncClient` | all endpoints, auth matrix (anon/operator/owner/device/wrong-device) |
| Contract | OpenAPI snapshot test | accidental API changes fail CI |
| Integration | docker compose (manager+pg+hub+agent) | enroll → provision (fake CF) → upload → deliver → wipe |
| Security | custom tamper suite, bandit, `schemathesis` fuzzing against OpenAPI | §13.9 list, auth bypass attempts, oversized/malformed bodies |
| Load | locust | 20 concurrent 500 MB uploads on a modest PC; login storm |
| Chaos | scripted kills | kill hub/agent mid-upload / mid-wipe / mid-update; disk full; clock skew ±5 min |
| Manual | checklist in RUNBOOK | real Cloudflare tunnel, real Windows machine, SmartScreen behavior |

Auth matrix test pattern: for **every route**, a parametrized test asserts the exact allowed principal set and `401/403` for all others. Generate this table from the router so new routes without a test fail CI.

---

## 18. Deployment

### 18.1 Manager (cloud)

- Small VPS (2 vCPU/4 GB is plenty) or a managed container platform; Docker Compose: `manager`, `postgres`, `caddy` (automatic TLS). Postgres daily backups (encrypted), tested restores.
- Secrets via Docker secrets/env files with 0600 perms; **no** release signing key on this server.
- Put the manager behind Cloudflare as well (proxied), restrict admin routes by Cloudflare Access/IP allow-list.
- Run migrations on deploy (`manager.py migrate`) with a lock; keep rollbacks possible.

### 18.2 Hub and agent (shop PCs, Windows primary)

- Install as **Windows services** (service wrapper such as NSSM/`pywin32` service or the launcher the installer team provides), running as a dedicated low-privilege service account with ACLs on `data_dir`.
- Auto-restart on failure; recovery actions configured by installer.
- `cloudflared` managed by the hub (§11.4).
- Firewall: hub LAN API reachable only from enrolled agent IPs/subnet if possible; public portal only via loopback to `cloudflared`.
- Single-PC mode: `vault-node --role both`.

### 18.3 Environments

`dev` (all local, fake Cloudflare) → `staging` (real Cloudflare zone `staging-vault.laddu.cc`, 2–3 real PCs) → `prod`. Keep separate Cloudflare tokens, DBs and signing keys per environment.

---

## 19. Observability and operations

- **Logs:** structlog JSON; fields: `ts, level, service, request_id, route, status, duration_ms, device_id?, cafe_id?`. Redaction processor enforced and unit-tested. Hub logs rotate (7 days) and live in `data_dir/logs`; **never** contain filenames/content.
- **Metrics (manager):** Prometheus endpoint `/metrics` (admin-only): enrolled devices, active devices, stale devices, update success rate, log append latency, provisioning failures.
- **Alerts:** device stale > 24 h (only if it was active), update failure spike, wipe failure reported, log append errors, certificate/token expiry in 14 days, Cloudflare reconciliation drift.
- **Health:** `/healthz` (process), `/readyz` (dependencies). Agent surfaces its health to the shell UI.
- **Runbook topics:** key ceremony, emergency revoke, restoring the manager, re-provisioning a tunnel, rotating peppers/KEKs, handling an abuse report, handling a customer dispute using receipts + log.
- **Privacy of telemetry:** coarse country only, no IPs stored beyond rate limiting windows, document everything the manager collects in a public privacy page.

---

## 20. Legal and compliance notes (India)

*This is engineering guidance, not legal advice — get a lawyer to review before launch.*

- **DPDP Act 2023 / rules:** as a processor/fiduciary of personal data (IDs, certificates, photos), you need a clear notice, purpose limitation, retention limits, breach-reporting process, and a grievance contact. Your "wipe after use" design is a strong fit, but document it.
- **Aadhaar and other sensitive IDs:** handling rules for Aadhaar numbers/copies are strict (masking, storage limits, restrictions on who may collect). Default behavior should support **masked previews** and never log document contents; get legal guidance before marketing Aadhaar-specific features.
- **IT Act / intermediary obligations:** you may receive takedown or law-enforcement requests; your architecture means there is nothing to hand over *by design* — still, define a process, and keep content-free audit evidence (receipts, wipe stats).
- **Akshaya/CSC program rules:** check whether Akshaya centers have contractual constraints on third-party software or on retaining records of service transactions. A shop may be *required* to keep some transaction records; make retention periods per-shop configurable *within safe bounds* (never retention of document contents by default).
- **Terms and trust page:** state what you collect, what you don't, the non-goals from §4, and how receipts/log verification work. Overclaiming ("military-grade", "100 % unrecoverable") is a liability.

---

## 21. Security checklist

Tick every box before any pilot with a real shop.

**Authentication & sessions**
- [ ] Argon2id with pepper; params tuned; rehash on login
- [ ] No default credentials; one-time bootstrap
- [ ] Refresh rotation + reuse detection; logout revokes family
- [ ] Rate limits + lockout; uniform error responses
- [ ] TOTP for owners/admins; recovery codes hashed
- [ ] Step-up auth on dangerous actions

**Transport & request integrity**
- [ ] TLS everywhere; HSTS on public hostnames
- [ ] Signed device requests with timestamp + nonce + body hash
- [ ] Public listener exposes *only* portal routes; staff/device routes unreachable via gateway
- [ ] CORS locked to portal origin; no wildcard with credentials
- [ ] Security headers on portal (CSP with nonce, `X-Content-Type-Options`, `Referrer-Policy: no-referrer`, `frame-ancestors 'none'`)

**Data handling**
- [ ] Plaintext never touches disk outside the session workspace
- [ ] AES-GCM at rest with AAD binding; DEKs shreddable
- [ ] Client filenames never used as paths; sanitized for display
- [ ] Magic-byte validation; extension allow-list; archive protections
- [ ] `secure_delete` on SQLite; wipe-on-boot verified
- [ ] Logs free of filenames/tokens/passwords (tested)

**Integrity**
- [ ] Chunk + tree hashes verified at every hop
- [ ] Receipts signed; transparency log hash-chained; head hash published externally
- [ ] Tamper test suite passes

**Supply chain & updates**
- [ ] Locked dependencies with hashes; scheduled audits
- [ ] SBOM + scans on every release
- [ ] Signed exe; attested build provenance
- [ ] Manifest signature, expiry, anti-rollback, revocation implemented and tested
- [ ] Root key offline; release signing behind human approval
- [ ] A/B update with automatic rollback

**Operations**
- [ ] Backups + restore drill for manager DB
- [ ] Incident runbook; abuse process; contact page
- [ ] Privacy notice published and matches reality

---

## 22. Per-phase prompts for the coding harness

Give the harness this whole README as context, then run **one phase prompt at a time**.

**Prompt template (use for every phase):**

> You are implementing **Phase N** of the Vault backend exactly as specified in README.md. Read §0 (rules), §7 (conventions), §8 (data model) and the Phase N section. Produce: (1) the code under the paths given in §6, (2) tests covering every item in the phase's Definition of Done, (3) Alembic migrations, (4) updated `docs/API.md` and OpenAPI export, (5) any ADRs for decisions you made. Run `ruff`, `mypy --strict`, and `pytest` and show the results. Do not implement anything from later phases. If the spec is ambiguous, choose the safer option and document it in an ADR. Finish by listing: files created, endpoints added, tests added, and any entries added to `docs/KNOWN_GAPS.md`.

**Phase-specific additions:**

- **Phase 0:** "Create the uv workspace, `vaultcommon` with all modules in §6, CI, pre-commit and the three ADRs. Include the hypothesis property tests listed in §9.3."
- **Phase 1:** "Implement hub auth (users, Argon2id+pepper, access/refresh tokens with rotation and reuse detection, bootstrap, rate limiting) and the agent skeleton with the two-tier local API contract in §10.6. Include the timing and log-redaction tests."
- **Phase 2:** "Implement manager endpoint provisioning behind a `CloudflareClient` protocol with a real (httpx) and a fake implementation, the slug validator with the confusable check, hub-side `tunnel.py`, and the Worker gateway in `apps/gateway`. Provisioning must be idempotent and resumable; include the kill-after-each-step test."
- **Phase 3:** "Implement `manager.py` (Typer CLI + FastAPI), enrollment with atomic token consumption, signed-request verification with nonce store, heartbeat, fleet APIs, admin login with TOTP, and the Docker Compose stack."
- **Phase 4:** "Implement drops, the chunked upload protocol, encrypted staging storage, receipts, the manager transparency log with hash chaining, the agent inbox sync with full verification, and the entire tamper test suite in §13.9."
- **Phase 4.5:** "Implement the session lifecycle, `WorkspaceProvider` interface with Dev and Linux implementations, wipe-on-boot, hub retention worker with crypto-shredding, and the canary-scan forensic test."
- **Phase 5:** "Harden login per §15: persistent lockout, layered rate limits, password policy with common-password list, TOTP with recovery codes, step-up auth, audit trail, and rehash reporting."
- **Phase 6:** "Implement the release manifest/signing scripts, manager release publishing + ring rollout + auto-halt, the agent updater with A/B apply and rollback, and the GitHub Actions workflows from §16.6. Include all negative update tests."

**After each phase, run this review prompt:**

> Act as a hostile security reviewer. Using §4 (threat model) and §21 (checklist), list concrete ways the Phase N code could be attacked or could leak data. For each, propose a fix and add a regression test. Do not weaken any existing control.

---

## 23. Milestone plan

A realistic schedule for one backend developer working part-time alongside a final-year course load. Adjust to your team size.

| Weeks | Milestone | Outcome |
|---|---|---|
| 1 | Phase 0 | Repo, CI, `vaultcommon`, ADRs |
| 2–3 | Phase 1 | Hub login + agent skeleton; Postman collection |
| 4 | Phase 2 | Provisioning with fake CF; gateway; staging run with real CF |
| 5–6 | Phase 3 | Manager, enrollment, heartbeats, fleet view, CLI |
| 7–9 | Phase 4 | Chunked upload, receipts, transparency log, agent sync, tamper tests |
| 10 | Phase 4.5 | Session/wipe engine, retention, canary tests |
| 11 | Phase 5 | Login hardening, TOTP, audit |
| 12–13 | Phase 6 | Signed releases, updater, CI/CD, rollout controls |
| 14 | Hardening | Security review pass, load/chaos tests, docs, demo script |

**Demo script for your project evaluation (suggested):**
1. `manager.py create-cafe` + `issue-token` → install on a clean VM/PC → machine appears in fleet view.
2. Claim slug `mycafe1` → portal live at `vault.laddu.cc/mycafe1/d/<code>`.
3. Upload a PDF from a phone → receipt shown → verify receipt offline with `scripts/verify_receipt.py`.
4. Open the file on the kiosk → end session → show wipe result and canary scan finding nothing.
5. Tamper with a stored chunk → show the agent refusing the file.
6. Publish a new signed release → canary machine updates; publish a bad one → automatic rollback.

---

## 24. Open questions to settle with your team

These affect design but not the first three phases, so decide them early but don't block on them.

1. **Sandbox technology** (Windows-only?). Options include Windows Sandbox (needs Pro/Enterprise), a throwaway local user profile plus ephemeral encrypted VHDX, or a purpose-built restricted desktop. This decides the Windows `WorkspaceProvider`.
2. **Who builds the portal frontend?** The backend defines the API; the page itself is a small static app (vanilla JS + `crypto.subtle` + libsodium).
3. **Do you target one PC per shop or many?** Many → LAN hub; one → `--role both`. Confirm the LAN assumptions (static IP/mDNS for hub discovery).
4. **Code-signing certificate:** which provider/budget? (Needed before any real pilot.)
5. **E2EE in v1 or v1.1?** The data model supports it; implementation can follow.
6. **Business-model enforcement:** what exactly happens on lapsed payment? (§12.3 suggests: grace period, then block new sessions, never block wipes.)
7. **Offline shops:** how many days of manager outage must the product tolerate?
8. **Languages:** Malayalam/English UI strings — backend should return stable error *codes*, UI translates.
9. **Where do release artifacts live?** Cloudflare R2 vs. S3 vs. GitHub Releases.

---

## 25. Appendix — API reference, env vars, snippets

### Appendix A — Endpoint summary

**Hub (staff + device listener, LAN/loopback)**

| Method | Path | Principal |
|---|---|---|
| POST | `/api/v1/bootstrap` | one-time code |
| POST | `/api/v1/auth/login` · `/refresh` · `/logout` · `/change-password` | anon / refresh / access |
| GET | `/api/v1/auth/me` | staff |
| GET/POST/PATCH | `/api/v1/users[/{id}]` | owner |
| POST/GET/DELETE | `/api/v1/drops[/{id}]` | staff |
| GET | `/api/v1/inbox` · `/inbox/{id}/manifest` · `/inbox/{id}/chunks/{idx}` | agent (signed) |
| POST | `/api/v1/inbox/{id}/ack` | agent (signed) |
| POST | `/api/v1/wipe/{upload_id}` · `/wipe-all` | staff / owner+step-up |
| GET | `/healthz` · `/readyz` · `/.well-known/vault-hub.json` | anon |

**Hub (public portal listener, tunnel-facing only)**

| Method | Path | Principal |
|---|---|---|
| GET | `/p/{code}` | drop code |
| POST | `/p/{code}/uploads` | drop code (+PIN, Turnstile) |
| PUT | `/p/{code}/uploads/{id}/chunks/{idx}` | upload token |
| GET | `/p/{code}/uploads/{id}` | upload token |
| POST | `/p/{code}/uploads/{id}/complete` | upload token |
| GET | `/p/{code}/uploads/{id}/receipt` | upload token |
| POST | `/p/abuse` | anon (rate-limited) |
| GET | `/static/*` · `/d/{code}` | anon (portal assets) |

**Manager**

| Method | Path | Principal |
|---|---|---|
| POST | `/api/v1/enroll` | enrollment token |
| POST | `/api/v1/devices/{id}/heartbeat` | device (signed) |
| GET | `/api/v1/updates/check` | device (signed) |
| GET | `/api/v1/releases/{version}/manifest` | device (signed) |
| POST/GET/DELETE | `/api/v1/endpoints[/{slug}]` | admin / device |
| GET | `/api/v1/endpoints/{slug}/tunnel-token` | hub device (signed) |
| POST | `/api/v1/log/entries` | hub device (signed) |
| GET | `/api/v1/log/checkpoint` · `/log/entries/{seq}` · `/log/verify` | public (read-only, no content) |
| POST | `/api/v1/receipts/verify` | public |
| * | `/api/v1/admin/*` | admin (+TOTP) |

### Appendix B — Stable error codes

`invalid_request, unauthorized, forbidden, step_up_required, not_found, conflict, rate_limited, account_locked (only after valid password), token_expired, token_reuse_detected, bad_signature, stale_timestamp, nonce_replayed, device_revoked, enrollment_token_invalid, enrollment_token_exhausted, slug_invalid, slug_taken, slug_reserved, provisioning_failed, drop_expired, drop_quota_exceeded, file_type_not_allowed, bad_chunk_index, chunk_hash_mismatch, tree_hash_mismatch, upload_incomplete, insufficient_storage, integrity_failure, update_rejected, wipe_failed, internal_error`

### Appendix C — Environment variables (excerpt)

| Variable | Service | Meaning |
|---|---|---|
| `VAULT_MGR_DB_URL` | manager | Postgres DSN |
| `VAULT_MGR_CF_API_TOKEN_FILE` | manager | Scoped Cloudflare token file |
| `VAULT_MGR_CF_ACCOUNT_ID` / `_ZONE_ID` / `_KV_NAMESPACE_ID` | manager | Cloudflare IDs |
| `VAULT_MGR_BASE_DOMAIN` | manager | e.g. `laddu.cc` |
| `VAULT_MGR_ENDPOINT_MODE` | manager | `path` (Worker) or `subdomain` |
| `VAULT_MGR_SIGNING_PUBKEYS_FILE` | manager | trusted release public keys (verification only) |
| `VAULT_HUB_MANAGER_URL` | hub/agent | Manager base URL |
| `VAULT_HUB_PASSWORD_PEPPER_FILE` | hub | Pepper file path |
| `VAULT_HUB_DATA_DIR` | hub | Data directory |
| `VAULT_HUB_UPLOAD_RETENTION_HOURS` | hub | Hard retention ceiling |
| `VAULT_HUB_SCAN_COMMAND` | hub | Optional AV scan command |
| `VAULT_AGENT_WORKSPACE_PROVIDER` | agent | `dev`, `linux_tmpfs`, `windows_vhd` |
| `VAULT_AGENT_HEARTBEAT_S` | agent | Heartbeat interval |
| `VAULT_AGENT_ROOT_PUBKEY` | agent | Compiled-in default; env override only in dev builds |

### Appendix D — Minimal receipt verification (reference)

```python
def verify_receipt(file_path: Path, receipt: dict, hub_sig: str, hub_pub: str) -> bool:
    chunk_size = receipt["chunk_size"]
    digests, size = [], 0
    with file_path.open("rb") as f:
        while chunk := f.read(chunk_size):
            digests.append(hashlib.sha256(chunk).digest()); size += len(chunk)
    return (
        size == receipt["size"]
        and tree_hash(digests, size, chunk_size) == receipt["tree_hash"]
        and verify_obj(hub_pub, receipt, hub_sig)
    )
```

### Appendix E — Database hygiene snippets

```python
# SQLite connect hook (SQLAlchemy event)
@event.listens_for(Engine, "connect")
def _pragmas(dbapi_conn, _):
    cur = dbapi_conn.cursor()
    for p in ("journal_mode=WAL", "synchronous=NORMAL", "foreign_keys=ON",
              "secure_delete=ON", "busy_timeout=5000"):
        cur.execute(f"PRAGMA {p}")
    cur.close()
```

```sql
-- Atomic enrollment-token consumption (Postgres)
UPDATE enrollment_tokens
   SET used = used + 1
 WHERE token_hash = :h AND revoked_at IS NULL AND expires_at > now() AND used < max_uses
RETURNING id, cafe_id, role_allowed;
-- 0 rows => reject (exhausted / expired / revoked / unknown, identical response)
```

### Appendix F — Definition of "done" for the whole project

- All six phases (plus 4.5) DoD green in CI.
- A fresh Windows machine goes from installer → enrolled → tunnel live → first remote upload → delivered → wiped in under 15 minutes following `docs/RUNBOOK.md`.
- Security checklist (§21) fully ticked, with an external reviewer's pass on the auth, upload and update paths.
- Public trust page and privacy notice match the implemented behavior line by line.

---

*End of document. Build in order, keep every phase green, and never trade a security property for convenience without an ADR.*
