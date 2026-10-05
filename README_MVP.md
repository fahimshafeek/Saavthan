# Vault MVP — Two-File Architecture Guide

This is the simplified, clean MVP architecture for the **Vault** project. Instead of dozens of micro-packages, complex migrations, and external dependencies, the entire backend is implemented in **just two Python files**:

1. [`manager.py`](file:///home/fahim/projects/hackathons/hackathena/manager.py) — **Central Authority & Fleet Notary (Makers' Cloud Server)**
2. [`server.py`](file:///home/fahim/projects/hackathons/hackathena/server.py) — **Service Provider Node (Shop Hub + Kiosk Agent + Upload Portal)**

---

## 1. How the 6 Work Requirements are Met

| Requirement | Where it lives | Mechanism in the 2-File MVP |
|---|---|---|
| **1) Backend with Login** | `server.py` & `manager.py` | Staff authentication with **Argon2id** password hashing, pre-hashing with HMAC pepper, bearer session tokens, and mutual Ed25519 signed requests between server and manager. |
| **2) Custom Endpoint Generation** | `server.py` | Generates drop links formatted as `https://vault.laddu.cc/<slug>/d/<code>` (or `/p/<code>`), integrating with Cloudflare Tunnel to provide vanity, verifiable URLs for customers. |
| **3) Auto-Registration & Fleet Tracking** | `manager.py` | Admin issues single-use enrollment tokens (`manager.py issue-token`). Nodes auto-register (`server.py enroll`), exchange Ed25519 identity keys, and send periodic heartbeats reporting uptime and health. |
| **4) File Sync & Anti-Forgery** | `server.py` $\leftrightarrow$ `manager.py` | 8 MiB chunked upload with per-chunk SHA-256 validation, domain-separated Tree Hashing (`vault-file-v1`), AES-256-GCM chunk encryption at rest, signed Ed25519 receipts, and synchronization to manager's append-only **Transparency Log**. |
| **4.5) Retention & Obliteration (The Core Promise)** | `server.py` | Ephemeral kiosk workspaces created per session. Files are delivered exclusively into the workspace. On session end, keys are crypto-shredded, workspace files are deleted, and absence is verified. Includes **Wipe-on-Boot** recovery after unexpected power loss. |
| **5) Hashing Login** | `server.py` | Memory-hard Argon2id ($m=64\text{ MiB}, t=3, p=2$) with constant-time verification, progressive lockout (5 failures $\to$ 5-minute lockout), and rate limiting. |
| **6) Automated Scripts & Signed Builds** | `manager.py` | Manager signs and publishes release manifests with version and checksums (`manager.py publish-release`). Nodes detect security updates via heartbeats. |

---

## 2. Quickstart & How to Run with `uv`

### Step 1: Start Central Manager (Makers Cloud Server)
```bash
# Terminal 1: Run Manager on port 8000
uv run python manager.py serve --port 8000
```
Open **`http://localhost:8000/`** in your browser to access the **Central Maker Console** (`manager.html`):
- **Fleet Command:** View real-time enrolled nodes, active OS image versions, heartbeats, and update statuses.
- **Café Tenants:** Register new Akshaya centers and internet cafés (`slug`, `name`, `email`).
- **Enrollment Tokens:** Issue single-use or multi-use zero-trust node provisioning tokens with 1-click clipboard copy.
- **Signed OTA Releases:** Upload `.bin` firmware/OS images, specify severity (`normal`, `security`, `critical`), and publish Ed25519 digitally signed release manifests.
- **Transparency Log & Verifier:** View immutable notary entries and use the **Public Dispute Verifier** to test any customer deposit receipt tree hash.

---

### Step 2: Start Service Provider Node (Shop Hub + Kiosk Agent)
```bash
# Terminal 2: Run Hub Node on port 8443
uv run python server.py serve --port 8443
```
Open **`http://localhost:8443/`** in your browser to access the **Staff / Kiosk Console** (`server.html`):
- **First-Time Bootstrap / Login:** Creates the initial owner account using **Argon2id**.
  - *Edge Case (Lockout):* 5 consecutive failed attempts locks the login screen with a live visual countdown timer.
- **Node Auto-Registration (Cloudflare Vanity Endpoint):** Enter Central Manager URL (`http://localhost:8000`) and the token issued above to link the node and assign its vanity slug (`vault.laddu.cc/<slug>`).
- **Customer Drops:** Generate secure customer upload drops with custom labels, max size limits, and TTL expiry.
  - Generates Cloudflare vanity link: `https://vault.laddu.cc/<slug>/d/<code>`
  - Generates local test link: `http://localhost:8443/p/<code>`
- **Customer Portal View (`/p/<code>`):**
  - Drag-and-drop file upload.
  - **Client-Side Cryptographic Chunking:** File is sliced into 8 MiB chunks using the HTML5 File API.
  - **In-Browser Web Crypto SHA-256:** Per-chunk hash calculated and validated in real time.
  - **Domain-Separated Merkle Tree Hash:** Replicates the server-side tree hash in the browser before final commit.
  - **Digital Deposit Receipt:** Displays Ed25519 signature and Manager Notary Ack Sequence `#`, with 1-click **Receipt Download (.json)**.
- **Ephemeral Kiosk Sessions & Obliteration Engine:**
  - Start isolated ephemeral kiosk session (`/session/start`).
  - Deliver verified customer documents exclusively into the ephemeral workspace (`/deliver/<upload_id>`).
  - **BIG RED OBLITERATION BUTTON:** Executes immediate crypto-shredding, purges workspace directory from disk, and verifies zero file residual with instant confirmation badge.
- **Signed OTA System Updater:**
  - One-click "Check & Apply OTA Update Now" (`/system/check-update`).
  - Verifies Ed25519 signature, SHA-256 checksums, activates the new `.bin` image, and updates fleet status on the manager.

---

### Step 3: Run the Complete Automated Test Suite
```bash
uv run pytest test_mvp.py -v
```

---

## 3. Threat Model & Edge Case Safeguards

- **Anti-Forgery & Tamper Resistance:** Every chunk is verified against `X-Chunk-SHA256`. The tree hash binds chunk order, chunk size, and total file length. Any single modified byte causes upload rejection.
- **Crypto-Shredding & AES-256-GCM:** Uploads are encrypted at rest using per-upload Data Encryption Keys (DEKs) bound with coordinate AAD (`upload_id:idx`).
- **Wipe Verification:** Ephemeral workspaces are isolated under `data_server/workspaces/<session_id>`. At session termination, the directory is recursively deleted and verified empty before clearing `pending_wipes`.
- **Wipe-on-Boot (Crash Recovery):** If power is abruptly disconnected mid-session, the server checks `pending_wipes` on boot and purges residual directories before accepting any new kiosk sessions.
- **OTA Image Authenticity:** Downloaded `.bin` images are verified against both the manager's Ed25519 digital signature and the manifest's SHA-256 checksum before activation. Tampered images are rejected immediately without altering the active image slot.
- **Air-Gapped & Offline Ready:** Both `manager.html` and `server.html` have **ZERO external CDN dependencies** (no external fonts, scripts, or CSS frameworks). They run 100% self-contained in local internet cafe LANs.
