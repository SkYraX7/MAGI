# MAGI — Multi-source Adaptive Graph Intelligence

A distributed, real-time threat-detection and campaign-correlation platform. MAGI
ingests endpoint telemetry from Windows (Sysmon/EVTX) and Linux (eBPF/auditd), maps
relationships in a Neo4j graph, enriches indicators against live OSINT feeds, and
renders the threat landscape as a live 3D force-directed graph over WebSockets.

> Named after the MAGI supercomputer from *Neon Genesis Evangelion* — three specialized
> subsystems reasoning as one: the **Ingest layer** watches, the **Graph Engine**
> reasons, the **Visual Interface** reveals.

See [CLAUDE.md](CLAUDE.md) for the full architecture and [design-draft.md](design-draft.md)
for the original blueprint.

---

## Implementation status

| Phase | Scope | Status |
|-------|-------|--------|
| **1** | Dual-platform telemetry ingestion (Windows + Linux collectors) | ✅ implemented |
| **2** | Neo4j graph engine (schema, driver, ingest, lifespan) | ✅ implemented |
| **3** | Threat-intel pipeline & Redis cache | ✅ implemented |
| **4** | FastAPI backend (auth, REST, WebSocket) & React 3D UI | ✅ implemented |
| **5** | Hardening, alerting, observability, Docker | ✅ implemented |

---

## What's built

### Phase 1 — Telemetry ingestion (`collectors/`)

- **`shared/schema.py`** — `UnifiedLogEvent` Pydantic model. Both daemons validate
  against it; malformed events are logged and dropped, never silently swallowed.
  Process hashes are lowercased and timestamps coerced to UTC at the boundary.
- **`shared/queue.py`** — the process-wide `asyncio.Queue` singleton that decouples
  ingestion from enrichment. Import the helpers — never instantiate a queue inline.
- **`shared/runtime.py`** — shared SIGINT/SIGTERM graceful-shutdown wiring and a
  stdout JSON drainer (the Phase 1 acceptance behavior).
- **`windows/sysmon_collector.py`** — tails `Microsoft-Windows-Sysmon/Operational`
  and maps event IDs **1** (process), **3** (network), **7** (image load), **22**
  (DNS) to `UnifiedLogEvent`. The XML→event mapping is a pure, unit-tested function;
  the live subscription needs `pywin32` + Administrator.
- **`windows/sysmon_config.xml`** — minimum Sysmon ruleset capturing exactly those IDs.
- **`linux/ebpf_collector.py`** — loads eBPF probes via `bcc`; **falls back to an
  auditd log parser** when eBPF is unavailable. The sockaddr-hex decoder is unit-tested.
- **`linux/ebpf_probes.c`** — raw eBPF tracing `sys_enter_connect` + `sys_enter_execve`.

### Phase 2 — Graph engine (`backend/`)

- **`config.py`** — `pydantic-settings` singleton; all secrets from `.env`.
- **`graph/driver.py`** — async Neo4j driver singleton (pool capped at
  `NEO4J_MAX_CONNECTIONS`), connectivity verified with exponential-backoff retries;
  writes go through managed (auto-retrying) transactions.
- **`graph/schema.py`** — idempotent constraint + index creation (`IF NOT EXISTS`).
  Uniqueness constraints are what make `MERGE` deduplicate nodes.
- **`graph/ingest.py`** — `log_network_event` / `log_process_event` / `log_dns_event`
  (+ `log_event` dispatcher). `MERGE` everywhere, `ON CREATE SET first_seen` /
  `ON MATCH SET last_seen`, fully parameterized Cypher — no string interpolation.
- **`main.py`** — FastAPI app; lifespan initializes the schema on startup, starts the
  enrichment pipeline that drains the shared queue into the graph, and closes the
  clients on shutdown.

### Phase 3 — Threat-intel pipeline & cache (`backend/cache/`, `backend/enrichment/`)

- **`cache/redis.py`** — async Redis client singleton; named TTL constants (24h IP cache,
  12h domain cache, 30s dedup, 60s rate window); key builders; atomic dedup
  (`SET NX EX`) and per-minute rate-limit helpers.
- **`enrichment/pipeline.py`** — the worker pool (`ENRICHMENT_WORKER_COUNT`). Per network
  event: event-hash → 30s dedup → IP cache → parallel fan-out → confidence score →
  cache write → bridge a `Threat_Campaign` + emit `threat_flag` when malicious.
- **`enrichment/scoring.py`** — pure additive confidence scorer (VT / Censys / Feodo /
  Emerging weights, capped at 1.0).
- **`enrichment/virustotal.py`, `censys.py`** — OSINT enrichers; skip cleanly without
  keys, enforce rate limits, validate responses with Pydantic, retry 429 with backoff.
- **`enrichment/feeds/feodo.py`, `emerging.py`** (+ `base.py`) — daily IP blocklists with
  O(1) membership, line-format validation, disk-cache fallback, and stale-feed alerting.
- **`enrichment/notify.py`** — `threat_flag` seam (logs in Phase 3; WebSocket in Phase 4).

**Schema note:** `UnifiedLogEvent` was extended with an optional `command_line` field,
now populated from Sysmon ID 1 and persisted onto `Process` nodes and `SPAWNED` edges.

**Design note:** a feed hit is treated as *authoritative attribution* — a Feodo/Emerging
match bridges a campaign even when its additive score (Feodo +0.40 / Emerging +0.30) sits
below `THREAT_CONFIDENCE_THRESHOLD` (default 0.5). This is what makes the Phase 3 goal (a
Feodo-listed IP → `Threat_Campaign` within 30s) hold regardless of the threshold.

### Phase 4 — API, realtime & 3D UI (`backend/auth.py`, `backend/routers/`, `frontend/`)

- **`auth.py`** — RS256 JWT issue/verify, bcrypt passwords (used directly), `role`-claim
  RBAC (`get_current_user` / `require_admin`), WS handshake token check.
- **`routers/`** — `POST /auth/token`; `GET /graph/nodes` (paginated, `limit≤500`),
  `/graph/campaigns`, `/graph/host/{name}`; `DELETE /graph/prune` (admin); `GET /healthz`;
  `WS /ws/live-threats` (token validated on handshake, replays current graph on connect).
- **`realtime.py`** — in-memory `ConnectionManager` + `ws:sessions`; broadcasts
  `node_add` / `edge_add` / `threat_flag` / `prune` to all clients.
- **`frontend/`** — React 18 + Vite + TS. `useWsGraph.ts` (exponential-backoff reconnect
  with jitter, state preserved across reconnects), `ThreatGraph.tsx` (`react-force-graph-3d`),
  `colorMap.ts` (blue hosts → red malicious IPs → orange campaigns), JWT `AuthContext`.
- **Alerting** = **OS-level toasts** via the browser Web Notifications API (`notifications.ts`)
  — a `threat_flag` raises a real Windows/macOS toast; no backend alerter service.

### Phase 5 — Hardening, observability & Docker

- **`/healthz`** pings Neo4j + Redis (503 with detail on failure); **`/metrics`** Prometheus.
- **`graph/prune.py`** — `AsyncIOScheduler` ages out stale benign edges and broadcasts a
  `prune` message; never touches campaign-linked or malicious nodes.
- Rate limiting (slowapi), CORS locked to `ALLOWED_ORIGINS`, graceful-shutdown ordering.
- **`docker-compose.yml`** (Neo4j + Redis + backend + frontend, healthchecks, named
  volumes; Neo4j/Redis kept off host ports), Dockerfiles, and **`scripts/neo4j_backup.sh`**
  (nightly dump + retention, cron-ready).

---

## Quick start (dev)

> Requires Python 3.12+ (3.11 also works for the test suite).

```bash
# 1. Environment
python -m venv .venv
source .venv/Scripts/activate          # Windows: .venv\Scripts\activate
pip install -e ".[dev,backend]"        # core + test + enrichment (redis, httpx, …)
#   add the platform extra you need:
pip install -e ".[windows]"            # Windows collector (pywin32)
#   Linux: install bcc from distro packages (NOT pip) — needs kernel headers

# 2. Config
cp .env.example .env                   # then edit secrets
```

### Run a collector (Phase 1 — emits validated JSON to stdout)

```bash
# Windows (run as Administrator; Sysmon >= v15 installed with sysmon_config.xml)
python -m collectors.windows.sysmon_collector

# Linux (root, or: setcap 'cap_bpf,cap_perfmon+ep' $(which python3))
sudo python -m collectors.linux.ebpf_collector
```

### Run the full stack (Phases 2–5)

```bash
# Everything (Neo4j + Redis + backend + frontend) in containers:
docker compose up --build
#   frontend  -> http://localhost:3000   (login, live 3D graph)
#   backend   -> http://localhost:8000   (/healthz, /metrics, /docs)

# First, create the admin login (writes a bcrypt hash):
python -m backend.auth hash 'your-password'    # paste into ADMIN_PASSWORD_HASH in .env
```

### Run backend + frontend separately (dev)

```bash
# Backend (needs Neo4j + Redis — e.g. the test stack):
docker compose -f docker-compose.test.yml up -d
uvicorn backend.main:app --reload
# /healthz -> {"neo4j": "ok", "redis": "ok"}

# Frontend (Vite dev server proxies /auth, /graph, /ws to :8000):
cd frontend && npm install && npm run dev      # http://localhost:3000
```

---

## Tests

```bash
# Unit tests — no external services required
pytest tests/unit -q

# Integration tests — need a live Neo4j (auto-skipped if unreachable)
docker compose -f docker-compose.test.yml up -d
pytest -m integration
```

The unit suite covers schema validation, both collectors' pure parsers, the queue
singleton, config loading, and ingest parameter construction. The integration suite
verifies the Phase 2 acceptance goal: re-ingesting identical events produces **no
duplicate nodes**, and 1,000 events yield the expected node/relationship counts.

---

## Deploying Sysmon (Windows targets)

```powershell
# Install with the MAGI ruleset (elevated)
sysmon64.exe -accepteula -i collectors\windows\sysmon_config.xml
# Update an existing install
sysmon64.exe -c collectors\windows\sysmon_config.xml
```
