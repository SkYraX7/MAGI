# MAGI (Multi-source Adaptive Graph Intelligence)

> MAGI is the supercomputer from *Neon Genesis Evangelion*, a distributed system of
> three specialized minds (MELCHIOR-1, BALTHASAR-2, CASPER-3) that together make decisions no single
> unit could. This project mirrors that design: the **Ingest layer** watches, the **Graph Engine**
> reasons, the **Visual Interface** reveals.

A distributed, real-time threat detection and campaign-correlation platform. It ingests endpoint
telemetry from Windows (Sysmon/EVTX) and Linux (eBPF/auditd), maps relationships in a Neo4j graph
database, enriches indicators against live OSINT feeds, and renders the threat landscape as a live
3D force-directed graph streamed over WebSockets.

---

## Alternative Name Suggestions

| Name | Source | Why it fits |
|------|--------|-------------|
| **MAGI** *(recommended)* | Neon Genesis Evangelion | Distributed supercomputer; three subsystems that reason as one — mirrors this system's three pillars |
| **Argus** | Greek myth / *God of War*, *Hades* | The hundred-eyed giant — all-seeing monitor |
| **Batou** | Ghost in the Shell | Cyberpunk detective who operates in the network layer |
| **Oracle** | DC Comics / *Batman: Arkham* | The all-knowing intelligence broker |
| **Raiden** | Metal Gear Solid 2 | Cyborg operative who exposes hidden networks |

---

## Tech Stack

| Layer | Technology | Notes |
|-------|-----------|-------|
| Ingest daemons | Python 3.12+ | — |
| Windows events | `pywin32` / `winevt` | Sysmon Event IDs 1, 3, 7, 22 |
| Linux events | `bcc` (eBPF) | Kernel ≥ 5.8, `CAP_BPF`; auditd fallback |
| In-process bus | `asyncio.Queue` | Single-host; upgrade to Redis Streams for multi-host |
| Backend API | FastAPI 0.115+ | — |
| WebSockets | FastAPI / Starlette native | — |
| Graph DB | Neo4j 5.x | Community edition is fine for dev |
| Cache / dedup | Redis 7.x | — |
| OSINT HTTP | `httpx` + `asyncio` | Async fan-out |
| Auth | JWT RS256 | `python-jose` + `passlib[bcrypt]` |
| Config | `pydantic-settings` v2 | `.env` file; no hardcoded secrets |
| Task scheduling | `apscheduler` 3.x | Pruning daemon |
| Frontend | React 18 + Vite | TypeScript |
| 3D graph | `react-force-graph-3d` | Three.js / WebGL |
| Frontend auth | React Context + `jose` | Token in `sessionStorage` only |
| Containerization | Docker + Compose v2 | Named volumes for data persistence |
| Backend tests | `pytest` + `pytest-asyncio` | — |
| Frontend tests | Vitest + Playwright | — |
| Metrics | `prometheus-fastapi-instrumentator` | `/metrics` endpoint |

---

## Repository Layout

```
magi/
├── .env.example                  # Copy to .env and fill secrets — never commit .env
├── docker-compose.yml            # Full local stack
├── docker-compose.test.yml       # Integration test stack (ephemeral Neo4j + Redis)
├── CLAUDE.md
│
├── collectors/
│   ├── shared/
│   │   ├── schema.py             # Pydantic: UnifiedLogEvent
│   │   └── queue.py              # asyncio.Queue singleton + put/get helpers
│   ├── windows/
│   │   ├── sysmon_collector.py   # Tails Sysmon/Operational event channel
│   │   └── sysmon_config.xml     # Minimum Sysmon config (IDs 1, 3, 7, 22)
│   └── linux/
│       ├── ebpf_collector.py     # eBPF loader via bcc; falls back to auditd parser
│       └── ebpf_probes.c         # Raw eBPF C: sys_enter_connect + sys_enter_execve
│
├── backend/
│   ├── main.py                   # FastAPI app factory + lifespan hooks
│   ├── auth.py                   # JWT RS256 issue / verify; role extraction
│   ├── config.py                 # pydantic-settings Settings (singleton)
│   ├── routers/
│   │   ├── ws.py                 # /ws/live-threats WebSocket endpoint
│   │   ├── graph.py              # REST: nodes, campaigns, host subgraph
│   │   └── health.py             # /healthz liveness + readiness
│   ├── graph/
│   │   ├── driver.py             # Neo4j driver singleton (max 50 connections)
│   │   ├── ingest.py             # log_network_event / log_process_event / log_dns_event
│   │   ├── schema.py             # Constraint + index setup (runs once at startup)
│   │   └── prune.py              # APScheduler job: delete stale benign edges
│   ├── cache/
│   │   └── redis.py              # Redis client singleton + TTL constants + dedup helpers
│   └── enrichment/
│       ├── pipeline.py           # Async worker pool: consumes queue, fans out to enrichers
│       ├── virustotal.py
│       ├── censys.py
│       └── feeds/
│           ├── feodo.py          # Abuse.ch Feodo Tracker (daily text blocklist)
│           └── emerging.py       # Emerging Threats Open Ruleset
│
├── frontend/
│   ├── src/
│   │   ├── App.tsx
│   │   ├── auth/
│   │   │   ├── AuthContext.tsx   # JWT provider; expiry check on mount
│   │   │   └── LoginPage.tsx
│   │   ├── graph/
│   │   │   ├── ThreatGraph.tsx   # react-force-graph-3d wrapper
│   │   │   ├── useWsGraph.ts     # WebSocket hook with exponential-backoff reconnect
│   │   │   └── colorMap.ts       # Node / link colour rules
│   │   └── api/
│   │       └── client.ts         # Axios instance; auto-attaches Bearer token
│   ├── vite.config.ts
│   └── playwright.config.ts
│
├── keys/
│   ├── private.pem               # RS256 signing key — gitignored
│   └── public.pem                # RS256 verify key — safe to commit
│
└── tests/
    ├── unit/                     # No external deps
    ├── integration/              # Requires Neo4j + Redis
    └── e2e/                      # Playwright browser tests
```

---

## Environment Variables (`.env.example`)

```dotenv
# Neo4j
NEO4J_URI=bolt://localhost:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD=changeme

# Redis
REDIS_URL=redis://localhost:6379/0

# JWT — generate keys with: openssl genrsa -out keys/private.pem 2048
#                            openssl rsa -in keys/private.pem -pubout -out keys/public.pem
JWT_PRIVATE_KEY_PATH=./keys/private.pem
JWT_PUBLIC_KEY_PATH=./keys/public.pem
JWT_ALGORITHM=RS256
JWT_EXPIRE_MINUTES=480

# OSINT API keys (leave blank to skip that enricher; warning logged at startup)
VIRUSTOTAL_API_KEY=
CENSYS_API_ID=
CENSYS_API_SECRET=

# Enrichment
ENRICHMENT_WORKER_COUNT=4
THREAT_CONFIDENCE_THRESHOLD=0.5

# Pruning daemon
PRUNE_INTERVAL_SECONDS=3600
PRUNE_STALE_AFTER_HOURS=6

# CORS (comma-separated origins)
ALLOWED_ORIGINS=http://localhost:3000

# Admin credentials for MVP (replace with a real user store post-MVP)
ADMIN_USERNAME=admin
ADMIN_PASSWORD_HASH=<bcrypt hash>
```

---

## Unified Log Schema

All collectors emit `UnifiedLogEvent`. Both daemons validate against this Pydantic model before
enqueuing — malformed events are logged and dropped, never silently swallowed.

```python
# collectors/shared/schema.py
from pydantic import BaseModel
from datetime import datetime
from typing import Literal, Optional

class UnifiedLogEvent(BaseModel):
    timestamp: datetime
    platform: str                           # hostname or cloud instance ID
    event_type: Literal["process", "network", "image_load", "dns"]
    source_process: str
    process_hash: str                       # SHA-256; empty string if unavailable
    pid: int
    parent_process: Optional[str] = None
    parent_hash: Optional[str] = None

    # network event fields
    direction: Optional[Literal["inbound", "outbound"]] = None
    local_ip: Optional[str] = None
    local_port: Optional[int] = None
    remote_ip: Optional[str] = None
    remote_port: Optional[int] = None
    protocol: Optional[Literal["tcp", "udp"]] = None

    # dns event fields
    queried_domain: Optional[str] = None
```

**Why four event types?**
- `process` — execution chains for parent → child pivots
- `network` — TCP/UDP connections (primary threat signal)
- `image_load` — DLL side-loading and LOLBin detection (Sysmon ID 7)
- `dns` — domain-based C2; correlates with `Threat_Campaign` nodes via domain resolution

---

## Neo4j Schema

### Constraints (created once on startup in `graph/schema.py`)

```cypher
CREATE CONSTRAINT host_name     IF NOT EXISTS FOR (h:Host)            REQUIRE h.name    IS UNIQUE;
CREATE CONSTRAINT process_hash  IF NOT EXISTS FOR (p:Process)         REQUIRE p.hash    IS UNIQUE;
CREATE CONSTRAINT ip_address    IF NOT EXISTS FOR (i:IP_Address)      REQUIRE i.address IS UNIQUE;
CREATE CONSTRAINT domain_name   IF NOT EXISTS FOR (d:Domain)          REQUIRE d.name    IS UNIQUE;
CREATE CONSTRAINT campaign_name IF NOT EXISTS FOR (c:Threat_Campaign) REQUIRE c.name    IS UNIQUE;
```

All process hashes are normalized to **lowercase** before MERGE to prevent case-variant duplicates.

### Node Properties

| Node | Required | Optional |
|------|---------|---------|
| `Host` | `name` | `os`, `os_version`, `first_seen`, `last_seen` |
| `Process` | `hash` | `name`, `path`, `command_line`, `first_seen` |
| `IP_Address` | `address` | `enriched_at`, `vt_score`, `censys_asn`, `country`, `is_malicious` |
| `Domain` | `name` | `enriched_at`, `resolved_ips[]`, `is_malicious` |
| `Threat_Campaign` | `name` | `aliases[]`, `description`, `source_feed`, `first_seen` |

### Relationships

| Relationship | From → To | Key Properties |
|-------------|-----------|---------------|
| `RUNS` | Host → Process | `first_seen` |
| `SPAWNED` | Process → Process | `timestamp`, `command_line` |
| `CONNECTED_TO` | Process → IP_Address | `timestamp`, `port`, `protocol`, `direction` |
| `QUERIED` | Process → Domain | `timestamp` |
| `RESOLVES_TO` | Domain → IP_Address | `ttl`, `last_checked` |
| `PART_OF_CAMPAIGN` | IP_Address → Threat_Campaign | `confidence`, `source_feed` |
| `TARGETS` | Threat_Campaign → Host | `first_detected` |

### Core Cypher Ingest Pattern

```cypher
// network event upsert (ingest.py)
MERGE (h:Host {name: $platform})
ON CREATE SET h.first_seen = $timestamp
ON MATCH  SET h.last_seen  = $timestamp

MERGE (p:Process {hash: $process_hash})
ON CREATE SET p.name = $source_process, p.first_seen = $timestamp

MERGE (ip:IP_Address {address: $remote_ip})

MERGE (h)-[:RUNS]->(p)
MERGE (p)-[:CONNECTED_TO {port: $remote_port, protocol: $protocol, direction: $direction}]->(ip)
  ON CREATE SET r.timestamp = $timestamp
```

---

## API Reference

### Authentication

```
POST /auth/token
Body: { "username": "...", "password": "..." }
Returns: { "access_token": "<jwt>", "token_type": "bearer" }
```

All other endpoints require `Authorization: Bearer <token>`. WebSocket endpoint accepts the token
as a query parameter: `/ws/live-threats?token=<jwt>` (validated on handshake, not per-message).

### REST Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/healthz` | Liveness probe — pings Neo4j + Redis; returns 200 or 503 with detail |
| GET | `/metrics` | Prometheus metrics |
| GET | `/graph/nodes` | Paginated node list (`?type=IP_Address&page=1&limit=100`) |
| GET | `/graph/campaigns` | Active campaigns with connected host count and confidence |
| GET | `/graph/host/{name}` | Full 2-hop subgraph for a single host |
| DELETE | `/graph/prune` | Manually trigger pruning (requires `role=admin` in JWT) |

### WebSocket `/ws/live-threats`

**Server → Client messages:**

```jsonc
// New node discovered (normal traffic)
{ "type": "node_add", "data": { "id": "...", "label": "Host", "properties": {} } }

// New edge discovered
{ "type": "edge_add", "data": { "source": "...", "target": "...", "rel": "CONNECTED_TO" } }

// Enrichment confirmed a threat
{ "type": "threat_flag", "data": { "node_id": "185.220.101.5", "campaign": "LockBit", "confidence": 0.92 } }

// Pruning complete — remove these from the local graph state
{ "type": "prune", "data": { "removed_edge_ids": ["..."] } }
```

**Client → Server:**

```jsonc
{ "type": "ping" }   // keepalive; server replies { "type": "pong" }
```

---

## WebSocket Reconnection (Frontend — `useWsGraph.ts`)

Must implement **exponential backoff with jitter** to avoid thundering-herd reconnects on backend
restart:

```
delay_ms = min(base_ms * 2^attempt + random(0, 1000), 30_000)
```

- Reset `attempt` counter on a successful `open` event.
- Show a non-blocking "Reconnecting…" banner in the UI during the gap.
- Preserve the last-known graph state in React state so the graph doesn't wipe on reconnect.
- On reconnect, the server replays all currently-active nodes/edges via `node_add`/`edge_add`
  messages (backend must support this replay on new WS connection).

---

## Redis Key Patterns & TTLs

| Key Pattern | Type | TTL | Purpose |
|------------|------|-----|---------|
| `ip:{address}` | Hash | 24h | Enrichment result cache |
| `domain:{name}` | Hash | 12h | DNS enrichment cache |
| `dedup:{sha256_of_event}` | String ("1") | 30s | Short-window event deduplication |
| `ws:sessions` | Set | none | Active WebSocket connection IDs (managed by lifespan) |
| `rate:osint:{api_name}` | Counter | 60s | Per-minute API call rate limiter |
| `feed:feodo:last_updated` | String | none | Timestamp of last successful feed download |
| `feed:emerging:last_updated` | String | none | Timestamp of last successful feed download |

---

## Enrichment Pipeline

```
asyncio.Queue  (ENRICHMENT_WORKER_COUNT parallel consumers)
      │
      ▼
┌─────────────────────────────────────────────────────────┐
│ 1. Compute event hash (SHA-256 of remote_ip + port +    │
│    process_hash + timestamp rounded to 5s window)       │
│ 2. Dedup check:   GET dedup:{hash}  → skip if exists    │
│    SET dedup:{hash} "1" EX 30                           │
│ 3. Cache check:   HGETALL ip:{remote_ip}                │
│    → use cached result if not expired                   │
│ 4. Fan-out (asyncio.gather):                            │
│      - VirusTotal IP reputation                         │
│      - Censys IP tags                                   │
│      - Feodo blocklist membership                       │
│      - Emerging Threats membership                      │
│ 5. Compute confidence score (see below)                 │
│ 6. HSET ip:{remote_ip} … EX 86400                       │
│ 7. If score ≥ THREAT_CONFIDENCE_THRESHOLD:              │
│      - MERGE Threat_Campaign node in Neo4j              │
│      - SET ip.is_malicious = true                       │
│      - Push threat_flag to all WS clients               │
└─────────────────────────────────────────────────────────┘
```

**Confidence scoring (additive, capped at 1.0):**

| Signal | Weight |
|--------|--------|
| VirusTotal detections ≥ 5 engines | +0.50 |
| VirusTotal detections 1–4 engines | +0.20 |
| Censys tag: `scanner` or `tor-exit` | +0.20 |
| Feodo Tracker hit | +0.40 |
| Emerging Threats hit | +0.30 |

**API failure handling:**
- HTTP 429: exponential backoff (1s → 2s → 4s), give up after 3 retries, log warning, skip enricher
- Empty API key at startup: log warning once, skip enricher for all events
- Feed download failure: serve the last cached feed file on disk; emit an alert if file is >48h old

---

## Graph Pruning (`graph/prune.py`)

APScheduler `BlockingScheduler` background thread, interval from `PRUNE_INTERVAL_SECONDS`.

```cypher
-- Remove stale benign CONNECTED_TO edges
MATCH (p:Process)-[r:CONNECTED_TO]->(ip:IP_Address)
WHERE r.timestamp < datetime() - duration({hours: $stale_after_hours})
  AND NOT (ip)-[:PART_OF_CAMPAIGN]->()
  AND NOT ip.is_malicious = true
DELETE r;

-- Remove orphaned Process nodes (no remaining edges)
MATCH (p:Process)
WHERE NOT (p)-[]-()
DELETE p;
```

**Never prune:**
- `Threat_Campaign` nodes (retain indefinitely for historical analysis)
- Any node with `is_malicious = true`
- Any node with a path to a `Threat_Campaign`

After pruning, push a `{ "type": "prune", "data": { "removed_edge_ids": [...] } }` message to all
WebSocket clients so they can remove stale edges from the frontend graph state.

---

## Implementation Phases

### Phase 1 — Dual-Platform Telemetry Ingestion (Week 1)

**Goal:** Both daemons emit validated `UnifiedLogEvent` JSON to stdout for ≥10 minutes with no crashes.

**Deliverables:**
- `collectors/shared/schema.py` — `UnifiedLogEvent` Pydantic model
- `collectors/shared/queue.py` — `asyncio.Queue` singleton (import from here; do not instantiate inline)
- `collectors/windows/sysmon_collector.py` — tails `Microsoft-Windows-Sysmon/Operational`; emits IDs 1, 3, 7, 22
- `collectors/windows/sysmon_config.xml` — minimum Sysmon ruleset (committed; deploy to target hosts)
- `collectors/linux/ebpf_collector.py` — eBPF via `bcc`; graceful fallback to `auditd` log parser if eBPF unavailable
- `collectors/linux/ebpf_probes.c` — eBPF C for `sys_enter_connect` + `sys_enter_execve`

**Platform requirements:**

*Windows:*
- Sysmon ≥ v15 installed and configured with `sysmon_config.xml`
- Collector process requires `SeSecurityPrivilege` (run as Administrator or with explicit privilege grant)

*Linux:*
- Kernel ≥ 5.8 for `CAP_BPF` support
- Either run as root, or: `sudo setcap 'cap_bpf,cap_perfmon+ep' $(which python3)`
- `bcc` package installed from distro packages (NOT PyPI wheel) — needs kernel headers

**Graceful shutdown:** Both daemons must catch `SIGTERM`/`SIGINT`, flush any buffered events to the
queue, then exit cleanly. Use `signal.signal()` or `asyncio` event for this.

**Log rotation:** Configure the OS log for the daemon process to rotate at 100 MB, retain 7 days.

---

### Phase 2 — Graph Database Engine (Week 2)

**Goal:** Feeding 1,000 events produces the correct graph with no duplicate nodes (verify with
`MATCH (n) RETURN labels(n), count(n)`).

**Deliverables:**
- `backend/graph/schema.py` — constraint + index creation; idempotent (uses `IF NOT EXISTS`)
- `backend/graph/driver.py` — `AsyncGraphDatabase.driver()` singleton; max 50 connections; retries on `ServiceUnavailable`
- `backend/graph/ingest.py` — `log_network_event()`, `log_process_event()`, `log_dns_event()`
- FastAPI lifespan that initializes schema on startup and closes driver on shutdown

**Critical rules:**
- Use `MERGE` everywhere, never bare `CREATE`
- `ON CREATE SET first_seen`, `ON MATCH SET last_seen` on all node upserts
- All Cypher must use parameterized queries — no f-string interpolation into Cypher
- Wrap every write in a `async with session.begin_transaction()` with retry logic

---

### Phase 3 — Threat Intel Pipeline & Cache Layer (Week 3)

**Goal:** A known-malicious IP (from Feodo tracker) creates a `Threat_Campaign` node bridged to it
within 30 seconds of the event arriving.

**Deliverables:**
- `backend/cache/redis.py` — client singleton; TTL constants as named module-level variables
- `backend/enrichment/pipeline.py` — async worker pool with `ENRICHMENT_WORKER_COUNT` workers
- Individual enricher modules: `virustotal.py`, `censys.py`, `feeds/feodo.py`, `feeds/emerging.py`
- Campaign MERGE query in `graph/ingest.py`
- `THREAT_CONFIDENCE_THRESHOLD` read from config; defaulted to 0.5

---

### Phase 4 — FastAPI Backend & 3D UI (Week 4)

**Goal:** Browser shows the live graph updating in real-time as test events are injected. Malicious
nodes visually distinct within 2 seconds of the `threat_flag` message.

**Deliverables:**
- `backend/main.py` — CORS from `ALLOWED_ORIGINS` env; rate limiting via `slowapi`; JWT middleware
- `backend/auth.py` — RS256 JWT; single admin user from env for MVP; `role` claim in payload
- All routers with pagination (`page`, `limit` params; max 500 per page)
- `frontend/` — Login page, `ThreatGraph.tsx`, `useWsGraph.ts` with reconnect backoff

**UI colour semantics:**

| Node / State | Colour | Extra |
|-------------|--------|-------|
| `Host` (normal) | `#4488cc` blue | — |
| `Process` (benign) | `#336699` muted blue | — |
| `IP_Address` (unenriched) | `#888888` grey | — |
| `IP_Address` (malicious) | `#ff4444` red | Expanding pulse animation |
| `Threat_Campaign` | `#ff8800` neon orange | Larger node radius |
| Paths to compromised hosts | Animated dashed line | Orange |

**WebSocket broadcast pattern:**
```
Neo4j write (ingest.py)
  └─► notify_clients(event)          # called after every successful write
        └─► get ws:sessions from Redis
              └─► push JSON to each active WS connection
```

The backend keeps a dict of `{session_id: WebSocket}` in memory (per process). `ws:sessions` in
Redis allows future horizontal scaling — a second backend instance would also receive the publish
via Redis Pub/Sub (add this when scaling beyond one process).

---

### Phase 5 — Hardening, Alerting & Observability (Week 5)

**Goal:** `docker compose up` brings the full stack from zero in <3 minutes. Killing and restarting
the backend causes all frontend WS clients to reconnect automatically within 30 seconds.

**Deliverables:**
- `/healthz` — pings Neo4j + Redis; returns `{ "neo4j": "ok", "redis": "ok" }` or 503 with detail
- `/metrics` — Prometheus via `prometheus-fastapi-instrumentator`
- Slack alerter: `POST` to `SLACK_WEBHOOK_URL` when a new `Threat_Campaign` node is created; fire-and-forget
- Graceful shutdown in `main.py` lifespan: flush enrichment queue → drain WS sessions → close Neo4j driver → close Redis
- `docker-compose.yml` with Docker healthchecks on all services and named volumes
- Neo4j nightly backup: shell script wrapping `neo4j-admin database dump`; scheduled via cron

---

## Docker Compose

```yaml
# docker-compose.yml
services:
  neo4j:
    image: neo4j:5
    environment:
      NEO4J_AUTH: neo4j/${NEO4J_PASSWORD}
      NEO4J_server_memory_heap_max__size: 1G
    volumes:
      - neo4j_data:/data
    healthcheck:
      test: ["CMD-SHELL", "cypher-shell -u neo4j -p ${NEO4J_PASSWORD} 'RETURN 1' || exit 1"]
      interval: 10s
      retries: 5
      start_period: 30s

  redis:
    image: redis:7-alpine
    command: redis-server --save 60 1 --appendonly yes
    volumes:
      - redis_data:/data
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 5s
      retries: 5

  backend:
    build:
      context: ./backend
      dockerfile: Dockerfile
    env_file: .env
    depends_on:
      neo4j:  { condition: service_healthy }
      redis:  { condition: service_healthy }
    ports:
      - "8000:8000"
    restart: unless-stopped

  frontend:
    build:
      context: ./frontend
      dockerfile: Dockerfile
    ports:
      - "3000:80"
    depends_on:
      - backend

volumes:
  neo4j_data:
  redis_data:
```

---

## Testing Strategy

### Unit Tests (`tests/unit/`) — no external deps

- `UnifiedLogEvent` validation: malformed events (missing required field, wrong type) are rejected
- Confidence scoring: known input combinations produce expected weighted sums
- JWT: valid token parses correctly; expired token raises; tampered signature raises
- Redis key helpers: correct key names and TTL values are generated
- Pruning Cypher: correct parameters are passed to the driver mock

### Integration Tests (`tests/integration/`) — uses `docker-compose.test.yml`

- `log_network_event()` called twice with the same data produces exactly one node of each type
- Enrichment pipeline: synthetic event with Feodo-listed IP → `Threat_Campaign` node exists in Neo4j
- Pruning: stale benign edge is removed; malicious edge is preserved

### End-to-End Tests (Playwright)

- Login: valid credentials grant access; invalid credentials show error message
- Graph render: WebSocket connection established within 3s of page load
- Threat flag: injecting a malicious event turns the IP node red within 2s
- Reconnect: simulate WS disconnect (kill backend, restart) → frontend reconnects within 30s

---

## Security Hardening Checklist

- [ ] JWT uses RS256 — private key in `keys/` directory, gitignored, never leaves backend
- [ ] All secrets loaded from `.env`, never hardcoded; `.env` is gitignored
- [ ] CORS `ALLOWED_ORIGINS` restricted to the frontend's actual origin
- [ ] WebSocket token validated on handshake — unauthenticated connections are closed immediately
- [ ] Neo4j exposed only on the internal Docker network, not on host ports
- [ ] Redis exposed only on the internal Docker network
- [ ] All Cypher uses parameterized queries — no string interpolation into query text
- [ ] Process hashes normalized to lowercase before MERGE (prevents case-variant duplicate nodes)
- [ ] Feed file downloads validated against expected line format before parsing
- [ ] OSINT API responses validated with Pydantic before use (don't trust external JSON shape)
- [ ] Enrichment worker errors are caught per-enricher — one failing API does not crash the worker

---

## Known Limitations & Design Decisions

| Limitation | Decision / Rationale |
|-----------|---------------------|
| eBPF requires elevated privileges | Document as requirement; provide `auditd` fallback for environments where eBPF is not available |
| `asyncio.Queue` is in-process | Sufficient for single-host deployments; upgrade to Redis Streams when scaling to multiple ingest hosts |
| WS session list is per-process in-memory | Adding Redis Pub/Sub in Phase 5 makes this horizontally scalable without code changes to enrichment logic |
| Neo4j Community has no RBAC | Enforce roles (`admin`, `viewer`) at the FastAPI layer via JWT claims |
| No event ordering guarantee from eBPF | Use event timestamps, not ingestion order, for all graph timestamps |
| VirusTotal free tier: 4 req/min | `rate:osint:virustotal` Redis counter enforces this; paid tier limit configurable via env |
| Windows collector needs Sysmon pre-installed | Documented as prerequisite; `sysmon_config.xml` committed for easy deployment |
| No persistent user store for MVP | Single admin user from env variables; replace with a database-backed user model post-MVP |
