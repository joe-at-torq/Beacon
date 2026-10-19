# Beacon — Threat Intelligence Manager for Torq

Beacon keeps one central database of observables (IOCs) in sync across any number of
[Torq](https://torq.io) workspaces. It connects to each workspace with a Torq service account, combines
every workspace's observables into one database, resolves conflicting verdicts, and pushes observables
back out according to sync rules you define.

On top of sync, Beacon can:

- **enrich** observables with threat-intel providers (VirusTotal, AlienVault OTX, AbuseIPDB, urlscan.io,
  Recorded Future, GreyNoise, EmailRep.io), by hand or automatically with enrichment rules;
- **normalize** the different providers' verdicts into one Torq reputation;
- **ingest threat feeds**: TAXII 2.1 collections, STIX 2.x bundles and plain-text IP/URL/domain lists;
- **publish** its database as a read-only **TAXII 2.1 server** for SIEMs, firewalls and other platforms.

It ships as a single Docker container that serves an HTTPS web UI (light and dark mode) and a REST API.

## Quick start

```bash
docker compose up -d --build
```

Open **https://localhost:8443** and sign in with **admin / admin**. You'll be asked to set a new
password straight away. The certificate is self-signed on first start, so your browser will warn
you the first time.

If port 8443 is already taken, choose another host port: `TIM_HOST_PORT=9443 docker compose up -d`.

Without compose:

```bash
docker build -t beacon .
docker run -d --name beacon -p 8443:8443 -v tim-data:/data beacon
```

All state lives in the `/data` volume: the SQLite database, encryption keys and TLS certificate.
Back up that volume to back up Beacon.

## Connecting a Torq workspace

1. In the Torq workspace, go to **Settings → API Keys** and create a **service** API key with a role
   that can read and write observables. Copy the client ID and secret.
2. In Beacon, go to **Settings → Workspaces → Add workspace**. Enter the key, pick the region (US, EU or
   JP), and click **Test connection**.
3. Repeat for each workspace. Client secrets are encrypted at rest.

Each Torq API key belongs to one workspace, so connect one key per workspace.

## How sync works

Each run (every 15 minutes by default, or on demand with **Sync now**) works in three phases:

1. **Pull:** every enabled workspace's observables are read into the central database. Values are
   normalized so the same observable is recognized everywhere. For example, IPv6 addresses are compressed
   and hostnames and hashes are lowercased.
2. **Merge:** the central reputation and description are updated.
   - **A change made in any workspace wins.** If a reputation or description changes in a workspace,
     whether on its own copy or one Beacon synced in, central takes the new value.
   - **Collision strategy for first sightings.** When an observable first shows up in a workspace with a
     different value, the configured strategy decides: *highest severity wins* (default), *most recent
     wins*, or *workspace priority*. Descriptions come from the winning copy or are merged from all copies.
3. **Push:** observables are created in, or updated in, the workspaces that a **rule** allows. A safety
   cap (5,000 changes per run by default) keeps a newly enabled rule from flooding Torq; the rest follow
   in the next run.

### Sync rules

Rules are an **allow-list**: with no rules, nothing is pushed. Each rule has:

- **From:** where an observable came from: workspaces it was *originally* seen in, **Central** (created
  or edited in Beacon), or a **threat feed**. Leave empty to match any workspace or Central. Feeds are
  never included implicitly; a rule must name them.
- **To:** the target workspaces. Leave empty to target all other workspaces.
- **Types / sub types:** for example, *IP address + IPv4 only*.
- **Minimum reputation** (optional).
- **Propagate updates:** also push reputation and description changes to copies that already exist.
- **Priority sync** (optional): reputations that sync **immediately**. When Beacon itself gives a matching
  observable one of them (a manual edit, an API call, threat-intel normalization, a feed), a sync starts
  within seconds instead of waiting for the interval. Bursts are combined into one run.

A copy Beacon pushed into B that nobody edits is never forwarded on to C. If someone in B *changes* it,
the change can flow from B to other workspaces, but only where a rule allows B as a source.

### Central edits and deletes

- Editing an observable in **Database** marks it as *centrally edited*. Workspace values no longer
  overwrite it, and the edit reaches workspaces through rules with **Central** as a source. **Revert**
  hands control back to the merge.
- Deleting an observable removes it from Beacon and blocks it from being imported again. Torq's API does
  not expose observable deletion, so the workspaces keep their copies.

## Threat intelligence

### Integrations

Connect providers in **Settings → Integrations**. Each one enriches the observable types it supports
(for example, AbuseIPDB looks up IP addresses only, and urlscan.io only SHA-256 hashes). From the
**Database**, enrich one observable or a selection; results and the raw API responses are stored on the
observable and shown on its **Enrichment** tab.

### Enrichment rules

**Rules → Enrichment rules** look up observables automatically as soon as they enter the database, from a
sync, a feed or by hand. A rule names a type, optional sub types and reputations, and the integrations to
use; only integrations that support the chosen type are offered. **Run on existing matches** enriches
observables already in the database.

Lookups wait in a background queue paced per provider (requests per minute and per day, editable in the
queue card; defaults are conservative free-tier guesses). A rate-limited or rejected provider pauses
instead of failing everything. Options per rule:

- **Re-enrichment window:** skip a provider that already enriched the observable within N days.
- **Don't wait for busy integrations:** when a provider is out of capacity (daily limit, rate-limited or
  disabled), skip it and enrich with the others instead of waiting.

### Reputation normalization

**Rules → Reputation normalization** maps each provider's signals (engine counts, abuse confidence, risk
scores, classifications…) to a Torq reputation, then combines the providers with a strategy (most
severe, least severe, most common, or provider priority). **Add recommended mappings** fills in sensible
defaults, including mapping clean results and lookups with no data to *Probably safe* so enriched
observables don't stay Unknown.

Normalization either **suggests** a reputation (shown with an Apply button on the observable) or
**applies it automatically** after each enrichment, optionally only ever raising severity.

## Threat feeds

Add feeds in **Settings → Integrations → Threat feeds**. Every feed has a poll interval, can be enabled or
disabled, and shows its status and counts. Observables from a feed reach workspaces only through sync rules
that name the feed, and they appear as their own column on the dashboard flow graph.

| Type | What it reads | Reputation |
|---|---|---|
| **TAXII 2.1** | A collection on a TAXII server (picked with **Load collections**); only new objects are fetched on each poll | The feed's default, refined by STIX hints (benign, anomalous, malicious). Existing observables are only ever raised. |
| **STIX bundle** | A STIX 2.x JSON bundle URL | Same as TAXII |
| **Text list** | A plain-text list with one IP, URL, domain or hash per line, e.g. [OpenPhish](https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt) or [Emerging Threats compromised IPs](https://rules.emergingthreats.net/blockrules/compromised-ips.txt) | Everything listed is set to the feed's reputation, including observables already in Beacon |

For text lists, Beacon remembers what each list contributed and applies only the **changes** on each
update: new values are added (or set to the feed's reputation), values still listed are left alone, and
values that drop off get back the reputation they had before, unless someone changed them since.
Comment lines, trailing comments and defanged values (`evil[.]com`, `hxxp://`) are handled.

For every feed type:

- **No duplicates:** a value already in Beacon, from a workspace, another feed or created by hand, is
  matched by type and normalized value and updated, never added twice.
- Observables edited centrally in Beacon are never changed by a feed.
- Revoked and expired STIX indicators are ignored, and stop counting as listed.

## Beacon TAXII server

Turn it on in **Settings → Integrations → Beacon TAXII server**. It publishes one read-only collection of
STIX 2.1 indicators, filtered by minimum reputation (default *Suspicious or risky*), types and sources.

- **Discovery URL:** `https://<host>:8443/taxii2/`
- **Authentication:** an API key from Settings → API (the *viewer* role is enough), sent as
  `Authorization: Bearer tim_…` or as HTTP Basic with any username and the key as the password.
- Clients that poll with `added_after` also receive downgraded and deleted observables as *revoked*, so
  they can retire them.

## Database

The **Database** page lists every observable, with filters for type, reputation, **source** (Central, a
workspace where it was first seen, or a feed), the workspaces it's present in, centrally edited and
enriched. Clicking an observable opens a panel with:

- **Overview:** stats, a **lifetime chart** (central reputation, each workspace's and feed's view over
  time), reputation and description editing, and workspace copies and feed listings;
- **Timeline:** every change, sync, enrichment and feed event;
- **Enrichment:** provider results, raw responses and the normalized reputation.

## Removing workspaces, integrations and feeds

Removing any of them asks for confirmation and offers to clean up:

- **Workspaces and feeds:** optionally delete the observables that came **only** from that source.
  Observables that also have another source are kept. Removed observables with copies in other
  workspaces are blocked from being re-imported, because Torq's API can't delete those copies.
- **Integrations:** optionally delete that provider's stored enrichment results. The observables are kept.

## Dashboard

The dashboard's widgets can be moved and resized; the layout is saved per user. They include KPIs, an
interactive **observable flow graph** (workspaces, Central, threat feeds, rule paths and live sync
activity), database growth, observables over time, reputation distribution, workspace health, recent sync
runs and activity, and **threat-intel enrichment** volume (lookups over time, automatic vs manual, per
integration, database coverage).

## REST API

Beacon has a documented, versioned API at `/api/v1`. Everything is under **Settings → API**:

- **Swagger UI:** `https://<host>:8443/api/v1/docs` (works offline)
- **OpenAPI spec:** `/api/v1/openapi.json`
- **Postman collection:** `/api/v1/postman.json`. After importing, set the `apiKey` variable.
- **API keys:** admins create keys in Settings → API. Each key has a role:
  - `viewer`: read only;
  - `analyst`: also observable changes, starting syncs and running enrichment rules;
  - `admin`: also rule changes.

  The key is shown once, and only a hash of it is stored.

```bash
export TIM_API_KEY="tim_…"
curl -sk -X POST https://localhost:8443/api/v1/observables/query \
  -H "Authorization: Bearer $TIM_API_KEY" -H "Content-Type: application/json" \
  -d '{"types":["TYPE_ID_IP_ADDRESS"],"min_severity":8,"sources":["central"]}'
```

| Area | Endpoints |
|---|---|
| Observables | `GET/POST /observables`, `GET/PATCH/DELETE /observables/{id}`, `POST /observables/{id}/revert`, `GET /observables/{id}/history` |
| Database query | `POST /observables/query`, `GET /observables/lookup` |
| Sync rules | `GET/POST /rules`, `GET/PUT/PATCH/DELETE /rules/{id}`, `POST /rules/preview` |
| Enrichment rules | `GET/POST /enrichment-rules`, `GET/PUT/PATCH/DELETE /enrichment-rules/{id}`, `POST /enrichment-rules/{id}/run`, `POST /enrichment-rules/preview`, `GET /enrichment-rules/queue` |
| Sync | `POST /sync` (returns 202 with the run id), `GET /sync/status`, `GET /sync/runs`, `GET /sync/runs/{id}` |
| Reference | `GET /workspaces`, `GET /meta` |

## Roles

| Role    | Can do |
|---------|--------|
| admin   | Everything, including users, workspaces, integrations, feeds, rules and settings |
| analyst | View everything, edit the database, enrich, trigger syncs and feed polls |
| viewer  | Read-only |

## Configuration

Most settings (sync interval, collision strategy, enrichment limits, TAXII server…) are in the UI.
Container environment variables:

| Variable | Default | Purpose |
|----------|---------|---------|
| `TIM_PORT` | `8443` | HTTPS port inside the container |
| `TIM_HOST_PORT` | `8443` | Host port used by `docker-compose.yml` |
| `TIM_TLS_CERT` / `TIM_TLS_KEY` | `/data/certs/*.pem` | Use your own certificate (mount it into the container) |
| `TIM_SESSION_HOURS` | `12` | How long a sign-in session lasts |
| `TIM_DISABLE_SCHEDULER` | `0` | Set to `1` to turn off all background jobs (scheduled syncs, enrichment queue, feed polling) |

## Development

Backend (FastAPI, SQLAlchemy, APScheduler):

```bash
cd backend
python3 -m venv .venv && .venv/bin/pip install -r requirements-dev.txt
.venv/bin/python -m pytest          # unit and end-to-end tests against mocked Torq, provider and feed APIs
TIM_DATA_DIR=./data .venv/bin/python -m app.bootstrap
TIM_DATA_DIR=./data .venv/bin/uvicorn app.main:app --port 8443 \
  --ssl-keyfile data/certs/key.pem --ssl-certfile data/certs/cert.pem
```

Frontend (React, Vite, Tailwind, Framer Motion, Recharts):

```bash
cd frontend
npm install
npm run dev    # http://localhost:5173, proxies /api to https://localhost:8443
npm run build  # type-checks and builds into frontend/dist
```

The internal API docs are at `/api/docs`. Brand artwork lives in `frontend/public/brand/` (cleaned,
transparent versions of the source images in the repository root).
