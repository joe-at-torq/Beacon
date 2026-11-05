# Introducing Beacon: One Source of Truth for Threat Intelligence Across Your Torq Workspaces

*A tour of Beacon's dashboard, database, rules engine and settings, and how they work together to keep
every workspace's observables accurate, enriched and in sync.*

> **[Screenshot: Beacon login page]**

---

## The problem: indicators that live in silos

Security teams that run more than one Torq workspace soon hit the same wall. Each workspace builds
up its own observables (IP addresses, domains, URLs, file hashes, email addresses), and each one
learns something different:

- a phishing URL flagged as malicious in the SOC workspace stays "Unknown" in the MSSP workspace next
  door;
- an analyst downgrades a false positive in one place, but the old verdict keeps firing playbooks
  everywhere else;
- threat-intel lookups are repeated in every workspace, burning API quota on the same indicator;
- external threat feeds have to be wired into each workspace separately.

Without a central place to reconcile all of this, you end up with conflicting verdicts, duplicated
effort and blind spots.

**Beacon** fixes this. It is a threat intelligence manager for Torq that keeps one central database of
observables in sync across any number of workspaces, enriches them with the threat-intel providers you
already use, turns those providers' different verdicts into one consistent reputation, pulls in external
threat feeds, and publishes the result to the rest of your security stack.

## What Beacon does at a glance

- **Central observable database.** Every workspace's observables are combined into one deduplicated
  database, and Beacon tracks where each one came from and where copies exist.
- **Rule-driven sync.** You decide exactly which observables flow from which sources to which
  workspaces. Nothing is pushed unless a rule allows it.
- **Conflict resolution.** When workspaces disagree about an observable, a strategy you choose
  decides the central verdict.
- **Threat-intel enrichment.** Look up observables with VirusTotal, AlienVault OTX, AbuseIPDB,
  urlscan.io, Recorded Future, GreyNoise and EmailRep.io, by hand or automatically.
- **Reputation normalization.** Each provider's signals (detection counts, abuse scores, risk scores,
  classifications) are mapped to a single Torq reputation and applied automatically.
- **Threat feeds.** Ingest TAXII 2.1 collections, STIX 2.x bundles and plain-text IP/URL/domain lists.
- **TAXII 2.1 server.** Publish Beacon's database as a read-only feed for SIEMs, firewalls and other
  threat-intel platforms.
- **Documented REST API.** Script anything you can do in the UI, with role-scoped API keys.

Beacon ships as a **single Docker container** that serves an HTTPS web interface (light and dark mode)
and the REST API. All state lives in one data volume, so backing up Beacon means backing up one volume.

---

## Getting started in minutes

```bash
docker compose up -d --build
```

Open `https://<host>:8443`, sign in with the default `admin / admin` account, and Beacon asks you to
set a new password straight away. On first start Beacon generates a self-signed TLS certificate; you can
swap in your own by mounting it into the container.

To connect a Torq workspace, create a **service API key** in that workspace (**Settings → API Keys**) with
permission to read and write observables, then add it in Beacon under **Settings → Workspaces**. Pick the
workspace's region (US, EU or JP), click **Test connection**, and you're done. Repeat for each workspace.
Client secrets are encrypted at rest.

From here, let's walk through Beacon tab by tab.

---

## The Dashboard

The Dashboard is Beacon's home screen: a live overview of the central database, the workspaces around
it and the traffic between them.

> **[Screenshot: Full dashboard view in dark mode]**

Every widget can be **dragged and resized**, and the layout is saved per user, so each analyst can
arrange the dashboard the way they work.

### KPI tiles

Four tiles along the top give the headline numbers: total **Observables** in the central database, how
many are **Malicious**, connected **Workspaces**, and **Active rules**.

### Observable flows

The centerpiece of the dashboard is an interactive graph of how observables move through your
environment.

> **[Screenshot: Observable flow graph showing workspaces, Beacon central and threat feeds]**

- **Beacon central** sits in the middle, with your workspaces around it.
- **Threat feeds** have their own column to the side, so external intel is easy to tell apart from
  workspace traffic.
- Each path shows what has already **synced** and what is **pending** for the next run, and which rule
  allows it.
- Toggle the **Rules** overlay to see the paths your sync rules open up. **Show allowed paths with no
  traffic** (off by default) also draws routes that are allowed but haven't carried anything yet.
- Click any node or path for details. Zoom, pan and **Fit to view** keep large environments readable.
- Switch to **Table view** for the same information as rows.

This graph answers the question every Beacon admin eventually asks: *"Where did this indicator come
from, and where is it going?"*

### Database growth and composition

- **Central database size** charts the growth of the database over time.
- **Observables by type** breaks the database down into IPs, domains, URLs, hashes, emails and more.
- **Observables over time** charts new observables by the date they were first observed, or the running
  total, over a period you choose.
- **Reputation distribution** shows the balance of malicious, suspicious, safe and unknown verdicts.
  It is a quick way to spot a backlog of unenriched indicators.

### Operations

- **Workspace health** shows each workspace's connection status, with a shortcut to manage it.
- **Recent sync runs** lists the latest runs and their results, linking to the full sync log.
- **Recent activity** is a live stream of changes across the database.

### Threat-intel enrichment

The enrichment widget shows how much work Beacon's threat-intel engine is doing for you.

> **[Screenshot: Threat-intel enrichment widget]**

It tracks total **Lookups**, how many were **Automatic (rules)** versus manual, the number of
**Observables enriched**, and **Database coverage** (the share of your database with threat-intel
data). A **By integration** breakdown shows which providers carry the load, and a table view gives you
the numbers per period.

---

## The Database

The Database tab is where analysts spend most of their time: a fast, filterable view of every
observable Beacon knows about.

> **[Screenshot: Database tab with filters and the observable list]**

### Finding observables

The list shows each observable's value, type, reputation, associated case count, the workspaces it's
present in, when it was last observed and when it was last updated. You can narrow it down by:

- **Search** across values and descriptions;
- **Type** and **Reputation**;
- **Source**: where the observable originally came from, whether a specific workspace, **Central**
  (created in Beacon) or a specific **threat feed**;
- **Workspace**: which workspaces currently hold a copy;
- **Edited only**: observables an analyst has edited centrally;
- **Enriched only**: observables with threat-intel results.

Rows can be expanded to show enrichment data inline without opening the observable.

### Working in bulk

Select observables one by one or a whole page at a time, then:

- **set a reputation** on all of them;
- **revert** central edits and hand control back to the workspaces;
- **enrich** them with every connected provider that supports their type (up to 50 at a time);
- **delete** them.

You can also **Add observable** by hand, with a type, sub type, value, reputation and description.

### The observable panel

Click any observable to open a wide side panel with everything Beacon knows about it, split into three
tabs.

> **[Screenshot: Observable panel, Overview tab with the lifetime chart]**

**Overview**

- Key dates: **First observed**, **Last observed**, **Added to Beacon** and **Updated**, plus
  associated cases across all workspaces.
- A **lifetime chart** that draws the observable's history from first sighting to now. One lane shows
  the central reputation and one lane each shows every workspace's and feed's view, colored by
  reputation. You can see at a glance when a workspace escalated it, when a feed listed it, and when the
  central verdict changed.
- **Reputation and description editing.** Saving an edit makes the observable *centrally
  authoritative*: workspace changes no longer overwrite it, and your edit flows out through sync rules
  that include Central as a source. **Revert** hands control back to the merge.
- **Workspace copies**: every workspace holding the observable, whether that copy is native to the
  workspace or synced in by Beacon, its remote reputation, cases and when it was last synced.
- **Feed listings**: every threat feed listing the observable, with the feed's reputation, how long the
  listing is valid and when it was last seen.

> **[Screenshot: Observable panel, Timeline tab]**

**Timeline**

A complete, chronological audit trail of the observable, including:

- creation;
- first sightings in workspaces;
- pushes and updates by Beacon;
- reputation changes in workspaces and centrally;
- description edits;
- central edits and reverts;
- feed listings and removals;
- every enrichment.

Each entry records who or what made the change: a user, an API key, a sync, a feed or the
normalization engine.

> **[Screenshot: Observable panel, Enrichment tab with the normalized verdict]**

**Enrichment**

Results from every provider that looked up the observable, such as detection counts, abuse
confidence, top OTX pulses and malware families, with the raw API responses available in a JSON viewer.
At the top, the **normalized reputation** banner shows Beacon's combined verdict and whether it has been
applied. If a verdict was held back by a safeguard, the banner explains why and offers **Apply anyway**.

---

## Rules

The Rules tab holds the three engines that automate Beacon: **Sync rules**, **Enrichment rules** and
**Reputation normalization**.

### Sync rules

> **[Screenshot: Sync rules list]**

Sync rules are an **allow-list**: with no rules, Beacon never pushes anything into your workspaces.
Each rule defines:

- **From (sources)**: workspaces where an observable was *originally* seen, **Central** (created or
  edited in Beacon), or a specific **threat feed**. Leave it empty to match any workspace or Central.
  Feeds are never included implicitly; a rule must name them, so external intel never leaks into a
  workspace by accident.
- **To (targets)**: the workspaces to push into. Leave it empty to target all other workspaces.
- **Observable types** and **sub types**, for example *IP address, IPv4 only*.
- **Minimum reputation**, for example only push observables rated *Suspicious* or worse.
- **Propagate updates**: also push later reputation and description changes to copies that already
  exist.
- **Sync immediately when the reputation is…** (priority sync): pick any reputations that shouldn't
  wait for the next scheduled run. When Beacon gives a matching observable one of those reputations,
  whether through a manual edit, an API call, normalization or a feed, a sync starts within seconds.
  Bursts of changes are combined into a single run.

> **[Screenshot: Sync rule editor with the impact preview]**

While you build a rule, the **Impact preview** shows how many observables it matches and what it would
push on the next sync, before you save it. Rules can be reordered by dragging, and enabled or disabled
individually.

Beacon also prevents loops: a copy that Beacon pushed into workspace B is never forwarded on to
workspace C unless someone in B actually changes it, and then only where a rule allows B as a source.

### Enrichment rules

> **[Screenshot: Enrichment rules with the queue card]**

Enrichment rules look up new observables automatically as soon as they enter the database, whether
they arrive from a sync, a threat feed or a manual entry. A rule reads like a sentence: *"when an IP
address, IPv4, rated Malicious comes in, enrich it with VirusTotal and AbuseIPDB."*

- Choose a **type**, optional **sub types** (types without sub types, such as email addresses, work too)
  and optional **reputations**.
- **Enrich with** offers only the integrations that support the chosen type, so you can't build a rule
  that would fail.
- **Re-enrichment** sets a window in days; a provider that already enriched the observable within that
  window is skipped, saving quota.
- **Don't wait for busy integrations**: if one provider has hit its daily limit, is rate-limited or is
  disabled, Beacon enriches with the others instead of waiting.
- **Run on existing matches** applies the rule to observables already in the database (up to 10,000 per
  run).

Lookups go through a background **queue** paced per provider, with requests-per-minute and per-day
limits you can edit, plus a **Today's usage** readout. If a provider rate-limits Beacon or rejects a key,
only that provider pauses; the rest keep working. Manual enrichment from the Database doesn't count
against these limits.

### Reputation normalization

Every threat-intel provider speaks its own language: VirusTotal reports engine detections, AbuseIPDB
an abuse confidence score, Recorded Future a risk score, GreyNoise a classification. Normalization turns
all of that into a single Torq reputation.

> **[Screenshot: Reputation normalization mappings and the test panel]**

- **Mappings** translate each provider's signals into a reputation, for example *"VirusTotal malicious
  detections ≥ 5 → Malicious"*. Mappings are evaluated in order, and the first match wins.
- **Combine sources** decides how providers' verdicts become one: **most severe**, **least severe**,
  **most common**, or **provider priority** (drag providers to set the order).
- **Add recommended mappings** fills in sensible defaults, including mapping clean results and "no data"
  lookups to *Probably safe*, so enriched observables don't sit at Unknown forever.
- **Test against your data** shows, before you save, what the current mappings would produce for every
  enriched observable in your database: current versus normalized reputation, and which changes would
  apply.

By default normalization is **automatic**: after every central enrichment, the observable's reputation
is set to the normalized verdict with no extra click. The **Only raise severity** safeguard (on by
default) holds back verdicts that would *lower* a reputation, so a quiet provider can't clear an
indicator an analyst flagged. Held-back verdicts are explained on the observable, with an **Apply
anyway** override. Prefer a human in the loop? Switch to **Suggest only**, and verdicts appear on each
observable with an **Apply** button. **Apply to N observables** brings observables enriched before a
mapping change into line in one step.

---

## Settings

Settings is where Beacon is connected to the outside world. It's organized into six tabs, and the
current Beacon version is shown in the bottom-right corner.

### Workspaces

> **[Screenshot: Workspaces tab]**

Each connected Torq workspace shows its region, whether it's enabled, and how many of its observables
are **native** (created in that workspace) versus **synced in** by Beacon. When adding or editing a
workspace you set:

- a display name;
- the region;
- a **priority**, used by the workspace-priority collision strategy;
- the service account's client ID and secret;
- whether it is enabled.

**Test connection** checks the credentials before you save.

### Integrations

The Integrations tab has three parts.

> **[Screenshot: Threat-intel integrations]**

**Threat-intel providers.** Connect VirusTotal, AlienVault OTX, AbuseIPDB, urlscan.io, Recorded Future,
GreyNoise and EmailRep.io with their API keys. Each card shows whether the provider is connected and
which observable types it **enriches**. For example, AbuseIPDB handles IP addresses only.

> **[Screenshot: Threat feeds list and the Add feed dialog]**

**Threat feeds.** Beacon supports three kinds of feed:

| Feed type | What it reads | How reputation is set |
|---|---|---|
| **TAXII 2.1** | A collection on a TAXII server (pick it with **Load collections**). Only new objects are fetched on each poll. | The feed's default reputation, refined by STIX hints (benign, anomalous, malicious). Existing observables are only ever raised. |
| **STIX bundle** | A STIX 2.x JSON bundle from a URL | Same as TAXII |
| **Text list** | A plain-text list with one value per line, such as the OpenPhish URL feed or the Emerging Threats compromised-IP list | Everything listed is set to the feed's reputation, including observables already in Beacon |

Every feed has:

- a name and URL;
- optional authentication (username and password, or a custom header);
- a poll interval;
- a default reputation;
- an **Enrich new observables** switch that runs your enrichment rules on what the feed adds.

STIX feeds add **Minimum confidence**, **First poll looks back** and **Retire after (days)**.

Text lists add **List contains** (IP addresses, URLs, domains, or auto-detect):

- Beacon handles comment lines, trailing comments, CSV columns and defanged values like `evil[.]com`
  and `hxxp://`.
- **Test** shows what a feed would produce before you save it: valid values by type, skipped lines and
  samples.
- **Delta updates:** Beacon remembers what each list contributed and applies only what changed on each
  poll.
  - New values are added or set to the feed's reputation.
  - Values still on the list are left alone.
  - Values that drop off get back the reputation they had before, unless someone changed them since.

Across all feed types:

- **No duplicates.** A value already in Beacon, whether from a workspace, another feed or entered by
  hand, is matched by type and normalized value and updated, never added twice.
- **Central edits win.** Observables an analyst edited centrally are never changed by a feed.
- **Feeds reach workspaces only through rules.** Observables from a feed reach workspaces only through
  sync rules that name that feed.
- **Feed cards show what each poll did.** Each card shows the feed's status and last error, plus counts
  from the latest poll.

> **[Screenshot: Beacon TAXII server settings]**

**Beacon TAXII server.** Turn Beacon into a threat-intel source for the rest of your stack. When
enabled, Beacon publishes a read-only TAXII 2.1 collection of STIX 2.1 indicators, filtered by:

- minimum reputation (default *Suspicious or risky*);
- observable types;
- sources.

The tab shows the **Discovery URL** and **Collection objects URL** to paste into your SIEM, firewall or
TIP. Clients authenticate with a Beacon API key (the read-only *viewer* role is enough). Clients that
poll incrementally also receive downgraded and deleted observables as *revoked*, so they can retire them
from blocklists automatically.

### API

> **[Screenshot: API tab with documentation links and API keys]**

Beacon's versioned REST API lives at `/api/v1`, and this tab is the hub for it:

- **Documentation:**
  - links to the interactive **Swagger UI** (which works offline);
  - downloads for the **OpenAPI spec** and a ready-to-import **Postman collection**;
  - a copyable **Base URL**.
- **API keys:**
  - **Creating keys.** Admins create keys with a name, a role (*viewer*, *analyst* or *admin*) and an
    optional expiry. A key is shown once and only its hash is stored.
  - **Managing keys.** The list shows when each key was last used, and keys can be revoked at any time.
- **Quick start:** copy-paste `curl` examples for querying the database, creating observables and
  starting a sync.

Everything in the UI is available through the API: observables, database queries, sync rules,
enrichment rules and syncs. That makes Beacon easy to drive from Torq workflows, SOAR playbooks or
scripts.

### Users

Local accounts that can sign in to Beacon, each with one of three roles:

| Role | Can do |
|---|---|
| **Admin** | Everything, including users, workspaces, integrations, feeds, rules and settings |
| **Analyst** | View everything, edit the database, enrich, and trigger syncs and feed polls |
| **Viewer** | Read only |

Admins can require a password change at next sign-in, and the list shows any pending password changes.

### General

> **[Screenshot: General settings]**

- **Collision handling** decides the central verdict when an observable first shows up in several
  workspaces with different values:
  - **highest severity wins** (the default);
  - **most recent wins**;
  - **workspace priority**.

  Descriptions can be taken from the winning copy or merged from all copies. Changing the strategy
  re-resolves existing observables.
- **Scheduled sync** turns automatic synchronization on or off and sets the interval (15 minutes by
  default). You can always start a run on demand with **Sync now**.
- **Appearance** picks light, dark or system theme, saved in your browser.

### Sync log

> **[Screenshot: Sync log with an expanded run]**

Every sync run, scheduled or manual, is recorded with its:

- start time and scope;
- status;
- counts of observables pulled, merged, in conflict, pushed and updated;
- duration.

Open a run to see each Torq API call it made, with request headers, request body and response body.
**Failed calls only** narrows the list to what went wrong. When a workspace misbehaves, this is the
first place to look.

---

## Under the hood: how a sync works

Each sync run, every 15 minutes by default, on demand, or within seconds for priority reputations,
works in three phases:

1. **Pull.** Every enabled workspace's observables are read into the central database. Values are
   normalized so the same indicator is recognized everywhere. For example, IPv6 addresses are compressed
   and hostnames and hashes are lowercased.
2. **Merge.** The central reputation and description are updated.
   - **Analyst changes win.** A change an analyst makes in any workspace is picked up centrally, whether
     on the workspace's own copy or one Beacon synced in.
   - **First sightings use your strategy.** When an observable first appears with conflicting values,
     the collision strategy decides.
3. **Push.** Observables are created or updated in the workspaces your rules allow. A safety cap (5,000
   changes per run by default) keeps a newly enabled rule from flooding Torq; the rest follow in the
   next run.

---

## Built-in safeguards

Beacon is designed to be safe to point at production workspaces:

- **Nothing is pushed without a rule**, and threat feeds must be named explicitly in a rule.
- **Central edits are authoritative.** Feeds, workspace changes and normalization never overwrite an
  analyst's central decision until someone clicks **Revert**.
- **Only raise severity** stops normalization from quietly downgrading indicators.
- **Deletes are deliberate.**
  - Removing a workspace, integration or feed asks for confirmation and offers to clean up.
  - For workspaces and feeds, Beacon offers to delete only the observables that came *exclusively* from
    that source. Observables with any other source are kept.
  - For integrations, Beacon offers to delete that provider's stored enrichment results.
  - Deleted observables are blocked from being imported again. Torq's API doesn't support deleting
    observables, so copies already in workspaces stay where they are.
- **Rate limits are respected** per provider, and a failing provider pauses on its own rather than
  breaking the queue.
- **Secrets are encrypted at rest.** API keys are stored only as hashes, and sign-in sessions expire.

---

## Putting it all together: a worked example

Here's how the pieces combine into an automated pipeline:

1. **Add a text-list feed** for the OpenPhish URL feed, polling hourly with a default reputation of
   *Malicious*. Beacon imports the list, matches any URLs already in your database, and from then on
   applies only the delta.
2. **Create an enrichment rule:** *"URLs rated Malicious → enrich with VirusTotal and urlscan.io, re-enrich
   after 7 days, don't wait for busy integrations."* New phishing URLs are looked up as they arrive,
   paced within your API quotas.
3. **Let normalization decide.** The recommended mappings turn provider results into a Torq reputation
   automatically, and *Only raise severity* makes sure nothing gets downgraded by accident.
4. **Create a sync rule** from the OpenPhish feed to your SOC and MSSP workspaces, with **Sync
   immediately when the reputation is Malicious**. Confirmed phishing URLs land in both workspaces within
   seconds, ready for Torq playbooks to block, hunt or enrich cases.
5. **Enable the Beacon TAXII server** with a minimum reputation of *Malicious*, and point your firewall
   at it. When a URL drops off the feed and is downgraded, the firewall receives it as revoked and
   removes it from its blocklist.
6. **Watch it on the Dashboard.** The feed appears in its own column on the observable flow graph, the
   enrichment widget shows the lookups that ran, and every observable's timeline records each step.

No scripts, no copy-pasting indicators between workspaces, and a full audit trail for every decision.

---

## Wrapping up

Beacon gives teams running multiple Torq workspaces what they've been missing:

- one central, deduplicated view of their threat intelligence;
- precise control over how it flows;
- automatic enrichment and consistent verdicts;
- a clean way to bring external feeds in and publish curated intel back out.

It runs as a single container, connects with standard Torq service accounts, and is fully scriptable
through its REST API.

Spin it up, connect your first two workspaces, and watch the flow graph light up.
