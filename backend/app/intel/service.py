"""Enrich observables through the enabled Beacon integrations."""

import asyncio

from sqlalchemy.orm import Session

from app import history
from app.intel.providers import PROVIDERS, IntelError, LookupResult
from app.models import Integration, IntelEnrichment, Observable, utcnow
from app.security import decrypt

INTEL_ENRICHED = "intel_enriched"


def active_integrations(db: Session) -> list[Integration]:
    return [i for i in db.query(Integration).filter_by(enabled=True).all() if i.provider in PROVIDERS]


def capabilities(db: Session) -> dict[str, list[str]]:
    """Observable type -> providers (enabled integrations) that can enrich it."""
    caps: dict[str, list[str]] = {}
    for integ in active_integrations(db):
        for type_id in PROVIDERS[integ.provider].types:
            caps.setdefault(type_id, []).append(integ.provider)
    return caps


async def lookup(api_key: str, provider_id: str, obs_type: str, value: str) -> LookupResult | BaseException:
    """One provider lookup. Errors are returned, not raised; IntelError keeps the HTTP status (e.g. 429)."""
    try:
        return await PROVIDERS[provider_id].lookup(api_key, obs_type, value)
    except Exception as e:  # noqa: BLE001 - every failure is recorded, never raised into callers
        return e


def apply_result(
    db: Session, obs: Observable, provider_id: str, result: LookupResult | BaseException, actor: str,
    *, normalize: bool = True, now=None, **detail,
) -> IntelEnrichment:
    """Store a lookup result on the observable (one row per provider), record history, then normalize."""
    row = next((e for e in obs.intel if e.provider == provider_id), None)
    if row is None:
        row = IntelEnrichment(observable_id=obs.id, provider=provider_id)
        obs.intel.append(row)
    row.fetched_at, row.fetched_by = now or utcnow(), actor[:64]
    if isinstance(result, BaseException):
        row.status = "error"
        row.error = str(result) if isinstance(result, IntelError) else repr(result)
        row.summary = {}
        row.data = None
    else:
        row.status, row.summary, row.data, row.error = result.status, result.summary, result.data, None
        history.record(
            obs, INTEL_ENRICHED, actor=actor[:64], field="intel", new=result.summary.get("verdict"),
            provider=provider_id, provider_name=PROVIDERS[provider_id].name,
            headline=result.summary.get("headline"), status=result.status, **detail,
        )
    if normalize:
        db.flush()
        # Reputation normalization (no-op unless the mode is "auto").
        from app.intel.normalize import auto_apply

        auto_apply(db, [obs], actor[:64])
    return row


async def enrich(
    db: Session, observables: list[Observable], username: str, providers: list[str] | None = None, concurrency: int = 4
) -> list[IntelEnrichment]:
    """Look each observable up in every enabled (or the requested) integration that supports its type."""
    integrations = {i.provider: i for i in active_integrations(db) if not providers or i.provider in providers}
    keys = {p: decrypt(i.api_key_enc) for p, i in integrations.items()}
    jobs = [(obs, p) for obs in observables for p in integrations if PROVIDERS[p].supports(obs.type, obs.sub_type)]
    sem = asyncio.Semaphore(concurrency)

    async def run(obs: Observable, provider_id: str):
        async with sem:
            return await lookup(keys[provider_id], provider_id, obs.type, obs.value)

    results = await asyncio.gather(*(run(o, p) for o, p in jobs))
    now = utcnow()
    saved = [apply_result(db, obs, p, result, username, normalize=False, now=now) for (obs, p), result in zip(jobs, results, strict=True)]
    db.flush()
    # Reputation normalization (no-op unless the mode is "auto").
    from app.intel.normalize import auto_apply

    auto_apply(db, observables, username)
    return saved
