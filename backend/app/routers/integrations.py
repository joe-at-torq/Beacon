from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.audit import log_event
from app.db import get_db
from app.intel.providers import PROVIDERS, IntelError
from app.intel.service import capabilities
from app.models import EnrichmentJob, Integration, User, utcnow
from app.security import decrypt, encrypt, get_active_user, require_admin
from app.serializers import iso
from app.services import source_cleanup

router = APIRouter(prefix="/api/integrations", tags=["integrations"])


class IntegrationIn(BaseModel):
    provider: str
    api_key: str = Field(min_length=8, max_length=512)
    name: str = ""
    enabled: bool = True


class IntegrationUpdate(BaseModel):
    api_key: str | None = Field(default=None, max_length=512)
    name: str | None = None
    enabled: bool | None = None


class TestIn(BaseModel):
    provider: str
    api_key: str = ""


def _out(i: Integration) -> dict:
    p = PROVIDERS.get(i.provider)
    key = decrypt(i.api_key_enc)
    return {
        "id": i.id,
        "provider": i.provider,
        "provider_name": p.name if p else i.provider,
        "name": i.name or (p.name if p else i.provider),
        "enabled": i.enabled,
        "key_hint": f"…{key[-4:]}" if len(key) >= 8 else "set",
        "types": p.types if p else [],
        "created_at": iso(i.created_at),
        "last_test_at": iso(i.last_test_at),
        "last_status": i.last_status,
        "last_error": i.last_error,
    }


def _provider(provider_id: str):
    p = PROVIDERS.get(provider_id)
    if not p:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"Unknown provider {provider_id!r}")
    return p


@router.get("/providers")
def list_providers(_: User = Depends(get_active_user)):
    return [
        {"id": p.id, "name": p.name, "description": p.description, "types": p.types, "key_help": p.key_help,
         "docs_url": p.docs_url, "color": p.color, "monogram": p.monogram, "sub_types": p.sub_types}
        for p in PROVIDERS.values()
    ]


@router.get("/capabilities")
def get_capabilities(db: Session = Depends(get_db), _: User = Depends(get_active_user)):
    """Observable type -> enabled providers that can enrich it (drives the UI's Enrich actions)."""
    return capabilities(db)


@router.get("")
def list_integrations(db: Session = Depends(get_db), _: User = Depends(get_active_user)):
    return [_out(i) for i in db.query(Integration).order_by(Integration.id).all()]


@router.post("", status_code=201)
def create_integration(body: IntegrationIn, db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    p = _provider(body.provider)
    if db.query(Integration).filter_by(provider=body.provider).first():
        raise HTTPException(status.HTTP_409_CONFLICT, f"{p.name} is already connected")
    integ = Integration(provider=body.provider, name=body.name.strip(), api_key_enc=encrypt(body.api_key.strip()),
                        enabled=body.enabled)
    db.add(integ)
    log_event(db, admin.username, "create_integration", "integration", p.name)
    db.commit()
    return _out(integ)


@router.patch("/{integration_id}")
def update_integration(integration_id: int, body: IntegrationUpdate, db: Session = Depends(get_db),
                       admin: User = Depends(require_admin)):
    integ = db.get(Integration, integration_id)
    if not integ:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Integration not found")
    if body.api_key:
        if len(body.api_key.strip()) < 8:
            raise HTTPException(422, "API key looks too short")
        integ.api_key_enc = encrypt(body.api_key.strip())
        integ.last_status = integ.last_error = None
    if body.name is not None:
        integ.name = body.name.strip()
    if body.enabled is not None:
        integ.enabled = body.enabled
    log_event(db, admin.username, "update_integration", "integration", integ.provider)
    db.commit()
    return _out(integ)


@router.get("/{integration_id}/delete-impact")
def delete_impact(integration_id: int, db: Session = Depends(get_db), _: User = Depends(require_admin)):
    """Lookup providers don't add observables; removing one can delete its stored enrichment results."""
    integ = db.get(Integration, integration_id)
    if not integ:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Integration not found")
    return {"enrichments": source_cleanup.enrichment_count(db, integ.provider)}


@router.delete("/{integration_id}", status_code=204)
def delete_integration(integration_id: int, remove_enrichment: bool = False, db: Session = Depends(get_db),
                       admin: User = Depends(require_admin)):
    integ = db.get(Integration, integration_id)
    if not integ:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Integration not found")
    removed = source_cleanup.remove_enrichment(db, integ.provider) if remove_enrichment else 0
    integ = db.get(Integration, integration_id)
    db.delete(integ)
    # Nothing can work off this provider's queued lookups any more.
    db.query(EnrichmentJob).filter(EnrichmentJob.provider == integ.provider, EnrichmentJob.status == "queued").delete(
        synchronize_session=False
    )
    log_event(db, admin.username, "delete_integration", "integration",
              integ.provider + (f" ({removed} enrichment results removed)" if removed else ""))
    db.commit()


@router.post("/test")
async def test_unsaved(body: TestIn, db: Session = Depends(get_db), _: User = Depends(require_admin)):
    """Test a key before saving; with an empty key, tests the stored key for that provider."""
    p = _provider(body.provider)
    key = body.api_key.strip()
    integ = db.query(Integration).filter_by(provider=body.provider).first()
    if not key and integ:
        key = decrypt(integ.api_key_enc)
    if not key:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "An API key is required")
    try:
        message, ok = await p.test(key), True
    except IntelError as e:
        message, ok = str(e), False
    except Exception as e:  # network errors etc.
        message, ok = f"{p.name} could not be reached: {e}", False
    if integ and not body.api_key.strip():
        integ.last_test_at, integ.last_status, integ.last_error = utcnow(), "ok" if ok else "error", None if ok else message
        db.commit()
    return {"ok": ok, "message": message}
