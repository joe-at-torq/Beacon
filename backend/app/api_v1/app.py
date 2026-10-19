"""The public, versioned Beacon API, mounted at /api/v1 with its own OpenAPI spec."""

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse

from app.api_v1 import enrichment_rules, observables, reference, rules, sync
from app.api_v1.postman import to_collection

DESCRIPTION = """
Programmatic access to the **Beacon** central observable database.

**Authentication**: create an API key in **Settings → API** and send it as
`Authorization: Bearer tim_…`. Each key has a role:
`viewer` (read only), `analyst` (also observable changes and syncs) or `admin` (also rules).
In this documentation, use **Authorize** to set your key, or just use your signed-in browser session.

**Conventions**: JSON everywhere; timestamps are ISO 8601 UTC; errors are `{"detail": "..."}`.
Enum values (types, sub types, reputations) are listed by `GET /meta`.
"""

TAGS = [
    {"name": "Observables", "description": "Create, read, update and delete observables in the central database."},
    {"name": "Database query", "description": "Search the central database with combinable filters."},
    {"name": "Rules", "description": "Directional sync rules (an allow-list) controlling what is pushed where."},
    {"name": "Enrichment rules", "description": "Automatically enrich new observables with threat-intel integrations, "
                                               "worked off by a rate-limited queue."},
    {"name": "Sync", "description": "Trigger synchronization with Torq workspaces and follow its progress."},
    {"name": "Reference", "description": "Workspaces and enum values needed to build requests."},
]

v1 = FastAPI(
    title="Beacon API",
    version="1.0.0",
    summary="Threat Intelligence Manager for Torq",
    description=DESCRIPTION,
    openapi_tags=TAGS,
    servers=[{"url": "/api/v1", "description": "This Beacon instance"}],
    docs_url=None,
    redoc_url=None,
    openapi_url="/openapi.json",
)
for module in (observables, rules, enrichment_rules, sync, reference):
    v1.include_router(module.router)

SWAGGER_HTML = """<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <title>Beacon API · Swagger UI</title>
    <link rel="icon" type="image/svg+xml" href="/favicon.svg" />
    <link rel="stylesheet" href="/swagger/swagger-ui.css" />
    <link rel="stylesheet" href="/swagger/tim-swagger.css" />
  </head>
  <body>
    <div id="swagger-ui"></div>
    <script src="/swagger/swagger-ui-bundle.js"></script>
    <script src="/swagger/swagger-ui-standalone-preset.js"></script>
    <script src="/swagger/tim-swagger-init.js"></script>
  </body>
</html>
"""


@v1.get("/docs", include_in_schema=False, response_class=HTMLResponse)
def swagger_ui():
    """Self-hosted Swagger UI (same-origin scripts only, so it works offline and under the CSP)."""
    return HTMLResponse(SWAGGER_HTML, headers={"Cache-Control": "no-cache"})


@v1.get("/postman.json", include_in_schema=False)
def postman_collection(request: Request):
    base_url = str(request.base_url).rstrip("/")
    if not base_url.endswith("/api/v1"):
        base_url += "/api/v1"
    return JSONResponse(
        to_collection(v1.openapi(), base_url),
        headers={"Content-Disposition": 'attachment; filename="Beacon API.postman_collection.json"'},
    )
