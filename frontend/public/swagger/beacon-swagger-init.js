// Swagger UI bootstrap for the Beacon API (external file: the CSP forbids inline scripts).
window.addEventListener("load", function () {
  window.ui = SwaggerUIBundle({
    url: "/api/v1/openapi.json",
    dom_id: "#swagger-ui",
    deepLinking: true,
    persistAuthorization: true,
    displayRequestDuration: true,
    filter: true,
    docExpansion: "list",
    defaultModelsExpandDepth: 0,
    presets: [SwaggerUIBundle.presets.apis, SwaggerUIStandalonePreset],
    layout: "BaseLayout",
    // Same-origin requests also carry the signed-in Beacon session, so "Try it out" works without a key.
    requestInterceptor: function (req) {
      req.credentials = "same-origin";
      return req;
    },
  });
});
