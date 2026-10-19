// Copies Swagger UI assets into dist/swagger so /api/v1/docs works offline (no CDN) under the strict CSP.
import { copyFileSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const src = dirname(require.resolve("swagger-ui-dist/package.json"));
const out = join(process.cwd(), "dist", "swagger");
mkdirSync(out, { recursive: true });
for (const f of ["swagger-ui.css", "swagger-ui-bundle.js", "swagger-ui-standalone-preset.js"]) {
  copyFileSync(join(src, f), join(out, f));
}
console.log("Swagger UI assets copied to dist/swagger");
