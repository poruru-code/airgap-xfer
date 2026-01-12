import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { defineConfig } from "vite";

const here = path.dirname(fileURLToPath(import.meta.url));

function resolveHttpsConfig() {
  if (process.env.VITE_HTTPS !== "1") {
    return undefined;
  }

  const certDir = process.env.VITE_HTTPS_CERT_DIR ?? path.join(here, "certs");
  const resolvedCertDir = path.isAbsolute(certDir) ? certDir : path.join(here, certDir);
  const certPath = process.env.VITE_HTTPS_CERT ?? path.join(resolvedCertDir, "localhost.pem");
  const keyPath = process.env.VITE_HTTPS_KEY ?? path.join(resolvedCertDir, "localhost-key.pem");

  if (!fs.existsSync(certPath) || !fs.existsSync(keyPath)) {
    throw new Error(
      `HTTPS enabled but cert/key missing. Expected ${certPath} and ${keyPath}. Run scripts/dev_https_pwa.sh.`,
    );
  }

  return {
    cert: fs.readFileSync(certPath),
    key: fs.readFileSync(keyPath),
  };
}

const httpsConfig = resolveHttpsConfig();

export default defineConfig({
  base: "./",
  server: {
    host: true,
    port: 5173,
    https: httpsConfig,
  },
  build: {
    outDir: "dist",
  },
});
