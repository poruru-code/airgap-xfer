import { execSync } from "node:child_process";
import { createWriteStream, existsSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import https from "node:https";
import { fileURLToPath } from "node:url";
import QRCode from "qrcode";

function run(cmd: string, cwd: string) {
  execSync(cmd, { cwd, stdio: "inherit" });
}

function downloadFile(url: string, dest: string): Promise<void> {
  if (existsSync(dest)) {
    return Promise.resolve();
  }
  return new Promise((resolve, reject) => {
    https
      .get(url, (res) => {
        if (res.statusCode && res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
          downloadFile(res.headers.location, dest).then(resolve, reject);
          return;
        }
        if (res.statusCode !== 200) {
          reject(new Error(`download failed: ${res.statusCode}`));
          return;
        }
        const file = createWriteStream(dest);
        res.pipe(file);
        file.on("finish", () => {
          file.close();
          resolve();
        });
      })
      .on("error", reject);
  });
}

export default async function globalSetup() {
  const here = path.dirname(fileURLToPath(import.meta.url));
  const repoRoot = path.resolve(here, "..", "..", "..");
  const artifactsDir = path.resolve(here, ".artifacts");
  mkdirSync(artifactsDir, { recursive: true });

  run("scripts/build_wasm_decode.sh", repoRoot);
  run("scripts/build_wasm_cimbar.sh", repoRoot);
  run("mise exec -- cargo build -p xfer-cli", repoRoot);

  const outDir = path.join(tmpdir(), `xfer-pwa-${Date.now()}`);
  const inputPath = path.join(outDir, "input.bin");
  mkdirSync(outDir, { recursive: true });

  const input = Buffer.alloc(64 * 1024);
  for (let i = 0; i < input.length; i += 1) {
    input[i] = i % 256;
  }
  writeFileSync(inputPath, input);

  const xferCli = path.join(repoRoot, "target", "debug", "xfer-cli");
  const cmd = [
    `"${xferCli}"`,
    `"${inputPath}"`,
    "--emit",
    "--emit-packets",
    `--out-dir \"${outDir}\"`,
    "--no-encrypt",
  ].join(" ");
  run(cmd, repoRoot);

  const qrPayload = "AIRGAP-TEST-QR";
  const qrPath = path.join(outDir, "qr.png");
  await QRCode.toFile(qrPath, qrPayload, {
    errorCorrectionLevel: "M",
    margin: 1,
    width: 256,
  });

  const cimbarUrl =
    "https://raw.githubusercontent.com/sz3/cimbar-samples/v0.5/6bit/4color_ecc30_fountain_0.png";
  const cimbarPath = path.join(outDir, "cimbar_sample.png");
  await downloadFile(cimbarUrl, cimbarPath);

  const artifactPaths = {
    packets: path.join(outDir, "packets.bin"),
    debug: path.join(outDir, "debug.json"),
    qr: qrPath,
    qrPayload,
    cimbar: cimbarPath,
  };

  writeFileSync(
    path.join(artifactsDir, "paths.json"),
    JSON.stringify(artifactPaths, null, 2),
    "utf-8",
  );
}
