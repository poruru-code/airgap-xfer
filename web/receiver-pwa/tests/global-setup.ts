import { execSync } from "node:child_process";
import { mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

function run(cmd: string, cwd: string) {
  execSync(cmd, { cwd, stdio: "inherit" });
}

export default async function globalSetup() {
  const here = path.dirname(fileURLToPath(import.meta.url));
  const repoRoot = path.resolve(here, "..", "..", "..");
  const artifactsDir = path.resolve(here, ".artifacts");
  mkdirSync(artifactsDir, { recursive: true });

  run("scripts/build_wasm_decode.sh", repoRoot);
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

  const artifactPaths = {
    packets: path.join(outDir, "packets.bin"),
    debug: path.join(outDir, "debug.json"),
  };

  writeFileSync(
    path.join(artifactsDir, "paths.json"),
    JSON.stringify(artifactPaths, null, 2),
    "utf-8",
  );
}
