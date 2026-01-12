import { expect, test } from "@playwright/test";
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const artifactsPath = path.resolve(here, ".artifacts", "paths.json");

function readArtifacts() {
  const raw = readFileSync(artifactsPath, "utf-8");
  const parsed = JSON.parse(raw) as { packets: string; debug: string };
  return parsed;
}

function valueForLabel(label: string) {
  return `#details div:has-text(\"${label}\") span:nth-child(2)`;
}

test("wasm-backed CRC32C parses packets.bin", async ({ page }) => {
  const { packets, debug } = readArtifacts();

  await page.goto("/");

  await page.setInputFiles("#packets-file", packets);
  await page.setInputFiles("#debug-file", debug);

  await expect(page.locator("#status")).toHaveText(/loaded/i);
  await expect(page.locator(valueForLabel("Wasm decoder"))).toHaveText(/ready/i);
  await expect(page.locator(valueForLabel("CRC32C backend"))).toHaveText(/wasm/i);
  await expect(page.locator("#checks")).toContainText("Session ID vs debug.json");
});
