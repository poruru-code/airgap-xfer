import "./style.css";
import {
  DATA_PACKET_HEADER_LEN,
  PACKETS_FILE_HEADER_LEN,
  initWasmDecoder,
  readPacketsFileHeader,
  parseDataPacket,
  wasmDecoderReady,
} from "./packets";

const packetsInput = document.querySelector<HTMLInputElement>("#packets-file");
const debugInput = document.querySelector<HTMLInputElement>("#debug-file");
const qrInput = document.querySelector<HTMLInputElement>("#qr-file");
const statusEl = document.querySelector<HTMLDivElement>("#status");
const qrStatusEl = document.querySelector<HTMLDivElement>("#qr-status");
const qrResultEl = document.querySelector<HTMLDivElement>("#qr-result");
const packetsSummaryEl = document.querySelector<HTMLDivElement>("#packets-summary");
const debugSummaryEl = document.querySelector<HTMLDivElement>("#debug-summary");
const checksEl = document.querySelector<HTMLDivElement>("#checks");
const detailsEl = document.querySelector<HTMLDivElement>("#details");

if (!packetsInput || !debugInput || !qrInput || !statusEl || !qrStatusEl || !qrResultEl || !packetsSummaryEl || !debugSummaryEl || !checksEl || !detailsEl) {
  throw new Error("missing required DOM elements");
}

type DebugInfo = {
  sessionIdHex: string;
  cryptoEnabled: boolean;
  chunkPlainLen?: number;
  compressedSize?: number;
  ciphertextSize?: number;
  symbolSize?: number;
};

type PacketsInfo = {
  headerSessionId: Uint8Array;
  headerPacketCount: number;
  headerPacketBytes: bigint;
  packetCount: number;
  packetBytes: bigint;
  payloadBytes: bigint;
  minSeq: number;
  maxSeq: number;
  payloadTypeCounts: Map<number, number>;
  sessionMismatchCount: number;
};

let debugInfo: DebugInfo | null = null;
let packetsInfo: PacketsInfo | null = null;
let wasmStatus: "loading" | "ready" | "failed" = "loading";
let wasmError: string | null = null;
let qrWorkerStatus: "loading" | "ready" | "failed" = "loading";
let qrWorkerError: string | null = null;
let qrResult: { text: string | null; format: string | null; durationMs: number | null } | null = null;
let qrDecodeId = 0;

const qrWorker = new Worker(new URL("./qr.worker.ts", import.meta.url), { type: "module" });
qrWorker.postMessage({ type: "init" });
qrWorker.onmessage = (event) => {
  const msg = event.data as
    | { type: "ready" }
    | { type: "decoded"; id: number; text: string | null; format: string | null; durationMs: number }
    | { type: "error"; id?: number; message: string };
  if (msg.type === "ready") {
    qrWorkerStatus = "ready";
    renderAll();
    return;
  }
  if (msg.type === "error") {
    qrWorkerStatus = "failed";
    qrWorkerError = msg.message;
    if (msg.id !== undefined) {
      setQrStatus("decode failed", true);
    }
    renderAll();
    return;
  }
  if (msg.type === "decoded") {
    if (msg.id !== qrDecodeId) {
      return;
    }
    qrResult = {
      text: msg.text,
      format: msg.format,
      durationMs: msg.durationMs,
    };
    if (msg.text) {
      setQrStatus("decoded", false);
    } else {
      setQrStatus("no QR code found", true);
    }
    renderAll();
  }
};

function setStatus(message: string, isError = false) {
  statusEl.textContent = message;
  statusEl.style.color = isError ? "#ff6b6b" : "var(--accent-2)";
}

function setQrStatus(message: string, isError = false) {
  qrStatusEl.textContent = message;
  qrStatusEl.style.color = isError ? "#ff6b6b" : "var(--accent-2)";
}

function bytesToHex(bytes: Uint8Array) {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function renderKeyValue(container: HTMLElement, entries: Array<[string, string]>) {
  container.innerHTML = "";
  if (entries.length === 0) {
    container.innerHTML = "<div><span>status</span><span class=\"mono\">no data</span></div>";
    return;
  }
  for (const [label, value] of entries) {
    const row = document.createElement("div");
    const key = document.createElement("span");
    const val = document.createElement("span");
    key.textContent = label;
    val.textContent = value;
    row.appendChild(key);
    row.appendChild(val);
    container.appendChild(row);
  }
}

function payloadTypeLabel(type: number) {
  switch (type) {
    case 0x01:
      return "HEADER";
    case 0x02:
      return "FOUNTAIN";
    case 0x03:
      return "KEYEX";
    case 0x04:
      return "HEARTBEAT";
    default:
      return `UNKNOWN(${type})`;
  }
}

function formatBytes(value: bigint) {
  const units = ["B", "KB", "MB", "GB", "TB"];
  let val = value;
  let idx = 0;
  while (val >= 1024n && idx < units.length - 1) {
    val /= 1024n;
    idx += 1;
  }
  return `${val} ${units[idx]}`;
}

async function handlePacketsFile(file: File) {
  setStatus("Reading packets.bin...", false);
  try {
    const buffer = await file.arrayBuffer();
    const { header, offset } = readPacketsFileHeader(buffer);

    let cursor = offset;
    let packetCount = 0;
    let packetBytes = 0n;
    let payloadBytes = 0n;
    let minSeq = Number.POSITIVE_INFINITY;
    let maxSeq = 0;
    let sessionMismatchCount = 0;
    const payloadTypeCounts = new Map<number, number>();

    while (cursor < buffer.byteLength) {
      const { packet, bytesRead } = parseDataPacket(buffer, cursor);
      packetCount += 1;
      packetBytes += BigInt(bytesRead);
      payloadBytes += BigInt(packet.payload.length);
      minSeq = Math.min(minSeq, packet.seq);
      maxSeq = Math.max(maxSeq, packet.seq);
      const labelCount = payloadTypeCounts.get(packet.payloadType) ?? 0;
      payloadTypeCounts.set(packet.payloadType, labelCount + 1);
      if (!equalBytes(packet.sessionId, header.sessionId)) {
        sessionMismatchCount += 1;
      }
      cursor += bytesRead;
    }

    if (cursor !== buffer.byteLength) {
      throw new Error("packet parsing ended before EOF");
    }

    packetsInfo = {
      headerSessionId: header.sessionId,
      headerPacketCount: header.packetCount,
      headerPacketBytes: header.packetBytes,
      packetCount,
      packetBytes,
      payloadBytes,
      minSeq: Number.isFinite(minSeq) ? minSeq : 0,
      maxSeq,
      payloadTypeCounts,
      sessionMismatchCount,
    };

    setStatus("packets.bin loaded", false);
    renderAll();
  } catch (err) {
    packetsInfo = null;
    setStatus(err instanceof Error ? err.message : "failed to parse packets.bin", true);
    renderAll();
  }
}

async function handleDebugFile(file: File) {
  setStatus("Reading debug.json...", false);
  try {
    const text = await file.text();
    const json = JSON.parse(text) as Record<string, unknown>;
    debugInfo = parseDebugInfo(json);
    setStatus("debug.json loaded", false);
    renderAll();
  } catch (err) {
    debugInfo = null;
    setStatus(err instanceof Error ? err.message : "failed to parse debug.json", true);
    renderAll();
  }
}

function parseDebugInfo(json: Record<string, unknown>): DebugInfo {
  const sessionIdHex = String(json.session_id ?? "");
  const crypto = (json.crypto as Record<string, unknown> | undefined) ?? {};
  const cryptoEnabled = crypto.enabled === undefined ? true : Boolean(crypto.enabled);
  const raptorq = (json.raptorq as Record<string, unknown> | undefined) ?? {};
  return {
    sessionIdHex,
    cryptoEnabled,
    chunkPlainLen: toNumber(json.chunk_plain_len),
    compressedSize: toNumber(json.compressed_size),
    ciphertextSize: toNumber(json.ciphertext_size),
    symbolSize: toNumber(raptorq.symbol_size),
  };
}

function toNumber(value: unknown): number | undefined {
  if (value === undefined || value === null) {
    return undefined;
  }
  const num = Number(value);
  return Number.isFinite(num) ? num : undefined;
}

function equalBytes(a: Uint8Array, b: Uint8Array) {
  if (a.length !== b.length) {
    return false;
  }
  for (let i = 0; i < a.length; i += 1) {
    if (a[i] !== b[i]) {
      return false;
    }
  }
  return true;
}

function renderAll() {
  const packetEntries: Array<[string, string]> = [];
  const debugEntries: Array<[string, string]> = [];
  const checkEntries: Array<[string, string]> = [];
  const detailEntries: Array<[string, string]> = [];

  if (packetsInfo) {
    packetEntries.push(["Header session", bytesToHex(packetsInfo.headerSessionId)]);
    packetEntries.push(["Header packet count", packetsInfo.headerPacketCount.toString()]);
    packetEntries.push(["Header packet bytes", `${packetsInfo.headerPacketBytes} B`]);
    packetEntries.push(["Parsed packet count", packetsInfo.packetCount.toString()]);
    packetEntries.push(["Parsed packet bytes", `${packetsInfo.packetBytes} B`]);
    packetEntries.push(["Payload bytes", formatBytes(packetsInfo.payloadBytes)]);
    packetEntries.push(["Seq range", `${packetsInfo.minSeq}..${packetsInfo.maxSeq}`]);

    const typeLines: string[] = [];
    for (const [type, count] of packetsInfo.payloadTypeCounts.entries()) {
      typeLines.push(`${payloadTypeLabel(type)}=${count}`);
    }
    detailEntries.push(["Payload types", typeLines.join(", ") || "none"]);
    detailEntries.push(["Packet header bytes", PACKETS_FILE_HEADER_LEN.toString()]);
    detailEntries.push(["Data packet header bytes", DATA_PACKET_HEADER_LEN.toString()]);
  }

  detailEntries.push(["Wasm decoder", wasmStatus]);
  if (wasmError) {
    detailEntries.push(["Wasm error", wasmError]);
  } else if (wasmStatus === "ready") {
    detailEntries.push(["CRC32C backend", wasmDecoderReady() ? "wasm" : "js"]);
  }

  detailEntries.push(["ZXing worker", qrWorkerStatus]);
  if (qrWorkerError) {
    detailEntries.push(["ZXing error", qrWorkerError]);
  }

  if (qrResult) {
    const qrEntries: Array<[string, string]> = [];
    qrEntries.push(["Text", qrResult.text ?? "(none)"]);
    qrEntries.push(["Format", qrResult.format ?? "(none)"]);
    if (qrResult.durationMs !== null) {
      qrEntries.push(["Decode ms", qrResult.durationMs.toFixed(1)]);
    }
    renderKeyValue(qrResultEl, qrEntries);
  } else {
    renderKeyValue(qrResultEl, []);
  }

  if (debugInfo) {
    debugEntries.push(["Session", debugInfo.sessionIdHex || "(missing)"]);
    debugEntries.push(["Crypto enabled", String(debugInfo.cryptoEnabled)]);
    if (debugInfo.chunkPlainLen !== undefined) {
      debugEntries.push(["Chunk size", `${debugInfo.chunkPlainLen} B`]);
    }
    if (debugInfo.compressedSize !== undefined) {
      debugEntries.push(["Compressed size", `${debugInfo.compressedSize} B`]);
    }
    if (debugInfo.ciphertextSize !== undefined) {
      debugEntries.push(["Ciphertext size", `${debugInfo.ciphertextSize} B`]);
    }
    if (debugInfo.symbolSize !== undefined) {
      debugEntries.push(["Symbol size", `${debugInfo.symbolSize} B`]);
    }
  }

  if (packetsInfo) {
    const countMatch = packetsInfo.packetCount === packetsInfo.headerPacketCount;
    const bytesMatch = packetsInfo.packetBytes === packetsInfo.headerPacketBytes;
    checkEntries.push(["Packet count", countMatch ? "ok" : "mismatch"]);
    checkEntries.push(["Packet bytes", bytesMatch ? "ok" : "mismatch"]);
    checkEntries.push([
      "Session ID in packets",
      packetsInfo.sessionMismatchCount === 0 ? "ok" : `mismatch (${packetsInfo.sessionMismatchCount})`,
    ]);
  }

  if (packetsInfo && debugInfo) {
    const headerHex = bytesToHex(packetsInfo.headerSessionId);
    checkEntries.push([
      "Session ID vs debug.json",
      headerHex === debugInfo.sessionIdHex ? "ok" : "mismatch",
    ]);
  }

  renderKeyValue(packetsSummaryEl, packetEntries);
  renderKeyValue(debugSummaryEl, debugEntries);
  renderKeyValue(checksEl, checkEntries);
  renderKeyValue(detailsEl, detailEntries);
}

packetsInput.addEventListener("change", () => {
  const file = packetsInput.files?.[0];
  if (!file) {
    return;
  }
  void handlePacketsFile(file);
});

debugInput.addEventListener("change", () => {
  const file = debugInput.files?.[0];
  if (!file) {
    return;
  }
  void handleDebugFile(file);
});

qrInput.addEventListener("change", () => {
  const file = qrInput.files?.[0];
  if (!file) {
    return;
  }
  void decodeQrFile(file);
});

renderAll();

void initWasmDecoder()
  .then(() => {
    wasmStatus = "ready";
    renderAll();
  })
  .catch((err) => {
    wasmStatus = "failed";
    wasmError = err instanceof Error ? err.message : "wasm init failed";
    renderAll();
  });

async function decodeQrFile(file: File) {
  if (qrWorkerStatus === "failed") {
    setQrStatus("ZXing worker failed", true);
    return;
  }
  if (qrWorkerStatus === "loading") {
    setQrStatus("ZXing worker loading...", false);
  }
  setQrStatus("decoding...", false);
  qrResult = null;
  renderAll();

  const bitmap = await createImageBitmap(file);
  const canvas = document.createElement("canvas");
  canvas.width = bitmap.width;
  canvas.height = bitmap.height;
  const context = canvas.getContext("2d");
  if (!context) {
    setQrStatus("canvas unavailable", true);
    return;
  }
  context.drawImage(bitmap, 0, 0);
  const imageData = context.getImageData(0, 0, canvas.width, canvas.height);
  qrDecodeId += 1;
  qrWorker.postMessage({ type: "decode", id: qrDecodeId, imageData });
}
