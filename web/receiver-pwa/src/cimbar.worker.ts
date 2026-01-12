/* eslint-disable no-restricted-globals */

type InitMessage = { type: "init"; baseUrl: string };
type DecodeMessage = {
  type: "decode";
  id: number;
  rgba: Uint8Array;
  width: number;
  height: number;
  mode?: number;
};

type WorkerMessage = InitMessage | DecodeMessage;

type ReadyResponse = { type: "ready"; bufsize: number | null };
type DecodeResponse = {
  type: "decoded";
  id: number;
  len: number;
  mode: number | null;
  status: "ok" | "nodata";
  bytes?: ArrayBuffer;
};

type ErrorResponse = { type: "error"; id?: number; message: string };

type WorkerResponse = ReadyResponse | DecodeResponse | ErrorResponse;

type EmscriptenModule = {
  HEAPU8: Uint8Array;
  _malloc: (size: number) => number;
  _free: (ptr: number) => void;
  _cimbard_get_bufsize?: () => number;
  _cimbard_scan_extract_decode?: (
    imgPtr: number,
    width: number,
    height: number,
    format: number,
    outPtr: number,
    outSize: number,
  ) => number;
  _cimbard_get_report?: (ptr: number, len: number) => number;
  _cimbard_configure_decode?: (mode: number) => void;
};

declare const self: DedicatedWorkerGlobalScope & {
  Module?: EmscriptenModule;
  importScripts?: (...urls: string[]) => void;
};

type CimbarAssets = {
  js: string;
  wasm: string;
  version?: string;
};

let initPromise: Promise<number | null> | null = null;
let wasmBaseUrl = "";
let bufsize: number | null = null;
let imgBuff: Uint8Array | null = null;
let fountainBuff: Uint8Array | null = null;
let errorBuff: Uint8Array | null = null;
let autoModeIndex = 0;

const AUTO_MODES = [67, 68, 4];

function ensureInit(baseUrl: string): Promise<number | null> {
  if (initPromise) {
    return initPromise;
  }

  wasmBaseUrl = baseUrl;

  initPromise = fetch(`${wasmBaseUrl}cimbar_assets.json`)
    .then(async (response) => {
      if (!response.ok) {
        throw new Error(`failed to load cimbar_assets.json (${response.status})`);
      }
      return (await response.json()) as CimbarAssets;
    })
    .then(
      (assets) =>
        new Promise<number | null>((resolve, reject) => {
          const module: Record<string, unknown> = {
            locateFile: (path: string) => `${wasmBaseUrl}${path}`,
            print: (...args: unknown[]) => console.log("[cimbar]", ...args),
            printErr: (...args: unknown[]) => console.error("[cimbar]", ...args),
            onRuntimeInitialized: () => {
              const detected =
                typeof self.Module?._cimbard_get_bufsize === "function"
                  ? self.Module._cimbard_get_bufsize()
                  : null;
              bufsize = Number.isFinite(detected) ? (detected as number) : null;
              resolve(bufsize);
            },
          };

          self.Module = module as EmscriptenModule;

          try {
            if (!self.importScripts) {
              throw new Error("importScripts unavailable in worker");
            }
            self.importScripts(`${wasmBaseUrl}${assets.js}`);
          } catch (err) {
            reject(err instanceof Error ? err : new Error("failed to load cimbar_js"));
          }
        }),
    );

  return initPromise;
}

function ensureBuffer(name: "img" | "fountain" | "error", size: number): Uint8Array {
  if (!self.Module) {
    throw new Error("cimbar module not ready");
  }
  if (!Number.isFinite(size) || size <= 0) {
    throw new Error(`invalid buffer size for ${name}`);
  }
  let current: Uint8Array | null = null;
  if (name === "img") {
    current = imgBuff;
  } else if (name === "fountain") {
    current = fountainBuff;
  } else {
    current = errorBuff;
  }
  if (!current || current.length < size) {
    if (current) {
      self.Module._free(current.byteOffset);
    }
    const ptr = self.Module._malloc(size);
    current = new Uint8Array(self.Module.HEAPU8.buffer, ptr, size);
    if (name === "img") {
      imgBuff = current;
    } else if (name === "fountain") {
      fountainBuff = current;
    } else {
      errorBuff = current;
    }
  }
  return current;
}

function getReport(): string {
  if (!self.Module?._cimbard_get_report) {
    return "";
  }
  const buff = ensureBuffer("error", 256);
  const len = self.Module._cimbard_get_report(buff.byteOffset, buff.length);
  if (len <= 0) {
    return "";
  }
  const view = new Uint8Array(self.Module.HEAPU8.buffer, buff.byteOffset, len);
  return new TextDecoder().decode(view);
}

function decodeFrame(message: DecodeMessage) {
  if (!self.Module || !self.Module._cimbard_scan_extract_decode) {
    const response: ErrorResponse = { type: "error", id: message.id, message: "cimbar module not ready" };
    self.postMessage(response as WorkerResponse);
    return;
  }
  if (!bufsize || bufsize <= 0) {
    const response: ErrorResponse = { type: "error", id: message.id, message: "cimbar bufsize unavailable" };
    self.postMessage(response as WorkerResponse);
    return;
  }

  let mode = message.mode ?? 0;
  if (!mode) {
    mode = AUTO_MODES[autoModeIndex % AUTO_MODES.length];
    autoModeIndex += 1;
  }
  if (mode && self.Module._cimbard_configure_decode) {
    self.Module._cimbard_configure_decode(mode);
  }

  const imgLen = message.rgba.length;
  const img = ensureBuffer("img", imgLen);
  img.set(message.rgba);
  const out = ensureBuffer("fountain", bufsize);

  const len = self.Module._cimbard_scan_extract_decode(
    img.byteOffset,
    message.width,
    message.height,
    4,
    out.byteOffset,
    out.length,
  );

  if (len <= 0) {
    if (len < 0) {
      const report = getReport();
      const response: ErrorResponse = {
        type: "error",
        id: message.id,
        message: report || `cimbar decode failed (${len})`,
      };
      self.postMessage(response as WorkerResponse);
      return;
    }
    const response: DecodeResponse = {
      type: "decoded",
      id: message.id,
      len,
      mode,
      status: "nodata",
    };
    self.postMessage(response as WorkerResponse);
    return;
  }

  const bytes = new Uint8Array(self.Module.HEAPU8.buffer, out.byteOffset, len).slice().buffer;
  const response: DecodeResponse = {
    type: "decoded",
    id: message.id,
    len,
    mode,
    status: "ok",
    bytes,
  };
  self.postMessage(response as WorkerResponse, [bytes]);
}

self.onmessage = (event: MessageEvent<WorkerMessage>) => {
  const msg = event.data;
  if (!msg) {
    return;
  }
  if (msg.type !== "init") {
    decodeFrame(msg);
    return;
  }

  ensureInit(msg.baseUrl)
    .then((bufsize) => {
      const response: ReadyResponse = { type: "ready", bufsize };
      self.postMessage(response as WorkerResponse);
    })
    .catch((err) => {
      const response: ErrorResponse = {
        type: "error",
        message: err instanceof Error ? err.message : "cimbar init failed",
      };
      self.postMessage(response as WorkerResponse);
    });
};
