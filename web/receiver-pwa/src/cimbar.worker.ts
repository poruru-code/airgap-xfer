/* eslint-disable no-restricted-globals */

type InitMessage = { type: "init"; baseUrl: string };

type WorkerMessage = InitMessage;

type ReadyResponse = { type: "ready"; bufsize: number | null };

type ErrorResponse = { type: "error"; message: string };

type WorkerResponse = ReadyResponse | ErrorResponse;

type EmscriptenModule = {
  HEAPU8: Uint8Array;
  _malloc: (size: number) => number;
  _free: (ptr: number) => void;
  _cimbard_get_bufsize?: () => number;
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
              const bufsize =
                typeof self.Module?._cimbard_get_bufsize === "function"
                  ? self.Module._cimbard_get_bufsize()
                  : null;
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

self.onmessage = (event: MessageEvent<WorkerMessage>) => {
  const msg = event.data;
  if (!msg) {
    return;
  }
  if (msg.type !== "init") {
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
