export type CimbarInitInfo = {
  bufsize: number | null;
};

type CimbarWorkerReady = { type: "ready"; bufsize: number | null };
type CimbarWorkerError = { type: "error"; message: string };

type CimbarWorkerMessage = CimbarWorkerReady | CimbarWorkerError;

let cimbarWorker: Worker | null = null;
let cimbarReady = false;
let cimbarError: string | null = null;
let cimbarBufsize: number | null = null;
let initPromise: Promise<CimbarInitInfo> | null = null;

export async function initCimbarDecoder(): Promise<CimbarInitInfo> {
  if (initPromise) {
    return initPromise;
  }
  initPromise = new Promise((resolve, reject) => {
    cimbarWorker = new Worker(new URL("./cimbar.worker.ts", import.meta.url), { type: "classic" });
    const base = import.meta.env.BASE_URL ?? "/";
    const wasmBase = new URL(`${base}wasm/cimbar/`, window.location.href).toString();

    cimbarWorker.onmessage = (event) => {
      const msg = event.data as CimbarWorkerMessage;
      if (msg.type === "ready") {
        cimbarReady = true;
        cimbarBufsize = msg.bufsize ?? null;
        resolve({ bufsize: cimbarBufsize });
        return;
      }
      cimbarReady = false;
      cimbarError = msg.message;
      reject(new Error(msg.message));
    };

    cimbarWorker.onerror = (event) => {
      cimbarReady = false;
      const message = event instanceof ErrorEvent ? event.message : "cimbar worker failed";
      cimbarError = message;
      reject(new Error(message));
    };

    cimbarWorker.postMessage({ type: "init", baseUrl: wasmBase });
  });
  return initPromise;
}

export function cimbarDecoderReady(): boolean {
  return cimbarReady;
}

export function cimbarDecoderError(): string | null {
  return cimbarError;
}

export function cimbarDecoderInfo(): CimbarInitInfo {
  return { bufsize: cimbarBufsize };
}
