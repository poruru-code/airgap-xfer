export type CimbarInitInfo = {
  bufsize: number | null;
};

export type CimbarDecodeResult = {
  bytes: Uint8Array | null;
  len: number;
  mode: number | null;
  status: "ok" | "nodata";
};

type CimbarWorkerReady = { type: "ready"; bufsize: number | null };
type CimbarWorkerDecoded = {
  type: "decoded";
  id: number;
  len: number;
  mode: number | null;
  status: "ok" | "nodata";
  bytes?: ArrayBuffer;
};
type CimbarWorkerError = { type: "error"; id?: number; message: string };

type CimbarWorkerMessage = CimbarWorkerReady | CimbarWorkerDecoded | CimbarWorkerError;

let cimbarWorker: Worker | null = null;
let cimbarReady = false;
let cimbarError: string | null = null;
let cimbarBufsize: number | null = null;
let initPromise: Promise<CimbarInitInfo> | null = null;
let nextDecodeId = 0;
const pending = new Map<number, { resolve: (value: CimbarDecodeResult) => void; reject: (err: Error) => void }>();

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
      if (msg.type === "decoded") {
        const entry = pending.get(msg.id);
        if (!entry) {
          return;
        }
        pending.delete(msg.id);
        const bytes = msg.bytes ? new Uint8Array(msg.bytes) : null;
        entry.resolve({
          bytes,
          len: msg.len,
          mode: msg.mode ?? null,
          status: msg.status,
        });
        return;
      }
      if (msg.type === "error") {
        if (msg.id !== undefined) {
          const entry = pending.get(msg.id);
          if (entry) {
            pending.delete(msg.id);
            entry.reject(new Error(msg.message));
          }
          return;
        }
        cimbarReady = false;
        cimbarError = msg.message;
        reject(new Error(msg.message));
      }
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

export async function decodeCimbarRgba(
  data: Uint8Array,
  width: number,
  height: number,
  options?: { mode?: number; transfer?: boolean },
): Promise<CimbarDecodeResult> {
  if (!cimbarWorker || !cimbarReady) {
    throw new Error("cimbar decoder not ready");
  }
  const id = nextDecodeId + 1;
  nextDecodeId = id;
  const transfer = options?.transfer ?? false;
  const payload = {
    type: "decode",
    id,
    rgba: data,
    width,
    height,
    mode: options?.mode,
  } as const;
  const promise = new Promise<CimbarDecodeResult>((resolve, reject) => {
    pending.set(id, { resolve, reject });
  });
  if (transfer) {
    cimbarWorker.postMessage(payload, [data.buffer]);
  } else {
    cimbarWorker.postMessage(payload);
  }
  return promise;
}
