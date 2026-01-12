import { prepareZXingModule, readBarcodes, type ReaderOptions } from "zxing-wasm/reader";
import zxingWasmUrl from "zxing-wasm/reader/zxing_reader.wasm?url";

type InitMessage = { type: "init" };
type DecodeMessage = { type: "decode"; id: number; imageData: ImageData };
type WorkerMessage = InitMessage | DecodeMessage;

type ReadyResponse = { type: "ready" };
type DecodeResponse = {
  type: "decoded";
  id: number;
  text: string | null;
  format: string | null;
  durationMs: number;
};
type ErrorResponse = { type: "error"; id?: number; message: string };

type WorkerResponse = ReadyResponse | DecodeResponse | ErrorResponse;

let initPromise: Promise<void> | null = null;

async function ensureReady(): Promise<void> {
  if (!initPromise) {
    initPromise = prepareZXingModule({
      overrides: {
        locateFile: (path) => {
          if (path.endsWith(".wasm")) {
            return zxingWasmUrl;
          }
          return path;
        },
      },
      fireImmediately: true,
    }).then(() => undefined);
  }
  return initPromise;
}

self.onmessage = async (event: MessageEvent<WorkerMessage>) => {
  const message = event.data;
  if (!message) {
    return;
  }

  if (message.type === "init") {
    try {
      await ensureReady();
      const response: ReadyResponse = { type: "ready" };
      self.postMessage(response as WorkerResponse);
    } catch (err) {
      const response: ErrorResponse = {
        type: "error",
        message: err instanceof Error ? err.message : "zxing init failed",
      };
      self.postMessage(response as WorkerResponse);
    }
    return;
  }

  if (message.type === "decode") {
    const started = performance.now();
    try {
      await ensureReady();
      const options: ReaderOptions = {
        formats: ["QRCode"],
        maxNumberOfSymbols: 1,
        tryHarder: true,
      };
      const results = await readBarcodes(message.imageData, options);
      const match = results[0];
      const response: DecodeResponse = {
        type: "decoded",
        id: message.id,
        text: match?.text ?? null,
        format: match?.format ?? null,
        durationMs: performance.now() - started,
      };
      self.postMessage(response as WorkerResponse);
    } catch (err) {
      const response: ErrorResponse = {
        type: "error",
        id: message.id,
        message: err instanceof Error ? err.message : "decode failed",
      };
      self.postMessage(response as WorkerResponse);
    }
  }
};
