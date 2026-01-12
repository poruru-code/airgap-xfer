import { prepareZXingModule, readBarcodes, type ReaderOptions } from "zxing-wasm/reader";
import zxingWasmUrl from "zxing-wasm/reader/zxing_reader.wasm?url";

type DecodeSource = "file" | "camera";

type InitMessage = { type: "init" };
type DecodeMessage = { type: "decode"; id: number; source: DecodeSource; imageData: ImageData };
type DecodeBitmapMessage = {
  type: "decode-bitmap";
  id: number;
  source: DecodeSource;
  bitmap: ImageBitmap;
  targetWidth: number;
  targetHeight: number;
};
type WorkerMessage = InitMessage | DecodeMessage | DecodeBitmapMessage;

type ReadyResponse = { type: "ready" };
type DecodeResponse = {
  type: "decoded";
  id: number;
  source: DecodeSource;
  text: string | null;
  format: string | null;
  durationMs: number;
};
type ErrorResponse = { type: "error"; id?: number; source?: DecodeSource; message: string };

type WorkerResponse = ReadyResponse | DecodeResponse | ErrorResponse;

let initPromise: Promise<void> | null = null;
let offscreenCanvas: OffscreenCanvas | null = null;
let offscreenContext: OffscreenCanvasRenderingContext2D | null = null;

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

function ensureOffscreenContext(width: number, height: number): OffscreenCanvasRenderingContext2D {
  if (typeof OffscreenCanvas === "undefined") {
    throw new Error("OffscreenCanvas unavailable");
  }
  if (!offscreenCanvas || offscreenCanvas.width !== width || offscreenCanvas.height !== height) {
    offscreenCanvas = new OffscreenCanvas(width, height);
    offscreenContext = offscreenCanvas.getContext("2d", { willReadFrequently: true });
  }
  if (!offscreenContext) {
    throw new Error("OffscreenCanvas context unavailable");
  }
  return offscreenContext;
}

async function decodeImageData(imageData: ImageData, id: number, source: DecodeSource, started: number) {
  await ensureReady();
  const options: ReaderOptions = {
    formats: ["QRCode"],
    maxNumberOfSymbols: 1,
    tryHarder: true,
  };
  const results = await readBarcodes(imageData, options);
  const match = results[0];
  const response: DecodeResponse = {
    type: "decoded",
    id,
    source,
    text: match?.text ?? null,
    format: match?.format ?? null,
    durationMs: performance.now() - started,
  };
  self.postMessage(response as WorkerResponse);
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
      await decodeImageData(message.imageData, message.id, message.source, started);
    } catch (err) {
      const response: ErrorResponse = {
        type: "error",
        id: message.id,
        source: message.source,
        message: err instanceof Error ? err.message : "decode failed",
      };
      self.postMessage(response as WorkerResponse);
    }
    return;
  }

  if (message.type === "decode-bitmap") {
    const started = performance.now();
    const bitmap = message.bitmap;
    try {
      const width = message.targetWidth > 0 ? message.targetWidth : bitmap.width;
      const height = message.targetHeight > 0 ? message.targetHeight : bitmap.height;
      const context = ensureOffscreenContext(width, height);
      context.drawImage(bitmap, 0, 0, width, height);
      const imageData = context.getImageData(0, 0, width, height);
      await decodeImageData(imageData, message.id, message.source, started);
    } catch (err) {
      const response: ErrorResponse = {
        type: "error",
        id: message.id,
        source: message.source,
        message: err instanceof Error ? err.message : "decode failed",
      };
      self.postMessage(response as WorkerResponse);
    } finally {
      bitmap.close();
    }
  }
};
