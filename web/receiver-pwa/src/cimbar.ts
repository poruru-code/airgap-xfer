type CimbarWasmModule = {
  default: (input?: RequestInfo | URL | Response | BufferSource | WebAssembly.Module) => Promise<void>;
  cimbar_version: () => string;
  cimbar_decode_rgba: (data: Uint8Array, width: number, height: number) => unknown;
};

let wasmDecode: ((data: Uint8Array, width: number, height: number) => unknown) | null = null;
let wasmVersion: (() => string) | null = null;

export async function initCimbarDecoder(): Promise<void> {
  const base = import.meta.env.BASE_URL ?? "/";
  const module = (await import(
    /* @vite-ignore */ `${base}wasm/cimbar/xfer_cimbar_wasm.js`
  )) as CimbarWasmModule;
  await module.default();
  wasmDecode = module.cimbar_decode_rgba;
  wasmVersion = module.cimbar_version;
}

export function cimbarDecoderReady(): boolean {
  return wasmDecode !== null;
}

export function cimbarVersion(): string | null {
  return wasmVersion ? wasmVersion() : null;
}

export function cimbarDecodeRgba(data: Uint8Array, width: number, height: number): string | null {
  if (!wasmDecode) {
    return null;
  }
  const result = wasmDecode(data, width, height);
  return typeof result === "string" && result.length > 0 ? result : null;
}
