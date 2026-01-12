export const PACKETS_FILE_MAGIC = 0x46505841; // "AXPF" little-endian
export const PACKETS_FILE_HEADER_LEN = 40;
export const PACKETS_FILE_VERSION_V1 = 1;

export const DATA_PACKET_HEADER_LEN = 25;

export type PacketsFileHeaderV1 = {
  flags: number;
  sessionId: Uint8Array;
  packetCount: number;
  packetBytes: bigint;
};

export type DataPacketV1 = {
  sessionId: Uint8Array;
  seq: number;
  payloadType: number;
  payload: Uint8Array;
};

type WasmDecodeModule = {
  default: (input?: RequestInfo | URL | Response | BufferSource | WebAssembly.Module) => Promise<void>;
  crc32c_bytes: (data: Uint8Array) => number;
  packets_header_crc_ok: (header: Uint8Array) => boolean;
};

let wasmCrc32c: ((data: Uint8Array) => number) | null = null;
let wasmHeaderOk: ((header: Uint8Array) => boolean) | null = null;

export async function initWasmDecoder(): Promise<void> {
  const base = import.meta.env.BASE_URL ?? "/";
  const module = (await import(
    /* @vite-ignore */ `${base}wasm/decode/xfer_decode_wasm.js`
  )) as WasmDecodeModule;
  await module.default();
  wasmCrc32c = module.crc32c_bytes;
  wasmHeaderOk = module.packets_header_crc_ok;
}

export function wasmDecoderReady(): boolean {
  return wasmCrc32c !== null;
}

export function packetsHeaderCrcOk(header: Uint8Array): boolean {
  if (wasmHeaderOk) {
    return wasmHeaderOk(header);
  }
  if (header.length < PACKETS_FILE_HEADER_LEN) {
    return false;
  }
  const expected = new DataView(header.buffer, header.byteOffset).getUint32(36, true);
  const computed = crc32c(header.subarray(0, 36));
  return expected === computed;
}

export function readPacketsFileHeader(
  buffer: ArrayBuffer,
): { header: PacketsFileHeaderV1; offset: number } {
  if (buffer.byteLength < PACKETS_FILE_HEADER_LEN) {
    throw new Error("packets header truncated");
  }
  const view = new DataView(buffer);
  return {
    header: parsePacketsFileHeader(view, 0),
    offset: PACKETS_FILE_HEADER_LEN,
  };
}

export function parsePacketsFileHeader(
  view: DataView,
  offset: number,
): PacketsFileHeaderV1 {
  const magic = view.getUint32(offset, true);
  if (magic !== PACKETS_FILE_MAGIC) {
    throw new Error("invalid packets file magic");
  }
  const version = view.getUint16(offset + 4, true);
  if (version !== PACKETS_FILE_VERSION_V1) {
    throw new Error(`unsupported packets file version ${version}`);
  }
  const flags = view.getUint16(offset + 6, true);
  const sessionId = new Uint8Array(view.buffer, view.byteOffset + offset + 8, 16);
  const packetCount = view.getUint32(offset + 24, true);
  const packetBytes = view.getBigUint64(offset + 28, true);
  const expectedCrc = view.getUint32(offset + 36, true);
  const computedCrc = crc32c(
    new Uint8Array(view.buffer, view.byteOffset + offset, 36),
  );
  if (expectedCrc !== computedCrc) {
    throw new Error("packets header crc mismatch");
  }
  return {
    flags,
    sessionId: new Uint8Array(sessionId),
    packetCount,
    packetBytes,
  };
}

export function parseDataPacket(
  buffer: ArrayBuffer,
  offset: number,
): { packet: DataPacketV1; bytesRead: number } {
  if (buffer.byteLength - offset < DATA_PACKET_HEADER_LEN + 4) {
    throw new Error("data packet truncated");
  }
  const view = new DataView(buffer, offset);
  const sessionId = new Uint8Array(view.buffer, view.byteOffset + 0, 16);
  const seq = view.getUint32(16, true);
  const payloadType = view.getUint8(20);
  const payloadLen = view.getUint32(21, true);
  const needed = DATA_PACKET_HEADER_LEN + payloadLen + 4;
  if (buffer.byteLength - offset < needed) {
    throw new Error("data packet payload truncated");
  }
  const payload = new Uint8Array(view.buffer, view.byteOffset + 25, payloadLen);
  const expectedCrc = view.getUint32(DATA_PACKET_HEADER_LEN + payloadLen, true);
  const computedCrc = crc32c(
    new Uint8Array(view.buffer, view.byteOffset + 0, DATA_PACKET_HEADER_LEN + payloadLen),
  );
  if (expectedCrc !== computedCrc) {
    throw new Error("data packet crc mismatch");
  }
  return {
    packet: {
      sessionId: new Uint8Array(sessionId),
      seq,
      payloadType,
      payload: new Uint8Array(payload),
    },
    bytesRead: needed,
  };
}

const CRC32C_TABLE: Uint32Array = (() => {
  const table = new Uint32Array(256);
  for (let i = 0; i < 256; i += 1) {
    let crc = i;
    for (let j = 0; j < 8; j += 1) {
      if ((crc & 1) !== 0) {
        crc = 0x82f63b78 ^ (crc >>> 1);
      } else {
        crc >>>= 1;
      }
    }
    table[i] = crc >>> 0;
  }
  return table;
})();

export function crc32c(data: Uint8Array): number {
  if (wasmCrc32c) {
    return wasmCrc32c(data);
  }
  let crc = 0xffffffff;
  for (let i = 0; i < data.length; i += 1) {
    const byte = data[i];
    const idx = (crc ^ byte) & 0xff;
    crc = CRC32C_TABLE[idx] ^ (crc >>> 8);
  }
  return (crc ^ 0xffffffff) >>> 0;
}
