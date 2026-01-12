# Airgap Xfer Implementation Plan

## Goals
- Sender: Rust native app (Windows/Linux/macOS), no GPU requirement
- Receiver: PWA (iOS/Android) with camera capture and WASM decode
- Pipeline: compress -> encrypt -> fountain code -> barcode -> fixed-resolution display
- One-way channel: no ARQ; loss handled by fountain coding
- Security: AEAD encryption with DH key exchange or PSK fallback

## Assumptions
- Phase 1 uses monochrome animated QR for fast iteration
- Phase 2+ targets Cimbar (high-density color barcode)
- Receiver uses Worker + OffscreenCanvas + ImageBitmap; SAB when available

## Decisions (v1 locked)
- AEAD: AES-256-GCM
- KDF: HKDF-SHA256
- Fountain: RaptorQ via raptorq crate (pure Rust)
- Compression: zstd (always enabled)
- Encryption: optional (AEAD_NONE supported)
- RaptorQ params: auto-computed via ObjectTransmissionInformation defaults
- chunk_plain_len: 4096 bytes
- tag_len: 16 bytes
- nonce: 96-bit (GCM standard)

## Display Requirements (v1)
- Renderer MUST use a fixed internal resolution (default: 1920x1080)
- Output MUST be scaled to the physical display using integer scaling only
- Non-integer scaling MUST be avoided; unused area MUST be filled with black
- Fullscreen (borderless) MUST NOT be used; rendering resolution MUST remain fixed

## Repository Layout (Cargo Workspace)
- crates/xfer-core: compression/encryption/manifest/chunking/CRC/stream IO
- crates/xfer-fountain: fountain coding (RaptorQ or initial simple FEC)
- crates/xfer-codec: barcode encoding abstraction (QR/Color/Cimbar)
- crates/xfer-render: frame generation and rendering (winit + wgpu)
- crates/xfer-cli: sender CLI app
- web/receiver-pwa: PWA receiver
- web/wasm/decode: WASM decode (C++ or Rust)

## Implementation Status (current)
- Workspace layout and crate skeletons created
- xfer-core: SessionHeaderV1/ManifestV1 pack/unpack + CRC32C + TLV helpers + AES-256-GCM/HKDF + Nonce/AAD + zstd reader/decoder helpers + encrypt/decrypt stream helpers + DataPacketV1 reader/writer + fixed test vectors implemented
- xfer-core: PacketsFileHeaderV1 (packets.bin header) + header reader added (required)
- xfer-fountain: RaptorQ wrapper encoder/decoder + helpers for default config/packet counts + roundtrip test implemented
- xfer-cli: generates session header/manifest, compresses (always) and optionally encrypts, emits session_header.bin/manifest.bin/debug.json/ciphertext.bin, packetizes ciphertext via RaptorQ to packets.bin (with header), optional RaptorQ stats
- xfer-cli (receiver): xfer-recv decrypts + decompresses ciphertext.bin using debug.json + PSK, or reconstructs ciphertext from packets.bin; decrypt is skipped when crypto.enabled=false
- xfer-cli (inspect): xfer-packets prints stats from packets.bin
- scripts: e2e_packets.sh for encrypted/plain packet roundtrip validation
- web/receiver-pwa: Playwright E2E to validate wasm-backed CRC32C parsing
- scripts: build_wasm_decode.sh to build wasm decode crate into `web/receiver-pwa/public/wasm/decode`
- web/receiver-pwa: Vite scaffold + packets inspector UI + packets.ts parser for packets.bin header/DataPacketV1 + CRC32C
- web/receiver-pwa: package manager is bun
- toolchain: bun via mise; wasm-pack installed via mise-managed cargo (scripts/build_wasm_decode.sh)
- web/wasm/decode: Rust wasm crate scaffold (crc32c + packets header CRC check)
- xfer-codec/xfer-render: not started

## Protocol Spec (v1)
### Binary Conventions
- Endianness: Little Endian
- CRC: CRC32C (Castagnoli)
- Version: u16 present in all top-level structures

### Session Header Frame v1 (repeated frames)
Fixed header (40 bytes):

| Offset | Size | Field            | Notes                                  |
| -----: | ---: | ---------------- | -------------------------------------- |
|      0 |    4 | magic            | ASCII "AXFR"                           |
|      4 |    2 | version          | 0x0001                                 |
|      6 |    1 | header_type      | 0x01 = session_header                  |
|      7 |    1 | flags            | bit0: has_dh, bit1: has_psk_hint       |
|      8 |   16 | session_id       | random 128-bit                          |
|     24 |    4 | header_seq       | increments on header updates           |
|     28 |    4 | payload_len      | bytes in payload                       |
|     32 |    4 | payload_crc32c   | CRC32C of payload                      |
|     36 |    4 | header_crc32c    | CRC32C of offset 0..35                 |

Payload (TLV): t:u16, l:u16, v:[l] (Little Endian). v1 requires these TLVs:
- 0x0001 file_meta
  - file_size:u64
  - file_name_len:u16 + bytes
  - mime_len:u16 + bytes
- 0x0002 codec_meta
  - codec_id:u16 (1=animQR, 2=cimbar)
  - fps_x100:u16 (3000 = 30.00fps)
  - frame_w:u16
  - frame_h:u16
- 0x0003 fountain_meta
  - fountain_id:u16 (1=raptorq)
  - symbol_size:u16
  - source_blocks:u32
  - symbols_per_block:u32
  - target_overhead_x1000:u16 (30 = 3.0%)
- 0x0004 crypto_meta
  - aead_id:u16 (0=NONE, 1=AES-256-GCM)
  - kdf_id:u16 (0=NONE, 1=HKDF-SHA256)
  - salt_len:u16 + salt
  - nonce_mode:u16 (0=NONE, 1=HKDF-Expand per Nonce spec)
  - Note: aead_id=0 implies no encryption; salt_len=0 and nonce_mode=0
- 0x0005 integrity_meta
  - manifest_hash_alg:u16 (1=SHA-256)
  - manifest_hash_len:u16 + bytes

### Manifest v1 (one-time validation)
Fixed header (48 bytes):

| Offset | Size | Field             | Notes                     |
| -----: | ---: | ----------------- | ------------------------- |
|      0 |    4 | magic             | ASCII "AXMF"              |
|      4 |    2 | version           | 0x0001                    |
|      6 |    2 | flags             | reserved                  |
|      8 |   16 | session_id        | matches session header    |
|     24 |    8 | orig_file_size    | bytes                     |
|     32 |    8 | compressed_size   | bytes                     |
|     40 |    4 | chunk_plain_len   | bytes                     |
|     44 |    4 | manifest_crc32c   | CRC32C of offset 0..43    |

Variable TLV section (same TLV format as session header):
- file_name, mime
- hash_of_ciphertext (recommended)
- hash_of_plaintext (optional if leakage concern)

### Data Packet (multiple per frame)
- session_id
- seq
- payload_type: HEADER / FOUNTAIN / KEYEX / HEARTBEAT
- payload_len
- payload
- crc32c

### Packets File Header v1 (packets.bin)
Fixed header (40 bytes):

| Offset | Size | Field            | Notes                           |
| -----: | ---: | ---------------- | ------------------------------- |
|      0 |    4 | magic            | ASCII "AXPF"                    |
|      4 |    2 | version          | 0x0001                          |
|      6 |    2 | flags            | reserved                        |
|      8 |   16 | session_id       | matches session header          |
|     24 |    4 | packet_count     | number of DataPacketV1 entries |
|     28 |    8 | packet_bytes     | bytes of DataPacketV1 data      |
|     36 |    4 | header_crc32c    | CRC32C of offset 0..35          |

Notes:
- packets.bin MUST start with this header; readers should treat missing/invalid headers as errors

### Nonce and AAD (v1)
- Nonce (96-bit): HKDF-Expand(master_nonce_key, session_id || sbn:u32 || esi:u32, 12 bytes)
- AAD: "AXPK" || version || session_id || sbn || esi || payload_type

## Work Breakdown

### Epic S1: xfer-core (compression/encryption/manifest)
- Status: done
- DONE: Define binary manifest + session header format
- DONE: Implement stream read -> zstd compress
- DONE: Implement AEAD encrypt (AES-256-GCM) with HKDF-SHA256
- DONE: Implement Nonce/AAD derivation per v1 spec
- DONE: Create deterministic test vectors (fixed vectors in unit tests)
- DONE: Acceptance: given fixed input, output matches stored test vectors

### Epic S2: xfer-fountain (loss tolerance)
- Status: partial
- TODO: Phase 1: simple fixed-redundancy sharding (PoC FEC)
- DONE: Phase 2+: integrate RaptorQ (raptorq crate)
- Sender API:
  - Encoder::new(K, symbol_size)
  - next_symbol() -> (esi, bytes)
- Receiver API:
  - Decoder::new(K, symbol_size)
  - push_symbol(esi, bytes)
  - is_complete() / recover()
- PARTIAL: wrapper uses RaptorqEncoder/RaptorqDecoder with next_packet/push_packet; packet output to packets.bin implemented; packet reader tool added
- TODO: Acceptance: recover original data with configured loss rate (with repair symbols)

### Epic S3: xfer-codec (barcode abstraction)
- Status: not started
- FrameEncoder trait:
  - encode_packets(packets) -> FrameImage
  - max_payload_per_frame()
- Phase 1: animated monochrome QR
- Phase 2: Cimbar encoder integration
- Acceptance: payload round-trip through encode/decode in test harness

### Epic S4: xfer-render (fixed-resolution display)
- Status: not started
- Implement winit + wgpu renderer with fixed FPS
- Frame scheduler:
  - constant FPS (e.g., 30)
  - insert header frames at interval
- UI overlays:
  - alignment guide, brightness/contrast tuning
  - calibration pattern for color barcode (Phase 2)
- Enforce integer-only scaling with black letterboxing per Display Requirements (v1)
- Acceptance: stable fixed-resolution rendering at target FPS

### Epic S5: key exchange and PSK fallback
- Status: not started
- DH flow (two-way if possible): A -> B -> derive
- PSK flow: passphrase-based KDF
- Minimize protocol branching by fixing session_id + salt + KDF
- Acceptance: shared key derived consistently on both ends

### Epic R1: PWA capture pipeline
- Status: partial
- DONE: Vite scaffold + file-based packets inspector UI
- TODO: getUserMedia camera setup
- TODO: ImageBitmap + OffscreenCanvas frame extraction
- TODO: Worker pipeline, SAB when available
- Acceptance: stable frame delivery at target FPS

### Epic R2: PWA/WASM decode
- Status: partial
- DONE: wasm decode crate scaffold (crc32c + packets header CRC check)
- DONE: PWA loads wasm decoder at startup (CRC32C backed by wasm when available)
- Phase 1: QR decode in JS/WASM
- Phase 2: Cimbar decode via WASM (libcimbar)
- Minimal image preprocessing (OpenCV WASM optional)
- Decoder telemetry: success rate, blur/brightness indicators
- Acceptance: decode success rate meets target in controlled lighting

### Epic R3: recovery, decrypt, save
- Status: partial
- Store received symbols in IndexedDB
- Fountain recovery in WASM or JS
- Decrypt -> decompress -> file save
- Acceptance: recovered file hash equals manifest_hash

## Phased Roadmap
### Phase 1 (Baseline Transfer)
- Rust sender shows animated QR in fixed-resolution window (no fullscreen)
- PWA decodes and reconstructs 1-10MB file
- Loss tolerance minimal (best-effort only)

### Phase 2 (Performance)
- Cimbar encoding/decoding
- WASM optimizations: Worker/SAB/OffscreenCanvas
- Target performance near documented 850 kbps class

### Phase 3 (Reliability + Security)
- Full fountain integration (RaptorQ/Wirehair)
- Key exchange or PSK finalized
- UX polish: "keep camera pointed" flow

## Initial Sprints
### Sprint 0 (Foundation)
- DONE: Create workspace and core crates
- DONE: Finalize manifest + session header binary format
- DONE: End-to-end path exists (compress + encrypt + ciphertext output); fixed vectors added

### Sprint 1 (Rendering)
- Status: not started
- wgpu fixed-resolution renderer with stable FPS
- Periodic header frame insertion

### Sprint 2 (PoC Transfer)
- Status: not started
- QR payload carrier
- PWA receiver: decode -> recover -> save (no loss tolerance)

## Risks and Mitigations
- Barcode decode instability: add alignment guide, telemetry, and adaptive FPS
- Mobile performance limits: use Worker/SAB and avoid main-thread decode
- Two-way key exchange infeasible: keep PSK fallback ready
- AES-GCM nonce reuse risk: enforce deterministic nonce derivation and test vectors

## Open Questions
- Target symbol_size and chunk_size for phase 1
- Required barcode format and resolution for MVP
- DH key exchange flow details vs PSK default
