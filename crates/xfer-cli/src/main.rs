use getrandom::fill;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::env;
use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use xfer_core::{
    derive_keys, encrypt_stream, tlv_codec_meta, tlv_crypto_meta, tlv_file_meta, tlv_fountain_meta,
    tlv_hash_ciphertext, tlv_integrity_meta, zstd_reader, DataPacketV1, EncryptResult,
    ManifestV1, PacketsFileHeaderV1, SessionHeaderV1, AEAD_AES_256_GCM, AEAD_NONE, CODEC_ANIM_QR,
    FOUNTAIN_RAPTORQ, HASH_SHA256, KDF_HKDF_SHA256, KDF_NONE, NONCE_MODE_HKDF_EXPAND,
    NONCE_MODE_NONE, PACKETS_FILE_HEADER_LEN, PAYLOAD_TYPE_FOUNTAIN, SESSION_HEADER_VERSION_V1,
};
use xfer_fountain::{ObjectTransmissionInformation, RaptorqEncoder};

struct CliOptions {
    input: PathBuf,
    emit: bool,
    emit_ciphertext: bool,
    emit_packets: bool,
    packets_out: Option<PathBuf>,
    raptorq_stats: bool,
    out_dir: PathBuf,
    chunk_plain_len: u32,
    codec: CodecConfig,
    fountain: FountainConfig,
    crypto: CryptoConfig,
    compression: CompressionConfig,
    psk: Option<Vec<u8>>,
}

struct CodecConfig {
    codec_id: u16,
    fps_x100: u16,
    frame_w: u16,
    frame_h: u16,
}

struct FountainConfig {
    symbol_size: u16,
    target_overhead_x1000: u16,
}

struct CryptoConfig {
    enabled: bool,
    aead_id: u16,
    kdf_id: u16,
    nonce_mode: u16,
    salt_len: usize,
}

struct CompressionConfig {
    zstd_level: i32,
}

struct RaptorqStats {
    block_count: u32,
    symbol_size: u16,
    source_symbols_total: u32,
    source_symbols_per_block: Vec<u32>,
    repair_symbols_per_block: u32,
    total_packets: u32,
    packet_count: Option<u32>,
    packet_bytes_total: Option<u64>,
    packets_file_bytes_total: Option<u64>,
    packets_path: Option<PathBuf>,
}

struct OutputPaths {
    session_header: PathBuf,
    manifest: PathBuf,
    debug_json: PathBuf,
    ciphertext: Option<PathBuf>,
}

fn main() {
    if let Err(err) = run() {
        eprintln!("error: {}", err);
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let mut options = parse_args()?;
    if !options.crypto.enabled {
        options.crypto.aead_id = AEAD_NONE;
        options.crypto.kdf_id = KDF_NONE;
        options.crypto.nonce_mode = NONCE_MODE_NONE;
        options.crypto.salt_len = 0;
    }

    if options.chunk_plain_len == 0 {
        return Err("chunk size must be > 0".to_string());
    }
    if options.fountain.symbol_size == 0 {
        return Err("symbol size must be > 0".to_string());
    }
    if options.crypto.enabled && options.crypto.salt_len == 0 {
        return Err("salt_len must be > 0 when encryption is enabled".to_string());
    }
    validate_zstd_level(options.compression.zstd_level)?;

    let path = options.input.clone();
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| "invalid file name".to_string())?;
    let metadata = std::fs::metadata(&path).map_err(|e| e.to_string())?;
    let orig_size = metadata.len();
    if orig_size == 0 {
        return Err("file size is zero".to_string());
    }
    if !options.crypto.enabled && options.psk.is_some() {
        return Err("psk provided but encryption is disabled".to_string());
    }

    let emit_ciphertext = options.emit_ciphertext || options.emit_packets;
    if options.emit || emit_ciphertext {
        std::fs::create_dir_all(&options.out_dir).map_err(|e| e.to_string())?;
    }

    let mut session_id = [0u8; 16];
    fill(&mut session_id).map_err(|e| e.to_string())?;
    let mut salt = Vec::new();
    let mut psk_source = "disabled";
    let mut psk_hex: Option<String> = None;
    let mut keys: Option<xfer_core::DerivedKeys> = None;
    if options.crypto.enabled {
        salt = vec![0u8; options.crypto.salt_len];
        fill(&mut salt).map_err(|e| e.to_string())?;

        let (psk, source, hex) = match options.psk.clone() {
            Some(psk) => (psk, "provided", None),
            None => {
                let mut generated = vec![0u8; 32];
                fill(&mut generated).map_err(|e| e.to_string())?;
                let hex = hex_encode(&generated);
                (generated, "generated", Some(hex))
            }
        };
        psk_source = source;
        psk_hex = hex;
        keys = Some(derive_keys(&psk, &salt).map_err(|e| e.to_string())?);
    }

    let mut ciphertext_path: Option<PathBuf> = None;
    let mut ciphertext_file: Option<File> = None;
    if emit_ciphertext {
        let path = options.out_dir.join("ciphertext.bin");
        let file = File::create(&path).map_err(|e| e.to_string())?;
        ciphertext_path = Some(path);
        ciphertext_file = Some(file);
    }

    let file = File::open(&path).map_err(|e| e.to_string())?;
    let base_reader = BufReader::new(file);
    let encoder = zstd_reader(base_reader, options.compression.zstd_level).map_err(|e| e.to_string())?;
    let mut reader: Box<dyn Read> = Box::new(encoder);

    let mut output: Option<&mut dyn Write> = ciphertext_file
        .as_mut()
        .map(|file| file as &mut dyn Write);
    let encrypt_result = if options.crypto.enabled {
        let keys = keys.as_ref().ok_or_else(|| "missing encryption keys".to_string())?;
        encrypt_stream(
            &mut *reader,
            options.chunk_plain_len,
            keys,
            &session_id,
            SESSION_HEADER_VERSION_V1,
            PAYLOAD_TYPE_FOUNTAIN,
            0,
            output.as_deref_mut(),
        )
        .map_err(|e| e.to_string())?
    } else {
        compress_stream(&mut *reader, options.chunk_plain_len, output.as_deref_mut())?
    };
    let ciphertext_hash = encrypt_result.ciphertext_hash;
    let ciphertext_size = encrypt_result.ciphertext_size;
    let compressed_size = encrypt_result.input_size;

    let mime = "application/octet-stream";
    let chunk_plain_len: u32 = options.chunk_plain_len;
    let raptorq_config =
        ObjectTransmissionInformation::with_defaults(ciphertext_size, options.fountain.symbol_size);
    let raptorq_symbol_size = raptorq_config.symbol_size();
    let raptorq_source_blocks = u32::from(raptorq_config.source_blocks());
    let total_symbols = div_ceil_u64(ciphertext_size, raptorq_symbol_size as u64) as u32;
    let (kl, ks, zl, zs) = partition(total_symbols, raptorq_source_blocks);
    let symbols_per_block = kl;
    let mut raptorq_stats = estimate_raptorq_stats(
        raptorq_source_blocks,
        raptorq_symbol_size,
        total_symbols,
        kl,
        ks,
        zl,
        zs,
        options.fountain.target_overhead_x1000,
    );
    if options.fountain.symbol_size != raptorq_symbol_size {
        eprintln!(
            "warning: requested symbol_size={} differs from raptorq_symbol_size={}",
            options.fountain.symbol_size, raptorq_symbol_size
        );
    }

    let file_meta = tlv_file_meta(orig_size, file_name, mime).map_err(|e| e.to_string())?;
    let ciphertext_hash_tlv =
        tlv_hash_ciphertext(HASH_SHA256, &ciphertext_hash).map_err(|e| e.to_string())?;
    let manifest = ManifestV1 {
        flags: 0,
        session_id,
        orig_file_size: orig_size,
        compressed_size,
        chunk_plain_len,
        tlvs: vec![file_meta.clone(), ciphertext_hash_tlv],
    };
    let manifest_bytes = manifest.pack().map_err(|e| e.to_string())?;
    let manifest_hash = sha256(&manifest_bytes);

    let codec_meta = tlv_codec_meta(
        options.codec.codec_id,
        options.codec.fps_x100,
        options.codec.frame_w,
        options.codec.frame_h,
    );
    let fountain_meta = tlv_fountain_meta(
        FOUNTAIN_RAPTORQ,
        raptorq_symbol_size,
        raptorq_source_blocks,
        symbols_per_block,
        options.fountain.target_overhead_x1000,
    );
    let crypto_meta = tlv_crypto_meta(
        options.crypto.aead_id,
        options.crypto.kdf_id,
        &salt,
        options.crypto.nonce_mode,
    )
    .map_err(|e| e.to_string())?;
    let integrity_meta =
        tlv_integrity_meta(HASH_SHA256, &manifest_hash).map_err(|e| e.to_string())?;

    let header = SessionHeaderV1 {
        flags: 0,
        session_id,
        header_seq: 0,
        tlvs: vec![file_meta, codec_meta, fountain_meta, crypto_meta, integrity_meta],
    };
    let header_bytes = header.pack().map_err(|e| e.to_string())?;

    let header_roundtrip = SessionHeaderV1::unpack(&header_bytes).map_err(|e| e.to_string())?;
    if header_roundtrip != header {
        return Err("session header roundtrip mismatch".to_string());
    }
    let manifest_roundtrip = ManifestV1::unpack(&manifest_bytes).map_err(|e| e.to_string())?;
    if manifest_roundtrip != manifest {
        return Err("manifest roundtrip mismatch".to_string());
    }

    println!(
        "file={} size={} compressed_size={} session_id={} manifest_hash={} ciphertext_hash={} header_len={} manifest_len={} ciphertext_size={}",
        path.display(),
        orig_size,
        compressed_size,
        hex_encode(&session_id),
        hex_encode(&manifest_hash),
        hex_encode(&ciphertext_hash),
        header_bytes.len(),
        manifest_bytes.len(),
        ciphertext_size
    );

    if let Some(psk_hex) = psk_hex.as_deref() {
        println!("psk_source=generated psk_hex={}", psk_hex);
    } else {
        println!("psk_source={}", psk_source);
    }

    if options.emit_packets {
        let packets_path = options
            .packets_out
            .clone()
            .unwrap_or_else(|| options.out_dir.join("packets.bin"));
        let ciphertext_bytes = if let Some(path) = ciphertext_path.as_ref() {
            std::fs::read(path).map_err(|e| e.to_string())?
        } else {
            return Err("emit packets requires ciphertext output".to_string());
        };
        let packet_stats = write_raptorq_packets(
            &ciphertext_bytes,
            &session_id,
            raptorq_symbol_size,
            options.fountain.target_overhead_x1000,
            &packets_path,
        )?;
        raptorq_stats.packet_count = Some(packet_stats.packet_count);
        raptorq_stats.packet_bytes_total = Some(packet_stats.packet_bytes_total);
        raptorq_stats.packets_file_bytes_total = Some(packet_stats.packets_file_bytes_total);
        raptorq_stats.packets_path = Some(packets_path.clone());
        println!(
            "wrote_packets={} packet_count={} packet_bytes_total={} packets_file_bytes_total={}",
            packets_path.display(),
            packet_stats.packet_count,
            packet_stats.packet_bytes_total,
            packet_stats.packets_file_bytes_total
        );
    }

    if options.raptorq_stats {
        println!(
            "raptorq_blocks={} raptorq_source_symbols_total={} raptorq_symbol_size={} raptorq_repair_per_block={}",
            raptorq_stats.block_count,
            raptorq_stats.source_symbols_total,
            raptorq_stats.symbol_size,
            raptorq_stats.repair_symbols_per_block
        );
    }

    let debug_json = build_debug_json(
        &path,
        orig_size,
        compressed_size,
        ciphertext_size,
        chunk_plain_len,
        symbols_per_block,
        &options,
        &raptorq_stats,
        &session_id,
        &salt,
        &manifest_hash,
        &ciphertext_hash,
        psk_source,
        psk_hex.as_deref(),
        ciphertext_path.as_deref(),
        header_bytes.len(),
        manifest_bytes.len(),
    )?;

    let output_paths = maybe_write_outputs(
        options.emit,
        &options.out_dir,
        &header_bytes,
        &manifest_bytes,
        &debug_json,
        ciphertext_path.clone(),
    )?;

    if let Some(paths) = output_paths {
        println!(
            "wrote_session_header={} wrote_manifest={} wrote_debug_json={}",
            paths.session_header.display(),
            paths.manifest.display(),
            paths.debug_json.display()
        );
        if let Some(cipher_path) = paths.ciphertext {
            println!("wrote_ciphertext={}", cipher_path.display());
        }
    } else if let Some(cipher_path) = ciphertext_path.as_deref() {
        println!("wrote_ciphertext={}", cipher_path.display());
    }

    Ok(())
}

fn default_codec_config() -> CodecConfig {
    CodecConfig {
        codec_id: CODEC_ANIM_QR,
        fps_x100: 3000,
        frame_w: 1920,
        frame_h: 1080,
    }
}

fn default_fountain_config() -> FountainConfig {
    FountainConfig {
        symbol_size: 1024,
        target_overhead_x1000: 30,
    }
}

fn default_crypto_config() -> CryptoConfig {
    CryptoConfig {
        enabled: true,
        aead_id: AEAD_AES_256_GCM,
        kdf_id: KDF_HKDF_SHA256,
        nonce_mode: NONCE_MODE_HKDF_EXPAND,
        salt_len: 16,
    }
}

fn default_compression_config() -> CompressionConfig {
    CompressionConfig {
        zstd_level: 3,
    }
}

fn parse_args() -> Result<CliOptions, String> {
    let mut input: Option<PathBuf> = None;
    let mut emit = false;
    let mut emit_ciphertext = false;
    let mut emit_packets = false;
    let mut packets_out: Option<PathBuf> = None;
    let mut raptorq_stats = false;
    let mut out_dir: Option<PathBuf> = None;
    let mut chunk_plain_len: u32 = 4096;
    let mut codec = default_codec_config();
    let mut fountain = default_fountain_config();
    let mut crypto = default_crypto_config();
    let mut compression = default_compression_config();
    let mut psk: Option<Vec<u8>> = None;

    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--emit" => emit = true,
            "--emit-ciphertext" => emit_ciphertext = true,
            "--emit-packets" => {
                emit_packets = true;
                emit = true;
            }
            "--packets-out" => {
                let path = args
                    .next()
                    .ok_or_else(|| "--packets-out requires a value".to_string())?;
                packets_out = Some(PathBuf::from(path));
                emit_packets = true;
                emit = true;
            }
            "--raptorq-stats" => raptorq_stats = true,
            "--out-dir" => {
                let dir = args
                    .next()
                    .ok_or_else(|| "--out-dir requires a value".to_string())?;
                out_dir = Some(PathBuf::from(dir));
                emit = true;
            }
            "--chunk-size" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--chunk-size requires a value".to_string())?;
                chunk_plain_len = parse_u32("chunk-size", &value)?;
            }
            "--symbol-size" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--symbol-size requires a value".to_string())?;
                fountain.symbol_size = parse_u16("symbol-size", &value)?;
            }
            "--overhead-x1000" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--overhead-x1000 requires a value".to_string())?;
                fountain.target_overhead_x1000 = parse_u16("overhead-x1000", &value)?;
            }
            "--fps-x100" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--fps-x100 requires a value".to_string())?;
                codec.fps_x100 = parse_u16("fps-x100", &value)?;
            }
            "--frame-w" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--frame-w requires a value".to_string())?;
                codec.frame_w = parse_u16("frame-w", &value)?;
            }
            "--frame-h" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--frame-h requires a value".to_string())?;
                codec.frame_h = parse_u16("frame-h", &value)?;
            }
            "--salt-len" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--salt-len requires a value".to_string())?;
                crypto.salt_len = parse_usize("salt-len", &value)?;
            }
            "--psk" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--psk requires a value".to_string())?;
                if value.is_empty() {
                    return Err("psk must not be empty".to_string());
                }
                psk = Some(value.into_bytes());
            }
            "--no-encrypt" => crypto.enabled = false,
            "--zstd-level" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--zstd-level requires a value".to_string())?;
                compression.zstd_level = parse_i32("zstd-level", &value)?;
            }
            "-h" | "--help" => return Err(usage()),
            _ => {
                if input.is_some() {
                    return Err(format!("unexpected argument: {}", arg));
                }
                input = Some(PathBuf::from(arg));
            }
        }
    }

    let input = input.ok_or_else(usage)?;
    let out_dir = out_dir.unwrap_or_else(|| PathBuf::from("."));

    Ok(CliOptions {
        input,
        emit,
        emit_ciphertext,
        emit_packets,
        packets_out,
        raptorq_stats,
        out_dir,
        chunk_plain_len,
        codec,
        fountain,
        crypto,
        compression,
        psk,
    })
}

fn usage() -> String {
    "usage: xfer-cli <file> [--emit] [--emit-ciphertext] [--emit-packets] [--packets-out <path>] [--raptorq-stats] [--out-dir <dir>] [--chunk-size <bytes>] [--symbol-size <bytes>] [--overhead-x1000 <n>] [--fps-x100 <n>] [--frame-w <px>] [--frame-h <px>] [--salt-len <bytes>] [--psk <string>] [--no-encrypt] [--zstd-level <n>]"
        .to_string()
}

fn validate_zstd_level(level: i32) -> Result<(), String> {
    if (-7..=22).contains(&level) {
        Ok(())
    } else {
        Err(format!("zstd level out of range: {}", level))
    }
}

fn parse_u16(name: &str, value: &str) -> Result<u16, String> {
    value
        .parse::<u16>()
        .map_err(|_| format!("invalid {}: {}", name, value))
}

fn parse_u32(name: &str, value: &str) -> Result<u32, String> {
    value
        .parse::<u32>()
        .map_err(|_| format!("invalid {}: {}", name, value))
}

fn parse_i32(name: &str, value: &str) -> Result<i32, String> {
    value
        .parse::<i32>()
        .map_err(|_| format!("invalid {}: {}", name, value))
}

fn parse_usize(name: &str, value: &str) -> Result<usize, String> {
    value
        .parse::<usize>()
        .map_err(|_| format!("invalid {}: {}", name, value))
}

fn maybe_write_outputs(
    emit: bool,
    out_dir: &Path,
    header: &[u8],
    manifest: &[u8],
    debug_json: &[u8],
    ciphertext: Option<PathBuf>,
) -> Result<Option<OutputPaths>, String> {
    if !emit {
        return Ok(None);
    }

    let session_header_path = out_dir.join("session_header.bin");
    let manifest_path = out_dir.join("manifest.bin");
    let debug_json_path = out_dir.join("debug.json");
    std::fs::write(&session_header_path, header).map_err(|e| e.to_string())?;
    std::fs::write(&manifest_path, manifest).map_err(|e| e.to_string())?;
    std::fs::write(&debug_json_path, debug_json).map_err(|e| e.to_string())?;

    Ok(Some(OutputPaths {
        session_header: session_header_path,
        manifest: manifest_path,
        debug_json: debug_json_path,
        ciphertext,
    }))
}

fn estimate_raptorq_stats(
    block_count: u32,
    symbol_size: u16,
    source_symbols_total: u32,
    kl: u32,
    ks: u32,
    zl: u32,
    zs: u32,
    overhead_x1000: u16,
) -> RaptorqStats {
    let mut source_symbols_per_block = Vec::new();
    for _ in 0..zl {
        source_symbols_per_block.push(kl);
    }
    for _ in 0..zs {
        source_symbols_per_block.push(ks);
    }
    let repair_symbols_per_block =
        div_ceil_u64(u64::from(kl) * u64::from(overhead_x1000), 1000) as u32;
    let total_packets =
        source_symbols_total + repair_symbols_per_block.saturating_mul(block_count);

    RaptorqStats {
        block_count,
        symbol_size,
        source_symbols_total,
        source_symbols_per_block,
        repair_symbols_per_block,
        total_packets,
        packet_count: None,
        packet_bytes_total: None,
        packets_file_bytes_total: None,
        packets_path: None,
    }
}

struct PacketStats {
    packet_count: u32,
    packet_bytes_total: u64,
    packets_file_bytes_total: u64,
}

fn write_raptorq_packets(
    ciphertext: &[u8],
    session_id: &[u8; 16],
    symbol_size: u16,
    overhead_x1000: u16,
    out_path: &Path,
) -> Result<PacketStats, String> {
    let encoder = RaptorqEncoder::with_defaults(ciphertext, symbol_size);
    let per_block = encoder.source_packets_per_block();
    let max_source = per_block.iter().copied().max().unwrap_or(0) as u64;
    let repair_per_block = div_ceil_u64(max_source * u64::from(overhead_x1000), 1000) as u32;
    let packets = encoder.encode_all_packets(repair_per_block);

    let mut writer = std::io::BufWriter::new(File::create(out_path).map_err(|e| e.to_string())?);
    writer
        .write_all(&vec![0u8; PACKETS_FILE_HEADER_LEN])
        .map_err(|e| e.to_string())?;
    let mut seq: u32 = 0;
    let mut packet_bytes_total: u64 = 0;
    for packet in packets {
        let payload = packet.serialize();
        let data_packet = DataPacketV1 {
            session_id: *session_id,
            seq,
            payload_type: PAYLOAD_TYPE_FOUNTAIN,
            payload,
        };
        let bytes = data_packet.pack().map_err(|e| e.to_string())?;
        writer.write_all(&bytes).map_err(|e| e.to_string())?;
        packet_bytes_total = packet_bytes_total
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| "packet bytes overflow".to_string())?;
        seq = seq
            .checked_add(1)
            .ok_or_else(|| "packet sequence overflow".to_string())?;
    }
    writer.flush().map_err(|e| e.to_string())?;
    writer
        .seek(SeekFrom::Start(0))
        .map_err(|e| e.to_string())?;

    let header = PacketsFileHeaderV1 {
        flags: 0,
        session_id: *session_id,
        packet_count: seq,
        packet_bytes: packet_bytes_total,
    };
    let header_bytes = header.pack().map_err(|e| e.to_string())?;
    if header_bytes.len() != PACKETS_FILE_HEADER_LEN {
        return Err("packets header size mismatch".to_string());
    }
    writer
        .write_all(&header_bytes)
        .map_err(|e| e.to_string())?;
    writer.flush().map_err(|e| e.to_string())?;

    Ok(PacketStats {
        packet_count: seq,
        packet_bytes_total,
        packets_file_bytes_total: packet_bytes_total
            .checked_add(PACKETS_FILE_HEADER_LEN as u64)
            .ok_or_else(|| "packet bytes overflow".to_string())?,
    })
}

fn compress_stream<R: Read + ?Sized, W: Write + ?Sized>(
    reader: &mut R,
    chunk_plain_len: u32,
    mut output: Option<&mut W>,
) -> Result<EncryptResult, String> {
    let chunk_len = usize::try_from(chunk_plain_len)
        .map_err(|_| "chunk size too large for platform".to_string())?;
    let mut buffer = vec![0u8; chunk_len];
    let mut hasher = Sha256::new();
    let mut total_size: u64 = 0;

    loop {
        let read = reader.read(&mut buffer).map_err(|e| e.to_string())?;
        if read == 0 {
            break;
        }
        if let Some(writer) = output.as_mut() {
            writer
                .write_all(&buffer[..read])
                .map_err(|e| e.to_string())?;
        }
        hasher.update(&buffer[..read]);
        total_size = total_size
            .checked_add(read as u64)
            .ok_or_else(|| "output size overflow".to_string())?;
    }

    if let Some(writer) = output.as_mut() {
        writer.flush().map_err(|e| e.to_string())?;
    }

    let digest = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&digest);

    Ok(EncryptResult {
        ciphertext_hash: hash,
        ciphertext_size: total_size,
        input_size: total_size,
    })
}

fn build_debug_json(
    path: &Path,
    orig_size: u64,
    compressed_size: u64,
    ciphertext_size: u64,
    chunk_plain_len: u32,
    symbols_per_block: u32,
    options: &CliOptions,
    raptorq_stats: &RaptorqStats,
    session_id: &[u8; 16],
    salt: &[u8],
    manifest_hash: &[u8; 32],
    ciphertext_hash: &[u8; 32],
    psk_source: &str,
    psk_hex: Option<&str>,
    ciphertext_path: Option<&Path>,
    header_len: usize,
    manifest_len: usize,
) -> Result<Vec<u8>, String> {
    let mut obj = json!({
        "file": path.display().to_string(),
        "orig_size": orig_size,
        "compressed_size": compressed_size,
        "ciphertext_size": ciphertext_size,
        "chunk_plain_len": chunk_plain_len,
        "symbols_per_block": symbols_per_block,
        "codec": {
            "codec_id": options.codec.codec_id,
            "fps_x100": options.codec.fps_x100,
            "frame_w": options.codec.frame_w,
            "frame_h": options.codec.frame_h,
        },
        "fountain": {
            "symbol_size": options.fountain.symbol_size,
            "source_blocks": raptorq_stats.block_count,
            "target_overhead_x1000": options.fountain.target_overhead_x1000,
        },
        "raptorq": {
            "block_count": raptorq_stats.block_count,
            "symbol_size": raptorq_stats.symbol_size,
            "source_symbols_total": raptorq_stats.source_symbols_total,
            "source_symbols_per_block": raptorq_stats.source_symbols_per_block,
            "repair_symbols_per_block": raptorq_stats.repair_symbols_per_block,
            "total_packets": raptorq_stats.total_packets,
        },
        "compression": {
            "enabled": true,
            "zstd_level": options.compression.zstd_level,
        },
        "crypto": {
            "enabled": options.crypto.enabled,
            "aead_id": options.crypto.aead_id,
            "kdf_id": options.crypto.kdf_id,
            "nonce_mode": options.crypto.nonce_mode,
            "salt_len": options.crypto.salt_len,
        },
        "session_id": hex_encode(session_id),
        "salt": hex_encode(salt),
        "manifest_hash": hex_encode(manifest_hash),
        "ciphertext_hash": hex_encode(ciphertext_hash),
        "psk_source": psk_source,
        "header_len": header_len,
        "manifest_len": manifest_len
    });

    if let Some(psk_hex) = psk_hex {
        if let Some(map) = obj.as_object_mut() {
            map.insert("psk_hex".to_string(), json!(psk_hex));
        }
    }

    if let Some(packet_count) = raptorq_stats.packet_count {
        if let Some(map) = obj.get_mut("raptorq").and_then(|v| v.as_object_mut()) {
            map.insert("packet_count".to_string(), json!(packet_count));
        }
    }

    if let Some(packet_bytes_total) = raptorq_stats.packet_bytes_total {
        if let Some(map) = obj.get_mut("raptorq").and_then(|v| v.as_object_mut()) {
            map.insert("packet_bytes_total".to_string(), json!(packet_bytes_total));
        }
    }

    if let Some(packets_file_bytes_total) = raptorq_stats.packets_file_bytes_total {
        if let Some(map) = obj.get_mut("raptorq").and_then(|v| v.as_object_mut()) {
            map.insert(
                "packets_file_bytes_total".to_string(),
                json!(packets_file_bytes_total),
            );
        }
    }

    if let Some(path) = raptorq_stats.packets_path.as_ref() {
        if let Some(map) = obj.get_mut("raptorq").and_then(|v| v.as_object_mut()) {
            map.insert(
                "packets_path".to_string(),
                json!(path.display().to_string()),
            );
        }
    }

    if let Some(ciphertext_path) = ciphertext_path {
        if let Some(map) = obj.as_object_mut() {
            map.insert(
                "ciphertext_path".to_string(),
                json!(ciphertext_path.display().to_string()),
            );
        }
    }

    serde_json::to_vec_pretty(&obj).map_err(|e| e.to_string())
}

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn div_ceil_u64(value: u64, divisor: u64) -> u64 {
    if divisor == 0 {
        return 0;
    }
    (value + divisor - 1) / divisor
}

fn div_ceil_u32(value: u32, divisor: u32) -> u32 {
    if divisor == 0 {
        return 0;
    }
    (value + divisor - 1) / divisor
}

fn partition(total_symbols: u32, source_blocks: u32) -> (u32, u32, u32, u32) {
    let il = div_ceil_u32(total_symbols, source_blocks);
    let is = total_symbols / source_blocks;
    let jl = total_symbols - is * source_blocks;
    let js = source_blocks - jl;
    (il, is, jl, js)
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write;
        let _ = write!(out, "{:02x}", byte);
    }
    out
}
