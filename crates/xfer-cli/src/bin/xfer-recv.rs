use serde_json::Value;
use std::env;
use std::fs::File;
use std::io::{BufReader, BufWriter, Cursor, Read};
use std::path::PathBuf;
use xfer_core::{
    decrypt_and_decompress, derive_keys, read_packets_file_header, zstd_decoder, DataPacketReader,
    PAYLOAD_TYPE_FOUNTAIN, SESSION_HEADER_VERSION_V1,
};
use xfer_fountain::{EncodingPacket, ObjectTransmissionInformation, RaptorqDecoder};

struct CliOptions {
    debug: PathBuf,
    ciphertext: Option<PathBuf>,
    packets: Option<PathBuf>,
    output: PathBuf,
    psk: Option<Vec<u8>>,
    psk_hex: Option<Vec<u8>>,
}

fn main() {
    if let Err(err) = run() {
        eprintln!("error: {}", err);
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let options = parse_args()?;
    let debug = read_debug_json(&options.debug)?;

    let session_id = parse_hex_16(&debug, "session_id")?;
    let crypto_enabled = get_bool_field(&debug, "crypto.enabled").unwrap_or(true);
    let salt = if crypto_enabled {
        parse_hex_vec(&debug, "salt")?
    } else {
        Vec::new()
    };
    let chunk_plain_len = get_u32_field(&debug, "chunk_plain_len")?;
    let compressed_size = get_u64_field(&debug, "compressed_size")?;
    let ciphertext_size = get_u64_field(&debug, "ciphertext_size")?;
    let raptorq_symbol_size = get_u32_field_optional(&debug, "raptorq.symbol_size")
        .or_else(|| get_u32_field_optional(&debug, "fountain.symbol_size"))
        .ok_or_else(|| "missing raptorq.symbol_size".to_string())?;
    let raptorq_symbol_size: u16 = raptorq_symbol_size
        .try_into()
        .map_err(|_| "raptorq.symbol_size out of range".to_string())?;

    let keys = if crypto_enabled {
        let psk = if let Some(psk) = options.psk {
            psk
        } else if let Some(psk_hex) = options.psk_hex {
            psk_hex
        } else if let Some(psk_hex) = get_optional_hex_field(&debug, "psk_hex")? {
            psk_hex
        } else {
            return Err("psk is required (use --psk or --psk-hex)".to_string());
        };
        Some(derive_keys(&psk, &salt).map_err(|e| e.to_string())?)
    } else {
        None
    };

    let reader: Box<dyn Read> = if let Some(path) = options.packets.as_ref() {
        let recovered = recover_ciphertext_from_packets(
            path,
            &session_id,
            ciphertext_size,
            raptorq_symbol_size,
        )?;
        Box::new(Cursor::new(recovered))
    } else if let Some(path) = options.ciphertext.as_ref() {
        Box::new(File::open(path).map_err(|e| e.to_string())?)
    } else {
        return Err("either --ciphertext or --packets is required".to_string());
    };
    let mut reader = BufReader::new(reader);
    let out = File::create(&options.output).map_err(|e| e.to_string())?;
    let mut writer = BufWriter::new(out);

    let written = if crypto_enabled {
        let keys = keys.as_ref().ok_or_else(|| "missing decryption keys".to_string())?;
        decrypt_and_decompress(
            &mut reader,
            &mut writer,
            chunk_plain_len,
            compressed_size,
            keys,
            &session_id,
            SESSION_HEADER_VERSION_V1,
            PAYLOAD_TYPE_FOUNTAIN,
            0,
            true,
        )
        .map_err(|e| e.to_string())?
    } else {
        let mut decoder = zstd_decoder(reader).map_err(|e| e.to_string())?;
        std::io::copy(&mut decoder, &mut writer).map_err(|e| e.to_string())?
    };

    println!("wrote_output={} bytes={}", options.output.display(), written);
    Ok(())
}

fn parse_args() -> Result<CliOptions, String> {
    let mut debug: Option<PathBuf> = None;
    let mut ciphertext: Option<PathBuf> = None;
    let mut packets: Option<PathBuf> = None;
    let mut output: Option<PathBuf> = None;
    let mut psk: Option<Vec<u8>> = None;
    let mut psk_hex: Option<Vec<u8>> = None;
    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--debug" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--debug requires a value".to_string())?;
                debug = Some(PathBuf::from(value));
            }
            "--ciphertext" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--ciphertext requires a value".to_string())?;
                ciphertext = Some(PathBuf::from(value));
            }
            "--packets" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--packets requires a value".to_string())?;
                packets = Some(PathBuf::from(value));
            }
            "--out" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--out requires a value".to_string())?;
                output = Some(PathBuf::from(value));
            }
            "--psk" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--psk requires a value".to_string())?;
                psk = Some(value.into_bytes());
            }
            "--psk-hex" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--psk-hex requires a value".to_string())?;
                psk_hex = Some(hex_decode(&value)?);
            }
            "-h" | "--help" => return Err(usage()),
            _ => return Err(format!("unexpected argument: {}", arg)),
        }
    }

    let debug = debug.ok_or_else(usage)?;
    if ciphertext.is_none() && packets.is_none() {
        return Err(usage());
    }
    let output = output.ok_or_else(usage)?;

    Ok(CliOptions {
        debug,
        ciphertext,
        packets,
        output,
        psk,
        psk_hex,
    })
}

fn usage() -> String {
    "usage: xfer-recv --debug <debug.json> --out <output> [--ciphertext <ciphertext.bin> | --packets <packets.bin>] [--psk <string> | --psk-hex <hex>]"
        .to_string()
}

fn read_debug_json(path: &PathBuf) -> Result<Value, String> {
    let data = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    serde_json::from_str(&data).map_err(|e| e.to_string())
}

fn get_u32_field(value: &Value, key: &str) -> Result<u32, String> {
    get_u64_field(value, key)?.try_into().map_err(|_| {
        format!("field {} is out of range for u32", key)
    })
}

fn get_u64_field(value: &Value, key: &str) -> Result<u64, String> {
    let mut current = value;
    for part in key.split('.') {
        current = current
            .get(part)
            .ok_or_else(|| format!("missing field {}", key))?;
    }
    current
        .as_u64()
        .ok_or_else(|| format!("field {} is not a u64", key))
}

fn get_u64_field_optional(value: &Value, key: &str) -> Option<u64> {
    let mut current = value;
    for part in key.split('.') {
        current = current.get(part)?;
    }
    current.as_u64()
}

fn get_u32_field_optional(value: &Value, key: &str) -> Option<u32> {
    get_u64_field_optional(value, key).and_then(|value| value.try_into().ok())
}

fn get_bool_field(value: &Value, key: &str) -> Option<bool> {
    let mut current = value;
    for part in key.split('.') {
        current = current.get(part)?;
    }
    current.as_bool()
}

fn get_optional_hex_field(value: &Value, key: &str) -> Result<Option<Vec<u8>>, String> {
    match get_string_field_optional(value, key)? {
        Some(hex) => Ok(Some(hex_decode(&hex)?)),
        None => Ok(None),
    }
}

fn get_string_field(value: &Value, key: &str) -> Result<String, String> {
    get_string_field_optional(value, key)?.ok_or_else(|| format!("missing field {}", key))
}

fn get_string_field_optional(value: &Value, key: &str) -> Result<Option<String>, String> {
    let mut current = value;
    for part in key.split('.') {
        match current.get(part) {
            Some(next) => current = next,
            None => return Ok(None),
        }
    }
    match current.as_str() {
        Some(value) => Ok(Some(value.to_string())),
        None => Err(format!("field {} is not a string", key)),
    }
}

fn parse_hex_vec(value: &Value, key: &str) -> Result<Vec<u8>, String> {
    let hex = get_string_field(value, key)?;
    hex_decode(&hex)
}

fn parse_hex_16(value: &Value, key: &str) -> Result<[u8; 16], String> {
    let bytes = parse_hex_vec(value, key)?;
    if bytes.len() != 16 {
        return Err(format!("field {} expected 16 bytes", key));
    }
    let mut out = [0u8; 16];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn hex_decode(input: &str) -> Result<Vec<u8>, String> {
    let input = input.trim();
    if input.len() % 2 != 0 {
        return Err("hex string length must be even".to_string());
    }
    let mut out = Vec::with_capacity(input.len() / 2);
    let bytes = input.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = from_hex(bytes[i])?;
        let lo = from_hex(bytes[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Ok(out)
}

fn from_hex(byte: u8) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err("invalid hex character".to_string()),
    }
}

fn recover_ciphertext_from_packets(
    packets_path: &PathBuf,
    session_id: &[u8; 16],
    ciphertext_size: u64,
    symbol_size: u16,
) -> Result<Vec<u8>, String> {
    if ciphertext_size > usize::MAX as u64 {
        return Err("ciphertext too large for this platform".to_string());
    }

    let file = File::open(packets_path).map_err(|e| e.to_string())?;
    let mut file_reader = BufReader::new(file);
    let header = read_packets_file_header(&mut file_reader).map_err(|e| e.to_string())?;
    if header.session_id != *session_id {
        return Err("session_id mismatch in packets header".to_string());
    }
    let mut reader = DataPacketReader::new(file_reader);
    let config = ObjectTransmissionInformation::with_defaults(ciphertext_size, symbol_size);
    let mut decoder = RaptorqDecoder::new(config);
    let mut recovered: Option<Vec<u8>> = None;
    let mut packet_count: u64 = 0;

    while let Some(packet) = reader.next_packet().map_err(|e| e.to_string())? {
        if packet.session_id != *session_id {
            return Err("session_id mismatch in packets".to_string());
        }
        if packet.payload_type != PAYLOAD_TYPE_FOUNTAIN {
            continue;
        }
        let encoding = EncodingPacket::deserialize(&packet.payload);
        recovered = decoder.push_packet(encoding);
        packet_count = packet_count.saturating_add(1);
        if recovered.is_some() {
            break;
        }
    }

    let recovered = recovered
        .or_else(|| decoder.recover())
        .ok_or_else(|| format!("insufficient packets (count={})", packet_count))?;

    if recovered.len() != ciphertext_size as usize {
        eprintln!(
            "warning: recovered ciphertext size {} does not match expected {}",
            recovered.len(),
            ciphertext_size
        );
    }

    Ok(recovered)
}
