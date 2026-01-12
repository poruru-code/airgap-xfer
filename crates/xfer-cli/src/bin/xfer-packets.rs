use std::env;
use std::fs::File;
use std::io::BufReader;
use std::path::PathBuf;
use xfer_core::{read_packets_file_header, DataPacketReader, PAYLOAD_TYPE_FOUNTAIN};

struct CliOptions {
    input: PathBuf,
    max_print: usize,
}

fn main() {
    if let Err(err) = run() {
        eprintln!("error: {}", err);
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let options = parse_args()?;
    let file = File::open(&options.input).map_err(|e| e.to_string())?;
    let mut file_reader = BufReader::new(file);
    let header = read_packets_file_header(&mut file_reader).map_err(|e| e.to_string())?;
    println!(
        "packets_header session_id={} packet_count_expected={} packet_bytes_expected={}",
        hex_encode(&header.session_id),
        header.packet_count,
        header.packet_bytes
    );
    let mut reader = DataPacketReader::new(file_reader);

    let mut count: u64 = 0;
    let mut payload_bytes: u64 = 0;
    let mut min_seq: Option<u32> = None;
    let mut max_seq: Option<u32> = None;
    let mut session_id: Option<[u8; 16]> = None;
    let mut fountain_count: u64 = 0;

    while let Some(packet) = reader.next_packet().map_err(|e| e.to_string())? {
        count = count.saturating_add(1);
        payload_bytes = payload_bytes.saturating_add(packet.payload.len() as u64);
        min_seq = Some(min_seq.map_or(packet.seq, |min| min.min(packet.seq)));
        max_seq = Some(max_seq.map_or(packet.seq, |max| max.max(packet.seq)));
        if session_id.is_none() {
            session_id = Some(packet.session_id);
        }
        if packet.payload_type == PAYLOAD_TYPE_FOUNTAIN {
            fountain_count = fountain_count.saturating_add(1);
        }
        if count as usize <= options.max_print {
            println!(
                "seq={} type={} payload_len={}",
                packet.seq,
                packet.payload_type,
                packet.payload.len()
            );
        }
    }

    if let Some(id) = session_id {
        println!("session_id={}", hex_encode(&id));
    }
    println!(
        "packet_count={} fountain_packets={} payload_bytes={} min_seq={} max_seq={}",
        count,
        fountain_count,
        payload_bytes,
        min_seq.unwrap_or(0),
        max_seq.unwrap_or(0)
    );
    Ok(())
}

fn parse_args() -> Result<CliOptions, String> {
    let mut input: Option<PathBuf> = None;
    let mut max_print: usize = 0;

    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--in" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--in requires a value".to_string())?;
                input = Some(PathBuf::from(value));
            }
            "--max" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--max requires a value".to_string())?;
                max_print = value
                    .parse::<usize>()
                    .map_err(|_| format!("invalid max: {}", value))?;
            }
            "-h" | "--help" => return Err(usage()),
            _ => return Err(format!("unexpected argument: {}", arg)),
        }
    }

    let input = input.ok_or_else(usage)?;
    Ok(CliOptions { input, max_print })
}

fn usage() -> String {
    "usage: xfer-packets --in <packets.bin> [--max <n>]".to_string()
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write;
        let _ = write!(out, "{:02x}", byte);
    }
    out
}
