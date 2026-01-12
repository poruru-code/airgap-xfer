use crc32c::crc32c;

mod crypto;
mod compress;
mod stream;
mod packet;
pub use crypto::{
    build_aad, decrypt_aead, derive_keys, derive_nonce, encrypt_aead, DerivedKeys, AEAD_KEY_LEN,
    AEAD_NONCE_LEN, AEAD_TAG_LEN, AAD_LEN,
};
pub use compress::{zstd_decoder, zstd_reader, ZstdDecoder, ZstdReader};
pub use stream::{decrypt_and_decompress, decrypt_stream, encrypt_stream, EncryptResult};
pub use packet::{
    read_next_packet, read_packets_file_header, DataPacketReader, DataPacketV1,
    PacketsFileHeaderV1, DATA_PACKET_HEADER_LEN, PACKETS_FILE_HEADER_LEN, PACKETS_FILE_MAGIC,
    PACKETS_FILE_VERSION_V1,
};

pub const SESSION_HEADER_MAGIC: [u8; 4] = *b"AXFR";
pub const MANIFEST_MAGIC: [u8; 4] = *b"AXMF";
pub const PACKET_MAGIC: [u8; 4] = *b"AXPK";

pub const SESSION_HEADER_VERSION_V1: u16 = 0x0001;
pub const MANIFEST_VERSION_V1: u16 = 0x0001;
pub const SESSION_HEADER_TYPE_V1: u8 = 0x01;

pub const SESSION_HEADER_FIXED_LEN: usize = 40;
pub const MANIFEST_FIXED_LEN: usize = 48;

pub const PAYLOAD_TYPE_HEADER: u8 = 0x01;
pub const PAYLOAD_TYPE_FOUNTAIN: u8 = 0x02;
pub const PAYLOAD_TYPE_KEYEX: u8 = 0x03;
pub const PAYLOAD_TYPE_HEARTBEAT: u8 = 0x04;

pub const TLV_FILE_META: u16 = 0x0001;
pub const TLV_CODEC_META: u16 = 0x0002;
pub const TLV_FOUNTAIN_META: u16 = 0x0003;
pub const TLV_CRYPTO_META: u16 = 0x0004;
pub const TLV_INTEGRITY_META: u16 = 0x0005;
pub const TLV_HASH_PLAINTEXT: u16 = 0x0100;
pub const TLV_HASH_CIPHERTEXT: u16 = 0x0101;

pub const CODEC_ANIM_QR: u16 = 0x0001;
pub const CODEC_CIMBAR: u16 = 0x0002;

pub const FOUNTAIN_RAPTORQ: u16 = 0x0001;

pub const AEAD_NONE: u16 = 0x0000;
pub const AEAD_AES_256_GCM: u16 = 0x0001;
pub const KDF_NONE: u16 = 0x0000;
pub const KDF_HKDF_SHA256: u16 = 0x0001;
pub const NONCE_MODE_NONE: u16 = 0x0000;
pub const NONCE_MODE_HKDF_EXPAND: u16 = 0x0001;
pub const HASH_SHA256: u16 = 0x0001;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlvRecord {
    pub t: u16,
    pub v: Vec<u8>,
}

impl TlvRecord {
    pub fn encoded_len(&self) -> Result<usize, Error> {
        if self.v.len() > u16::MAX as usize {
            return Err(Error::TlvLengthTooLarge {
                length: self.v.len(),
            });
        }
        Ok(4 + self.v.len())
    }

    pub fn encode_into(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        let len = self.encoded_len()?;
        let v_len = (len - 4) as u16;
        out.extend_from_slice(&self.t.to_le_bytes());
        out.extend_from_slice(&v_len.to_le_bytes());
        out.extend_from_slice(&self.v);
        Ok(())
    }
}

pub fn tlv_file_meta(file_size: u64, file_name: &str, mime: &str) -> Result<TlvRecord, Error> {
    let mut v = Vec::new();
    v.extend_from_slice(&file_size.to_le_bytes());

    let file_name_len = checked_u16_len(file_name.len(), "file_name")?;
    v.extend_from_slice(&file_name_len.to_le_bytes());
    v.extend_from_slice(file_name.as_bytes());

    let mime_len = checked_u16_len(mime.len(), "mime")?;
    v.extend_from_slice(&mime_len.to_le_bytes());
    v.extend_from_slice(mime.as_bytes());

    let record = TlvRecord {
        t: TLV_FILE_META,
        v,
    };
    record.encoded_len()?;
    Ok(record)
}

pub fn tlv_codec_meta(codec_id: u16, fps_x100: u16, frame_w: u16, frame_h: u16) -> TlvRecord {
    let mut v = Vec::with_capacity(8);
    v.extend_from_slice(&codec_id.to_le_bytes());
    v.extend_from_slice(&fps_x100.to_le_bytes());
    v.extend_from_slice(&frame_w.to_le_bytes());
    v.extend_from_slice(&frame_h.to_le_bytes());
    TlvRecord {
        t: TLV_CODEC_META,
        v,
    }
}

pub fn tlv_fountain_meta(
    fountain_id: u16,
    symbol_size: u16,
    source_blocks: u32,
    symbols_per_block: u32,
    target_overhead_x1000: u16,
) -> TlvRecord {
    let mut v = Vec::with_capacity(14);
    v.extend_from_slice(&fountain_id.to_le_bytes());
    v.extend_from_slice(&symbol_size.to_le_bytes());
    v.extend_from_slice(&source_blocks.to_le_bytes());
    v.extend_from_slice(&symbols_per_block.to_le_bytes());
    v.extend_from_slice(&target_overhead_x1000.to_le_bytes());
    TlvRecord {
        t: TLV_FOUNTAIN_META,
        v,
    }
}

pub fn tlv_crypto_meta(
    aead_id: u16,
    kdf_id: u16,
    salt: &[u8],
    nonce_mode: u16,
) -> Result<TlvRecord, Error> {
    let mut v = Vec::new();
    v.extend_from_slice(&aead_id.to_le_bytes());
    v.extend_from_slice(&kdf_id.to_le_bytes());

    let salt_len = checked_u16_len(salt.len(), "salt")?;
    v.extend_from_slice(&salt_len.to_le_bytes());
    v.extend_from_slice(salt);
    v.extend_from_slice(&nonce_mode.to_le_bytes());

    let record = TlvRecord {
        t: TLV_CRYPTO_META,
        v,
    };
    record.encoded_len()?;
    Ok(record)
}

pub fn tlv_integrity_meta(
    manifest_hash_alg: u16,
    manifest_hash: &[u8],
) -> Result<TlvRecord, Error> {
    let mut v = Vec::new();
    v.extend_from_slice(&manifest_hash_alg.to_le_bytes());
    let hash_len = checked_u16_len(manifest_hash.len(), "manifest_hash")?;
    v.extend_from_slice(&hash_len.to_le_bytes());
    v.extend_from_slice(manifest_hash);

    let record = TlvRecord {
        t: TLV_INTEGRITY_META,
        v,
    };
    record.encoded_len()?;
    Ok(record)
}

pub fn tlv_hash_plaintext(hash_alg: u16, hash: &[u8]) -> Result<TlvRecord, Error> {
    tlv_hash_meta(TLV_HASH_PLAINTEXT, hash_alg, hash, "plaintext_hash")
}

pub fn tlv_hash_ciphertext(hash_alg: u16, hash: &[u8]) -> Result<TlvRecord, Error> {
    tlv_hash_meta(TLV_HASH_CIPHERTEXT, hash_alg, hash, "ciphertext_hash")
}

fn tlv_hash_meta(
    tlv_type: u16,
    hash_alg: u16,
    hash: &[u8],
    field: &'static str,
) -> Result<TlvRecord, Error> {
    let mut v = Vec::new();
    v.extend_from_slice(&hash_alg.to_le_bytes());
    let hash_len = checked_u16_len(hash.len(), field)?;
    v.extend_from_slice(&hash_len.to_le_bytes());
    v.extend_from_slice(hash);

    let record = TlvRecord { t: tlv_type, v };
    record.encoded_len()?;
    Ok(record)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionHeaderV1 {
    pub flags: u8,
    pub session_id: [u8; 16],
    pub header_seq: u32,
    pub tlvs: Vec<TlvRecord>,
}

impl SessionHeaderV1 {
    pub fn pack(&self) -> Result<Vec<u8>, Error> {
        let payload = encode_tlvs(&self.tlvs)?;
        let payload_len = payload.len();
        if payload_len > u32::MAX as usize {
            return Err(Error::PayloadLengthTooLarge {
                length: payload_len,
            });
        }
        let payload_crc = crc32c(&payload);

        let mut header = Vec::with_capacity(SESSION_HEADER_FIXED_LEN + payload_len);
        header.extend_from_slice(&SESSION_HEADER_MAGIC);
        header.extend_from_slice(&SESSION_HEADER_VERSION_V1.to_le_bytes());
        header.push(SESSION_HEADER_TYPE_V1);
        header.push(self.flags);
        header.extend_from_slice(&self.session_id);
        header.extend_from_slice(&self.header_seq.to_le_bytes());
        header.extend_from_slice(&(payload_len as u32).to_le_bytes());
        header.extend_from_slice(&payload_crc.to_le_bytes());

        let header_crc = crc32c(&header);
        header.extend_from_slice(&header_crc.to_le_bytes());
        header.extend_from_slice(&payload);
        Ok(header)
    }

    pub fn unpack(buf: &[u8]) -> Result<Self, Error> {
        if buf.len() < SESSION_HEADER_FIXED_LEN {
            return Err(Error::BufferTooSmall {
                needed: SESSION_HEADER_FIXED_LEN,
                actual: buf.len(),
            });
        }

        let magic = array4(&buf[0..4]);
        if magic != SESSION_HEADER_MAGIC {
            return Err(Error::InvalidMagic {
                expected: SESSION_HEADER_MAGIC,
                found: magic,
            });
        }

        let version = read_u16_le(buf, 4)?;
        if version != SESSION_HEADER_VERSION_V1 {
            return Err(Error::UnsupportedVersion {
                expected: SESSION_HEADER_VERSION_V1,
                found: version,
            });
        }

        let header_type = buf[6];
        if header_type != SESSION_HEADER_TYPE_V1 {
            return Err(Error::InvalidHeaderType { found: header_type });
        }

        let flags = buf[7];
        let session_id = array16(&buf[8..24]);
        let header_seq = read_u32_le(buf, 24)?;
        let payload_len = read_u32_le(buf, 28)? as usize;
        let payload_crc = read_u32_le(buf, 32)?;
        let header_crc = read_u32_le(buf, 36)?;

        let computed_header_crc = crc32c(&buf[0..36]);
        if computed_header_crc != header_crc {
            return Err(Error::CrcMismatch {
                kind: "session_header",
                expected: header_crc,
                computed: computed_header_crc,
            });
        }

        let needed = SESSION_HEADER_FIXED_LEN + payload_len;
        if buf.len() < needed {
            return Err(Error::BufferTooSmall {
                needed,
                actual: buf.len(),
            });
        }

        let payload = &buf[SESSION_HEADER_FIXED_LEN..needed];
        let computed_payload_crc = crc32c(payload);
        if computed_payload_crc != payload_crc {
            return Err(Error::CrcMismatch {
                kind: "session_payload",
                expected: payload_crc,
                computed: computed_payload_crc,
            });
        }

        let tlvs = decode_tlvs(payload)?;

        Ok(SessionHeaderV1 {
            flags,
            session_id,
            header_seq,
            tlvs,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestV1 {
    pub flags: u16,
    pub session_id: [u8; 16],
    pub orig_file_size: u64,
    pub compressed_size: u64,
    pub chunk_plain_len: u32,
    pub tlvs: Vec<TlvRecord>,
}

impl ManifestV1 {
    pub fn pack(&self) -> Result<Vec<u8>, Error> {
        let payload = encode_tlvs(&self.tlvs)?;
        let mut header = Vec::with_capacity(MANIFEST_FIXED_LEN + payload.len());
        header.extend_from_slice(&MANIFEST_MAGIC);
        header.extend_from_slice(&MANIFEST_VERSION_V1.to_le_bytes());
        header.extend_from_slice(&self.flags.to_le_bytes());
        header.extend_from_slice(&self.session_id);
        header.extend_from_slice(&self.orig_file_size.to_le_bytes());
        header.extend_from_slice(&self.compressed_size.to_le_bytes());
        header.extend_from_slice(&self.chunk_plain_len.to_le_bytes());

        let manifest_crc = crc32c(&header);
        header.extend_from_slice(&manifest_crc.to_le_bytes());
        header.extend_from_slice(&payload);
        Ok(header)
    }

    pub fn unpack(buf: &[u8]) -> Result<Self, Error> {
        if buf.len() < MANIFEST_FIXED_LEN {
            return Err(Error::BufferTooSmall {
                needed: MANIFEST_FIXED_LEN,
                actual: buf.len(),
            });
        }

        let magic = array4(&buf[0..4]);
        if magic != MANIFEST_MAGIC {
            return Err(Error::InvalidMagic {
                expected: MANIFEST_MAGIC,
                found: magic,
            });
        }

        let version = read_u16_le(buf, 4)?;
        if version != MANIFEST_VERSION_V1 {
            return Err(Error::UnsupportedVersion {
                expected: MANIFEST_VERSION_V1,
                found: version,
            });
        }

        let flags = read_u16_le(buf, 6)?;
        let session_id = array16(&buf[8..24]);
        let orig_file_size = read_u64_le(buf, 24)?;
        let compressed_size = read_u64_le(buf, 32)?;
        let chunk_plain_len = read_u32_le(buf, 40)?;
        let manifest_crc = read_u32_le(buf, 44)?;

        let computed_crc = crc32c(&buf[0..44]);
        if computed_crc != manifest_crc {
            return Err(Error::CrcMismatch {
                kind: "manifest",
                expected: manifest_crc,
                computed: computed_crc,
            });
        }

        let tlv_bytes = &buf[MANIFEST_FIXED_LEN..];
        let tlvs = decode_tlvs(tlv_bytes)?;

        Ok(ManifestV1 {
            flags,
            session_id,
            orig_file_size,
            compressed_size,
            chunk_plain_len,
            tlvs,
        })
    }
}

pub fn encode_tlvs(records: &[TlvRecord]) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    for record in records {
        record.encode_into(&mut out)?;
    }
    Ok(out)
}

pub fn decode_tlvs(buf: &[u8]) -> Result<Vec<TlvRecord>, Error> {
    let mut records = Vec::new();
    let mut offset = 0;
    while offset < buf.len() {
        if buf.len() - offset < 4 {
            return Err(Error::TlvTruncated {
                offset,
                needed: 4,
                remaining: buf.len() - offset,
            });
        }
        let t = u16::from_le_bytes([buf[offset], buf[offset + 1]]);
        let l = u16::from_le_bytes([buf[offset + 2], buf[offset + 3]]) as usize;
        offset += 4;
        if buf.len() - offset < l {
            return Err(Error::TlvTruncated {
                offset,
                needed: l,
                remaining: buf.len() - offset,
            });
        }
        let v = buf[offset..offset + l].to_vec();
        offset += l;
        records.push(TlvRecord { t, v });
    }
    Ok(records)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    InvalidMagic { expected: [u8; 4], found: [u8; 4] },
    UnsupportedVersion { expected: u16, found: u16 },
    InvalidHeaderType { found: u8 },
    BufferTooSmall { needed: usize, actual: usize },
    PayloadLengthTooLarge { length: usize },
    CrcMismatch {
        kind: &'static str,
        expected: u32,
        computed: u32,
    },
    FieldLengthTooLarge { field: &'static str, length: usize },
    TlvLengthTooLarge { length: usize },
    TlvTruncated {
        offset: usize,
        needed: usize,
        remaining: usize,
    },
    CompressionError { message: String },
    IoError { message: String },
    InvalidKeyLength { length: usize },
    HkdfInvalidLength { label: &'static str },
    AeadFailure,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::InvalidMagic { expected, found } => write!(
                f,
                "invalid magic: expected {:?} got {:?}",
                expected, found
            ),
            Error::UnsupportedVersion { expected, found } => {
                write!(f, "unsupported version: expected {} got {}", expected, found)
            }
            Error::InvalidHeaderType { found } => {
                write!(f, "invalid header type: {}", found)
            }
            Error::BufferTooSmall { needed, actual } => write!(
                f,
                "buffer too small: needed {} bytes, got {}", needed, actual
            ),
            Error::PayloadLengthTooLarge { length } => {
                write!(f, "payload length too large: {}", length)
            }
            Error::CrcMismatch {
                kind,
                expected,
                computed,
            } => write!(
                f,
                "crc mismatch for {}: expected {:08x} computed {:08x}",
                kind, expected, computed
            ),
            Error::FieldLengthTooLarge { field, length } => {
                write!(f, "field length too large for {}: {}", field, length)
            }
            Error::TlvLengthTooLarge { length } => {
                write!(f, "tlv length too large: {}", length)
            }
            Error::TlvTruncated {
                offset,
                needed,
                remaining,
            } => write!(
                f,
                "tlv truncated at {}: needed {} bytes, remaining {}",
                offset, needed, remaining
            ),
            Error::CompressionError { message } => write!(f, "compression error: {}", message),
            Error::IoError { message } => write!(f, "io error: {}", message),
            Error::InvalidKeyLength { length } => {
                write!(f, "invalid key length: {}", length)
            }
            Error::HkdfInvalidLength { label } => {
                write!(f, "hkdf invalid length for {}", label)
            }
            Error::AeadFailure => write!(f, "aead operation failed"),
        }
    }
}

impl std::error::Error for Error {}

fn read_u16_le(buf: &[u8], offset: usize) -> Result<u16, Error> {
    if buf.len() < offset + 2 {
        return Err(Error::BufferTooSmall {
            needed: offset + 2,
            actual: buf.len(),
        });
    }
    Ok(u16::from_le_bytes([buf[offset], buf[offset + 1]]))
}

fn read_u32_le(buf: &[u8], offset: usize) -> Result<u32, Error> {
    if buf.len() < offset + 4 {
        return Err(Error::BufferTooSmall {
            needed: offset + 4,
            actual: buf.len(),
        });
    }
    Ok(u32::from_le_bytes([
        buf[offset],
        buf[offset + 1],
        buf[offset + 2],
        buf[offset + 3],
    ]))
}

fn read_u64_le(buf: &[u8], offset: usize) -> Result<u64, Error> {
    if buf.len() < offset + 8 {
        return Err(Error::BufferTooSmall {
            needed: offset + 8,
            actual: buf.len(),
        });
    }
    Ok(u64::from_le_bytes([
        buf[offset],
        buf[offset + 1],
        buf[offset + 2],
        buf[offset + 3],
        buf[offset + 4],
        buf[offset + 5],
        buf[offset + 6],
        buf[offset + 7],
    ]))
}

fn array4(slice: &[u8]) -> [u8; 4] {
    [slice[0], slice[1], slice[2], slice[3]]
}

fn array16(slice: &[u8]) -> [u8; 16] {
    let mut out = [0u8; 16];
    out.copy_from_slice(slice);
    out
}

fn checked_u16_len(len: usize, field: &'static str) -> Result<u16, Error> {
    if len > u16::MAX as usize {
        return Err(Error::FieldLengthTooLarge { field, length: len });
    }
    Ok(len as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_header_roundtrip() {
        let tlvs = vec![
            tlv_file_meta(1234, "file.bin", "application/octet-stream").expect("file meta"),
            tlv_codec_meta(0x0001, 3000, 1920, 1080),
        ];
        let header = SessionHeaderV1 {
            flags: 0x03,
            session_id: [0xAB; 16],
            header_seq: 7,
            tlvs,
        };
        let packed = header.pack().expect("pack");
        let unpacked = SessionHeaderV1::unpack(&packed).expect("unpack");
        assert_eq!(header, unpacked);
    }

    #[test]
    fn manifest_roundtrip() {
        let manifest = ManifestV1 {
            flags: 0x0102,
            session_id: [0xCD; 16],
            orig_file_size: 1234,
            compressed_size: 567,
            chunk_plain_len: 4096,
            tlvs: vec![tlv_integrity_meta(0x0001, &[0xAA, 0xBB, 0xCC]).expect("integrity")],
        };
        let packed = manifest.pack().expect("pack");
        let unpacked = ManifestV1::unpack(&packed).expect("unpack");
        assert_eq!(manifest, unpacked);
    }

    #[test]
    fn detects_bad_crc() {
        let header = SessionHeaderV1 {
            flags: 0x00,
            session_id: [0x11; 16],
            header_seq: 1,
            tlvs: vec![TlvRecord {
                t: 0x0001,
                v: vec![0x01, 0x02],
            }],
        };
        let mut packed = header.pack().expect("pack");
        packed[10] ^= 0xFF;
        let err = SessionHeaderV1::unpack(&packed).unwrap_err();
        match err {
            Error::CrcMismatch { .. } => {}
            other => panic!("unexpected error: {:?}", other),
        }
    }
}
