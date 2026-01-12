use crc32c::crc32c;
use std::io::Read;

use crate::Error;

pub const DATA_PACKET_HEADER_LEN: usize = 25;
pub const PACKETS_FILE_MAGIC: [u8; 4] = *b"AXPF";
pub const PACKETS_FILE_VERSION_V1: u16 = 0x0001;
pub const PACKETS_FILE_HEADER_LEN: usize = 40;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataPacketV1 {
    pub session_id: [u8; 16],
    pub seq: u32,
    pub payload_type: u8,
    pub payload: Vec<u8>,
}

pub struct DataPacketReader<R: Read> {
    inner: R,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketsFileHeaderV1 {
    pub flags: u16,
    pub session_id: [u8; 16],
    pub packet_count: u32,
    pub packet_bytes: u64,
}

impl<R: Read> DataPacketReader<R> {
    pub fn new(inner: R) -> Self {
        DataPacketReader { inner }
    }

    pub fn next_packet(&mut self) -> Result<Option<DataPacketV1>, Error> {
        read_next_packet(&mut self.inner)
    }
}

impl PacketsFileHeaderV1 {
    pub fn pack(&self) -> Result<Vec<u8>, Error> {
        let mut out = Vec::with_capacity(PACKETS_FILE_HEADER_LEN);
        out.extend_from_slice(&PACKETS_FILE_MAGIC);
        out.extend_from_slice(&PACKETS_FILE_VERSION_V1.to_le_bytes());
        out.extend_from_slice(&self.flags.to_le_bytes());
        out.extend_from_slice(&self.session_id);
        out.extend_from_slice(&self.packet_count.to_le_bytes());
        out.extend_from_slice(&self.packet_bytes.to_le_bytes());
        let crc = crc32c(&out);
        out.extend_from_slice(&crc.to_le_bytes());
        Ok(out)
    }

    pub fn unpack(buf: &[u8]) -> Result<Self, Error> {
        if buf.len() < PACKETS_FILE_HEADER_LEN {
            return Err(Error::BufferTooSmall {
                needed: PACKETS_FILE_HEADER_LEN,
                actual: buf.len(),
            });
        }

        let magic = array4(&buf[0..4]);
        if magic != PACKETS_FILE_MAGIC {
            return Err(Error::InvalidMagic {
                expected: PACKETS_FILE_MAGIC,
                found: magic,
            });
        }

        let version = read_u16_le(buf, 4)?;
        if version != PACKETS_FILE_VERSION_V1 {
            return Err(Error::UnsupportedVersion {
                expected: PACKETS_FILE_VERSION_V1,
                found: version,
            });
        }

        let flags = read_u16_le(buf, 6)?;
        let session_id = array16(&buf[8..24]);
        let packet_count = read_u32_le(buf, 24)?;
        let packet_bytes = read_u64_le(buf, 28)?;
        let header_crc = read_u32_le(buf, 36)?;

        let computed_crc = crc32c(&buf[0..36]);
        if computed_crc != header_crc {
            return Err(Error::CrcMismatch {
                kind: "packets_header",
                expected: header_crc,
                computed: computed_crc,
            });
        }

        Ok(PacketsFileHeaderV1 {
            flags,
            session_id,
            packet_count,
            packet_bytes,
        })
    }
}

pub fn read_packets_file_header<R: Read>(reader: &mut R) -> Result<PacketsFileHeaderV1, Error> {
    let mut buf = [0u8; PACKETS_FILE_HEADER_LEN];
    reader.read_exact(&mut buf).map_err(|e| Error::IoError {
        message: e.to_string(),
    })?;
    PacketsFileHeaderV1::unpack(&buf)
}

impl DataPacketV1 {
    pub fn pack(&self) -> Result<Vec<u8>, Error> {
        let payload_len = self.payload.len();
        if payload_len > u32::MAX as usize {
            return Err(Error::PayloadLengthTooLarge { length: payload_len });
        }

        let mut out = Vec::with_capacity(DATA_PACKET_HEADER_LEN + payload_len + 4);
        out.extend_from_slice(&self.session_id);
        out.extend_from_slice(&self.seq.to_le_bytes());
        out.push(self.payload_type);
        out.extend_from_slice(&(payload_len as u32).to_le_bytes());
        out.extend_from_slice(&self.payload);

        let crc = crc32c(&out);
        out.extend_from_slice(&crc.to_le_bytes());
        Ok(out)
    }

    pub fn unpack(buf: &[u8]) -> Result<Self, Error> {
        if buf.len() < DATA_PACKET_HEADER_LEN + 4 {
            return Err(Error::BufferTooSmall {
                needed: DATA_PACKET_HEADER_LEN + 4,
                actual: buf.len(),
            });
        }

        let session_id = array16(&buf[0..16]);
        let seq = read_u32_le(buf, 16)?;
        let payload_type = buf[20];
        let payload_len = read_u32_le(buf, 21)? as usize;
        let needed = DATA_PACKET_HEADER_LEN + payload_len + 4;
        if buf.len() < needed {
            return Err(Error::BufferTooSmall {
                needed,
                actual: buf.len(),
            });
        }

        let payload = buf[DATA_PACKET_HEADER_LEN..DATA_PACKET_HEADER_LEN + payload_len].to_vec();
        let expected_crc =
            read_u32_le(buf, DATA_PACKET_HEADER_LEN + payload_len)?;
        let computed_crc = crc32c(&buf[..DATA_PACKET_HEADER_LEN + payload_len]);
        if expected_crc != computed_crc {
            return Err(Error::CrcMismatch {
                kind: "data_packet",
                expected: expected_crc,
                computed: computed_crc,
            });
        }

        Ok(DataPacketV1 {
            session_id,
            seq,
            payload_type,
            payload,
        })
    }
}

pub fn read_next_packet<R: Read>(reader: &mut R) -> Result<Option<DataPacketV1>, Error> {
    let mut header = [0u8; DATA_PACKET_HEADER_LEN];
    if !read_exact_or_eof(reader, &mut header)? {
        return Ok(None);
    }

    let payload_len = u32::from_le_bytes([header[21], header[22], header[23], header[24]]) as usize;
    let mut payload = vec![0u8; payload_len];
    read_exact_or_eof(reader, &mut payload)?;

    let mut crc = [0u8; 4];
    read_exact_or_eof(reader, &mut crc)?;

    let mut buf = Vec::with_capacity(DATA_PACKET_HEADER_LEN + payload_len + 4);
    buf.extend_from_slice(&header);
    buf.extend_from_slice(&payload);
    buf.extend_from_slice(&crc);

    Ok(Some(DataPacketV1::unpack(&buf)?))
}

fn read_exact_or_eof<R: Read>(reader: &mut R, buf: &mut [u8]) -> Result<bool, Error> {
    let mut read_total = 0;
    while read_total < buf.len() {
        match reader.read(&mut buf[read_total..]) {
            Ok(0) => {
                if read_total == 0 {
                    return Ok(false);
                }
                return Err(Error::IoError {
                    message: "unexpected EOF while reading data packet".to_string(),
                });
            }
            Ok(n) => read_total += n,
            Err(e) => {
                return Err(Error::IoError {
                    message: e.to_string(),
                })
            }
        }
    }
    Ok(true)
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

fn read_u16_le(buf: &[u8], offset: usize) -> Result<u16, Error> {
    if buf.len() < offset + 2 {
        return Err(Error::BufferTooSmall {
            needed: offset + 2,
            actual: buf.len(),
        });
    }
    Ok(u16::from_le_bytes([buf[offset], buf[offset + 1]]))
}

fn array4(slice: &[u8]) -> [u8; 4] {
    let mut out = [0u8; 4];
    out.copy_from_slice(slice);
    out
}

fn array16(slice: &[u8]) -> [u8; 16] {
    let mut out = [0u8; 16];
    out.copy_from_slice(slice);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn data_packet_roundtrip() {
        let packet = DataPacketV1 {
            session_id: [0xAA; 16],
            seq: 42,
            payload_type: 0x02,
            payload: vec![1, 2, 3, 4, 5],
        };
        let bytes = packet.pack().expect("pack");
        let unpacked = DataPacketV1::unpack(&bytes).expect("unpack");
        assert_eq!(packet, unpacked);
    }

    #[test]
    fn data_packet_bad_crc() {
        let packet = DataPacketV1 {
            session_id: [0xBB; 16],
            seq: 7,
            payload_type: 0x02,
            payload: vec![9, 9, 9],
        };
        let mut bytes = packet.pack().expect("pack");
        bytes[10] ^= 0xFF;
        let err = DataPacketV1::unpack(&bytes).unwrap_err();
        match err {
            Error::CrcMismatch { .. } => {}
            other => panic!("unexpected error: {:?}", other),
        }
    }

    #[test]
    fn packets_header_roundtrip() {
        let header = PacketsFileHeaderV1 {
            flags: 0,
            session_id: [0x11; 16],
            packet_count: 12,
            packet_bytes: 3456,
        };
        let bytes = header.pack().expect("pack");
        let unpacked = PacketsFileHeaderV1::unpack(&bytes).expect("unpack");
        assert_eq!(header, unpacked);
    }

    #[test]
    fn packets_header_reader() {
        let header = PacketsFileHeaderV1 {
            flags: 0,
            session_id: [0x22; 16],
            packet_count: 1,
            packet_bytes: 0,
        };
        let packet = DataPacketV1 {
            session_id: [0x22; 16],
            seq: 0,
            payload_type: 0x02,
            payload: vec![1, 2, 3],
        };
        let mut buf = Vec::new();
        buf.extend_from_slice(&header.pack().expect("header pack"));
        buf.extend_from_slice(&packet.pack().expect("packet pack"));

        let mut cursor = Cursor::new(buf);
        let parsed = read_packets_file_header(&mut cursor).expect("read header");
        assert_eq!(parsed, header);
        let mut reader = DataPacketReader::new(cursor);
        let read_packet = reader.next_packet().expect("next").expect("packet");
        assert_eq!(read_packet, packet);
    }
}
