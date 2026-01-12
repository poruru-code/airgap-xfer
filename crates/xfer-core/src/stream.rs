use std::io::{Read, Write};

use sha2::{Digest, Sha256};

use crate::{
    build_aad, decrypt_aead, derive_nonce, encrypt_aead, zstd_decoder, AAD_LEN, AEAD_TAG_LEN,
    DerivedKeys, Error,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptResult {
    pub ciphertext_hash: [u8; 32],
    pub ciphertext_size: u64,
    pub input_size: u64,
}

pub fn encrypt_stream<R: Read + ?Sized, W: Write + ?Sized>(
    reader: &mut R,
    chunk_plain_len: u32,
    keys: &DerivedKeys,
    session_id: &[u8; 16],
    version: u16,
    payload_type: u8,
    sbn: u32,
    mut output: Option<&mut W>,
) -> Result<EncryptResult, Error> {
    let chunk_len = usize::try_from(chunk_plain_len)
        .map_err(|_| Error::IoError {
            message: "chunk size too large for platform".to_string(),
        })?;
    let mut buffer = vec![0u8; chunk_len];
    let mut hasher = Sha256::new();
    let mut esi: u32 = 0;
    let mut ciphertext_size: u64 = 0;
    let mut input_size: u64 = 0;

    loop {
        let read = reader.read(&mut buffer).map_err(|e| Error::IoError {
            message: e.to_string(),
        })?;
        if read == 0 {
            break;
        }
        input_size = input_size
            .checked_add(read as u64)
            .ok_or_else(|| Error::IoError {
                message: "input size overflow".to_string(),
            })?;
        let nonce = derive_nonce(&keys.nonce_key, session_id, sbn, esi)?;
        let aad = build_aad(version, session_id, sbn, esi, payload_type);
        let ciphertext = encrypt_aead(&keys.aead_key, &nonce, &aad, &buffer[..read])?;
        if let Some(writer) = output.as_mut() {
            writer
                .write_all(&ciphertext)
                .map_err(|e| Error::IoError {
                    message: e.to_string(),
                })?;
        }
        hasher.update(&ciphertext);
        ciphertext_size = ciphertext_size
            .checked_add(ciphertext.len() as u64)
            .ok_or_else(|| Error::IoError {
                message: "ciphertext size overflow".to_string(),
            })?;
        esi = esi
            .checked_add(1)
            .ok_or_else(|| Error::IoError {
                message: "encoding symbol id overflow".to_string(),
            })?;
    }

    if let Some(writer) = output.as_mut() {
        writer.flush().map_err(|e| Error::IoError {
            message: e.to_string(),
        })?;
    }

    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    Ok(EncryptResult {
        ciphertext_hash: out,
        ciphertext_size,
        input_size,
    })
}

pub fn decrypt_stream<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    chunk_plain_len: u32,
    compressed_size: u64,
    keys: &DerivedKeys,
    session_id: &[u8; 16],
    version: u16,
    payload_type: u8,
    sbn: u32,
) -> Result<u64, Error> {
    let mut decrypt_reader = DecryptReader::new(
        reader,
        chunk_plain_len,
        compressed_size,
        keys,
        session_id,
        version,
        payload_type,
        sbn,
    )?;
    std::io::copy(&mut decrypt_reader, writer).map_err(|e| Error::IoError {
        message: e.to_string(),
    })
}

pub fn decrypt_and_decompress<R: Read, W: Write>(
    reader: R,
    writer: &mut W,
    chunk_plain_len: u32,
    compressed_size: u64,
    keys: &DerivedKeys,
    session_id: &[u8; 16],
    version: u16,
    payload_type: u8,
    sbn: u32,
    decompress: bool,
) -> Result<u64, Error> {
    let decrypt_reader = DecryptReader::new(
        reader,
        chunk_plain_len,
        compressed_size,
        keys,
        session_id,
        version,
        payload_type,
        sbn,
    )?;

    if decompress {
        let mut decoder = zstd_decoder(decrypt_reader)?;
        std::io::copy(&mut decoder, writer).map_err(|e| Error::IoError {
            message: e.to_string(),
        })
    } else {
        let mut plain_reader = decrypt_reader;
        std::io::copy(&mut plain_reader, writer).map_err(|e| Error::IoError {
            message: e.to_string(),
        })
    }
}

struct DecryptReader<R: Read> {
    inner: R,
    keys: DerivedKeys,
    session_id: [u8; 16],
    version: u16,
    payload_type: u8,
    sbn: u32,
    chunk_plain_len: u32,
    remaining_plain: u64,
    esi: u32,
    buffer: Vec<u8>,
    offset: usize,
}

impl<R: Read> DecryptReader<R> {
    fn new(
        inner: R,
        chunk_plain_len: u32,
        compressed_size: u64,
        keys: &DerivedKeys,
        session_id: &[u8; 16],
        version: u16,
        payload_type: u8,
        sbn: u32,
    ) -> Result<Self, Error> {
        Ok(DecryptReader {
            inner,
            keys: keys.clone(),
            session_id: *session_id,
            version,
            payload_type,
            sbn,
            chunk_plain_len,
            remaining_plain: compressed_size,
            esi: 0,
            buffer: Vec::new(),
            offset: 0,
        })
    }

    fn fill_next(&mut self) -> Result<(), Error> {
        if self.remaining_plain == 0 {
            self.buffer.clear();
            self.offset = 0;
            return Ok(());
        }

        let expected_plain = self
            .remaining_plain
            .min(self.chunk_plain_len as u64) as usize;
        let expected_cipher = expected_plain + AEAD_TAG_LEN;

        let mut cipher_buf = vec![0u8; expected_cipher];
        self.inner
            .read_exact(&mut cipher_buf)
            .map_err(|e| Error::IoError {
                message: e.to_string(),
            })?;

        let nonce = derive_nonce(&self.keys.nonce_key, &self.session_id, self.sbn, self.esi)?;
        let aad = build_aad(
            self.version,
            &self.session_id,
            self.sbn,
            self.esi,
            self.payload_type,
        );
        if aad.len() != AAD_LEN {
            return Err(Error::IoError {
                message: "aad length mismatch".to_string(),
            });
        }

        let plain = decrypt_aead(&self.keys.aead_key, &nonce, &aad, &cipher_buf)?;
        if plain.len() != expected_plain {
            return Err(Error::IoError {
                message: "plaintext length mismatch".to_string(),
            });
        }

        self.buffer = plain;
        self.offset = 0;
        self.remaining_plain = self
            .remaining_plain
            .checked_sub(expected_plain as u64)
            .ok_or_else(|| Error::IoError {
                message: "remaining size underflow".to_string(),
            })?;
        self.esi = self.esi.checked_add(1).ok_or_else(|| Error::IoError {
            message: "encoding symbol id overflow".to_string(),
        })?;

        Ok(())
    }
}

impl<R: Read> Read for DecryptReader<R> {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }

        if self.offset >= self.buffer.len() {
            if let Err(err) = self.fill_next() {
                return Err(std::io::Error::new(std::io::ErrorKind::Other, err));
            }
        }

        if self.buffer.is_empty() {
            return Ok(0);
        }

        let to_copy = out.len().min(self.buffer.len() - self.offset);
        out[..to_copy].copy_from_slice(&self.buffer[self.offset..self.offset + to_copy]);
        self.offset += to_copy;
        Ok(to_copy)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{derive_keys, encrypt_stream, zstd_reader, PAYLOAD_TYPE_FOUNTAIN, SESSION_HEADER_VERSION_V1};
    use std::io::Cursor;

    fn hex(bytes: &[u8]) -> String {
        let mut out = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            use std::fmt::Write;
            let _ = write!(out, "{:02x}", byte);
        }
        out
    }

    #[test]
    fn decrypt_roundtrip_uncompressed() {
        let input = b"vector-input-plaintext";
        let session_id = [0x42u8; 16];
        let psk = b"psk-fixed";
        let salt = b"salt-fixed-1234";
        let keys = derive_keys(psk, salt).expect("keys");

        let mut reader = Cursor::new(input.as_slice());
        let result = encrypt_stream(
            &mut reader,
            8,
            &keys,
            &session_id,
            SESSION_HEADER_VERSION_V1,
            PAYLOAD_TYPE_FOUNTAIN,
            0,
            None::<&mut Vec<u8>>,
        )
        .expect("encrypt");

        let mut ciphertext_reader = Cursor::new(Vec::new());
        let mut reader = Cursor::new(input.as_slice());
        let result_full = encrypt_stream(
            &mut reader,
            8,
            &keys,
            &session_id,
            SESSION_HEADER_VERSION_V1,
            PAYLOAD_TYPE_FOUNTAIN,
            0,
            Some(&mut ciphertext_reader),
        )
        .expect("encrypt with output");

        assert_eq!(result, result_full);

        let mut ciphertext = ciphertext_reader.into_inner();
        let mut plain_out = Vec::new();
        let mut cipher_cursor = Cursor::new(&mut ciphertext);
        let bytes_written = decrypt_and_decompress(
            &mut cipher_cursor,
            &mut plain_out,
            8,
            result.input_size,
            &keys,
            &session_id,
            SESSION_HEADER_VERSION_V1,
            PAYLOAD_TYPE_FOUNTAIN,
            0,
            false,
        )
        .expect("decrypt");

        assert_eq!(bytes_written, input.len() as u64);
        assert_eq!(plain_out, input);
    }

    #[test]
    fn decrypt_roundtrip_compressed() {
        let input = b"vector-input-plaintext-compress";
        let session_id = [0x33u8; 16];
        let psk = b"psk-fixed";
        let salt = b"salt-fixed-1234";
        let keys = derive_keys(psk, salt).expect("keys");

        let cursor = Cursor::new(input.as_slice());
        let mut zstd = zstd_reader(cursor, 3).expect("zstd");
        let mut ciphertext = Vec::new();
        let result = encrypt_stream(
            &mut zstd,
            8,
            &keys,
            &session_id,
            SESSION_HEADER_VERSION_V1,
            PAYLOAD_TYPE_FOUNTAIN,
            0,
            Some(&mut ciphertext),
        )
        .expect("encrypt");

        let mut plain_out = Vec::new();
        let mut cipher_cursor = Cursor::new(&ciphertext);
        let bytes_written = decrypt_and_decompress(
            &mut cipher_cursor,
            &mut plain_out,
            8,
            result.input_size,
            &keys,
            &session_id,
            SESSION_HEADER_VERSION_V1,
            PAYLOAD_TYPE_FOUNTAIN,
            0,
            true,
        )
        .expect("decrypt");

        assert_eq!(bytes_written, input.len() as u64);
        assert_eq!(plain_out, input);
    }

    #[test]
    fn fixed_vectors_v1() {
        let input = b"The quick brown fox jumps over the lazy dog.";
        let session_id = [0x11u8; 16];
        let psk = b"psk-fixed";
        let salt = b"salt-fixed-1234";
        let keys = derive_keys(psk, salt).expect("keys");

        let mut reader = Cursor::new(input.as_slice());
        let result = encrypt_stream(
            &mut reader,
            16,
            &keys,
            &session_id,
            SESSION_HEADER_VERSION_V1,
            PAYLOAD_TYPE_FOUNTAIN,
            0,
            None::<&mut Vec<u8>>,
        )
        .expect("encrypt");

        let expected_plain_hash =
            "eec2a2de21a5531e683c4dab24acca82a8439bb274c970b4fd010c7b978b84b5";
        let expected_plain_ciphertext_size = 92u64;
        let expected_plain_input_size = input.len() as u64;

        let update = std::env::var("UPDATE_VECTORS").is_ok();
        let plain_result = result;

        let cursor = Cursor::new(input.as_slice());
        let mut zstd = zstd_reader(cursor, 3).expect("zstd");
        let result = encrypt_stream(
            &mut zstd,
            16,
            &keys,
            &session_id,
            SESSION_HEADER_VERSION_V1,
            PAYLOAD_TYPE_FOUNTAIN,
            0,
            None::<&mut Vec<u8>>,
        )
        .expect("encrypt");
        let comp_result = result;

        if update {
            println!(
                "plain input_size={} ciphertext_size={} hash={}",
                plain_result.input_size,
                plain_result.ciphertext_size,
                hex(&plain_result.ciphertext_hash)
            );
            println!(
                "compressed input_size={} ciphertext_size={} hash={}",
                comp_result.input_size,
                comp_result.ciphertext_size,
                hex(&comp_result.ciphertext_hash)
            );
            return;
        }

        let expected_comp_hash =
            "72f8f0b1efb127d6b4bd445ba7aaed295ff4052a9088bb2eb2dbdc0282d7378e";
        let expected_comp_input_size = 53u64;
        let expected_comp_ciphertext_size = 117u64;

        assert_eq!(plain_result.input_size, expected_plain_input_size);
        assert_eq!(
            plain_result.ciphertext_size,
            expected_plain_ciphertext_size
        );
        assert_eq!(hex(&plain_result.ciphertext_hash), expected_plain_hash);
        assert_eq!(comp_result.input_size, expected_comp_input_size);
        assert_eq!(comp_result.ciphertext_size, expected_comp_ciphertext_size);
        assert_eq!(hex(&comp_result.ciphertext_hash), expected_comp_hash);
    }
}
