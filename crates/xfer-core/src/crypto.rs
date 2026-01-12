use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;

use crate::{Error, PACKET_MAGIC};

pub const AEAD_KEY_LEN: usize = 32;
pub const AEAD_NONCE_LEN: usize = 12;
pub const AAD_LEN: usize = 31;
pub const AEAD_TAG_LEN: usize = 16;

const HKDF_INFO_AEAD_KEY: &[u8] = b"axfr/aead/key";
const HKDF_INFO_NONCE_KEY: &[u8] = b"axfr/aead/nonce";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerivedKeys {
    pub aead_key: [u8; AEAD_KEY_LEN],
    pub nonce_key: [u8; AEAD_KEY_LEN],
}

pub fn derive_keys(ikm: &[u8], salt: &[u8]) -> Result<DerivedKeys, Error> {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);

    let mut aead_key = [0u8; AEAD_KEY_LEN];
    hk.expand(HKDF_INFO_AEAD_KEY, &mut aead_key)
        .map_err(|_| Error::HkdfInvalidLength {
            label: "aead_key",
        })?;

    let mut nonce_key = [0u8; AEAD_KEY_LEN];
    hk.expand(HKDF_INFO_NONCE_KEY, &mut nonce_key)
        .map_err(|_| Error::HkdfInvalidLength {
            label: "nonce_key",
        })?;

    Ok(DerivedKeys { aead_key, nonce_key })
}

pub fn derive_nonce(
    nonce_key: &[u8; AEAD_KEY_LEN],
    session_id: &[u8; 16],
    sbn: u32,
    esi: u32,
) -> Result<[u8; AEAD_NONCE_LEN], Error> {
    let hk = Hkdf::<Sha256>::from_prk(nonce_key).map_err(|_| Error::HkdfInvalidLength {
        label: "nonce_prk",
    })?;

    let mut info = [0u8; 24];
    info[0..16].copy_from_slice(session_id);
    info[16..20].copy_from_slice(&sbn.to_le_bytes());
    info[20..24].copy_from_slice(&esi.to_le_bytes());

    let mut nonce = [0u8; AEAD_NONCE_LEN];
    hk.expand(&info, &mut nonce)
        .map_err(|_| Error::HkdfInvalidLength { label: "nonce" })?;
    Ok(nonce)
}

pub fn build_aad(
    version: u16,
    session_id: &[u8; 16],
    sbn: u32,
    esi: u32,
    payload_type: u8,
) -> [u8; AAD_LEN] {
    let mut aad = [0u8; AAD_LEN];
    aad[0..4].copy_from_slice(&PACKET_MAGIC);
    aad[4..6].copy_from_slice(&version.to_le_bytes());
    aad[6..22].copy_from_slice(session_id);
    aad[22..26].copy_from_slice(&sbn.to_le_bytes());
    aad[26..30].copy_from_slice(&esi.to_le_bytes());
    aad[30] = payload_type;
    aad
}

pub fn encrypt_aead(
    key: &[u8; AEAD_KEY_LEN],
    nonce: &[u8; AEAD_NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, Error> {
    let cipher =
        Aes256Gcm::new_from_slice(key).map_err(|_| Error::InvalidKeyLength { length: key.len() })?;
    cipher
        .encrypt(Nonce::from_slice(nonce), Payload { msg: plaintext, aad })
        .map_err(|_| Error::AeadFailure)
}

pub fn decrypt_aead(
    key: &[u8; AEAD_KEY_LEN],
    nonce: &[u8; AEAD_NONCE_LEN],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, Error> {
    let cipher =
        Aes256Gcm::new_from_slice(key).map_err(|_| Error::InvalidKeyLength { length: key.len() })?;
    cipher
        .decrypt(Nonce::from_slice(nonce), Payload { msg: ciphertext, aad })
        .map_err(|_| Error::AeadFailure)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{PAYLOAD_TYPE_FOUNTAIN, SESSION_HEADER_VERSION_V1};

    #[test]
    fn aes_gcm_roundtrip() {
        let keys = derive_keys(b"ikm", b"salt").expect("derive keys");
        let session_id = [0x11u8; 16];
        let nonce = derive_nonce(&keys.nonce_key, &session_id, 1, 2).expect("nonce");
        let aad = build_aad(
            SESSION_HEADER_VERSION_V1,
            &session_id,
            1,
            2,
            PAYLOAD_TYPE_FOUNTAIN,
        );
        let plaintext = b"hello";
        let ciphertext = encrypt_aead(&keys.aead_key, &nonce, &aad, plaintext).expect("encrypt");
        let decrypted = decrypt_aead(&keys.aead_key, &nonce, &aad, &ciphertext).expect("decrypt");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn aad_mismatch_fails() {
        let keys = derive_keys(b"ikm", b"salt").expect("derive keys");
        let session_id = [0x22u8; 16];
        let nonce = derive_nonce(&keys.nonce_key, &session_id, 3, 4).expect("nonce");
        let aad = build_aad(
            SESSION_HEADER_VERSION_V1,
            &session_id,
            3,
            4,
            PAYLOAD_TYPE_FOUNTAIN,
        );
        let mut bad_aad = aad;
        bad_aad[AAD_LEN - 1] ^= 0x01;
        let plaintext = b"payload";
        let ciphertext = encrypt_aead(&keys.aead_key, &nonce, &aad, plaintext).expect("encrypt");
        let err = decrypt_aead(&keys.aead_key, &nonce, &bad_aad, &ciphertext).unwrap_err();
        assert_eq!(err, Error::AeadFailure);
    }
}
