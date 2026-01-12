use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn crc32c_bytes(data: &[u8]) -> u32 {
    crc32c::crc32c(data)
}

#[wasm_bindgen]
pub fn packets_header_crc_ok(header: &[u8]) -> bool {
    if header.len() < 40 {
        return false;
    }
    if &header[0..4] != b"AXPF" {
        return false;
    }
    let expected = u32::from_le_bytes([header[36], header[37], header[38], header[39]]);
    crc32c::crc32c(&header[0..36]) == expected
}
