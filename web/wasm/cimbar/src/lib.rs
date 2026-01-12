use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn cimbar_version() -> String {
    "stub".to_string()
}

#[wasm_bindgen]
pub fn cimbar_decode_rgba(_rgba: &[u8], _width: u32, _height: u32) -> JsValue {
    JsValue::NULL
}
