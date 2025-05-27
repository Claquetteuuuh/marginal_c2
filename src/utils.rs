pub fn bytes_to_string(bytes: Vec<u8>) -> String {
    String::from_utf8(bytes).unwrap()
}

pub fn bytes_to_string_lossy(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).to_string()
}
