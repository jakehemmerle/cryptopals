pub use utils::*;

pub mod utils {
    pub fn parse_file_base64(filename: &str) -> Vec<u8> {
        use std::fs;

        let file = fs::read_to_string(filename).unwrap();
        base64::decode(file.replace("\n", "").as_bytes()).unwrap()
    }
}
