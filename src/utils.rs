pub use utils::*;

pub mod utils {
    use ::aes::cipher::generic_array::GenericArray;
    use ::aes::cipher::typenum::U16;
    use ::aes::Block;
    use itertools::Itertools;
    pub fn parse_file_base64(filename: &str) -> Vec<u8> {
        use std::fs;

        let file = fs::read_to_string(filename).unwrap();
        base64::decode(file.replace('\n', "").as_bytes()).unwrap()
    }

    /// this generates an output buffer from the block count (assuming 16-byte blocks)
    #[allow(dead_code)]
    pub fn output_from_block_count(block_count: usize) -> Vec<GenericArray<u8, U16>> {
        let mut empty_buffer = Vec::<u8>::with_capacity(block_count * 16);
        for _ in 0..(block_count * 16) {
            empty_buffer.push(0);
        }
        let output = empty_buffer
            .chunks(16)
            .into_iter()
            .map(GenericArray::<u8, U16>::clone_from_slice)
            .collect_vec();

        output
    }

    /// This turns a slice of bytes (eg ciphertext) into 16 byte blocks ready for encryption;
    #[allow(dead_code)]
    pub fn input_to_padded_blocks(input: &[u8]) -> Vec<GenericArray<u8, U16>> {
        let mut output = Vec::<u8>::with_capacity(input.len());
        output.extend_from_slice(input);
        let padding = 16 - (input.len() % 16);
        output.extend(vec![42u8; padding]);

        let blocks = output
            .chunks(16)
            .into_iter()
            .map(GenericArray::<u8, U16>::clone_from_slice)
            .collect_vec();

        blocks
    }

    pub fn text_to_io(input: Vec<u8>) -> (Vec<Block>, Vec<Block>) {
        let input = input_to_padded_blocks(input.as_slice());
        let output = output_from_block_count(input.len());
        (input, output)
    }
}
