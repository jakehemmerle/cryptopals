pub use aes_ecb::*;

#[allow(dead_code)]
pub mod aes_ecb {
    use aes::{
        cipher::{generic_array::GenericArray, BlockDecrypt, KeyInit},
        Aes128, Block,
    };

    pub struct AesEcb128 {
        key: Block,
        cipher: Aes128,
    }

    impl AesEcb128 {
        pub fn new(key: &[u8]) -> Self {
            assert!(key.len() <= 16);

            let mut key_array = GenericArray::from([0u8; 16]);
            key_array.copy_from_slice(key);

            let cipher = Aes128::new(&key_array);

            AesEcb128 {
                key: key_array,
                cipher,
            }
        }

        /// This should write plaintext to a provided input buffer, not allocate mem itself
        pub fn decrypt(&self, ciphertext: &[u8]) -> Vec<u8> {
            let encrypted_blocks = ciphertext.chunks(16);

            // allocate mutable buffer
            let mut plaintext = Vec::<Block>::with_capacity(encrypted_blocks.len());

            // fill buffer
            plaintext.extend(
                encrypted_blocks
                    .map(|block| Block::clone_from_slice(block))
                    .collect::<Vec<Block>>(),
            );

            // decrypt (parallelizable)
            self.cipher.decrypt_blocks(&mut plaintext);

            // flatten out of blocks, same length as the slice
            plaintext.into_iter().flatten().collect::<Vec<u8>>()
        }
    }
}
