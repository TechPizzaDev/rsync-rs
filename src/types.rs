use crate::consts::*;

///
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum CryptoHashType {
    ///
    Md4,
    ///
    Blake2,
    ///
    Blake3,
}

///
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum RollingHashType {
    ///
    Adler32,
    ///
    RabinKarp,
}

impl CryptoHashType {
    ///
    pub fn sum_len(&self) -> usize {
        (match self {
            CryptoHashType::Md4 => MD4_SUM_LENGTH,
            CryptoHashType::Blake2 => BLAKE2_SUM_LENGTH,
            CryptoHashType::Blake3 => BLAKE3_SUM_LENGTH,
        }) as usize
    }
}
