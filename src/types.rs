use strum::{EnumIter, IntoEnumIterator};

use crate::consts::*;

pub trait HashType {
    fn sum_len(&self) -> usize;

    fn iter() -> impl Iterator<Item = Self>;
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, EnumIter)]
pub enum CryptoHashType {
    Md4,
    Blake2,
    Blake3,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, EnumIter)]
pub enum RollingHashType {
    Rollsum,
    RabinKarp,
}

impl HashType for CryptoHashType {
    fn sum_len(&self) -> usize {
        (match self {
            CryptoHashType::Md4 => MD4_SUM_LENGTH,
            CryptoHashType::Blake2 => BLAKE2_SUM_LENGTH,
            CryptoHashType::Blake3 => BLAKE3_SUM_LENGTH,
        }) as usize
    }

    fn iter() -> impl Iterator<Item = Self> {
        <Self as IntoEnumIterator>::iter()
    }
}

impl HashType for RollingHashType {
    fn sum_len(&self) -> usize {
        match self {
            RollingHashType::Rollsum => 4,
            RollingHashType::RabinKarp => 4,
        }
    }

    fn iter() -> impl Iterator<Item = Self> {
        <Self as IntoEnumIterator>::iter()
    }
}
