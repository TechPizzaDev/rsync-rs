use std::hash::{BuildHasherDefault, Hasher};

/// A very simple hasher designed for diffusing weak hashes.
#[derive(Default)]
pub struct DiffuseHasher {
    state: u32,
}

impl Hasher for DiffuseHasher {
    fn write(&mut self, _: &[u8]) {
        panic!("not designed for general writes");
    }

    #[inline]
    fn write_u32(&mut self, val: u32) {
        debug_assert_eq!(self.state, 0, "can't hash more than one u32");
        self.state = val;
    }

    #[cfg(target_pointer_width = "64")]
    #[inline]
    fn finish(&self) -> u64 {
        // the avalanche function from xxhash
        let mut val = self.state as u64;
        val ^= val >> 33;
        val = val.wrapping_mul(0xC2B2AE3D27D4EB4F);
        val ^= val >> 29;
        val = val.wrapping_mul(0x165667B19E3779F9);
        val ^= val >> 32;
        val
    }

    #[cfg(target_pointer_width = "32")]
    #[inline]
    fn finish(&self) -> u64 {
        let mut val = self.state;
        val ^= val >> 15;
        val = val.wrapping_mul(0x85EBCA77);
        val ^= val >> 13;
        val = val.wrapping_mul(0xC2B2AE3D);
        val ^= val >> 16;
        val as u64
    }
}

pub type BuildDiffuseHasher = BuildHasherDefault<DiffuseHasher>;
