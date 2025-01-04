use crate::sum_hash::{RollingHash, SumHash};

const RK_SEED: u32 = 1;
const RK_FACTOR: u32 = 0x08104225_u32;
const RK_MOD_INV_FACTOR: u32 = 0x98f009ad_u32;
const RK_ADJ: u32 = (RK_FACTOR - 1) * RK_SEED;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct RabinKarpHash {
    hash: u32,
    factor: u32,
}

impl Default for RabinKarpHash {
    fn default() -> Self {
        Self {
            hash: RK_SEED,
            factor: 1,
        }
    }
}
impl SumHash for RabinKarpHash {
    type Sum = [u8; 4];

    fn finish(&self) -> Self::Sum {
        self.hash.to_be_bytes()
    }

    fn update(&mut self, buf: &[u8]) -> &mut Self {
        for b in buf {
            self.hash = self.hash.wrapping_mul(RK_FACTOR).wrapping_add(*b as u32);
        }
        self.factor = self.factor.wrapping_mul(uint32_pow(RK_FACTOR, buf.len()));
        self
    }
}
impl RollingHash for RabinKarpHash {
    #[inline]
    fn rollout(&mut self, _size: usize, old: u8) -> &mut Self {
        self.factor = self.factor.wrapping_mul(RK_MOD_INV_FACTOR);
        self.hash = self
            .hash
            .wrapping_sub(self.factor.wrapping_mul(RK_ADJ.wrapping_add(old as u32)));
        self
    }

    #[inline]
    fn rotate(&mut self, _size: usize, old: u8, new: u8) -> &mut Self {
        let new = self.hash.wrapping_mul(RK_FACTOR).wrapping_add(new as u32);
        let old = self.factor.wrapping_mul(RK_ADJ.wrapping_add(old as u32));
        self.hash = new.wrapping_sub(old);
        self
    }

    #[inline]
    fn rollin(&mut self, new: u8) -> &mut Self {
        self.hash = self.hash.wrapping_mul(RK_FACTOR).wrapping_add(new as u32);
        self.factor = self.factor.wrapping_mul(RK_FACTOR);
        self
    }
}

fn uint32_pow(mut m: u32, mut p: usize) -> u32 {
    let mut ans = 1u32;
    while p != 0 {
        if (p & 1) != 0 {
            ans = ans.wrapping_mul(m);
        }
        m = m.wrapping_mul(m);
        p >>= 1;
    }
    ans
}
