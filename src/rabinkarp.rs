use crate::sum_hash::{RollingHash, SumHash};

const RK_SEED: u32 = 1;
const RK_FACTOR: u32 = 0x08104225; // same multiplier as used in librsync
const RK_FACTOR_2: u32 = RK_FACTOR.wrapping_mul(RK_FACTOR);
const RK_FACTOR_3: u32 = RK_FACTOR.wrapping_mul(RK_FACTOR_2);
const RK_FACTOR_4: u32 = RK_FACTOR.wrapping_mul(RK_FACTOR_3);
const RK_FACTOR_5: u32 = RK_FACTOR.wrapping_mul(RK_FACTOR_4);
const RK_FACTOR_6: u32 = RK_FACTOR.wrapping_mul(RK_FACTOR_5);
const RK_FACTOR_7: u32 = RK_FACTOR.wrapping_mul(RK_FACTOR_6);
const RK_FACTOR_8: u32 = RK_FACTOR.wrapping_mul(RK_FACTOR_7);
const RK_MOD_INV_FACTOR: u32 = 0x98f009ad;
const RK_ADJUST: u32 = (RK_FACTOR - 1) * RK_SEED;

const RK_FACTOR_POW2: [u32; 32] = [
    0x08104225, 0xa5b71959, 0xf9c080f1, 0x7c71e2e1, 0x0bb409c1, 0x4dc72381, 0xd17a8701, 0x96260e01,
    0x55101c01, 0x2d303801, 0x66a07001, 0xfe40e001, 0xc081c001, 0x91038001, 0x62070001, 0xc40e0001,
    0x881c0001, 0x10380001, 0x20700001, 0x40e00001, 0x81c00001, 0x03800001, 0x07000001, 0x0e000001,
    0x1c000001, 0x38000001, 0x70000001, 0xe0000001, 0xc0000001, 0x80000001, 0x00000001, 0x00000001,
];

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct RabinKarpHash {
    hash: u32,
    factor: u32,
}

impl RabinKarpHash {
    #[inline]
    fn rollin_one(&mut self, new: u8) -> u32 {
        self.hash.wrapping_mul(RK_FACTOR).wrapping_add(new as u32)
    }

    #[inline]
    fn rollout_one(&mut self, old: u8) -> u32 {
        self.hash
            .wrapping_sub(self.factor.wrapping_mul(RK_ADJUST.wrapping_add(old as u32)))
    }
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
        let chunks = buf.chunks_exact(16);
        let tail = chunks.remainder();

        for chunk in chunks {
            self.hash = rollin_2x8(self.hash, chunk);
        }
        for b in tail {
            self.hash = self.rollin_one(*b);
        }
        self.factor = self.factor.wrapping_mul(rk_pow(buf.len() as u32));
        self
    }
}
impl RollingHash for RabinKarpHash {
    #[inline]
    fn rollout(&mut self, _size: usize, old: u8) -> &mut Self {
        self.factor = self.factor.wrapping_mul(RK_MOD_INV_FACTOR);
        self.hash = self.rollout_one(old);
        self
    }

    #[inline]
    fn rotate(&mut self, _size: usize, old: u8, new: u8) -> &mut Self {
        self.hash = self.rollin_one(new);
        self.hash = self.rollout_one(old);
        self
    }

    #[inline]
    fn rollin(&mut self, new: u8) -> &mut Self {
        self.hash = self.rollin_one(new);
        self.factor = self.factor.wrapping_mul(RK_FACTOR);
        self
    }
}

// TODO: manually SIMD (unpack 16x u8 to 4x4 u32 -> mul and horiz sum)
#[inline(always)]
fn rollin_2x4(hash: u32, buf: &[u8], i: usize) -> u32 {
    let base = RK_FACTOR_8.wrapping_mul(hash);
    base.wrapping_add(RK_FACTOR_7.wrapping_mul(buf[i + 0] as u32))
        .wrapping_add(RK_FACTOR_6.wrapping_mul(buf[i + 1] as u32))
        .wrapping_add(RK_FACTOR_5.wrapping_mul(buf[i + 2] as u32))
        .wrapping_add(RK_FACTOR_4.wrapping_mul(buf[i + 3] as u32))
        .wrapping_add(RK_FACTOR_3.wrapping_mul(buf[i + 4] as u32))
        .wrapping_add(RK_FACTOR_2.wrapping_mul(buf[i + 5] as u32))
        .wrapping_add(RK_FACTOR.wrapping_mul(buf[i + 6] as u32))
        .wrapping_add(buf[i + 7] as u32)
}

#[inline(always)]
fn rollin_2x8(hash: u32, buf: &[u8]) -> u32 {
    rollin_2x4(rollin_2x4(hash, buf, 0), buf, 8)
}

fn rk_pow(n: u32) -> u32 {
    let mut result = 1u32;
    let len = (n | 1).ilog2() + 1;
    for i in 0..len {
        if n & (1 << i) != 0 {
            result = result.wrapping_mul(RK_FACTOR_POW2[i as usize]);
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use crate::sum_hash::SumHash;

    use super::{RabinKarpHash, RollingHash, RK_FACTOR};
    use quickcheck_macros::quickcheck;

    pub fn basic_update<'a>(_self: &'a mut RabinKarpHash, buf: &[u8]) -> &'a mut RabinKarpHash {
        for b in buf {
            _self.hash = _self.hash.wrapping_mul(RK_FACTOR).wrapping_add(*b as u32);
        }
        _self.factor = _self.factor.wrapping_mul(uint32_pow(RK_FACTOR, buf.len()));
        _self
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

    #[quickcheck]
    fn rollin_one(buf: Vec<u8>) -> bool {
        let sum1 = RabinKarpHash::default().update(&buf).finish();
        let sum2 = buf
            .into_iter()
            .fold(RabinKarpHash::default(), |mut s: RabinKarpHash, new: u8| {
                s.rollin(new);
                s
            })
            .finish();
        sum1 == sum2
    }

    #[quickcheck]
    fn optimized_update(buf: Vec<u8>) -> bool {
        let sum1 = RabinKarpHash::default().update(&buf).finish();
        let sum2 = basic_update(&mut RabinKarpHash::default(), &buf).finish();
        sum1 == sum2
    }

    #[quickcheck]
    fn update_twice(mut buf1: Vec<u8>, buf2: Vec<u8>) -> bool {
        let sum1 = RabinKarpHash::default()
            .update(&buf1)
            .update(&buf2)
            .finish();
        buf1.extend(&buf2);

        let sum2 = RabinKarpHash::default().update(&buf1).finish();
        sum1 == sum2
    }

    #[quickcheck]
    fn rotate_one(mut buf: Vec<u8>, byte: u8) -> bool {
        if buf.is_empty() {
            return true;
        }
        let sum1 = RabinKarpHash::default()
            .update(&buf)
            .rotate(buf.len(), buf[0], byte)
            .finish();
        buf.push(byte);

        let sum2 = RabinKarpHash::default().update(&buf[1..]).finish();
        sum1 == sum2
    }

    #[quickcheck]
    fn rollout_one(buf: Vec<u8>) -> bool {
        if buf.is_empty() {
            return true;
        }
        let sum1 = RabinKarpHash::default()
            .update(&buf)
            .rollout(buf.len(), buf[0])
            .finish();
        let sum2 = RabinKarpHash::default().update(&buf[1..]).finish();
        sum1 == sum2
    }
}
