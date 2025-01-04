use crate::consts::MAX_STRONG_SUM_LENGTH;

pub trait SumHash: Clone {
    type Sum: Default + AsRef<[u8]> + 'static;

    fn finish(&self) -> Self::Sum;

    fn update(&mut self, input: &[u8]) -> &mut Self;

    fn update_many<'a>(pairs: impl Iterator<Item = (&'a mut Self, &'a [u8])>)
    where
        Self: 'a,
    {
        for (state, input) in pairs {
            state.update(input);
        }
    }

    fn finish_many<'a>(states: impl Iterator<Item = &'a Self>) -> impl Iterator<Item = Self::Sum>
    where
        Self: 'a,
    {
        states.map(|s| s.finish())
    }

    /// Get the maximum amount of inputs that [`sum_of_many`] can process in parallel.
    /// [`None`] means [`sum_of_many`] is not specialized.
    ///
    /// [`sum_of_many`]: SumHasher::sum_of_many
    fn degree_of_many(&self) -> Option<usize> {
        None
    }
}

pub trait CryptoHash: SumHash {}

pub trait RollingHash: SumHash {
    fn rotate(&mut self, size: usize, old: u8, new: u8) -> &mut Self;

    #[allow(dead_code)]
    fn rollin(&mut self, new: u8) -> &mut Self;

    #[allow(dead_code)]
    fn rollout(&mut self, size: usize, old: u8) -> &mut Self;
}

#[derive(Default, Clone)]
pub struct Md4Hash(crate::md4::Md4State);

impl SumHash for Md4Hash {
    type Sum = [u8; 16];

    fn finish(&self) -> Self::Sum {
        self.0.finish()
    }

    fn update(&mut self, input: &[u8]) -> &mut Self {
        self.0.update(input);
        self
    }

    fn update_many<'a>(pairs: impl Iterator<Item = (&'a mut Self, &'a [u8])>)
    where
        Self: 'a,
    {
        crate::md4::md4_many(pairs.map(|s| (&mut s.0 .0, s.1)))
    }

    fn degree_of_many(&self) -> Option<usize> {
        Some(crate::md4::simd::MAX_LANES.max(1))
    }
}
impl CryptoHash for Md4Hash {}

#[derive(Clone)]
pub struct Blake2Hash(blake2b_simd::State);

impl Blake2Hash {
    #[inline]
    fn params() -> blake2b_simd::Params {
        let mut params = blake2b_simd::Params::new();
        params.hash_length(MAX_STRONG_SUM_LENGTH as usize);
        params
    }

    #[inline]
    fn hash_to_sum(hash: &blake2b_simd::Hash) -> <Self as SumHash>::Sum {
        hash.as_bytes().try_into().unwrap()
    }
}
impl Default for Blake2Hash {
    fn default() -> Self {
        Self(Self::params().to_state())
    }
}
impl SumHash for Blake2Hash {
    type Sum = [u8; 32];

    fn finish(&self) -> Self::Sum {
        Self::hash_to_sum(&self.0.finalize())
    }

    fn update(&mut self, input: &[u8]) -> &mut Self {
        self.0.update(input);
        self
    }

    fn update_many<'a>(pairs: impl Iterator<Item = (&'a mut Self, &'a [u8])>) {
        blake2b_simd::many::update_many(pairs.map(|s| (&mut s.0 .0, s.1)));
    }

    fn degree_of_many(&self) -> Option<usize> {
        Some(blake2b_simd::many::MAX_DEGREE.max(1))
    }
}
impl CryptoHash for Blake2Hash {}

#[derive(Default, Clone)]
pub struct Blake3Hash(blake3::Hasher);

impl SumHash for Blake3Hash {
    type Sum = [u8; 32];

    fn finish(&self) -> Self::Sum {
        (*self.0.finalize().as_bytes()).into()
    }

    fn update(&mut self, input: &[u8]) -> &mut Self {
        self.0.update(input);
        self
    }
}
impl CryptoHash for Blake3Hash {}
