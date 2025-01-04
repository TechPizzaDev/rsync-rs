use std::hash::Hash;

use crate::consts::MAX_STRONG_SUM_LENGTH;

pub trait SumHash: Default + Clone {
    type Sum: Default + AsRef<[u8]>;

    fn finish(&self) -> Self::Sum;

    fn update(&mut self, input: &[u8]);

    fn sum_of(input: &[u8]) -> Self::Sum
    where
        Self: Default,
    {
        let mut state = Self::default();
        state.update(input);
        state.finish()
    }

    fn sum_of_many<'a>(
        inputs: impl ExactSizeIterator<Item = &'a [u8]>,
    ) -> impl ExactSizeIterator<Item = Self::Sum>
    where
        Self: Default,
    {
        inputs.map(|input| Self::sum_of(input))
    }

    /// Get the maximum amount of inputs that [`sum_of_many`] can process in parallel.
    /// [`None`] means [`sum_of_many`] is not specialized.
    ///
    /// [`sum_of_many`]: SumHasher::sum_of_many
    fn degree_of_many() -> Option<usize> {
        None
    }
}

pub trait CryptoHash: SumHash {}

pub trait RollingHash: SumHash {
    fn rotate(&mut self, size: usize, old: u8, new: u8);

    #[allow(dead_code)]
    fn rollin(&mut self, new: u8);

    #[allow(dead_code)]
    fn rollout(&mut self, size: usize, old: u8);
}

#[derive(Default, Clone)]
pub struct Md4Hash(crate::md4::Md4State);

impl SumHash for Md4Hash {
    type Sum = [u8; 16];

    fn finish(&self) -> Self::Sum {
        self.0.finish()
    }

    fn update(&mut self, input: &[u8]) {
        self.0.update(input);
    }

    fn sum_of_many<'a>(
        inputs: impl ExactSizeIterator<Item = &'a [u8]>,
    ) -> impl ExactSizeIterator<Item = Self::Sum> {
        crate::md4::md4_many(inputs).map(|o| o.into())
    }

    fn degree_of_many() -> Option<usize> {
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

    fn update(&mut self, input: &[u8]) {
        self.0.update(input);
    }

    fn sum_of(input: &[u8]) -> Self::Sum {
        let params = Self::params();
        Self::hash_to_sum(&params.hash(input))
    }

    fn sum_of_many<'a>(
        inputs: impl ExactSizeIterator<Item = &'a [u8]>,
    ) -> impl ExactSizeIterator<Item = Self::Sum> {
        let params = Self::params();
        let mut jobs = inputs
            .map(|input| blake2b_simd::many::HashManyJob::new(&params, input))
            .collect::<Vec<_>>();

        blake2b_simd::many::hash_many(jobs.iter_mut());

        jobs.into_iter()
            .map(|job| Self::hash_to_sum(&job.to_hash()))
    }

    fn degree_of_many() -> Option<usize> {
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

    fn update(&mut self, input: &[u8]) {
        self.0.update(input);
    }
}
impl CryptoHash for Blake3Hash {}
