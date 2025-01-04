use std::marker::PhantomData;

use tokio_util::{
    bytes::BytesMut,
    codec::{Decoder, Encoder},
};

pub trait Codec<I, O, E>:
    Encoder<I, Error = E> + Decoder<Item = O, Error = E>
{
    fn encoder_degree(&self) -> Option<usize> {
        None
    }
}

pub struct DynCodec<T, I, O, E>(T, PhantomData<(I, O, E)>)
where
    E: From<std::io::Error>;

impl<T, I, O, E> DynCodec<T, I, O, E>
where
    E: From<std::io::Error>,
{
    pub fn new(inner: T) -> Self {
        Self(inner, PhantomData)
    }
}

impl<T, I, O, E> Encoder<I> for DynCodec<T, I, O, E>
where
    T: AsMut<dyn Codec<I, O, E>>,
    E: From<std::io::Error>,
{
    type Error = E;

    fn encode(&mut self, item: I, dst: &mut BytesMut) -> Result<(), Self::Error> {
        self.0.as_mut().encode(item, dst)
    }
}

impl<T, I, O, E> Decoder for DynCodec<T, I, O, E>
where
    T: AsMut<dyn Codec<I, O, E>>,
    E: From<std::io::Error>,
{
    type Item = O;
    type Error = E;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        self.0.as_mut().decode(src)
    }

    fn decode_eof(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        self.0.as_mut().decode_eof(buf)
    }
}

impl<T, I, O, E> Codec<I, O, E> for DynCodec<T, I, O, E>
where
    T: AsMut<dyn Codec<I, O, E>> + AsRef<dyn Codec<I, O, E>>,
    E: From<std::io::Error>,
{
    fn encoder_degree(&self) -> Option<usize> {
        self.0.as_ref().encoder_degree()
    }
}
