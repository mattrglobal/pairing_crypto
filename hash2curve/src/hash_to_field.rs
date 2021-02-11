//! Implements hash_to_field and related hashing primitives

use digest::{Digest, ExtendableOutput, Update, generic_array::{GenericArray, ArrayLength, typenum:: Unsigned}, XofReader, BlockInput};
use std::marker::PhantomData;

pub fn hash_to_field<T, X, O>(msg: &[u8], dst: &[u8]) -> GenericArray<T, O>
where
    T: FromRO + Default,
    X: ExpandMsg,
    O: ArrayLength<T> {

    let len_per_elm = <T as FromRO>::Length::to_usize();
    let len_in_bytes = O::to_usize() * len_per_elm;
    let random_bytes = X::expand_message(msg, dst, len_in_bytes);

    let mut out = GenericArray::<T, O>::default();
    for i in 0..O::to_usize() {
        let bytes_to_convert = &random_bytes[i * len_per_elm..(i+1) * len_per_elm];
        let bytes_arr = GenericArray::<u8, <T as FromRO>::Length>::from_slice(bytes_to_convert);
        out[i] = T::from_ro(bytes_arr);
    }
    out
}

/// Generate a field element from a random string of bytes
pub trait FromRO {
    type Length: ArrayLength<u8>;

    fn from_ro(okm: &GenericArray<u8, <Self as FromRO>::Length>) -> Self;
}

impl<T: BaseFromRO> FromRO for T {
    type Length = <T as BaseFromRO>::BaseLength;

    fn from_ro(okm: &GenericArray<u8, <Self as FromRO>::Length>) -> T { T::from_okm(okm) }
}

/// Generate an element of a base field for a random string of bytes
/// (used by FromRO for extension fields).
pub trait BaseFromRO {
    type BaseLength: ArrayLength<u8>;

    fn from_okm(okm: &GenericArray<u8, <Self as BaseFromRO>::BaseLength>) -> Self;
}

/// For types implementing expand_message of hash_to_field
pub trait ExpandMsg {
    fn expand_message(msg: &[u8], dst: &[u8], len_in_bytes: usize) -> Vec<u8>;
}

/// Placeholder type for implementing expand_message_xof for ExpandMsg trait
#[derive(Debug)]
pub struct ExpandMsgXof<HashT> {
    phantom: PhantomData<HashT>,
}

impl<HashT> ExpandMsg for ExpandMsgXof<HashT>
where HashT: Default + ExtendableOutput + Update
{
    fn expand_message(msg: &[u8], dst: &[u8], len_in_bytes: usize) -> Vec<u8> {
        let mut out = vec![0u8; len_in_bytes];
        let mut reader = HashT::default()
            .chain(msg)
            .chain([(len_in_bytes >> 8) as u8, len_in_bytes as u8])
            .chain(dst)
            .chain([dst.len() as u8])
            .finalize_xof();
        reader.read(out.as_mut_slice());
        out
    }
}

/// Placeholder type for implementing expand_message_xmd based
#[derive(Debug)]
pub struct ExpandMsgXmd<HashT> {
    phandom: PhantomData<HashT>
}

impl<HashT> ExpandMsg for ExpandMsgXmd<HashT>
where HashT: Digest + BlockInput {
    fn expand_message(msg: &[u8], dst: &[u8], len_in_bytes: usize) -> Vec<u8> {
        let b_in_bytes = <HashT as Digest>::OutputSize::to_usize();
        let ell = (len_in_bytes + b_in_bytes - 1) / b_in_bytes;

        if ell > 255 {
            panic!("ell is too big in expand_message_xmd");
        }

        let b_0 = HashT::new()
            .chain(GenericArray::<u8, <HashT as BlockInput>::BlockSize>::default())
            .chain(msg)
            .chain([(len_in_bytes >> 8) as u8, len_in_bytes as u8, 0u8])
            .chain(dst)
            .chain([dst.len() as u8])
            .finalize();

        let mut b_vals = Vec::<u8>::with_capacity(ell * len_in_bytes);
        b_vals.extend_from_slice(HashT::new()
            .chain(b_0.as_slice())
            .chain([1u8])
            .chain(dst)
            .chain([dst.len() as u8])
            .finalize()
            .as_slice());

        for i in 1..ell {
            let mut tmp = GenericArray::<u8, <HashT as Digest>::OutputSize>::default();
            b_0.iter().zip(&b_vals[(i - 1) * b_in_bytes..i * b_in_bytes])
                .enumerate()
                .for_each(|(j, (b0val, b1val))| tmp[j] = b0val ^ b1val);
            b_vals.extend_from_slice(HashT::new()
                .chain(tmp)
                .chain([(i + 1) as u8])
                .chain(dst)
                .chain([dst.len() as u8])
                .finalize()
                .as_slice());
        }

        b_vals.truncate(len_in_bytes);
        b_vals
    }
}