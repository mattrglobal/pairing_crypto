use core::marker::PhantomData;
use digest::{
    generic_array::{typenum::Unsigned, GenericArray},
    BlockInput, Digest, ExtendableOutput, Update, XofReader,
};

/// Trait for types implementing expand_message interface for hash_to_field
pub trait ExpandMsg {
    /// Expands `msg` to the required number of bytes in `buf`
    fn expand_message(msg: &[u8], dst: &[u8], buf: &mut [u8]);
}

/// Placeholder type for implementing expand_message_xof based on a hash function
#[derive(Debug)]
pub struct ExpandMsgXof<HashT> {
    phantom: PhantomData<HashT>,
}

/// Placeholder type for implementing expand_message_xmd based on a hash function
#[derive(Debug)]
pub struct ExpandMsgXmd<HashT> {
    phantom: PhantomData<HashT>,
}

/// ExpandMsgXof implements expand_message_xof for the ExpandMsg trait
impl<HashT> ExpandMsg for ExpandMsgXof<HashT>
where
    HashT: Default + ExtendableOutput + Update,
{
    fn expand_message(msg: &[u8], dst: &[u8], buf: &mut [u8]) {
        let len_in_bytes = buf.len();
        let mut r = HashT::default()
            .chain(msg)
            .chain([(len_in_bytes >> 8) as u8, len_in_bytes as u8])
            .chain(dst)
            .chain([dst.len() as u8])
            .finalize_xof();
        r.read(buf);
    }
}

/// ExpandMsgXmd implements expand_message_xmd for the ExpandMsg trait
impl<HashT> ExpandMsg for ExpandMsgXmd<HashT>
where
    HashT: Digest + BlockInput,
{
    fn expand_message(msg: &[u8], dst: &[u8], buf: &mut [u8]) {
        let len_in_bytes = buf.len();
        let b_in_bytes = HashT::OutputSize::to_usize();
        let ell = (len_in_bytes + b_in_bytes - 1) / b_in_bytes;
        if ell > 255 {
            panic!("ell was too big in expand_message_xmd");
        }
        let b_0 = HashT::new()
            .chain(GenericArray::<u8, HashT::BlockSize>::default())
            .chain(msg)
            .chain([(len_in_bytes >> 8) as u8, len_in_bytes as u8, 0u8])
            .chain(dst)
            .chain([dst.len() as u8])
            .finalize();

        // 288 is the most bytes that will be drawn
        // G2 requires 128 * 2 for hash_to_curve
        // but if a 48 byte digest is used then
        // 48 * 6 = 288
        let mut b_vals = [0u8; 288];
        // b_1
        b_vals[..b_in_bytes].copy_from_slice(
            HashT::new()
                .chain(&b_0[..])
                .chain([1u8])
                .chain(dst)
                .chain([dst.len() as u8])
                .finalize()
                .as_ref(),
        );

        for i in 1..ell {
            // b_0 XOR b_(idx - 1)
            let mut tmp = GenericArray::<u8, HashT::OutputSize>::default();
            b_0.iter()
                .zip(&b_vals[(i - 1) * b_in_bytes..i * b_in_bytes])
                .enumerate()
                .for_each(|(j, (b0val, bi1val))| tmp[j] = b0val ^ bi1val);
            b_vals[i * b_in_bytes..(i + 1) * b_in_bytes].copy_from_slice(
                HashT::new()
                    .chain(tmp)
                    .chain([(i + 1) as u8])
                    .chain(dst)
                    .chain([dst.len() as u8])
                    .finalize()
                    .as_ref(),
            );
        }
        buf.copy_from_slice(&b_vals[..len_in_bytes]);
    }
}
