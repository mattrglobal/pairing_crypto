use group::Curve;

use crate::{
    bbs::{
        ciphersuites::BbsCiphersuiteParameters,
        core::generator::{
            memory_cached_generator::MemoryCachedGenerators,
            Generators,
        },
    },
    Error,
};

pub(crate) fn create_generators<C>(
    count: usize,
    extension_count: usize,
) -> Result<Vec<Vec<u8>>, Error>
where
    C: BbsCiphersuiteParameters,
{
    let mut result = Vec::new();
    let mut generators =
        MemoryCachedGenerators::<C>::new(count, extension_count)?;
    result.push(generators.Q_1.to_affine().to_compressed().to_vec());
    result.push(generators.Q_2.to_affine().to_compressed().to_vec());
    for i in 0..count - 2 {
        match generators.get_message_generator(i) {
            Some(g) => result.push(g.to_affine().to_compressed().to_vec()),
            _ => {
                return Err(Error::CryptoOps {
                    cause: "unexpected generator `None` value".to_owned(),
                })
            }
        }
    }
    Ok(result)
}
