use group::Curve;

use crate::{
    bbs::{
        ciphersuites::BbsCiphersuiteParameters,
        core::generator::{
            memory_cached_generator::MemoryCachedGenerators,
            Generators,
        },
        interface::BbsInterfaceParameter,
    },
    Error,
};

pub(crate) fn create_generators<I>(
    count: usize,
    private_holder_binding: Option<bool>,
) -> Result<Vec<Vec<u8>>, Error>
where
    I: BbsInterfaceParameter,
{
    let mut result = Vec::new();
    let generators =
        MemoryCachedGenerators::<I>::new(count - 2, private_holder_binding)?;

    result.push(I::Ciphersuite::p1()?.to_affine().to_compressed().to_vec());
    result.push(generators.Q.to_affine().to_compressed().to_vec());
    result.extend(
        generators
            .message_generators_iter()
            .map(|g| g.to_affine().to_compressed().to_vec())
            .collect::<Vec<Vec<u8>>>(),
    );
    if result.len() != count {
        return Err(Error::CryptoOps {
            cause: "unexpected generators creation failure".to_owned(),
        });
    }

    Ok(result)
}
