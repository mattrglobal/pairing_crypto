pub(crate) mod constant;
mod h2s_param;
mod h2s_util;

pub(crate) use h2s_param::HashToScalarParameter;
pub(crate) use h2s_util::{
    create_random_scalar,
    do_hash_to_scalar,
    map_message_to_scalar_as_hash,
};
