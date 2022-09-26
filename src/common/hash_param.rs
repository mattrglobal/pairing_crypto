use super::ciphersuite::CipherSuiteParameter;
use crate::curves::bls12_381::hash_to_curve::ExpandMessage;

pub(crate) trait ExpandMessageParameter: CipherSuiteParameter {
    type Expander: ExpandMessage;
}

pub(crate) mod constant;
pub(crate) mod h2c;
pub(crate) mod h2s;
