use core::fmt::Debug;

pub(crate) trait InterfaceParameter: Debug + Clone {
    const ID: InterfaceId;
}

pub(crate) enum InterfaceId {
    BbsH2gHm2s,
    BbsH2gHm2sNym,
}

impl InterfaceId {
    pub(crate) fn as_octets(&self) -> &[u8] {
        match &self {
            InterfaceId::BbsH2gHm2s => b"H2G_HM2S_",
            InterfaceId::BbsH2gHm2sNym => b"H2G_HM2S_PSEUDONYM_",
        }
    }
}
