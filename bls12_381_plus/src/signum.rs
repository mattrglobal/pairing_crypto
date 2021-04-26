use core::ops::BitXor;

/// Result of sgn0
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Sgn0Result {
    /// Either 0 or positive
    NonNegative,
    /// Neither 0 or positive
    Negative,
}

impl Sgn0Result {
    pub const fn as_u8(&self) -> u8 {
        match *self {
            Self::Negative => 1,
            Self::NonNegative => 0,
        }
    }
}

impl BitXor for Sgn0Result {
    type Output = Self;
    fn bitxor(self, rhs: Self) -> Self {
        if self == rhs {
            Self::NonNegative
        } else {
            Self::Negative
        }
    }
}
