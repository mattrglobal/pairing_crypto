macro_rules! to_bytes {
    ($size:expr) => {
        pub fn to_bytes(&self) -> [u8; $size] {
            let mut d = [0u8; $size];
            self.0.serialize(&mut d.as_mut(), true).unwrap();
            d
        }
    };
}

macro_rules! from_secret {
    ($name:ident) => {
        impl From<&SecretKey> for $name {
            fn from(sk: &SecretKey) -> Self {
                let mut p = Self::default();
                p.0.mul_assign(sk.0);
                p
            }
        }
    };
}

macro_rules! default_impl {
    ($name:ident, $ty:ident) => {
        impl Default for $name {
            fn default() -> Self {
                Self($ty::zero())
            }
        }
    };
}

macro_rules! sum_impl {
    ($name:ident) => {
        impl std::iter::Sum<$name> for $name {
            fn sum<I: Iterator<Item = $name>>(mut iter: I) -> Self {
                let mut value = $name::default();
                while let Some(v) = iter.next() {
                    value.0.add_assign(&v.0);
                }
                value
            }
        }

        impl<'a> std::iter::Sum<&'a $name> for $name {
            fn sum<I: Iterator<Item = &'a $name>>(mut iter: I) -> Self {
                let mut value = $name::default();
                while let Some(v) = iter.next() {
                    value.0.add_assign(&v.0);
                }
                value
            }
        }
    };
}

macro_rules! from_impl {
    ($name:ident, $ty:ident, $size:expr) => {
        impl From<[u8; $size]> for $name {
            fn from(d: [u8; $size]) -> Self {
                let mut c = std::io::Cursor::new(d);
                Self($ty::deserialize(&mut c, true).unwrap())
            }
        }

        impl TryFrom<&[u8]> for $name {
            type Error = String;

            fn try_from(d: &[u8]) -> Result<Self, Self::Error> {
                let mut c = std::io::Cursor::new(d);
                Ok(Self($ty::deserialize(&mut c, true).map_err(|_| {
                    format!("invalid {} bytes", stringify!($name))
                })?))
            }
        }
    };
}

macro_rules! serial {
    ($name:ident, $ty:ident, $size:expr) => {
        impl serde::Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                use serde::ser::Error;
                let mut d = [0u8; $size];
                self.0.serialize(&mut d.as_mut(), true).map_err(|_| {
                    S::Error::custom(format!(
                        "an error occurred while serializing {}",
                        stringify!($name)
                    ))
                })?;
                d.serialize(serializer)
            }
        }
        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D>(
                deserializer: D,
            ) -> Result<Self, <D as serde::Deserializer<'de>>::Error>
            where
                D: serde::Deserializer<'de>,
            {
                let d = <[u8; $size]>::deserialize(deserializer)?;
                let mut c = std::io::Cursor::new(d);
                let p = $ty::deserialize(&mut c, true).map_err(|_| {
                    serde::de::Error::custom(format!("can't deserialize {}", stringify!($ty)))
                })?;
                Ok(Self(p))
            }
        }
    };
}
