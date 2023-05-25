use serde::Serialize;
use std::path::PathBuf;
use serde;

pub fn save_test_vector<T>(fixture: &T, output_file: &PathBuf)
where
    T: Serialize,
{
    std::fs::write(
        output_file,
        serde_json::to_string_pretty(&fixture).unwrap(),
    )
    .unwrap();
}

#[macro_export]
macro_rules! serialize_key_pair_impl {
    ($serialize_fn_name:ident, $key_pair_ty:ty) => {
        fn $serialize_fn_name<S>(
            key_pair: &$key_pair_ty,
            serializer: S
        ) -> Result<S::Ok, S::Error>
        where
            S: Serializer
        {
            let mut state = serializer.serialize_struct("KeyPair", 2)?;
            state.serialize_field(
                "secretKey",
                &hex::encode(key_pair.secret_key.to_bytes()),
            )?;
            state.serialize_field(
                "publicKey",
                &hex::encode(key_pair.public_key.to_octets()),
            )?;
            state.end()
        }
    };
}

#[macro_export]
macro_rules! deserialize_key_pair_impl {
    ($deserialize_fn_name:ident, $key_pair_ty:ident, $secret_key_ty:ty, $public_key_ty:ty) => {
        pub fn $deserialize_fn_name<'de, D>(
            deserializer: D,
        ) -> Result<$key_pair_ty, D::Error>
        where
            D: Deserializer<'de>,
        {
            #[derive(Deserialize)]
            #[serde(field_identifier, rename_all = "camelCase")]
            enum KeyPairField {
                SecretKey,
                PublicKey,
            }
        
            struct KeyPairVisitor;
            impl<'de> de::Visitor<'de> for KeyPairVisitor {
                type Value = $key_pair_ty;
        
                fn expecting(
                    &self,
                    formatter: &mut std::fmt::Formatter,
                ) -> std::fmt::Result {
                    formatter.write_str("struct KeyPair")
                }
        
                fn visit_map<V>(self, mut map: V) -> Result<$key_pair_ty, V::Error>
                where
                    V: MapAccess<'de>,
                {
                    macro_rules! check_duplicate_and_set_field {
                        ($value:ident) => {{
                            if $value.is_some() {
                                return Err(de::Error::duplicate_field("$value"));
                            }
                            $value = Some(map.next_value()?);
                        }};
                    }
                    let mut secret_key = None;
                    let mut public_key = None;
        
                    while let Some(key) = map.next_key()? {
                        match key {
                            KeyPairField::SecretKey => {
                                check_duplicate_and_set_field!(secret_key)
                            }
                            KeyPairField::PublicKey => {
                                check_duplicate_and_set_field!(public_key)
                            }
                        }
                    }
        
                    let secret_key: &str = secret_key
                        .ok_or_else(|| de::Error::missing_field("secretKey"))?;
                    let public_key: &str = public_key
                        .ok_or_else(|| de::Error::missing_field("publicKey"))?;
        
                    let secret_key =
                        <$secret_key_ty>::from_vec(&hex::decode(secret_key).unwrap()).unwrap();
                    let public_key =
                        <$public_key_ty>::from_vec(&hex::decode(public_key).unwrap()).unwrap();
        
                    Ok($key_pair_ty {
                        secret_key,
                        public_key,
                    })
                }
            }
            const FIELDS: &[&str] = &["secretKey", "publicKey"];
            deserializer.deserialize_struct("KeyPair", FIELDS, KeyPairVisitor)
        }
    };
}

pub use serialize_key_pair_impl;
pub use deserialize_key_pair_impl;