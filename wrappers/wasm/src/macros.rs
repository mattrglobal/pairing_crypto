// Copyright 2020
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
// ------------------------------------------------------------------------------
macro_rules! wasm_impl {
    (
     $name:ident,
     $($field:ident:$type:ty),*) => {
        #[allow(non_snake_case)]
        #[derive(Debug, Deserialize, Serialize)]
        /// Macro declaring struct name
        pub struct $name {
            $(
                /// Macro declaring field and type
                pub $field: $type,
            )*
        }

        try_from_impl!($name);
    };
}

macro_rules! try_from_impl {
    ($name:ident) => {
        impl core::convert::TryFrom<JsValue> for $name {
            type Error = serde_wasm_bindgen::Error;

            fn try_from(value: JsValue) -> Result<Self, Self::Error> {
                serde_wasm_bindgen::from_value::<$name>(value)
            }
        }
    };
}

macro_rules! vec_to_u8_sized_array {
    (
        $value:expr,
        $length:expr
    ) => {
        <[u8; $length]>::try_from($value).map_err(|_| {
            serde_wasm_bindgen::Error::new::<&str>(
                "vector to fixed-sized array conversion failed",
            )
        })?
    };
}
