macro_rules! set_byte_array_impl {
    ($name:ident,$static:expr,$property:ident) => {
        #[no_mangle]
        pub extern "C" fn $name(
            handle: u64,
            value: ByteArray,
            err: &mut ExternError,
        ) -> i32 {
            let value = value.to_vec();
            if value.is_empty() {
                *err = ExternError::new_error(
                    ErrorCode::new(1),
                    "value cannot be empty",
                );
                return 1;
            }
            $static.call_with_result_mut(
                err,
                handle,
                |ctx| -> Result<(), PairingCryptoFfiError> {
                    let v = value.to_vec();
                    ctx.$property = v;
                    Ok(())
                },
            );
            err.get_code().code()
        }
    };
}

macro_rules! add_byte_array_impl {
    (
     $name_bytes:ident,
     $static:expr,
     $property:ident
    ) => {
        #[no_mangle]
        pub extern "C" fn $name_bytes(
            handle: u64,
            value: ByteArray,
            err: &mut ExternError,
        ) -> i32 {
            let value = value.to_vec();
            if value.is_empty() {
                *err = ExternError::new_error(
                    ErrorCode::new(1),
                    "value cannot be empty",
                );
                return 1;
            }
            $static.call_with_output_mut(err, handle, |ctx| {
                ctx.$property.push(value);
            });
            err.get_code().code()
        }
    };
}
