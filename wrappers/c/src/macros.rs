macro_rules! add_set_key_bytes_impl {
    ($name:ident,$static:expr,$property:ident,$type:ident) => {
        #[no_mangle]
        pub extern "C" fn $name(handle: u64, value: ByteArray, err: &mut ExternError) -> i32 {
            let value = value.to_vec();
            if value.is_empty() {
                *err = ExternError::new_error(
                    ErrorCode::new(1),
                    &format!("{} cannot be empty", stringify!($type)),
                );
                return 1;
            }
            $static.call_with_result_mut(err, handle, |ctx| -> Result<(), PairingCryptoFfiError> {
                let v = $type::from_vec(value.to_vec())?;
                ctx.$property = Some(v);
                Ok(())
            });
            err.get_code().code()
        }
    };
}

macro_rules! add_set_message_bytes_impl {
    (
     $name_bytes:ident,
     $static:expr
    ) => {
        #[no_mangle]
        pub extern "C" fn $name_bytes(
            handle: u64,
            message: ByteArray,
            err: &mut ExternError,
        ) -> i32 {
            let message = message.to_vec();
            if message.is_empty() {
                *err = ExternError::new_error(ErrorCode::new(1), "Message cannot be empty");
                return 1;
            }
            $static.call_with_output_mut(err, handle, |ctx| {
                ctx.messages.push(Message::hash(message));
            });
            err.get_code().code()
        }
    };
}
