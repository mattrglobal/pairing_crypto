package pairing_crypto;

public class Bbs {

    static {
        System.loadLibrary("pairing_crypto_jni");
    }

    private static native int bbs_bls12381_generate_key_pair(byte[] seed, byte[] keyInfo, byte[] public_key, byte[] secret_key);

    private static native long bbs_bls12381_sign_context_init();

    private static native int bbs_bls12381_sign_context_set_secret_key(long handle, byte[] secret_key);

    private static native int bbs_bls12381_sign_context_set_public_key(long handle, byte[] public_key);

    private static native int bbs_bls12381_sign_context_set_header(long handle, byte[] header);

    private static native int bbs_bls12381_sign_context_add_message(long handle, byte[] message);

    private static native int bbs_bls12381_sign_context_finish(long handle, byte[] signature);

    private static native long bbs_bls12381_verify_context_init();

    private static native int bbs_bls12381_verify_context_set_public_key(long handle, byte[] public_key);

    private static native int bbs_bls12381_verify_context_set_header(long handle, byte[] header);

    private static native int bbs_bls12381_verify_context_add_message(long handle, byte[] message);

    private static native int bbs_bls12381_verify_context_set_signature(long handle, byte[] signature);

    private static native int bbs_bls12381_verify_context_finish(long handle);

    private static native long bbs_bls12381_create_proof_context_init();

    private static native int bbs_bls12381_create_proof_context_set_public_key(long handle, byte[] public_key);

    private static native int bbs_bls12381_create_proof_context_set_header(long handle, byte[] header);

    private static native int bbs_bls12381_create_proof_context_set_signature(long handle, byte[] signature);

    private static native int bbs_bls12381_create_proof_context_set_presentation_message(long handle, byte[] presentation_message);

    private static native int bbs_bls12381_create_proof_context_add_proof_message_bytes(long handle, byte[] message, boolean reveal);

    private static native int bbs_bls12381_create_proof_context_finish(long handle, byte[] proof);

    private static native long bbs_bls12381_verify_proof_context_init();

    private static native int bbs_bls12381_verify_proof_context_set_public_key(long handle, byte[] public_key);

    private static native int bbs_bls12381_verify_proof_context_set_header(long handle, byte[] header);

    private static native int bbs_bls12381_verify_proof_context_set_proof(long handle, byte[] proof);

    private static native int bbs_bls12381_verify_proof_context_set_presentation_message(long handle, byte[] presentation_message);

    private static native int bbs_bls12381_verify_proof_context_set_total_message_count(long handle, int total_message_count);

    private static native int bbs_bls12381_verify_proof_context_add_message(long handle, int index, byte[] message);

    private static native int bbs_bls12381_verify_proof_context_finish(long handle);

    private static native String get_last_error();

    public static KeyPair generateBls12381KeyPair (byte[] ikm, byte[] keyInfo) throws Exception {
        byte[] public_key = new byte[KeyPair.BBS_BLS12381_PUBLIC_KEY_SIZE];
        byte[] secret_key = new byte[KeyPair.BBS_BLS12381_SECRET_KEY_SIZE];
        if (0 != bbs_bls12381_generate_key_pair(ikm, keyInfo, public_key, secret_key)) {
            throw new Exception("Unable to generate keys");
        }
        return new KeyPair(public_key, secret_key);
    }

}
