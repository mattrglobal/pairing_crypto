package pairing_crypto;

public class Bbs {

    static {
        System.loadLibrary("pairing_crypto_jni");
    }

    private static native int bbs_bls12381_generate_key_pair(byte[] seed, byte[] keyInfo, byte[] public_key, byte[] secret_key);

    private static native String get_last_error();

    public static KeyPair generateKeyPair (byte[] ikm, byte[] keyInfo) throws Exception {
        byte[] public_key = new byte[KeyPair.BBS_BLS12381_PUBLIC_KEY_SIZE];
        byte[] secret_key = new byte[KeyPair.BBS_BLS12381_SECRET_KEY_SIZE];
        if (0 != bbs_bls12381_generate_key_pair(ikm, keyInfo, public_key, secret_key)) {
            throw new Exception("Unable to generate keys");
        }
        return new KeyPair(public_key, secret_key);
    }

}
