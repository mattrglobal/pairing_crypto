package pairing_crypto;

public class KeyPair {
    public byte[] secretKey;
    public byte[] publicKey;

    public KeyPair(byte[] publicKey, byte[] secretKey) {
        this.publicKey = publicKey;
        this.secretKey = secretKey;
    }

    public static final int BBS_BLS12381_SECRET_KEY_SIZE = 32;
    public static final int BBS_BLS12381_PUBLIC_KEY_SIZE = 96;
}
