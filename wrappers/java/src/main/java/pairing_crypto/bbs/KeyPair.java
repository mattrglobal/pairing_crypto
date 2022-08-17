package pairing_crypto;

public class KeyPair {
    public byte[] secretKey;
    public byte[] publicKey;

    public KeyPair(byte[] publicKey, byte[] secretKey) {
        this.publicKey = publicKey;
        this.secretKey = secretKey;
    }
}
