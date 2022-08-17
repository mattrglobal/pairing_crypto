package pairing_crypto;

import java.util.HashSet;
import java.util.Map;
import java.util.HashMap;

public class Bbs {


    public static final int BBS_BLS12381_SECRET_KEY_SIZE = 32;
    public static final int BBS_BLS12381_PUBLIC_KEY_SIZE = 96;
    public static final int BBS_BLS12381_SIGNATURE_SIZE = 112;

    static {
        System.loadLibrary("pairing_crypto_jni");
    }

    private static native int bbs_bls12381_shake256_generate_key_pair(byte[] seed, byte[] keyInfo, byte[] public_key, byte[] secret_key);

    private static native long bbs_bls12381_shake256_sign_context_init();

    private static native int bbs_bls12381_shake256_sign_context_set_secret_key(long handle, byte[] secret_key);

    private static native int bbs_bls12381_shake256_sign_context_set_public_key(long handle, byte[] public_key);

    private static native int bbs_bls12381_shake256_sign_context_set_header(long handle, byte[] header);

    private static native int bbs_bls12381_shake256_sign_context_add_message(long handle, byte[] message);

    private static native int bbs_bls12381_shake256_sign_context_finish(long handle, byte[] signature);

    private static native long bbs_bls12381_shake256_verify_context_init();

    private static native int bbs_bls12381_shake256_verify_context_set_public_key(long handle, byte[] public_key);

    private static native int bbs_bls12381_shake256_verify_context_set_header(long handle, byte[] header);

    private static native int bbs_bls12381_shake256_verify_context_add_message(long handle, byte[] message);

    private static native int bbs_bls12381_shake256_verify_context_set_signature(long handle, byte[] signature);

    private static native int bbs_bls12381_shake256_verify_context_finish(long handle);

    private static native int bbs_bls12381_shake256_get_proof_size(int numberOfUndisclosedMessages);

    private static native long bbs_bls12381_shake256_proof_gen_context_init();

    private static native int bbs_bls12381_shake256_proof_gen_context_set_public_key(long handle, byte[] public_key);

    private static native int bbs_bls12381_shake256_proof_gen_context_set_header(long handle, byte[] header);

    private static native int bbs_bls12381_shake256_proof_gen_context_set_signature(long handle, byte[] signature);

    private static native int bbs_bls12381_shake256_proof_gen_context_set_presentation_message(long handle, byte[] presentation_message);

    private static native int bbs_bls12381_shake256_proof_gen_context_add_message(long handle, boolean reveal, byte[] message);

    private static native int bbs_bls12381_shake256_proof_gen_context_finish(long handle, byte[] proof);

    private static native long bbs_bls12381_shake256_proof_verify_context_init();

    private static native int bbs_bls12381_shake256_proof_verify_context_set_public_key(long handle, byte[] public_key);

    private static native int bbs_bls12381_shake256_proof_verify_context_set_header(long handle, byte[] header);

    private static native int bbs_bls12381_shake256_proof_verify_context_set_proof(long handle, byte[] proof);

    private static native int bbs_bls12381_shake256_proof_verify_context_set_presentation_message(long handle, byte[] presentation_message);

    private static native int bbs_bls12381_shake256_proof_verify_context_set_total_message_count(long handle, int total_message_count);

    private static native int bbs_bls12381_shake256_proof_verify_context_add_message(long handle, int index, byte[] message);

    private static native int bbs_bls12381_shake256_proof_verify_context_finish(long handle);

    private static native String get_last_error();

    public static KeyPair generateBls12381KeyPair (byte[] ikm, byte[] keyInfo) throws Exception {
        byte[] publicKey = new byte[BBS_BLS12381_PUBLIC_KEY_SIZE];
        byte[] secretKey = new byte[BBS_BLS12381_SECRET_KEY_SIZE];
        if (0 != bbs_bls12381_shake256_generate_key_pair(ikm, keyInfo, publicKey, secretKey)) {
            throw new Exception("Unable to generate keys");
        }
        return new KeyPair(publicKey, secretKey);
    }
    
    public static byte[] sign(byte[] secretKey, byte[] publicKey, byte[] header, byte[][] messages) throws Exception {
        long handle = bbs_bls12381_shake256_sign_context_init();
        if (0 == handle) {
            throw new Exception("Unable to create signing context");
        }
        if (0 != bbs_bls12381_shake256_sign_context_set_secret_key(handle, secretKey)) {
            throw new Exception("Unable to set secret key");
        }
        if (0 != bbs_bls12381_shake256_sign_context_set_public_key(handle, publicKey)) {
            throw new Exception("Unable to set public key");
        }
        if (0 != bbs_bls12381_shake256_sign_context_set_header(handle, header)) {
            throw new Exception("Unable to set header");
        }
        for (byte[] message : messages) {
            if (0 != bbs_bls12381_shake256_sign_context_add_message(handle, message)) {
                throw new Exception("Unable to add message");
            }
        }
        byte[] signature = new byte[BBS_BLS12381_SIGNATURE_SIZE];
        if (0 != bbs_bls12381_shake256_sign_context_finish(handle, signature)) {
            throw new Exception("Unable to create signature");
        }
        return signature;
    }

    public static boolean verify(byte[] publicKey, byte[] header, byte[] signature, byte[][] messages) throws Exception {
        long handle = bbs_bls12381_shake256_verify_context_init();
        if (0 == handle) {
            throw new Exception("Unable to create verify signature context");
        }
        if (0 != bbs_bls12381_shake256_verify_context_set_public_key(handle, publicKey)) {
            throw new Exception("Unable to set public key");
        }
        if (0 != bbs_bls12381_shake256_verify_context_set_header(handle, header)) {
            throw new Exception("Unable to set header");
        }
        if (0 != bbs_bls12381_shake256_verify_context_set_signature(handle, signature)) {
            throw new Exception("Unable to set signature");
        }
        for (byte[] message : messages) {
            if (0 != bbs_bls12381_shake256_verify_context_add_message(handle, message)) {
                throw new Exception("Unable to add message");
            }
        }
        int res = bbs_bls12381_shake256_verify_context_finish(handle);

        switch (res) {
            case 0:
                return true;
            case 1:
                return false;
            default:
                throw new Exception("Unable to verify signature");
        }
    }

    public static byte[] createProof(byte[] publicKey, byte[] header, byte[] presentationMessage, byte[] signature, HashSet<Integer> disclosedIndices, byte[][] messages) throws Exception {
        int numberOfUndisclosedMessages = 0;
        long handle = bbs_bls12381_shake256_proof_gen_context_init();
        if (0 == handle) {
            throw new Exception("Unable to create proof context");
        }
        if (0 != bbs_bls12381_shake256_proof_gen_context_set_public_key(handle, publicKey)) {
            throw new Exception("Unable to set public key");
        }
        if (0 != bbs_bls12381_shake256_proof_gen_context_set_header(handle, header)) {
            throw new Exception("Unable to set header");
        }
        if (0 != bbs_bls12381_shake256_proof_gen_context_set_presentation_message(handle, presentationMessage)) {
            throw new Exception("Unable to set presentation message");
        }
        if (0 != bbs_bls12381_shake256_proof_gen_context_set_signature(handle, signature)) {
            throw new Exception("Unable to set signature: " + get_last_error());
        }
        int i = 0;
        for (byte[] message : messages) {
            boolean reveal = false;
            if (disclosedIndices.contains(i)) {
                reveal = true;
            } else {
                numberOfUndisclosedMessages++;
                reveal = false;
            }
            if (0 != bbs_bls12381_shake256_proof_gen_context_add_message(handle, reveal, message)) {
                throw new Exception("Unable to add message");
            }
            i++;
        }
        int proofSize = bbs_bls12381_shake256_get_proof_size(numberOfUndisclosedMessages);
        if (proofSize <= 0) {
            throw new Exception("Unable to get proof size");
        }
        byte[] proof = new byte[proofSize];
        if (0 != bbs_bls12381_shake256_proof_gen_context_finish(handle, proof)) {
            throw new Exception("Unable to create proof");
        }
        return proof;
    }

    public static boolean verifyProof(byte[] publicKey, byte[] header, byte[] presentationMessage, byte[] proof, Integer totalMessageCount, HashMap<Integer, byte[]> messages) throws Exception {
        long handle = bbs_bls12381_shake256_proof_verify_context_init();
        if (0 == handle) {
            throw new Exception("Unable to create verify signature context");
        }
        if (0 != bbs_bls12381_shake256_proof_verify_context_set_public_key(handle, publicKey)) {
            throw new Exception("Unable to set public key");
        }
        if (0 != bbs_bls12381_shake256_proof_verify_context_set_header(handle, header)) {
            throw new Exception("Unable to set header");
        }
        if (0 != bbs_bls12381_shake256_proof_verify_context_set_presentation_message(handle, presentationMessage)) {
            throw new Exception("Unable to set presentation message");
        }
        if (0 != bbs_bls12381_shake256_proof_verify_context_set_proof(handle, proof)) {
            throw new Exception("Unable to set proof");
        }
        if (0 != bbs_bls12381_shake256_proof_verify_context_set_total_message_count(handle, totalMessageCount)) {
            throw new Exception("Unable to set total-message-count");
        }
        for (Map.Entry<Integer, byte[]> message : messages.entrySet()) {
            if (0 != bbs_bls12381_shake256_proof_verify_context_add_message(handle, message.getKey(), message.getValue())) {
                throw new Exception("Unable to add message");
            }
        }
        int res = bbs_bls12381_shake256_proof_verify_context_finish(handle);

        switch (res) {
            case 0:
                return true;
            case 1:
                return false;
            default:
                throw new Exception("Unable to verify proof");
        }
    }
}
