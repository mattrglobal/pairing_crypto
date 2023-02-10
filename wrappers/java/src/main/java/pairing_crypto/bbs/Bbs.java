package pairing_crypto;

import java.util.HashSet;
import java.util.HashMap;

abstract class Bbs {
    abstract KeyPair generateKeyPair (byte[] ikm, byte[] keyInfo) throws Exception;
    abstract byte[] sign(byte[] secretKey, byte[] publicKey, byte[] header, byte[][] messages) throws Exception;
    abstract boolean verify(byte[] publicKey, byte[] header, byte[] signature, byte[][] messages) throws Exception;
    abstract byte[] createProof(byte[] publicKey, byte[] header, byte[] presentationHeader, byte[] signature, boolean verifySignature, HashSet<Integer> disclosedIndices, byte[][] messages) throws Exception;
    abstract boolean verifyProof(byte[] publicKey, byte[] header, byte[] presentationHeader, byte[] proof, HashMap<Integer, byte[]> messages) throws Exception;
}
