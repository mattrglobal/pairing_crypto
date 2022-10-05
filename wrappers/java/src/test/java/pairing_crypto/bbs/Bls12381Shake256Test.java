package pairing_crypto;

import java.util.HashSet;
import java.util.Arrays;
import java.util.HashMap;

import org.junit.Test;
import static org.junit.Assert.*;

public class Bls12381Shake256Test {
       
    private void shouldThrowExceptionMessageWhenFailToGenerateKeyPairHelper(Bbs bbs) {
        byte[] ikm = null;
        byte[] keyInfo = null;

        try {
            bbs.generateKeyPair(ikm, keyInfo);
            fail("Expected an exception to be thrown");
        } catch (Exception exception) {
            assertEquals("Unable to generate keys", exception.getMessage());
        }
    }

    private void canGenerateKeyPairHelper(Bbs bbs) {
        byte[] ikm = new byte[32];
        byte[] keyInfo = new byte[10];
        KeyPair keyPair = null;

        try {
            keyPair = bbs.generateKeyPair(ikm, keyInfo);
        } catch (Exception exception) {
            exception.printStackTrace();
        }

        assertNotNull(keyPair);
        assertEquals(Bls12381Shake256.PUBLIC_KEY_SIZE, keyPair.publicKey.length);
        assertEquals(Bls12381Shake256.SECRET_KEY_SIZE, keyPair.secretKey.length);
    }

    private void canSignVerifyMessageHelper(Bbs bbs) {
        byte[] ikm = new byte[32];
        byte[] keyInfo = new byte[10];
        KeyPair keyPair = null;

        try {
            keyPair = bbs.generateKeyPair(ikm, keyInfo);
        } catch (Exception exception) {
            exception.printStackTrace();
        }

        byte[] header = "test-header".getBytes();

        byte[][] messages = {
                "message1".getBytes(),
                "message2".getBytes(),
                "message3".getBytes(),
        };
        byte[] secretKey = keyPair.secretKey;
        byte[] publicKey = keyPair.publicKey;

        byte[] signature = new byte[Bls12381Shake256.SIGNATURE_SIZE];

        try {
            signature = bbs.sign(keyPair.secretKey, keyPair.publicKey, header, messages);
        } catch (Exception exception) {
            exception.printStackTrace();
        }

        assertNotNull(signature);

        boolean isVerified = false;

        try {
            isVerified = bbs.verify(publicKey, header, signature, messages);
        } catch (Exception exception) {
            exception.printStackTrace();
        }

        assertTrue(isVerified);
    }

    private void signatureVerifyNegativeTestsHelper(Bbs bbs) {
        byte[] ikm = "some-truely-random-key-material-32-bytes-long".getBytes();
        byte[] keyInfo1 = "test-key-info-1".getBytes();
        byte[] keyInfo2 = "test-key-info-2".getBytes();
        KeyPair keyPair1 = null;
        KeyPair keyPair2 = null;
        byte[] header1 = "test-header1".getBytes();
        byte[] header2 = "test-header2".getBytes();
        byte[][] messages1 = {
                "message1".getBytes(),
                "message2".getBytes(),
                "message3".getBytes(),
        };
        boolean isVerified = false;
        byte[] signature1 = new byte[Bls12381Shake256.SIGNATURE_SIZE];

        // generate key-pairs
        try {
            keyPair1 = bbs.generateKeyPair(ikm, keyInfo1);
        } catch (Exception exception) {
            exception.printStackTrace();
        }
        try {
            keyPair2 = bbs.generateKeyPair(ikm, keyInfo2);
        } catch (Exception exception) {
            exception.printStackTrace();
        }

        // generate signature
        try {
            signature1 = bbs.sign(keyPair1.secretKey, keyPair1.publicKey, header1, messages1);
        } catch (Exception exception) {
            exception.printStackTrace();
        }
        assertNotNull(signature1);

        // verify signature
        try {
            isVerified = bbs.verify(keyPair1.publicKey, header1, signature1, messages1);
        } catch (Exception exception) {
            exception.printStackTrace();
        }
        assertTrue(isVerified);

        // verify signature - wrong public key
        try {
            isVerified = bbs.verify(keyPair2.publicKey, header1, signature1, messages1);
        } catch (Exception exception) {
            exception.printStackTrace();
        }
        assertFalse(isVerified);

        // verify signature - wrong header
        try {
            isVerified = bbs.verify(keyPair1.publicKey, header2, signature1, messages1);
        } catch (Exception exception) {
            exception.printStackTrace();
        }
        assertFalse(isVerified);

        // verify signature - tampered signature
        byte[] signature2 = signature1;
        signature2[Bls12381Shake256.SIGNATURE_SIZE-1] += 1;
        try {
            isVerified = bbs.verify(keyPair1.publicKey, header1, signature2, messages1);
        } catch (Exception exception) {
            exception.printStackTrace();
        }
        assertFalse(isVerified);

        // verify signature - wrong messages
        messages1[0] = "tampered-message".getBytes();
        try {
            isVerified = bbs.verify(keyPair1.publicKey, header1, signature1, messages1);
        } catch (Exception exception) {
            exception.printStackTrace();
        }
        assertFalse(isVerified);
    }

    private void canCreateVerifyProofHelper(Bbs bbs) {
        byte[] ikm = new byte[32];
        byte[] keyInfo = new byte[10];
        KeyPair keyPair = null;

        try {
            keyPair = bbs.generateKeyPair(ikm, keyInfo);
        } catch (Exception exception) {
            exception.printStackTrace();
        }

        byte[] header = "test-header".getBytes();

        byte[][] messages = {
                "message1".getBytes(),
                "message2".getBytes(),
                "message3".getBytes(),
        };
        byte[] secretKey = keyPair.secretKey;
        byte[] publicKey = keyPair.publicKey;

        byte[] signature = new byte[Bls12381Shake256.SIGNATURE_SIZE];

        try {
            signature = bbs.sign(secretKey, publicKey, header, messages);
        } catch (Exception exception) {
            exception.printStackTrace();
        }

        assertNotNull(signature);

        boolean isVerified = false;

        try {
            isVerified = bbs.verify(publicKey, header, signature, messages);
        } catch (Exception exception) {
            exception.printStackTrace();
        }

        assertTrue(isVerified);

        // All disclosed messages
        byte[] presentationHeader = "test-presentation-header".getBytes();
        HashSet<Integer> allDisclosedIndices = new HashSet(Arrays.asList(0, 1, 2));
        byte[] proof = new byte[0];
        try {
            proof = bbs.createProof(publicKey, header, presentationHeader, signature, false, allDisclosedIndices, messages);
        } catch (Exception exception) {
            exception.printStackTrace();
        }
        assertNotNull(proof);
        HashMap<Integer, byte[]> allDisclosedMessages = new HashMap<Integer, byte[]>();
        allDisclosedMessages.put(0, messages[0]);
        allDisclosedMessages.put(1, messages[1]);
        allDisclosedMessages.put(2, messages[2]);
        try {
            isVerified = bbs.verifyProof(publicKey, header, presentationHeader, proof, messages.length, allDisclosedMessages);
        } catch (Exception exception) {
            exception.printStackTrace();
        }
        assertTrue(isVerified);

        // Few disclosed messages
        HashSet<Integer> fewDisclosedIndices = new HashSet(Arrays.asList(1));
        HashMap<Integer, byte[]> fewDisclosedMessages = new HashMap<Integer, byte[]>();
        fewDisclosedMessages.put(1, messages[1]);
        try {
            proof = bbs.createProof(publicKey, header, presentationHeader, signature, false, fewDisclosedIndices, messages);
        } catch (Exception exception) {
            exception.printStackTrace();
        }
        assertNotNull(proof);
        try {
            isVerified = bbs.verifyProof(publicKey, header, presentationHeader, proof, messages.length, fewDisclosedMessages);
        } catch (Exception exception) {
            exception.printStackTrace();
        }
        assertTrue(isVerified);
    }


    private void proofVerifyNegativeTestsHelper(Bbs bbs) {
              byte[] ikm = "some-truely-random-key-material-32-bytes-long".getBytes();
        byte[] keyInfo1 = "test-key-info-1".getBytes();
        byte[] keyInfo2 = "test-key-info-2".getBytes();
        KeyPair keyPair1 = null;
        KeyPair keyPair2 = null;
        byte[] header1 = "test-header1".getBytes();
        byte[] header2 = "test-header2".getBytes();
        byte[] presentationHeader1 = "test-presentation-header1".getBytes();
        byte[] presentationHeader2 = "test-presentation-header2".getBytes();
        byte[][] messages1 = {
                "message1".getBytes(),
                "message2".getBytes(),
                "message3".getBytes(),
        };
        boolean isVerified = false;
        byte[] signature1 = new byte[Bls12381Shake256.SIGNATURE_SIZE];
        byte[] proof1 = new byte[0];
        HashMap<Integer, byte[]> tamperedDisclosedMessages = new HashMap<Integer, byte[]>();

        // generate key-pairs
        try {
            keyPair1 = bbs.generateKeyPair(ikm, keyInfo1);
        } catch (Exception exception) {
            exception.printStackTrace();
        }
        try {
            keyPair2 = bbs.generateKeyPair(ikm, keyInfo2);
        } catch (Exception exception) {
            exception.printStackTrace();
        }

        // generate signature
        try {
            signature1 = bbs.sign(keyPair1.secretKey, keyPair1.publicKey, header1, messages1);
        } catch (Exception exception) {
            exception.printStackTrace();
        }
        assertNotNull(signature1);

        // verify signature
        try {
            isVerified = bbs.verify(keyPair1.publicKey, header1, signature1, messages1);
        } catch (Exception exception) {
            exception.printStackTrace();
        }
        assertTrue(isVerified);

        // generate proof for all disclosed messages
        HashSet<Integer> allDisclosedIndices = new HashSet(Arrays.asList(0, 1, 2));
        try {
            proof1 = bbs.createProof(keyPair1.publicKey, header1, presentationHeader1, signature1, false, allDisclosedIndices, messages1);
        } catch (Exception exception) {
            exception.printStackTrace();
        }
        assertNotNull(proof1);

        // verify proof
        HashMap<Integer, byte[]> allDisclosedMessages = new HashMap<Integer, byte[]>();
        allDisclosedMessages.put(0, messages1[0]);
        allDisclosedMessages.put(1, messages1[1]);
        allDisclosedMessages.put(2, messages1[2]);
        try {
            isVerified = bbs.verifyProof(keyPair1.publicKey, header1, presentationHeader1, proof1, messages1.length, allDisclosedMessages);
        } catch (Exception exception) {
            exception.printStackTrace();
        }
        assertTrue(isVerified);

        // verify proof - wrong public key
        try {
            isVerified = bbs.verifyProof(keyPair2.publicKey, header1, presentationHeader1, proof1, messages1.length, allDisclosedMessages);
        } catch (Exception exception) {
            exception.printStackTrace();
        }
        assertFalse(isVerified);

        // verify proof - wrong header
        try {
            isVerified = bbs.verifyProof(keyPair1.publicKey, header2, presentationHeader1, proof1, messages1.length, allDisclosedMessages);
        } catch (Exception exception) {
            exception.printStackTrace();
        }
        assertFalse(isVerified);

        // verify proof - wrong presentation header
        try {
            isVerified = bbs.verifyProof(keyPair1.publicKey, header1, presentationHeader2, proof1, messages1.length, allDisclosedMessages);
        } catch (Exception exception) {
            exception.printStackTrace();
        }
        assertFalse(isVerified);

        // verify proof - wrong proof data
        byte[] proof2 = proof1;
        proof2[proof2.length - 1] += 1;
        try {
            isVerified = bbs.verifyProof(keyPair1.publicKey, header1, presentationHeader1, proof2, messages1.length, allDisclosedMessages);
        } catch (Exception exception) {
            exception.printStackTrace();
        }
        assertFalse(isVerified);

        // verify proof - wrong message-list length
        try {
            isVerified = bbs.verifyProof(keyPair1.publicKey, header1, presentationHeader1, proof1, messages1.length - 1, allDisclosedMessages);
        } catch (Exception exception) {
            exception.printStackTrace();
        }
        assertFalse(isVerified);

        // verify proof - tampered message
        tamperedDisclosedMessages = allDisclosedMessages;
        tamperedDisclosedMessages.put(0, "wrong-message".getBytes());
        try {
            isVerified = bbs.verifyProof(keyPair1.publicKey, header1, presentationHeader1, proof1, messages1.length, tamperedDisclosedMessages);
        } catch (Exception exception) {
            exception.printStackTrace();
        }
        assertFalse(isVerified);

        // verify proof - original messages at wrong indices
        tamperedDisclosedMessages.put(0, messages1[1]);
        tamperedDisclosedMessages.put(1, messages1[2]);
        tamperedDisclosedMessages.put(2, messages1[0]);
        try {
            isVerified = bbs.verifyProof(keyPair1.publicKey, header1, presentationHeader1, proof1, messages1.length, tamperedDisclosedMessages);
        } catch (Exception exception) {
            exception.printStackTrace();
        }
        assertFalse(isVerified);

        // verify proof - more disclosed messages than original
        tamperedDisclosedMessages.put(0, messages1[0]);
        tamperedDisclosedMessages.put(1, messages1[1]);
        tamperedDisclosedMessages.put(2, messages1[2]);
        tamperedDisclosedMessages.put(3, "message4".getBytes());
        try {
            isVerified = bbs.verifyProof(keyPair1.publicKey, header1, presentationHeader1, proof1, messages1.length, tamperedDisclosedMessages);
        } catch (Exception exception) {
            exception.printStackTrace();
        }
        assertFalse(isVerified);
    }

    @Test
    public void shouldThrowExceptionMessageWhenFailToGenerateKeyPair() {
        shouldThrowExceptionMessageWhenFailToGenerateKeyPairHelper(new Bls12381Sha256());
        shouldThrowExceptionMessageWhenFailToGenerateKeyPairHelper(new Bls12381Shake256());
    }

    @Test
    public void canGenerateKeyPair() {
        canGenerateKeyPairHelper(new Bls12381Sha256());
        canGenerateKeyPairHelper(new Bls12381Shake256());
    }

    @Test
    public void canSignVerifyMessage() {
        canSignVerifyMessageHelper(new Bls12381Sha256());
        canSignVerifyMessageHelper(new Bls12381Shake256());
    }

        @Test
    public void signatureVerifyNegativeTests() {
        signatureVerifyNegativeTestsHelper(new Bls12381Sha256());
        signatureVerifyNegativeTestsHelper(new Bls12381Shake256());
    }

    @Test
    public void canCreateVerifyProof() {
        canCreateVerifyProofHelper(new Bls12381Sha256());
        canCreateVerifyProofHelper(new Bls12381Shake256());
    }

        @Test
    public void proofVerifyNegativeTests() {
        proofVerifyNegativeTestsHelper(new Bls12381Sha256());
        proofVerifyNegativeTestsHelper(new Bls12381Shake256());
    }
}
