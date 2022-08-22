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
        byte[] presentation_header = "test-presentation-header".getBytes();
        HashSet<Integer> allDisclosedIndices = new HashSet(Arrays.asList(0, 1, 2));
        byte[] proof = new byte[0];
        try {
            proof = bbs.createProof(publicKey, header, presentation_header, signature, allDisclosedIndices, messages);
        } catch (Exception exception) {
            exception.printStackTrace();
        }
        assertNotNull(proof);
        HashMap<Integer, byte[]> allDisclosedMessages = new HashMap<Integer, byte[]>();
        allDisclosedMessages.put(0, messages[0]);
        allDisclosedMessages.put(1, messages[1]);
        allDisclosedMessages.put(2, messages[2]);
        try {
            isVerified = bbs.verifyProof(publicKey, header, presentation_header, proof, messages.length, allDisclosedMessages);
        } catch (Exception exception) {
            exception.printStackTrace();
        }
        assertTrue(isVerified);

        // Few disclosed messages
        HashSet<Integer> fewDisclosedIndices = new HashSet(Arrays.asList(1));
        HashMap<Integer, byte[]> fewDisclosedMessages = new HashMap<Integer, byte[]>();
        fewDisclosedMessages.put(1, messages[1]);
        try {
            proof = bbs.createProof(publicKey, header, presentation_header, signature, fewDisclosedIndices, messages);
        } catch (Exception exception) {
            exception.printStackTrace();
        }
        assertNotNull(proof);
        try {
            isVerified = bbs.verifyProof(publicKey, header, presentation_header, proof, messages.length, fewDisclosedMessages);
        } catch (Exception exception) {
            exception.printStackTrace();
        }
        assertTrue(isVerified);
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
    public void canCreateVerifyProof() {
        canCreateVerifyProofHelper(new Bls12381Sha256());
        canCreateVerifyProofHelper(new Bls12381Shake256());
    }
}
