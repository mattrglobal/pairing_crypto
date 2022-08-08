package pairing_crypto;

import java.util.HashSet;
import java.util.Arrays;
import java.util.HashMap;

import org.junit.Test;
import static org.junit.Assert.*;

public class BbsTest {
       
    @Test public void shouldThrowExceptionMessageWhenFailToGenerateBbsBls12381KeyPair() {
        byte[] ikm = null;
        byte[] keyInfo = null;

        try {
            Bbs.generateBls12381KeyPair(ikm, keyInfo);
            fail("Expected an exception to be thrown");
        } catch (Exception exception) {
            assertEquals("Unable to generate keys", exception.getMessage());
        }
    }

    @Test public void canGenerateBbsBls12381KeyPair() {
        byte[] ikm = new byte[32];
        byte[] keyInfo = new byte[10];
        KeyPair keyPair = null;


        try {
            keyPair = Bbs.generateBls12381KeyPair(ikm, keyInfo);
        } catch (Exception exception) {
            exception.printStackTrace();
        }

        assertNotNull(keyPair);
        assertEquals(KeyPair.BBS_BLS12381_PUBLIC_KEY_SIZE, keyPair.publicKey.length);
        assertEquals(KeyPair.BBS_BLS12381_SECRET_KEY_SIZE, keyPair.secretKey.length);
    }

    @Test public void canSignVerifyMessage() {
        byte[] ikm = new byte[32];
        byte[] keyInfo = new byte[10];
        KeyPair keyPair = null;

        try {
            keyPair = Bbs.generateBls12381KeyPair(ikm, keyInfo);
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

        byte[] signature = new byte[Bbs.BBS_BLS12381_SIGNATURE_SIZE];

        try {
            signature = Bbs.sign(keyPair.secretKey, keyPair.publicKey, header, messages);
        } catch (Exception exception) {
            exception.printStackTrace();
        }

        assertNotNull(signature);

        boolean isVerified = false;

        try {
            isVerified = Bbs.verify(publicKey, header, signature, messages);
        } catch (Exception exception) {
            exception.printStackTrace();
        }

        assertTrue(isVerified);
    }

    @Test public void canCreateVerifyProof() {
        byte[] ikm = new byte[32];
        byte[] keyInfo = new byte[10];
        KeyPair keyPair = null;

        try {
            keyPair = Bbs.generateBls12381KeyPair(ikm, keyInfo);
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

        byte[] signature = new byte[Bbs.BBS_BLS12381_SIGNATURE_SIZE];

        try {
            signature = Bbs.sign(secretKey, publicKey, header, messages);
        } catch (Exception exception) {
            exception.printStackTrace();
        }

        assertNotNull(signature);

        boolean isVerified = false;

        try {
            isVerified = Bbs.verify(publicKey, header, signature, messages);
        } catch (Exception exception) {
            exception.printStackTrace();
        }

        assertTrue(isVerified);

        // All disclosed messages
        byte[] presentation_message = "test-presentation-message".getBytes();
        HashSet<Integer> allDisclosedIndices = new HashSet(Arrays.asList(0, 1, 2));
        byte[] proof = new byte[0];
        try {
            proof = Bbs.createProof(publicKey, header, presentation_message, signature, allDisclosedIndices, messages);
        } catch (Exception exception) {
            exception.printStackTrace();
        }
        assertNotNull(proof);
        HashMap<Integer, byte[]> allDisclosedMessages = new HashMap<Integer, byte[]>();
        allDisclosedMessages.put(0, messages[0]);
        allDisclosedMessages.put(1, messages[1]);
        allDisclosedMessages.put(2, messages[2]);
        try {
            isVerified = Bbs.verifyProof(publicKey, header, presentation_message, proof, allDisclosedMessages);
        } catch (Exception exception) {
            exception.printStackTrace();
        }
        assertTrue(isVerified);

        // Few disclosed messages
        HashSet<Integer> fewDisclosedIndices = new HashSet(Arrays.asList(1));
        HashMap<Integer, byte[]> fewDisclosedMessages = new HashMap<Integer, byte[]>();
        fewDisclosedMessages.put(1, messages[1]);
        try {
            proof = Bbs.createProof(publicKey, header, presentation_message, signature, fewDisclosedIndices, messages);
        } catch (Exception exception) {
            exception.printStackTrace();
        }
        assertNotNull(proof);
        try {
            isVerified = Bbs.verifyProof(publicKey, header, presentation_message, proof, fewDisclosedMessages);
        } catch (Exception exception) {
            exception.printStackTrace();
        }
        assertTrue(isVerified);
    }

}
