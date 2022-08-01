package pairing_crypto;

public class ProofGenRevealMessage {

    public boolean reveal;
    public byte[] message;

    public ProofGenRevealMessage(boolean reveal, byte[] message) {
        this.reveal = reveal;
        this.message = message;
    }
}