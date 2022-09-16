#import <Foundation/Foundation.h>

#import "pairing_crypto_bbs.h"
#import "include/bbs/bbs_bls12381_shake256_proof.h"
#import "include/PairingCryptoError.h"

@interface BbsBls12381Shake256Proof ()

/** @brief proof */
@property(nonatomic, readwrite) NSData *value;

@end

/** @brief BBS-Bls12381-Shake-256 Proof */
@implementation BbsBls12381Shake256Proof

/** @brief Create a BBS proof. */
- (void) doCreateProof:(NSData *_Nonnull)publicKey
                       header:(NSData *_Nullable)header
          presentationMessage:(NSData *_Nullable)presentationMessage
                    signature:(NSData *_Nonnull)signature
             disclosedIndices:(NSSet *_Nullable)disclosedIndices
                     messages:(NSArray *_Nullable)messages
                    withError:(NSError *_Nullable *_Nullable)errorPtr {
    
    pairing_crypto_error_t *err = (pairing_crypto_error_t*) malloc(sizeof(pairing_crypto_error_t));
    
    uint64_t deriveProofHandle = bbs_bls12_381_shake_256_proof_gen_context_init(err);
    
    if (deriveProofHandle == 0) {
        *errorPtr = [PairingCryptoError errorFromPairingCryptoError:err];
        return;
    }
    
    pairing_crypto_byte_buffer_t *publicKeyBuffer = (pairing_crypto_byte_buffer_t *)malloc(sizeof(pairing_crypto_byte_buffer_t));
    publicKeyBuffer->len = publicKey.length;
    publicKeyBuffer->data = (uint8_t *)publicKey.bytes;

    if (bbs_bls12_381_shake_256_proof_gen_context_set_public_key(deriveProofHandle, publicKeyBuffer, err) != 0) {
        *errorPtr = [PairingCryptoError errorFromPairingCryptoError:err];
        return;
    }

    if (header) {
        pairing_crypto_byte_buffer_t *headerBuffer = (pairing_crypto_byte_buffer_t *)malloc(sizeof(pairing_crypto_byte_buffer_t));
        headerBuffer->len = header.length;
        headerBuffer->data = (uint8_t *)header.bytes;

        if (bbs_bls12_381_shake_256_proof_gen_context_set_header(deriveProofHandle, headerBuffer, err) > 0) {
            *errorPtr = [PairingCryptoError errorFromPairingCryptoError:err];
            return;
        }
    }

    if (presentationMessage) {
        pairing_crypto_byte_buffer_t *presentationMessageBuffer = (pairing_crypto_byte_buffer_t *)malloc(sizeof(pairing_crypto_byte_buffer_t));
        presentationMessageBuffer->len = presentationMessage.length;
        presentationMessageBuffer->data = (uint8_t *)presentationMessage.bytes;

        if (bbs_bls12_381_shake_256_proof_gen_context_set_presentation_header(deriveProofHandle, presentationMessageBuffer, err) > 0) {
            *errorPtr = [PairingCryptoError errorFromPairingCryptoError:err];
            return;
        }
    }
    
    pairing_crypto_byte_buffer_t *signatureBuffer = (pairing_crypto_byte_buffer_t *)malloc(sizeof(pairing_crypto_byte_buffer_t));
    signatureBuffer->len = signature.value.length;
    signatureBuffer->data = (uint8_t *)signature.value.bytes;

    if (bbs_bls12_381_shake_256_proof_gen_context_set_signature(deriveProofHandle, signatureBuffer, err) != 0) {
        *errorPtr = [PairingCryptoError errorFromPairingCryptoError:err];
        return;
    }

    if (disclosedIndices && messages && [messages count] != 0) {
        int i = 0;
        for (NSData *message in messages) {
            pairing_crypto_byte_buffer_t *messageBuffer = (pairing_crypto_byte_buffer_t *)malloc(sizeof(pairing_crypto_byte_buffer_t));
            messageBuffer->len = message.length;
            messageBuffer->data = (uint8_t *)message.bytes;
        
            BOOL isDisclosed = [disclosedIndices containsObject:[[NSNumber alloc] initWithInt:i]];
        
            if (bbs_bls12_381_shake_256_proof_gen_context_add_message(deriveProofHandle, isDisclosed, messageBuffer, err) > 0) {
                *errorPtr = [PairingCryptoError errorFromPairingCryptoError:err];
                return;
            }
        
            i++;
        }
    }
    
    pairing_crypto_byte_buffer_t *proof = (pairing_crypto_byte_buffer_t*) malloc(sizeof(pairing_crypto_byte_buffer_t));
    
    if (bbs_bls12_381_shake_256_proof_gen_context_finish(deriveProofHandle, proof, err) != 0) {
        *errorPtr = [PairingCryptoError errorFromPairingCryptoError:err];
        return;
    }
    
    self.value = [[NSData alloc] initWithBytesNoCopy:proof->data
                                              length:(NSUInteger)proof->len
                                        freeWhenDone:true];
    
    free(err);
}

/** @brief Verify a BBS proof. */
- (bool)doVerifyProof:(NSData *_Nonnull)publicKey
                      header:(NSData *_Nullable)header
         presentationMessage:(NSData *_Nullable)presentationMessage
         total_message_count:(NSUInteger)total_message_count
                    messages:(NSDictionary *_Nullable)messages
                   withError:(NSError *_Nullable *_Nullable)errorPtr  {
    
    pairing_crypto_error_t *err = (pairing_crypto_error_t*) malloc(sizeof(pairing_crypto_error_t));
    
    uint64_t verifyProofHandle = bbs_bls12_381_shake_256_proof_verify_context_init(err);
    
    if (verifyProofHandle == 0) {
        *errorPtr = [PairingCryptoError errorFromPairingCryptoError:err];
        return false;
    }
    
    pairing_crypto_byte_buffer_t *publicKeyBuffer = (pairing_crypto_byte_buffer_t *)malloc(sizeof(pairing_crypto_byte_buffer_t));
    publicKeyBuffer->len = publicKey.length;
    publicKeyBuffer->data = (uint8_t *)publicKey.bytes;

    if (bbs_bls12_381_shake_256_proof_verify_context_set_public_key(verifyProofHandle, publicKeyBuffer, err) != 0) {
        *errorPtr = [PairingCryptoError errorFromPairingCryptoError:err];
        return false;
    }

    if (header) {
        pairing_crypto_byte_buffer_t *headerBuffer = (pairing_crypto_byte_buffer_t *)malloc(sizeof(pairing_crypto_byte_buffer_t));
        headerBuffer->len = header.length;
        headerBuffer->data = (uint8_t *)header.bytes;

        if (bbs_bls12_381_shake_256_proof_verify_context_set_header(verifyProofHandle, headerBuffer, err) > 0) {
            *errorPtr = [PairingCryptoError errorFromPairingCryptoError:err];
            return false;
        }
    }

    if (presentationMessage) {
        pairing_crypto_byte_buffer_t *presentationMessageBuffer = (pairing_crypto_byte_buffer_t *)malloc(sizeof(pairing_crypto_byte_buffer_t));
        presentationMessageBuffer->len = presentationMessage.length;
        presentationMessageBuffer->data = (uint8_t *)presentationMessage.bytes;

        if (bbs_bls12_381_shake_256_proof_verify_context_set_presentation_header(verifyProofHandle, presentationMessageBuffer, err) > 0) {
            *errorPtr = [PairingCryptoError errorFromPairingCryptoError:err];
            return false;
        }
    }

    if (bbs_bls12_381_shake_256_proof_verify_context_set_total_message_count(verifyProofHandle, total_message_count, err) != 0) {
        *errorPtr = [PairingCryptoError errorFromPairingCryptoError:err];
        return false;
    }
    
    pairing_crypto_byte_buffer_t *proofBuffer = (pairing_crypto_byte_buffer_t *)malloc(sizeof(pairing_crypto_byte_buffer_t));
    proofBuffer->len = self.value.length;
    proofBuffer->data = (uint8_t *)self.value.bytes;

    if (bbs_bls12_381_shake_256_proof_verify_context_set_proof(verifyProofHandle, proofBuffer, err) != 0) {
        *errorPtr = [PairingCryptoError errorFromPairingCryptoError:err];
        return false;
    }

    if (messages && [messages count] != 0) {
        for (id index in messages) {
            NSData* message = [messages objectForKey: index];
            pairing_crypto_byte_buffer_t *messageBuffer = (pairing_crypto_byte_buffer_t *)malloc(sizeof(pairing_crypto_byte_buffer_t));
            messageBuffer->len = message.length;
            messageBuffer->data = (uint8_t *)message.bytes;
                
            if (bbs_bls12_381_shake_256_proof_verify_context_add_message(verifyProofHandle, [index intValue], messageBuffer, err) > 0) {
                *errorPtr = [PairingCryptoError errorFromPairingCryptoError:err];
                return false;
            }
        }
    }

    if (bbs_bls12_381_shake_256_proof_verify_context_finish(verifyProofHandle, err) != 0) {
        *errorPtr = [PairingCryptoError errorFromPairingCryptoError:err];
        return false;
    }
    
    free(err);
    return true;
}

@end
