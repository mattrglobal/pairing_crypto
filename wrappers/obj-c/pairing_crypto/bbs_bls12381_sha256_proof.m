#import <Foundation/Foundation.h>

#import "PairingCryptoError.h"
#import "pairing_crypto_bbs.h"
#import "bbs_bls12381_sha256_proof.h"
#import "bbs_signature.h"

/** @brief BBS-Bls12381-Sha-256 Proof */
@implementation PCLBbsBls12381Sha256Proof

@synthesize value;

/** @brief Create a BBS proof. */
- (void) doCreateProof:(NSData *_Nonnull)publicKey
                       header:(NSData *_Nullable)header
          presentationHeader:(NSData *_Nullable)presentationHeader
                    signature:(PCLBbsSignature *_Nonnull)signature
              verifySignature:(BOOL)verifySignature
             disclosedIndices:(NSSet *_Nullable)disclosedIndices
                     messages:(NSArray *_Nullable)messages
                    withError:(NSError *_Nullable *_Nullable)errorPtr {
    pairing_crypto_byte_buffer_t *publicKeyBuffer = nil;
    pairing_crypto_byte_buffer_t* headerBuffer = nil;
    pairing_crypto_byte_buffer_t* presentationHeaderBuffer = nil;
    pairing_crypto_byte_buffer_t* signatureBuffer = nil;
    pairing_crypto_byte_buffer_t* messageBuffer = nil;
    pairing_crypto_byte_buffer_t* proof = nil;

    pairing_crypto_error_t *err = (pairing_crypto_error_t*) malloc(sizeof(pairing_crypto_error_t));

    uint64_t deriveProofHandle = bbs_bls12_381_sha_256_proof_gen_context_init(err);
    if (deriveProofHandle == 0) {
        *errorPtr = [PairingCryptoError errorFromPairingCryptoError:err];
        goto exit;
    }

    publicKeyBuffer = (pairing_crypto_byte_buffer_t *)malloc(sizeof(pairing_crypto_byte_buffer_t));
    publicKeyBuffer->len = publicKey.length;
    publicKeyBuffer->data = (uint8_t *)publicKey.bytes;
    if (bbs_bls12_381_sha_256_proof_gen_context_set_public_key(deriveProofHandle, publicKeyBuffer, err) != 0) {
        *errorPtr = [PairingCryptoError errorFromPairingCryptoError:err];
        goto exit;
    }

    if (header) {
        headerBuffer = (pairing_crypto_byte_buffer_t *)malloc(sizeof(pairing_crypto_byte_buffer_t));
        headerBuffer->len = header.length;
        headerBuffer->data = (uint8_t *)header.bytes;
        if (bbs_bls12_381_sha_256_proof_gen_context_set_header(deriveProofHandle, headerBuffer, err) > 0) {
            *errorPtr = [PairingCryptoError errorFromPairingCryptoError:err];
            goto exit;
        }
    }

    if (presentationHeader) {
        presentationHeaderBuffer = (pairing_crypto_byte_buffer_t *)malloc(sizeof(pairing_crypto_byte_buffer_t));
        presentationHeaderBuffer->len = presentationHeader.length;
        presentationHeaderBuffer->data = (uint8_t *)presentationHeader.bytes;
        if (bbs_bls12_381_sha_256_proof_gen_context_set_presentation_header(deriveProofHandle, presentationHeaderBuffer, err) > 0) {
            *errorPtr = [PairingCryptoError errorFromPairingCryptoError:err];
            goto exit;
        }
    }

    signatureBuffer = (pairing_crypto_byte_buffer_t *)malloc(sizeof(pairing_crypto_byte_buffer_t));
    signatureBuffer->len = signature.value.length;
    signatureBuffer->data = (uint8_t *)signature.value.bytes;
    if (bbs_bls12_381_sha_256_proof_gen_context_set_signature(deriveProofHandle, signatureBuffer, err) != 0) {
        *errorPtr = [PairingCryptoError errorFromPairingCryptoError:err];
        goto exit;
    }

    if (bbs_bls12_381_sha_256_proof_gen_context_set_verify_signature(deriveProofHandle, verifySignature, err) != 0) {
        *errorPtr = [PairingCryptoError errorFromPairingCryptoError:err];
        goto exit;
    }

    messageBuffer = (pairing_crypto_byte_buffer_t *)malloc(sizeof(pairing_crypto_byte_buffer_t));
    if (disclosedIndices && messages && [messages count] != 0) {
        int i = 0;
        for (NSData *message in messages) {
            messageBuffer->len = message.length;
            messageBuffer->data = (uint8_t *)message.bytes;

            BOOL isDisclosed = [disclosedIndices containsObject:[[NSNumber alloc] initWithInt:i]];

            if (bbs_bls12_381_sha_256_proof_gen_context_add_message(deriveProofHandle, isDisclosed, messageBuffer, err) > 0) {
                *errorPtr = [PairingCryptoError errorFromPairingCryptoError:err];
                goto exit;
            }

            i++;
        }
    }

    proof = (pairing_crypto_byte_buffer_t*) malloc(sizeof(pairing_crypto_byte_buffer_t));
    if (bbs_bls12_381_sha_256_proof_gen_context_finish(deriveProofHandle, proof, err) != 0) {
        *errorPtr = [PairingCryptoError errorFromPairingCryptoError:err];
        goto exit;
    }

    self.value = [[NSData alloc] initWithBytesNoCopy:proof->data
                                              length:(NSUInteger)proof->len
                                        freeWhenDone:true];

    free(err);

exit:
    if (proof != nil) {
        free(proof);
    }
    if (messageBuffer != nil) {
        free(messageBuffer);
    }
    if (signatureBuffer != nil) {
        free(signatureBuffer);
    }
    if (presentationHeaderBuffer != nil) {
        free(presentationHeaderBuffer);
    }
    if (headerBuffer != nil) {
        free(headerBuffer);
    }
    if (publicKeyBuffer != nil) {
        free(publicKeyBuffer);
    }
}

/** @brief Verify a BBS proof. */
- (bool)doVerifyProof:(NSData *_Nonnull)publicKey
                      header:(NSData *_Nullable)header
         presentationHeader:(NSData *_Nullable)presentationHeader
                    messages:(NSDictionary *_Nullable)messages
                   withError:(NSError *_Nullable *_Nullable)errorPtr  {
    bool result = false;
    pairing_crypto_byte_buffer_t *publicKeyBuffer = nil;
    pairing_crypto_byte_buffer_t* headerBuffer = nil;
    pairing_crypto_byte_buffer_t* presentationHeaderBuffer = nil;
    pairing_crypto_byte_buffer_t* proofBuffer = nil;
    pairing_crypto_byte_buffer_t* messageBuffer = nil;

    pairing_crypto_error_t *err = (pairing_crypto_error_t*) malloc(sizeof(pairing_crypto_error_t));

    uint64_t verifyProofHandle = bbs_bls12_381_sha_256_proof_verify_context_init(err);
    if (verifyProofHandle == 0) {
        *errorPtr = [PairingCryptoError errorFromPairingCryptoError:err];
        goto exit;
    }

    publicKeyBuffer = (pairing_crypto_byte_buffer_t *)malloc(sizeof(pairing_crypto_byte_buffer_t));
    publicKeyBuffer->len = publicKey.length;
    publicKeyBuffer->data = (uint8_t *)publicKey.bytes;
    if (bbs_bls12_381_sha_256_proof_verify_context_set_public_key(verifyProofHandle, publicKeyBuffer, err) != 0) {
        *errorPtr = [PairingCryptoError errorFromPairingCryptoError:err];
        goto exit;
    }

    if (header) {
        headerBuffer = (pairing_crypto_byte_buffer_t *)malloc(sizeof(pairing_crypto_byte_buffer_t));
        headerBuffer->len = header.length;
        headerBuffer->data = (uint8_t *)header.bytes;
        if (bbs_bls12_381_sha_256_proof_verify_context_set_header(verifyProofHandle, headerBuffer, err) > 0) {
            *errorPtr = [PairingCryptoError errorFromPairingCryptoError:err];
            goto exit;
        }
    }

    if (presentationHeader) {
        presentationHeaderBuffer = (pairing_crypto_byte_buffer_t *)malloc(sizeof(pairing_crypto_byte_buffer_t));
        presentationHeaderBuffer->len = presentationHeader.length;
        presentationHeaderBuffer->data = (uint8_t *)presentationHeader.bytes;
        if (bbs_bls12_381_sha_256_proof_verify_context_set_presentation_header(verifyProofHandle, presentationHeaderBuffer, err) > 0) {
            *errorPtr = [PairingCryptoError errorFromPairingCryptoError:err];
            goto exit;
        }
    }

    proofBuffer = (pairing_crypto_byte_buffer_t *)malloc(sizeof(pairing_crypto_byte_buffer_t));
    proofBuffer->len = self.value.length;
    proofBuffer->data = (uint8_t *)self.value.bytes;
    if (bbs_bls12_381_sha_256_proof_verify_context_set_proof(verifyProofHandle, proofBuffer, err) != 0) {
        *errorPtr = [PairingCryptoError errorFromPairingCryptoError:err];
        goto exit;
    }

    messageBuffer = (pairing_crypto_byte_buffer_t *)malloc(sizeof(pairing_crypto_byte_buffer_t));
    if (messages && [messages count] != 0) {
        for (id index in messages) {
            NSData* message = [messages objectForKey: index];
            messageBuffer->len = message.length;
            messageBuffer->data = (uint8_t *)message.bytes;
            if (bbs_bls12_381_sha_256_proof_verify_context_add_message(verifyProofHandle, [index intValue], messageBuffer, err) > 0) {
                *errorPtr = [PairingCryptoError errorFromPairingCryptoError:err];
                goto exit;
            }
        }
    }

    if (bbs_bls12_381_sha_256_proof_verify_context_finish(verifyProofHandle, err) != 0) {
        *errorPtr = [PairingCryptoError errorFromPairingCryptoError:err];
        goto exit;
    }

    free(err);
    result = true;

exit:
    if (messageBuffer != nil) {
        free(messageBuffer);
    }
    if (proofBuffer != nil) {
        free(proofBuffer);
    }
    if (presentationHeaderBuffer != nil) {
        free(presentationHeaderBuffer);
    }
    if (headerBuffer != nil) {
        free(headerBuffer);
    }
    if (publicKeyBuffer != nil) {
        free(publicKeyBuffer);
    }
    return result;
}

@end
