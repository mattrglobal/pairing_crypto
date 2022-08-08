#import <Foundation/Foundation.h>

#import "pairing_crypto.h"
#import "bbs_proof.h"
#import "BbsSignatureError.h"

@interface BbsProof ()

/** @brief A BBS Signature Proof */
@property(nonatomic, readwrite) NSData *value;

@end

/** @brief A BBS Signature Proof */
@implementation BbsProof

/** @brief Creates a BBS signature proof from the raw bytes  */
- (nullable instancetype)initWithBytes:(NSData* _Nonnull)bytes
                             withError:(NSError *_Nullable*_Nullable)errorPtr {
    
    [self createFromBytes:bytes
                withError:errorPtr];
    return self;
}

/** @brief Creates a BBS signature proof */
- (nullable instancetype)createProof:(NSData *_Nonnull)publicKey
                              header:(NSData *)header
                 presentationMessage:(NSData *)presentationMessage
                           signature:(NSData *_Nonnull)signature
                    disclosedIndices:(NSSet *)disclosedIndices
                            messages:(NSArray *)messages
                           withError:(NSError *_Nullable *_Nullable)errorPtr {
    
    [self createSignatureProof:publicKey
                        header:header
           presentationMessage:presentationMessage
                     signature:signature
              disclosedIndices:disclosedIndices
                      messages:messages
                     withError:errorPtr];
    return self;
}

/** @brief Initializes a key pair */
- (bool)verifyProof:(NSData *_Nonnull)publicKey
             header:(NSData *)header
presentationMessage:(NSData *)presentationMessage
              proof:(NSData *_Nonnull)proof
           messages:(NSDictionary *)messages
          withError:(NSError *_Nullable *_Nullable)errorPtr {
    
    return [self verifySignatureProof:publicKey
                               header:header
                  presentationMessage:presentationMessage
                                proof:proof
                             messages:messages
                            withError:errorPtr];
}

/** @brief Initializes a key pair */
- (nullable instancetype)createFromBytes:(NSData* _Nonnull)bytes
                               withError:(NSError *_Nullable*_Nullable)errorPtr {
    
    self.value = [[NSData alloc] initWithData:bytes];
    return self;
}

- (void) createSignatureProof:(NSData *_Nonnull)publicKey
                       header:(NSData *)header
          presentationMessage:(NSData *)presentationMessage
                    signature:(NSData *_Nonnull)signature
             disclosedIndices:(NSSet *)disclosedIndices
                     messages:(NSArray *)messages
                    withError:(NSError *_Nullable *_Nullable)errorPtr {
    
    pairing_crypto_error_t *err = (pairing_crypto_error_t*) malloc(sizeof(pairing_crypto_error_t));
    
    uint64_t deriveProofHandle = bbs_bls12381_derive_proof_context_init(err);
    
    if (deriveProofHandle == 0) {
        *errorPtr = [BbsSignatureError errorFromBbsSignatureError:err];
        return;
    }
    
    pairing_crypto_byte_buffer_t publicKeyBuffer;
    publicKeyBuffer.len = publicKey.length;
    publicKeyBuffer.data = (uint8_t *)publicKey.bytes;

    if (bbs_bls12381_derive_proof_context_set_public_key(deriveProofHandle, publicKeyBuffer, err) != 0) {
        *errorPtr = [BbsSignatureError errorFromBbsSignatureError:err];
        return false;
    }

    pairing_crypto_byte_buffer_t headerBuffer;
    headerBuffer.len = header.length;
    headerBuffer.data = (uint8_t *)header.bytes;

    if (bbs_bls12381_derive_proof_context_set_header(deriveProofHandle, headerBuffer, err) > 0) {
        *errorPtr = [BbsSignatureError errorFromBbsSignatureError:err];
        return;
    }

    pairing_crypto_byte_buffer_t presentationMessageBuffer;
    presentationMessageBuffer.len = header.length;
    presentationMessageBuffer.data = (uint8_t *)header.bytes;

    if (bbs_bls12381_derive_proof_context_set_presentation_message(deriveProofHandle, presentationMessageBuffer, err) > 0) {
        *errorPtr = [BbsSignatureError errorFromBbsSignatureError:err];
        return;
    }
    
    pairing_crypto_byte_buffer_t signatureBuffer;
    signatureBuffer.len = self.value.length;
    signatureBuffer.data = (uint8_t *)self.value.bytes;

    if (bbs_bls12381_derive_proof_context_set_signature(deriveProofHandle, signatureBuffer, err) != 0) {
        *errorPtr = [BbsSignatureError errorFromBbsSignatureError:err];
        return false;
    }

    int i = 0;
    for (NSData *message in messages) {
        pairing_crypto_byte_buffer_t messageBuffer;
        messageBuffer.len = message.length;
        messageBuffer.data = (uint8_t *)message.bytes;
        
        BOOL isDisclosed = [disclosedIndices containsObject:[[NSNumber alloc] initWithInt:i]];
        
        if (bbs_bls12381_derive_proof_context_add_message(deriveProofHandle, isDisclosed, messageBuffer, err) > 0) {
            *errorPtr = [BbsSignatureError errorFromBbsSignatureError:err];
            return;
        }
        
        i++;
    }
    
    pairing_crypto_byte_buffer_t *proof = (pairing_crypto_byte_buffer_t*) malloc(sizeof(pairing_crypto_byte_buffer_t));
    
    if (bbs_bls12381_derive_proof_context_finish(deriveProofHandle, proof, err) != 0) {
        *errorPtr = [BbsSignatureError errorFromBbsSignatureError:err];
        return;
    }
    
    self.value = [[NSData alloc] initWithBytesNoCopy:proof->data
                                              length:(NSUInteger)proof->len
                                        freeWhenDone:true];
    
    free(err);
}

/** @brief Initializes a key pair */
- (bool)verifySignatureProof:(NSData *_Nonnull)publicKey
                      header:(NSData *)header
         presentationMessage:(NSData *)presentationMessage
                       proof:(NSData *_Nonnull)proof
                    messages:(NSDictionary *)messages
                   withError:(NSError *_Nullable *_Nullable)errorPtr  {
    
    pairing_crypto_error_t *err = (pairing_crypto_error_t*) malloc(sizeof(pairing_crypto_error_t));
    
    uint64_t verifyProofHandle = bbs_bls12381_verify_proof_context_init(err);
    
    if (verifyProofHandle == 0) {
        *errorPtr = [BbsSignatureError errorFromBbsSignatureError:err];
        return false;
    }
    
    pairing_crypto_byte_buffer_t publicKeyBuffer;
    publicKeyBuffer.len = publicKey.length;
    publicKeyBuffer.data = (uint8_t *)publicKey.bytes;

    if (bbs_bls12381_verify_proof_context_set_public_key(verifyProofHandle, publicKeyBuffer, err) != 0) {
        *errorPtr = [BbsSignatureError errorFromBbsSignatureError:err];
        return false;
    }

    pairing_crypto_byte_buffer_t headerBuffer;
    headerBuffer.len = header.length;
    headerBuffer.data = (uint8_t *)header.bytes;

    if (bbs_bls12381_verify_proof_context_set_header(verifyProofHandle, headerBuffer, err) > 0) {
        *errorPtr = [BbsSignatureError errorFromBbsSignatureError:err];
        return;
    }

    pairing_crypto_byte_buffer_t presentationMessageBuffer;
    presentationMessageBuffer.len = header.length;
    presentationMessageBuffer.data = (uint8_t *)header.bytes;

    if (bbs_bls12381_verify_proof_context_set_presentation_message(verifyProofHandle, presentationMessageBuffer, err) > 0) {
        *errorPtr = [BbsSignatureError errorFromBbsSignatureError:err];
        return;
    }
    
    pairing_crypto_byte_buffer_t proofBuffer;
    proofBuffer.len = self.value.length;
    proofBuffer.data = (uint8_t *)self.value.bytes;

    if (bbs_bls12381_verify_proof_context_set_proof(verifyProofHandle, proofBuffer, err) != 0) {
        *errorPtr = [BbsSignatureError errorFromBbsSignatureError:err];
        return false;
    }

    for (id index in messages) {
        NSData* message = [messages objectForKey: index];
        pairing_crypto_byte_buffer_t messageBuffer;
        messageBuffer.len = message.length;
        messageBuffer.data = (uint8_t *)message.bytes;
                
        if (bbs_bls12381_verify_proof_context_add_message(verifyProofHandle, [index intValue], messageBuffer, err) > 0) {
            *errorPtr = [BbsSignatureError errorFromBbsSignatureError:err];
            return false;
        }
    }
    
    
    if (bbs_bls12381_verify_proof_context_finish(verifyProofHandle, err) != 0) {
        *errorPtr = [BbsSignatureError errorFromBbsSignatureError:err];
        return false;
    }
    
    return true;
}

@end
