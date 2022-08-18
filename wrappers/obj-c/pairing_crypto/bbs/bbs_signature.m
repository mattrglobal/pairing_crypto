#import <Foundation/Foundation.h>

#import "bbs_signature.h"
#import "pairing_crypto_bbs.h"
#import "BbsSignatureError.h"

/** @brief BBS Signature */
@interface BbsSignature ()

/** @brief signature */
@property(nonatomic, readwrite) NSData *value;

@end

/** @brief BBS Signature */
@implementation BbsSignature

/**
* @brief Creates a BBS signature from the raw bytes
*/
- (nullable instancetype)initWithBytes:(NSData* _Nonnull)bytes
                             withError:(NSError *_Nullable*_Nullable)errorPtr {
    
    [self createFromBytes:bytes
                withError:errorPtr];
    return self;
}

/**
* @brief Creates a BBS signature
*/
- (nullable instancetype)sign:(BbsKeyPair* _Nonnull)keyPair
                       header:(NSData *_Nullable)header
                     messages:(NSArray *_Nullable)messages
                    withError:(NSError *_Nullable*_Nullable)errorPtr {
    
    [self createSignature:keyPair
                   header:header
                 messages:messages
                withError:errorPtr];
    return self;
}

/**
* @Verifies the BBS signature
*/
- (bool)verify:(NSData *_Nonnull)publicKey
        header:(NSData *_Nullable)header
      messages:(NSArray *_Nullable)messages
     withError:(NSError *_Nullable*_Nullable)errorPtr {
    
    return [self verifySignature:publicKey
                          header:header
                        messages:messages
                       withError:errorPtr];
}

- (nullable instancetype)createFromBytes:(NSData* _Nonnull)bytes
                               withError:(NSError *_Nullable*_Nullable)errorPtr {
    
    self.value = [[NSData alloc] initWithData:bytes];
    return self;
}

- (void) createSignature:(BbsKeyPair* _Nonnull)keyPair
                  header:(NSData *_Nullable)header
                messages:(NSArray *_Nullable)messages
               withError:(NSError* _Nullable*_Nullable)errorPtr {
    
    pairing_crypto_error_t *err = (pairing_crypto_error_t*) malloc(sizeof(pairing_crypto_error_t));
    
    uint64_t createSignatureHandle = bbs_bls12_381_shake_256_sign_context_init(err);
    
    if (createSignatureHandle == 0) {
        *errorPtr = [BbsSignatureError errorFromBbsSignatureError:err];
        return;
    }

    pairing_crypto_byte_buffer_t secretKeyBuffer;
    secretKeyBuffer.len = keyPair.secretKey.length;
    secretKeyBuffer.data = (uint8_t *)keyPair.secretKey.bytes;

    if (bbs_bls12_381_shake_256_sign_context_set_secret_key(createSignatureHandle, secretKeyBuffer, err) > 0) {
        *errorPtr = [BbsSignatureError errorFromBbsSignatureError:err];
        return;
    }
    
    pairing_crypto_byte_buffer_t publicKeyBuffer;
    publicKeyBuffer.len = keyPair.publicKey.length;
    publicKeyBuffer.data = (uint8_t *)keyPair.publicKey.bytes;

    if (bbs_bls12_381_shake_256_sign_context_set_public_key(createSignatureHandle, publicKeyBuffer, err) > 0) {
        *errorPtr = [BbsSignatureError errorFromBbsSignatureError:err];
        return;
    }

    if (header) {
        pairing_crypto_byte_buffer_t headerBuffer;
        headerBuffer.len = header.length;
        headerBuffer.data = (uint8_t *)header.bytes;

        if (bbs_bls12_381_shake_256_sign_context_set_header(createSignatureHandle, headerBuffer, err) > 0) {
            *errorPtr = [BbsSignatureError errorFromBbsSignatureError:err];
            return;
        }
    }

    if (messages && [messages count] != 0) {
        for (NSData *message in messages) {
            pairing_crypto_byte_buffer_t messageBuffer;
            messageBuffer.len = message.length;
            messageBuffer.data = (uint8_t *)message.bytes;
        
            if (bbs_bls12_381_shake_256_sign_context_add_message(createSignatureHandle, messageBuffer, err) > 0) {
                *errorPtr = [BbsSignatureError errorFromBbsSignatureError:err];
                return;
                }
            }
    }
    
    pairing_crypto_byte_buffer_t *signature = (pairing_crypto_byte_buffer_t*) malloc(sizeof(pairing_crypto_byte_buffer_t));
    
    if (bbs_bls12_381_shake_256_sign_context_finish(createSignatureHandle, signature, err) > 0) {
        *errorPtr = [BbsSignatureError errorFromBbsSignatureError:err];
        return;
    }
    
    free(err);
    self.value = [[NSData alloc] initWithBytesNoCopy:signature->data
                                              length:(NSUInteger)signature->len
                                        freeWhenDone:true];
}

- (bool)verifySignature:(NSData *_Nonnull)publicKey
                 header:(NSData *_Nullable)header
               messages:(NSArray *_Nullable)messages
              withError:(NSError *_Nullable*_Nullable)errorPtr {
    
    pairing_crypto_error_t *err = (pairing_crypto_error_t*) malloc(sizeof(pairing_crypto_error_t));
    
    uint64_t verifySignatureHandle = bbs_bls12_381_shake_256_verify_context_init(err);
    
    if (verifySignatureHandle == 0) {
        *errorPtr = [BbsSignatureError errorFromBbsSignatureError:err];
        return false;
    }
    
        
    pairing_crypto_byte_buffer_t publicKeyBuffer;
    publicKeyBuffer.len = publicKey.length;
    publicKeyBuffer.data = (uint8_t *)publicKey.bytes;

    if (bbs_bls12_381_shake_256_verify_context_set_public_key(verifySignatureHandle, publicKeyBuffer, err) != 0) {
        *errorPtr = [BbsSignatureError errorFromBbsSignatureError:err];
        return false;
    }

    if (header) {
        pairing_crypto_byte_buffer_t headerBuffer;
        headerBuffer.len = header.length;
        headerBuffer.data = (uint8_t *)header.bytes;

        if (bbs_bls12_381_shake_256_verify_context_set_header(verifySignatureHandle, headerBuffer, err) > 0) {
            *errorPtr = [BbsSignatureError errorFromBbsSignatureError:err];
            return false;
        }
    }
    
    pairing_crypto_byte_buffer_t signatureBuffer;
    signatureBuffer.len = self.value.length;
    signatureBuffer.data = (uint8_t *)self.value.bytes;

    if (bbs_bls12_381_shake_256_verify_context_set_signature(verifySignatureHandle, signatureBuffer, err) != 0) {
        *errorPtr = [BbsSignatureError errorFromBbsSignatureError:err];
        return false;
    }

    if (messages && [messages count] != 0) {
        for (NSData *message in messages) {
            pairing_crypto_byte_buffer_t messageBuffer;
            messageBuffer.len = message.length;
            messageBuffer.data = (uint8_t *)message.bytes;
        
            if (bbs_bls12_381_shake_256_verify_context_add_message(verifySignatureHandle, messageBuffer, err) != 0) {
                *errorPtr = [BbsSignatureError errorFromBbsSignatureError:err];
                return false;
            }
        }
    }
    
    if (bbs_bls12_381_shake_256_verify_context_finish(verifySignatureHandle, err) != 0) {
        *errorPtr = [BbsSignatureError errorFromBbsSignatureError:err];
        return false;
    }
    
    free(err);
    return true;
}

@end
