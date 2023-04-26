#import <Foundation/Foundation.h>

#import "PairingCryptoError.h"
#import "pairing_crypto_bbs.h"
#import "bbs_bls12381_shake256_signature.h"

/** @brief BBS-Bls12381-Shake-256 Signature */
@implementation BbsBls12381Shake256Signature

- (void) createSignature:(NSData *_Nonnull)secretKey
               publicKey:(NSData *_Nonnull)publicKey
                  header:(NSData *_Nullable)header
                messages:(NSArray *_Nullable)messages
               withError:(NSError* _Nullable*_Nullable)errorPtr {
    pairing_crypto_byte_buffer_t *secretKeyBuffer = nil;
    pairing_crypto_byte_buffer_t *publicKeyBuffer = nil;
    pairing_crypto_byte_buffer_t* headerBuffer = nil;
    pairing_crypto_byte_buffer_t* messageBuffer = nil;
    pairing_crypto_byte_buffer_t* signature = nil;

    pairing_crypto_error_t *err = (pairing_crypto_error_t*) malloc(sizeof(pairing_crypto_error_t));

    uint64_t createSignatureHandle = bbs_bls12_381_shake_256_sign_context_init(err);
    if (createSignatureHandle == 0) {
        *errorPtr = [PairingCryptoError errorFromPairingCryptoError:err];
        goto exit;
    }

    secretKeyBuffer = (pairing_crypto_byte_buffer_t *)malloc(sizeof(pairing_crypto_byte_buffer_t));
    secretKeyBuffer->len = secretKey.length;
    secretKeyBuffer->data = (uint8_t *)secretKey.bytes;
    if (bbs_bls12_381_shake_256_sign_context_set_secret_key(createSignatureHandle, secretKeyBuffer, err) > 0) {
        *errorPtr = [PairingCryptoError errorFromPairingCryptoError:err];
        goto exit;
    }

    publicKeyBuffer = (pairing_crypto_byte_buffer_t *)malloc(sizeof(pairing_crypto_byte_buffer_t));
    publicKeyBuffer->len = publicKey.length;
    publicKeyBuffer->data = (uint8_t *)publicKey.bytes;
    if (bbs_bls12_381_shake_256_sign_context_set_public_key(createSignatureHandle, publicKeyBuffer, err) > 0) {
        *errorPtr = [PairingCryptoError errorFromPairingCryptoError:err];
        goto exit;
    }

    if (header) {
        headerBuffer = (pairing_crypto_byte_buffer_t *)malloc(sizeof(pairing_crypto_byte_buffer_t));
        headerBuffer->len = header.length;
        headerBuffer->data = (uint8_t *)header.bytes;
        if (bbs_bls12_381_shake_256_sign_context_set_header(createSignatureHandle, headerBuffer, err) > 0) {
            *errorPtr = [PairingCryptoError errorFromPairingCryptoError:err];
            goto exit;
        }
    }

    messageBuffer = (pairing_crypto_byte_buffer_t *)malloc(sizeof(pairing_crypto_byte_buffer_t));
    if (messages && [messages count] != 0) {
        for (NSData *message in messages) {
            messageBuffer->len = message.length;
            messageBuffer->data = (uint8_t *)message.bytes;
            if (bbs_bls12_381_shake_256_sign_context_add_message(createSignatureHandle, messageBuffer, err) > 0) {
                *errorPtr = [PairingCryptoError errorFromPairingCryptoError:err];
                goto exit;
                }
            }
    }

    signature = (pairing_crypto_byte_buffer_t*) malloc(sizeof(pairing_crypto_byte_buffer_t));
    if (bbs_bls12_381_shake_256_sign_context_finish(createSignatureHandle, signature, err) > 0) {
        *errorPtr = [PairingCryptoError errorFromPairingCryptoError:err];
        goto exit;
    }

    free(err);
    self.value = [[NSData alloc] initWithBytesNoCopy:signature->data
                                              length:(NSUInteger)signature->len
                                        freeWhenDone:true];

exit:
    if (signature != nil) {
        free(signature);
    }
    if (messageBuffer != nil) {
        free(messageBuffer);
    }
    if (headerBuffer != nil) {
        free(headerBuffer);
    }
    if (publicKeyBuffer != nil) {
        free(publicKeyBuffer);
    }
    if (secretKeyBuffer != nil) {
        free(secretKeyBuffer);
    }
}

- (bool)verifySignature:(NSData *_Nonnull)publicKey
                 header:(NSData *_Nullable)header
               messages:(NSArray *_Nullable)messages
              withError:(NSError *_Nullable*_Nullable)errorPtr {
    bool result = false;
    pairing_crypto_byte_buffer_t* publicKeyBuffer = nil;
    pairing_crypto_byte_buffer_t* headerBuffer = nil;
    pairing_crypto_byte_buffer_t* signatureBuffer = nil;
    pairing_crypto_byte_buffer_t* messageBuffer = nil;

    pairing_crypto_error_t *err = (pairing_crypto_error_t*) malloc(sizeof(pairing_crypto_error_t));

    uint64_t verifySignatureHandle = bbs_bls12_381_shake_256_verify_context_init(err);
    if (verifySignatureHandle == 0) {
        *errorPtr = [PairingCryptoError errorFromPairingCryptoError:err];
        goto exit;
    }


    publicKeyBuffer = (pairing_crypto_byte_buffer_t *)malloc(sizeof(pairing_crypto_byte_buffer_t));
    publicKeyBuffer->len = publicKey.length;
    publicKeyBuffer->data = (uint8_t *)publicKey.bytes;
    if (bbs_bls12_381_shake_256_verify_context_set_public_key(verifySignatureHandle, publicKeyBuffer, err) != 0) {
        *errorPtr = [PairingCryptoError errorFromPairingCryptoError:err];
        goto exit;
    }

    headerBuffer = (pairing_crypto_byte_buffer_t *)malloc(sizeof(pairing_crypto_byte_buffer_t));
    if (header) {
        headerBuffer->len = header.length;
        headerBuffer->data = (uint8_t *)header.bytes;
        if (bbs_bls12_381_shake_256_verify_context_set_header(verifySignatureHandle, headerBuffer, err) > 0) {
            *errorPtr = [PairingCryptoError errorFromPairingCryptoError:err];
            goto exit;
        }
    }

    signatureBuffer = (pairing_crypto_byte_buffer_t *)malloc(sizeof(pairing_crypto_byte_buffer_t));
    signatureBuffer->len = self.value.length;
    signatureBuffer->data = (uint8_t *)self.value.bytes;
    if (bbs_bls12_381_shake_256_verify_context_set_signature(verifySignatureHandle, signatureBuffer, err) != 0) {
        *errorPtr = [PairingCryptoError errorFromPairingCryptoError:err];
        goto exit;
    }

    messageBuffer = (pairing_crypto_byte_buffer_t *)malloc(sizeof(pairing_crypto_byte_buffer_t));
    if (messages && [messages count] != 0) {
        for (NSData *message in messages) {
            messageBuffer->len = message.length;
            messageBuffer->data = (uint8_t *)message.bytes;
            if (bbs_bls12_381_shake_256_verify_context_add_message(verifySignatureHandle, messageBuffer, err) != 0) {
                *errorPtr = [PairingCryptoError errorFromPairingCryptoError:err];
                goto exit;
            }
        }
    }

    if (bbs_bls12_381_shake_256_verify_context_finish(verifySignatureHandle, err) != 0) {
        *errorPtr = [PairingCryptoError errorFromPairingCryptoError:err];
        goto exit;
    }

    result = true;
    free(err);

exit:
    if (messageBuffer != nil) {
        free(messageBuffer);
    }
    if (signatureBuffer != nil) {
        free(signatureBuffer);
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
