#import <Foundation/Foundation.h>

#import "bbs_bls12381_shake256_key_pair.h"
#import "pairing_crypto_bbs.h"
#import "PairingCryptoError.h"

/** @brief BBS-Bls12381-Shake256 key pair */
@interface BbsBls12381Shake256KeyPair ()

/** @brief secret key */
@property(nonatomic, readwrite) NSData *secretKey;

/** @brief public key */
@property(nonatomic, readwrite) NSData *publicKey;

@end

@implementation BbsBls12381Shake256KeyPair

- (void) generateKeyPair:(NSData *_Nonnull)ikm
                 keyInfo:(NSData *_Nullable)keyInfo
                withError:(NSError *_Nullable *_Nullable)errorPtr {
    
    pairing_crypto_byte_buffer_t ikmBuffer;
    ikmBuffer.len = ikm.length;
    ikmBuffer.data = (uint8_t *)ikm.bytes;

    pairing_crypto_byte_buffer_t keyInfoBuffer;
    if (keyInfo != nil) {
        keyInfoBuffer.len = keyInfo.length;
        keyInfoBuffer.data = (uint8_t *)keyInfo.bytes;
    }
    else {
        keyInfoBuffer.len = 0;
    }
    
    pairing_crypto_byte_buffer_t *publicKey = (pairing_crypto_byte_buffer_t*) malloc(sizeof(pairing_crypto_byte_buffer_t));
    pairing_crypto_byte_buffer_t *secretKey = (pairing_crypto_byte_buffer_t*) malloc(sizeof(pairing_crypto_byte_buffer_t));
    pairing_crypto_error_t *err = (pairing_crypto_error_t*) malloc(sizeof(pairing_crypto_error_t));

    int32_t ret = bbs_bls12_381_shake_256_generate_key_pair(ikmBuffer, keyInfoBuffer, secretKey, publicKey, err);
    
    if (ret > 0) {
        *errorPtr = [PairingCryptoError errorFromPairingCryptoError:err];
        return;
    }
    
    self.publicKey = [[NSData alloc] initWithBytesNoCopy:publicKey->data length:(NSUInteger)publicKey->len freeWhenDone:true];
    self.secretKey = [[NSData alloc] initWithBytesNoCopy:secretKey->data length:(NSUInteger)secretKey->len freeWhenDone:true];
    
    free(err);
}

@end
