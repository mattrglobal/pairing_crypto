#import <Foundation/Foundation.h>

#import "PairingCryptoError.h"
#import "pairing_crypto_bbs.h"
#import "bbs_bls12381_shake256_key_pair.h"

@implementation BbsBls12381Shake256KeyPair

@synthesize publicKey;

@synthesize secretKey;

- (void) generateKeyPair:(NSData *_Nullable)ikm
                 keyInfo:(NSData *_Nullable)keyInfo
                withError:(NSError *_Nullable *_Nullable)errorPtr {

    pairing_crypto_error_t *err = (pairing_crypto_error_t*) malloc(sizeof(pairing_crypto_error_t));

    pairing_crypto_byte_buffer_t ikmBuffer;
    if (ikm != nil) {
        ikmBuffer.len = ikm.length;
        ikmBuffer.data = (uint8_t *)ikm.bytes;
    }
    else {
        ikmBuffer.len = 0;
    }

    pairing_crypto_byte_buffer_t keyInfoBuffer;
    if (keyInfo != nil) {
        keyInfoBuffer.len = keyInfo.length;
        keyInfoBuffer.data = (uint8_t *)keyInfo.bytes;
    }
    else {
        keyInfoBuffer.len = 0;
    }

    pairing_crypto_byte_buffer_t *sk = (pairing_crypto_byte_buffer_t*) malloc(sizeof(pairing_crypto_byte_buffer_t));
    pairing_crypto_byte_buffer_t *pk = (pairing_crypto_byte_buffer_t*) malloc(sizeof(pairing_crypto_byte_buffer_t));

    int32_t ret = bbs_bls12_381_shake_256_generate_key_pair(ikmBuffer, keyInfoBuffer, sk, pk, err);

    if (ret > 0) {
        *errorPtr = [PairingCryptoError errorFromPairingCryptoError:err];
        return;
    }

    self.secretKey = [[NSData alloc] initWithBytesNoCopy:sk->data length:(NSUInteger)sk->len freeWhenDone:true];
    self.publicKey = [[NSData alloc] initWithBytesNoCopy:pk->data length:(NSUInteger)pk->len freeWhenDone:true];

    free(pk);
    free(sk);
    free(err);
}

- (void)dealloc {
    [self.secretKey release];
    [self.publicKey release];
    [super dealloc];
}

@end
