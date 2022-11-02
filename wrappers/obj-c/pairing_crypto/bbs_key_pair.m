#import <Foundation/Foundation.h>

#import "PairingCryptoError.h"
#import "pairing_crypto_bbs.h"
#import "bbs_key_pair.h"

/** @brief BBS key pair */
@interface BbsKeyPair ()

/** @brief secret key */
@property(nonatomic, readwrite) NSData *secretKey;

/** @brief public key */
@property(nonatomic, readwrite) NSData *publicKey;

@end

@implementation BbsKeyPair

- (nullable instancetype)initWithIkm:(NSData *_Nonnull)ikm
                             keyInfo:(NSData *_Nullable)keyInfo
                           withError:(NSError *_Nullable *_Nullable)errorPtr {
    [self generateKeyPair:ikm keyInfo:keyInfo withError:errorPtr];
    return self;
}

- (void) generateKeyPair:(NSData *_Nonnull)ikm
                 keyInfo:(NSData *_Nullable)keyInfo
                withError:(NSError *_Nullable *_Nullable)errorPtr {

    [self doesNotRecognizeSelector:_cmd];

}

@end
