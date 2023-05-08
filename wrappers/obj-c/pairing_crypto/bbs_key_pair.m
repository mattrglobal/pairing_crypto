#import <Foundation/Foundation.h>

#import "PairingCryptoError.h"
#import "pairing_crypto_bbs.h"
#import "bbs_key_pair.h"


@implementation PCLBbsKeyPair

- (nullable instancetype)initWithIkm:(NSData *_Nullable)ikm
                             keyInfo:(NSData *_Nullable)keyInfo
                           withError:(NSError *_Nullable *_Nullable)errorPtr {
    [self generateKeyPair:ikm keyInfo:keyInfo withError:errorPtr];
    return self;
}

- (void) generateKeyPair:(NSData *_Nullable)ikm
                 keyInfo:(NSData *_Nullable)keyInfo
                withError:(NSError *_Nullable *_Nullable)errorPtr {

    [self doesNotRecognizeSelector:_cmd];

}

@end
