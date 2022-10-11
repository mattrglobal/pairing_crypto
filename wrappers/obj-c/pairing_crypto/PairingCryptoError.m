#import <Foundation/Foundation.h>
#import "PairingCryptoError.h"

static NSString *const PairingCryptoErrorDomain = @"PairingCryptoError";

@implementation PairingCryptoError

+ (NSError *)errorFromPairingCryptoError:(pairing_crypto_error_t *)error {

    NSMutableDictionary *userInfo = [NSMutableDictionary new];

    if (error->message != NULL) {
        [userInfo setValue:[NSString stringWithUTF8String:error->message] forKey:@"message"];
        free(error->message);
    }

    free(error);
    return [NSError errorWithDomain:PairingCryptoErrorDomain code:error->code userInfo:userInfo];
}

@end
