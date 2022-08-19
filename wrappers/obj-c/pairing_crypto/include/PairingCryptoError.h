#ifndef NSError_PairingCryptoError_h
#define NSError_PairingCryptoError_h

#import <Foundation/Foundation.h>
#include "pairing_crypto_common.h"

@interface PairingCryptoError : NSObject

// TODO review ideally this would be an extension of NSError but there were issues with this approach
+ (NSError *)errorFromPairingCryptoError:(pairing_crypto_error_t *)error;

@end

#endif /* NSError_PairingCryptoError_h */
