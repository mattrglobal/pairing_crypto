#import <Foundation/Foundation.h>
#import "BbsSignatureError.h"
#import "pairing_crypto.h"

static NSString *const BbsSignatureErrorDomain = @"BbsSignatureError";

@implementation BbsSignatureError

+ (NSError *)errorFromBbsSignatureError:(bbs_signature_error_t *)error {
    
    NSMutableDictionary *userInfo = [NSMutableDictionary new];
    
    if (error->message != NULL) {
        [userInfo setValue:[NSString stringWithUTF8String:error->message] forKey:@"message"];
        free(error->message);
    }
    
    free(error);
    return [NSError errorWithDomain:BbsSignatureErrorDomain code:error->code userInfo:userInfo];
}

@end
