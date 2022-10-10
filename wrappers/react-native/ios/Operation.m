// Inspired by @see https://raw.githubusercontent.com/Emurgo/react-native-cardano/master/ios/RNCSafeOperation.m

#import "Operation.h"
#import <React/RCTConvert.h>

@implementation RnBaseOperation

- (void)exec:(id)param withResolver:(RCTPromiseResolveBlock)resolve withRejecter:(RCTPromiseRejectBlock)reject {
    NSError* error = nil;
    id result = [self exec:param error:&error];
    if (error != nil) {
        reject([NSString stringWithFormat:@"%li", (long)[error code]],
               [error localizedDescription],
               error);
    } else {
        resolve(result);
    }
}

- (id)exec:(id)param error:(NSError **)error {
    NSAssert(true, @"Reload");
    return nil;
}

@end

@interface Operation<In, Out> (/* Private */)

@property (copy) Out (^callback)(In param, NSError** error);

@end

@implementation Operation

+ (RnBaseOperation *)new:(_Nullable id (^)(_Nullable id param, NSError** error))cb {
    return [[Operation alloc] initWithCallback: cb];
}

- (Operation *)initWithCallback:(_Nullable id(^)(_Nullable id param, NSError** error))cb {
    if (self = [super init]) {
        self.callback = cb;
    }
    return self;
}

- (id)exec:(id)param error:(NSError **)error {
    return self.callback(param, error);
}

@end
