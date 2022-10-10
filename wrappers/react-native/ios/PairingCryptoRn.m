#import <Foundation/Foundation.h>
#import <React/RCTConvert.h>

// #import "include/bbs/bbs_signature.h"
// #import "include/bbs/bbs_bls12381_sha256_key_pair.h"

#import <pairing-crypto/bbs_signature.h>
#import <pairing-crypto/bbs_bls12381_sha256_key_pair.h>

// #import <pairing-crypto/pairing_crypto_bbs.h>
// #import <pairing-crypto/bbs/bbs_signature.m>

#import "Convert.h"
#import "Operation.h"
#import "PairingCryptoRn.h"

#ifdef RCT_NEW_ARCH_ENABLED
#import "RNPairingCryptoRnSpec.h"
#endif

@implementation PairingCryptoRn

RCT_EXPORT_MODULE()

//TODO check heap allocations are all free'd

RCT_EXPORT_METHOD(Bls12381Sha256GenerateKeyPair:(NSDictionary *)request
                  withResolver:(RCTPromiseResolveBlock)resolve
                  withRejecter:(RCTPromiseRejectBlock)reject)
{
  Operation<NSDictionary*, NSDictionary*> *operation = [Operation new:^NSDictionary*(NSDictionary* request, NSError** error) {
      NSData *ikm = nil;
      NSData *keyInfo = nil;

      if ([request valueForKey:@"ikm"] != nil) {
        ikm = [Convert dataFromByteArray:[RCTConvert NSArray:request[@"ikm"]]];
      }
      if ([request valueForKey:@"keyInfo"] != nil) {
        ikm = [Convert dataFromByteArray:[RCTConvert NSArray:request[@"keyInfo"]]];
      }

      BbsBls12381Sha256KeyPair *keyPair = [[BbsBls12381Sha256KeyPair alloc] initWithIkm:ikm
                                                                                keyInfo:keyInfo
                                                                              withError:error];

      return [NSDictionary dictionaryWithObjects:@[[Convert byteArrayFromData:keyPair.publicKey],
                                                   [Convert byteArrayFromData:keyPair.secretKey]]
                                         forKeys:@[@"publicKey",
                                                   @"secretKey"]];
    }];

  [operation exec:request
     withResolver:resolve
     withRejecter:reject];
}

@end
