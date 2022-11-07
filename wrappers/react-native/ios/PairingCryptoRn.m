#import <Foundation/Foundation.h>
#import <React/RCTConvert.h>

#import <bbs_signature.h>
#import <bbs_bls12381_sha256_key_pair.h>
#import <bbs_bls12381_shake256_key_pair.h>
#import <bbs_bls12381_sha256_signature.h>
#import <bbs_bls12381_shake256_signature.h>
#import <bbs_bls12381_sha256_proof.h>
#import <bbs_bls12381_shake256_proof.h>

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
        // TODO: Remove this fallback when obj-c wrapper supports nullable ikm
        else {
            int ikmLength = 32;
            NSMutableData* bytes = [NSMutableData dataWithLength:ikmLength];
            int result = SecRandomCopyBytes(kSecRandomDefault, ikmLength, [bytes mutableBytes]);
            NSAssert(result == errSecSuccess, @"Error generating random bytes: %d", result);
            ikm = bytes;
        }
        if ([request valueForKey:@"keyInfo"] != nil) {
            ikm = [Convert dataFromByteArray:[RCTConvert NSArray:request[@"keyInfo"]]];
        }
        
        BbsBls12381Sha256KeyPair *keyPair = [[BbsBls12381Sha256KeyPair alloc] initWithIkm:ikm keyInfo:keyInfo
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

RCT_EXPORT_METHOD(Bls12381Shake256GenerateKeyPair:(NSDictionary *)request
                  withResolver:(RCTPromiseResolveBlock)resolve
                  withRejecter:(RCTPromiseRejectBlock)reject)
{
    Operation<NSDictionary*, NSDictionary*> *operation = [Operation new:^NSDictionary*(NSDictionary* request, NSError** error) {
        NSData *ikm = nil;
        NSData *keyInfo = nil;
        
        if ([request valueForKey:@"ikm"] != nil) {
            ikm = [Convert dataFromByteArray:[RCTConvert NSArray:request[@"ikm"]]];
        }
        // TODO: Remove this fallback when obj-c wrapper supports nullable ikm
        else {
            int ikmLength = 32;
            NSMutableData* bytes = [NSMutableData dataWithLength:ikmLength];
            int result = SecRandomCopyBytes(kSecRandomDefault, ikmLength, [bytes mutableBytes]);
            NSAssert(result == errSecSuccess, @"Error generating random bytes: %d", result);
            ikm = bytes;
        }
        if ([request valueForKey:@"keyInfo"] != nil) {
            ikm = [Convert dataFromByteArray:[RCTConvert NSArray:request[@"keyInfo"]]];
        }
        
        BbsBls12381Shake256KeyPair *keyPair = [[BbsBls12381Shake256KeyPair alloc] initWithIkm:ikm keyInfo:keyInfo
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

RCT_EXPORT_METHOD(Bls12381Sha256Sign:(NSDictionary *)request
                  withResolver:(RCTPromiseResolveBlock)resolve
                  withRejecter:(RCTPromiseRejectBlock)reject)
{
    Operation<NSDictionary*, NSArray*> *operation = [Operation new:^NSArray*(NSDictionary* request, NSError** error) {
        NSArray *messages = nil;
        NSData *header = nil;
        NSData *secretKey = [Convert dataFromByteArray:[RCTConvert NSArray:request[@"secretKey"]]];
        NSData *publicKey = [Convert dataFromByteArray:[RCTConvert NSArray:request[@"publicKey"]]];
        
        if ([request valueForKey:@"header"] != nil) {
            header = [Convert dataFromByteArray:[RCTConvert NSArray:request[@"header"]]];
        }
        if ([request valueForKey:@"messages"] != nil) {
            messages = [Convert dataArrayFromArrayOfByteArrays:[RCTConvert NSArray:request[@"messages"]]];
        }
        
        BbsBls12381Sha256Signature *signature = [[BbsBls12381Sha256Signature alloc] sign:secretKey
                                                                               publicKey:publicKey
                                                                                  header:header
                                                                                messages:messages
                                                                               withError:error];
        return [Convert byteArrayFromData:signature.value];
    }];
    
    [operation exec:request
       withResolver:resolve
       withRejecter:reject];
}

RCT_EXPORT_METHOD(Bls12381Shake256Sign:(NSDictionary *)request
                  withResolver:(RCTPromiseResolveBlock)resolve
                  withRejecter:(RCTPromiseRejectBlock)reject)
{
    Operation<NSDictionary*, NSArray*> *operation = [Operation new:^NSArray*(NSDictionary* request, NSError** error) {
        NSArray *messages = nil;
        NSData *header = nil;
        NSData *secretKey = [Convert dataFromByteArray:[RCTConvert NSArray:request[@"secretKey"]]];
        NSData *publicKey = [Convert dataFromByteArray:[RCTConvert NSArray:request[@"publicKey"]]];
        
        if ([request valueForKey:@"header"] != nil) {
            header = [Convert dataFromByteArray:[RCTConvert NSArray:request[@"header"]]];
        }
        if ([request valueForKey:@"messages"] != nil) {
            messages = [Convert dataArrayFromArrayOfByteArrays:[RCTConvert NSArray:request[@"messages"]]];
        }
        
        BbsBls12381Shake256Signature *signature = [[BbsBls12381Shake256Signature alloc] sign:secretKey
                                                                                   publicKey:publicKey
                                                                                      header:header
                                                                                    messages:messages
                                                                                   withError:error];
        return [Convert byteArrayFromData:signature.value];
    }];
    
    [operation exec:request
       withResolver:resolve
       withRejecter:reject];
}

RCT_EXPORT_METHOD(Bls12381Sha256Verify:(NSDictionary *)request
                  withResolver:(RCTPromiseResolveBlock)resolve
                  withRejecter:(RCTPromiseRejectBlock)reject)
{
    Operation<NSDictionary*, NSNumber*> *operation = [Operation new:^NSNumber*(NSDictionary* request, NSError** error) {
        NSArray *messages = nil;
        NSData *header = nil;
        NSData *publicKey = [Convert dataFromByteArray:[RCTConvert NSArray:request[@"publicKey"]]];
        NSData *signatureBytes = [Convert dataFromByteArray:[RCTConvert NSArray:request[@"signature"]]];
        
        if ([request valueForKey:@"header"] != nil) {
            header = [Convert dataFromByteArray:[RCTConvert NSArray:request[@"header"]]];
        }
        if ([request valueForKey:@"messages"] != nil) {
            messages = [Convert dataArrayFromArrayOfByteArrays:[RCTConvert NSArray:request[@"messages"]]];
        }
        
        BbsBls12381Sha256Signature *signature = [[BbsBls12381Sha256Signature alloc] initWithBytes:signatureBytes
                                                                                        withError:error];
        return [[NSNumber alloc] initWithBool:[signature verify:publicKey
                                                         header:header
                                                       messages:messages
                                                      withError:error]];
    }];
    
    [operation exec:request
       withResolver:resolve
       withRejecter:reject];
}

RCT_EXPORT_METHOD(Bls12381Shake256Verify:(NSDictionary *)request
                  withResolver:(RCTPromiseResolveBlock)resolve
                  withRejecter:(RCTPromiseRejectBlock)reject)
{
    Operation<NSDictionary*, NSNumber*> *operation = [Operation new:^NSNumber*(NSDictionary* request, NSError** error) {
        NSArray *messages = nil;
        NSData *header = nil;
        NSData *publicKey = [Convert dataFromByteArray:[RCTConvert NSArray:request[@"publicKey"]]];
        NSData *signatureBytes = [Convert dataFromByteArray:[RCTConvert NSArray:request[@"signature"]]];
        
        if ([request valueForKey:@"header"] != nil) {
            header = [Convert dataFromByteArray:[RCTConvert NSArray:request[@"header"]]];
        }
        if ([request valueForKey:@"messages"] != nil) {
            messages = [Convert dataArrayFromArrayOfByteArrays:[RCTConvert NSArray:request[@"messages"]]];
        }
        
        BbsBls12381Shake256Signature *signature = [[BbsBls12381Shake256Signature alloc] initWithBytes:signatureBytes
                                                                                            withError:error];
        
        bool isVerified = [signature verify:publicKey
                                     header:header
                                   messages:messages
                                  withError:error];
        
        return [[NSNumber alloc] initWithBool:isVerified];
    }];
    
    [operation exec:request
       withResolver:resolve
       withRejecter:reject];
}

RCT_EXPORT_METHOD(Bls12381Sha256ProofVerify:(NSDictionary *)request
                  withResolver:(RCTPromiseResolveBlock)resolve
                  withRejecter:(RCTPromiseRejectBlock)reject)
{
    Operation<NSDictionary*, NSNumber*> *operation = [Operation new:^NSNumber*(NSDictionary* request, NSError** error) {
        NSMutableDictionary *disclosedMessage = nil;
        NSData *header = nil;
        NSData *presentationHeader = nil;
        NSData *publicKey = [Convert dataFromByteArray:[RCTConvert NSArray:request[@"publicKey"]]];
        NSData *proofBytes = [Convert dataFromByteArray:[RCTConvert NSArray:request[@"proof"]]];
        NSInteger totalMessageCount = [RCTConvert NSInteger:request[@"totalMessageCount"]];
        
        if ([request valueForKey:@"header"] != nil) {
            header = [Convert dataFromByteArray:[RCTConvert NSArray:request[@"header"]]];
        }
        if ([request valueForKey:@"presentationHeader"] != nil) {
            presentationHeader = [Convert dataFromByteArray:[RCTConvert NSArray:request[@"presentationHeader"]]];
        }
        if ([request valueForKey:@"messages"] != nil) {
            disclosedMessage = [[NSMutableDictionary alloc] init];
            NSDictionary *messagesInput = [RCTConvert NSDictionary:request[@"messages"]];
            
            for (NSString *key in messagesInput) {
                NSArray *messageBytes = [RCTConvert NSArray:[messagesInput valueForKey:key]];
                
                [disclosedMessage setObject:[Convert dataFromByteArray:messageBytes]
                                     forKey:[[NSNumber alloc] initWithLong:[key integerValue]]];
            }
        }
        
        BbsBls12381Sha256Proof *proof = [[BbsBls12381Sha256Proof alloc] initWithBytes:proofBytes
                                                                            withError:error];
        
        bool isVerified = [proof verifyProof:publicKey
                                      header:header
                          presentationHeader:presentationHeader
                           totalMessageCount:totalMessageCount
                                    messages:disclosedMessage
                                   withError:error];
        
        return [[NSNumber alloc] initWithBool:isVerified];
    }];
    
    [operation exec:request
       withResolver:resolve
       withRejecter:reject];
}

RCT_EXPORT_METHOD(Bls12381Shake256ProofVerify:(NSDictionary *)request
                  withResolver:(RCTPromiseResolveBlock)resolve
                  withRejecter:(RCTPromiseRejectBlock)reject)
{
    Operation<NSDictionary*, NSNumber*> *operation = [Operation new:^NSNumber*(NSDictionary* request, NSError** error) {
        NSMutableDictionary *disclosedMessage = nil;
        NSData *header = nil;
        NSData *presentationHeader = nil;
        NSData *publicKey = [Convert dataFromByteArray:[RCTConvert NSArray:request[@"publicKey"]]];
        NSData *proofBytes = [Convert dataFromByteArray:[RCTConvert NSArray:request[@"proof"]]];
        NSInteger totalMessageCount = [RCTConvert NSInteger:request[@"totalMessageCount"]];
        
        if ([request valueForKey:@"header"] != nil) {
            header = [Convert dataFromByteArray:[RCTConvert NSArray:request[@"header"]]];
        }
        if ([request valueForKey:@"presentationHeader"] != nil) {
            presentationHeader = [Convert dataFromByteArray:[RCTConvert NSArray:request[@"presentationHeader"]]];
        }
        if ([request valueForKey:@"messages"] != nil) {
            NSDictionary *messagesInput = [RCTConvert NSDictionary:request[@"messages"]];
            disclosedMessage = [[NSMutableDictionary alloc] init];
            
            for (NSString *key in messagesInput) {
                NSArray *messageBytes = [RCTConvert NSArray:[messagesInput valueForKey:key]];
                [disclosedMessage setObject:[Convert dataFromByteArray:messageBytes] forKey:key];
            }
        }
        
        BbsBls12381Shake256Proof *proof = [[BbsBls12381Shake256Proof alloc] initWithBytes:proofBytes
                                                                                withError:error];
        
        bool isVerified = [proof verifyProof:publicKey
                                      header:header
                          presentationHeader:presentationHeader
                           totalMessageCount:totalMessageCount
                                    messages:disclosedMessage
                                   withError:error];
        
        return [[NSNumber alloc] initWithBool:isVerified];
    }];
    
    [operation exec:request
       withResolver:resolve
       withRejecter:reject];
}

RCT_EXPORT_METHOD(Bls12381Sha256ProofGen:(NSDictionary *)request
                  withResolver:(RCTPromiseResolveBlock)resolve
                  withRejecter:(RCTPromiseRejectBlock)reject)
{
    Operation<NSDictionary*, NSArray*> *operation = [Operation new:^NSArray*(NSDictionary* request, NSError** error) {
        NSMutableSet *disclosedIndices = nil;
        NSMutableArray *messages = nil;
        NSData *header = nil;
        NSData *presentationHeader = nil;
        NSData *publicKey = [Convert dataFromByteArray:[RCTConvert NSArray:request[@"publicKey"]]];
        NSData *signatureBytes = [Convert dataFromByteArray:[RCTConvert NSArray:request[@"signature"]]];
        BOOL verifySignature = [request[@"verifySignature"] isEqual:@([RCTConvert BOOL:@(YES)])];
        
        if ([request valueForKey:@"header"] != nil) {
            header = [Convert dataFromByteArray:[RCTConvert NSArray:request[@"header"]]];
        }
        if ([request valueForKey:@"presentationHeader"] != nil) {
            presentationHeader = [Convert dataFromByteArray:[RCTConvert NSArray:request[@"presentationHeader"]]];
        }
        if ([request valueForKey:@"messages"] != nil) {
            NSArray *messagesInput = [RCTConvert NSArray:request[@"messages"]];
            
            disclosedIndices = [[NSMutableSet alloc] init];
            messages = [[NSMutableArray alloc] init];
            
            for (int idx = 0; idx < [messagesInput count]; idx++) {
                NSDictionary *input = [RCTConvert NSDictionary:messagesInput[idx]];
                NSArray *messageBytes = [RCTConvert NSArray:input[@"value"]];
                
                if ([input[@"reveal"] isEqual:@([RCTConvert BOOL:@(YES)])]) {
                    [disclosedIndices addObject:[NSNumber numberWithInt:idx]];
                }
                [messages addObject:[Convert dataFromByteArray:messageBytes]];
            }
        }
        
        BbsBls12381Sha256Signature *signature = [[BbsBls12381Sha256Signature alloc] initWithBytes:signatureBytes
                                                                                        withError:error];
        
        BbsBls12381Sha256Proof *proof = [[BbsBls12381Sha256Proof alloc] createProof:publicKey
                                                                             header:header
                                                                 presentationHeader:presentationHeader
                                                                          signature:signature
                                                                    verifySignature:verifySignature
                                                                   disclosedIndices:disclosedIndices
                                                                           messages:messages
                                                                          withError:error];
        
        return [Convert byteArrayFromData:proof.value];
    }];
    
    [operation exec:request
       withResolver:resolve
       withRejecter:reject];
}

RCT_EXPORT_METHOD(Bls12381Shake256ProofGen:(NSDictionary *)request
                  withResolver:(RCTPromiseResolveBlock)resolve
                  withRejecter:(RCTPromiseRejectBlock)reject)
{
    Operation<NSDictionary*, NSArray*> *operation = [Operation new:^NSArray*(NSDictionary* request, NSError** error) {
        NSMutableSet *disclosedIndices = nil;
        NSMutableArray *messages = nil;
        NSData *header = nil;
        NSData *presentationHeader = nil;
        NSData *publicKey = [Convert dataFromByteArray:[RCTConvert NSArray:request[@"publicKey"]]];
        NSData *signatureBytes = [Convert dataFromByteArray:[RCTConvert NSArray:request[@"signature"]]];
        BOOL verifySignature = [request[@"verifySignature"] isEqual:@([RCTConvert BOOL:@(YES)])];
        
        if ([request valueForKey:@"header"] != nil) {
            header = [Convert dataFromByteArray:[RCTConvert NSArray:request[@"header"]]];
        }
        if ([request valueForKey:@"presentationHeader"] != nil) {
            presentationHeader = [Convert dataFromByteArray:[RCTConvert NSArray:request[@"presentationHeader"]]];
        }
        if ([request valueForKey:@"messages"] != nil) {
            NSArray *messagesInput = [RCTConvert NSArray:request[@"messages"]];
            
            disclosedIndices = [[NSMutableSet alloc] init];
            messages = [[NSMutableArray alloc] init];
            
            for (int idx = 0; idx < [messagesInput count]; idx++) {
                NSDictionary *input = [RCTConvert NSDictionary:messagesInput[idx]];
                NSArray *messageBytes = [RCTConvert NSArray:input[@"value"]];
                
                if ([input[@"reveal"] isEqual:@([RCTConvert BOOL:@(YES)])]) {
                    [disclosedIndices addObject:[NSNumber numberWithInt:idx]];
                }
                [messages addObject:[Convert dataFromByteArray:messageBytes]];
            }
        }
        
        BbsBls12381Shake256Signature *signature = [[BbsBls12381Shake256Signature alloc] initWithBytes:signatureBytes
                                                                                            withError:error];
        
        BbsBls12381Shake256Proof *proof = [[BbsBls12381Shake256Proof alloc] createProof:publicKey
                                                                                 header:header
                                                                     presentationHeader:presentationHeader
                                                                              signature:signature
                                                                        verifySignature:verifySignature
                                                                       disclosedIndices:disclosedIndices
                                                                               messages:messages
                                                                              withError:error];
        
        return [Convert byteArrayFromData:proof.value];
    }];
    
    [operation exec:request
       withResolver:resolve
       withRejecter:reject];
}

@end
