#import <Foundation/Foundation.h>

#import "pairing_crypto_bbs.h"
#import "include/bbs/bbs_proof.h"
#import "include/PairingCryptoError.h"

@interface BbsProof ()

/** @brief A BBS Proof */
@property(nonatomic, readwrite) NSData *value;

@end

/** @brief A BBS Proof */
@implementation BbsProof

/** @brief Create a BBS proof from the raw bytes. */
- (nullable instancetype)initWithBytes:(NSData* _Nonnull)bytes
                             withError:(NSError *_Nullable*_Nullable)errorPtr {
    
    [self createFromBytes:bytes
                withError:errorPtr];
    return self;
}

/** @brief Create a BBS proof. */
- (nullable instancetype)createProof:(NSData *_Nonnull)publicKey
                              header:(NSData *_Nullable)header
                 presentationMessage:(NSData *_Nullable)presentationMessage
                           signature:(NSData *_Nonnull)signature
                    disclosedIndices:(NSSet *_Nullable)disclosedIndices
                            messages:(NSArray *_Nullable)messages
                           withError:(NSError *_Nullable *_Nullable)errorPtr {
    
    [self doCreateProof:publicKey
                        header:header
           presentationMessage:presentationMessage
                     signature:signature
              disclosedIndices:disclosedIndices
                      messages:messages
                     withError:errorPtr];
    return self;
}

/** @brief Verify a BBS proof. */
- (bool)verifyProof:(NSData *_Nonnull)publicKey
             header:(NSData *_Nullable)header
presentationMessage:(NSData *_Nullable)presentationMessage
total_message_count:(NSUInteger)total_message_count
           messages:(NSDictionary *_Nullable)messages
          withError:(NSError *_Nullable *_Nullable)errorPtr {
    
    return [self doVerifyProof:publicKey
                               header:header
                  presentationMessage:presentationMessage
                  total_message_count:total_message_count
                             messages:messages
                            withError:errorPtr];
}

/** @brief Create a BBS proof from the raw bytes. */
- (nullable instancetype)createFromBytes:(NSData* _Nonnull)bytes
                               withError:(NSError *_Nullable*_Nullable)errorPtr {
    
    self.value = [[NSData alloc] initWithData:bytes];
    return self;
}

/** @brief Create a BBS proof. */
- (void) doCreateProof:(NSData *_Nonnull)publicKey
                       header:(NSData *_Nullable)header
          presentationMessage:(NSData *_Nullable)presentationMessage
                    signature:(NSData *_Nonnull)signature
             disclosedIndices:(NSSet *_Nullable)disclosedIndices
                     messages:(NSArray *_Nullable)messages
                    withError:(NSError *_Nullable *_Nullable)errorPtr {
    
                [self doesNotRecognizeSelector:_cmd];
}

/** @brief Verify a BBS proof. */
- (bool)doVerifyProof:(NSData *_Nonnull)publicKey
                      header:(NSData *_Nullable)header
         presentationMessage:(NSData *_Nullable)presentationMessage
         total_message_count:(NSUInteger)total_message_count
                    messages:(NSDictionary *_Nullable)messages
                   withError:(NSError *_Nullable *_Nullable)errorPtr  {

                   [self doesNotRecognizeSelector:_cmd];
}

@end
