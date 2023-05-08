#import <Foundation/Foundation.h>

#import "PairingCryptoError.h"
#import "pairing_crypto_bbs.h"
#import "bbs_proof.h"

/** @brief A BBS Proof */
@implementation PCLBbsProof

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
                 presentationHeader:(NSData *_Nullable)presentationHeader
                           signature:(PCLBbsSignature *_Nonnull)signature
                     verifySignature:(BOOL)verifySignature
                    disclosedIndices:(NSSet *_Nullable)disclosedIndices
                            messages:(NSArray *_Nullable)messages
                           withError:(NSError *_Nullable *_Nullable)errorPtr {

    [self doCreateProof:publicKey
                        header:header
           presentationHeader:presentationHeader
                     signature:signature
               verifySignature:(BOOL)verifySignature
              disclosedIndices:disclosedIndices
                      messages:messages
                     withError:errorPtr];
    return self;
}

/** @brief Verify a BBS proof. */
- (bool)verifyProof:(NSData *_Nonnull)publicKey
             header:(NSData *_Nullable)header
presentationHeader:(NSData *_Nullable)presentationHeader
           messages:(NSDictionary *_Nullable)messages
          withError:(NSError *_Nullable *_Nullable)errorPtr {

    return [self doVerifyProof:publicKey
                               header:header
                  presentationHeader:presentationHeader
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
          presentationHeader:(NSData *_Nullable)presentationHeader
                    signature:(PCLBbsSignature *_Nonnull)signature
              verifySignature:(BOOL)verifySignature
             disclosedIndices:(NSSet *_Nullable)disclosedIndices
                     messages:(NSArray *_Nullable)messages
                    withError:(NSError *_Nullable *_Nullable)errorPtr {

                [self doesNotRecognizeSelector:_cmd];
}

/** @brief Verify a BBS proof. */
- (bool)doVerifyProof:(NSData *_Nonnull)publicKey
                      header:(NSData *_Nullable)header
         presentationHeader:(NSData *_Nullable)presentationHeader
                    messages:(NSDictionary *_Nullable)messages
                   withError:(NSError *_Nullable *_Nullable)errorPtr  {

                   [self doesNotRecognizeSelector:_cmd];
    return false;
}

@end
