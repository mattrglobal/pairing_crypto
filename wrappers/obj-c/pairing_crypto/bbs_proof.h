#ifndef bbs_signature_proof_h
#define bbs_signature_proof_h

#import "bbs_key_pair.h"
#import "bbs_signature.h"

/** @brief BBS Signature Proof */
@interface BbsProof : NSObject

/** @brief proof */
@property(nonatomic, readonly) NSData *_Nonnull value;

/**
 * @brief Creates a BBS signature proof from the raw bytes
 */
- (nullable instancetype)initWithBytes:(NSData *_Nonnull)bytes
                             withError:(NSError *_Nullable *_Nullable)errorPtr;

/**
 * @brief Creates a BBS signature proof
 */
- (nullable instancetype)createProof:(NSData *_Nonnull)publicKey
                              header:(NSData *_Nullable)header
                 presentationMessage:(NSData *_Nullable)presentationMessage
                           signature:(NSData *_Nonnull)signature
                    disclosedIndices:(NSSet *_Nullable)disclosedIndices
                            messages:(NSArray *_Nullable)messages
                           withError:(NSError *_Nullable *_Nullable)errorPtr;

/**
 * @Verifies the BBS signature proof
 */
- (bool)verifyProof:(NSData *_Nonnull)publicKey
                 header:(NSData *_Nullable)header
    presentationMessage:(NSData *_Nullable)presentationMessage
                  proof:(NSData *_Nonnull)proof
               messages:(NSDictionary *_Nullable)messages
              withError:(NSError *_Nullable *_Nullable)errorPtr;

@end

#endif /* bbs_signature_proof_h */
