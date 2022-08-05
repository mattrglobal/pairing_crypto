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
- (nullable instancetype)createProof:(BbsSignature *_Nonnull)signature
                             keyPair:(BbsKeyPair *_Nonnull)keyPair
                               nonce:(NSData *_Nonnull)nonce
                            messages:(NSArray *_Nonnull)messages
                            revealed:(NSArray *_Nonnull)revealed
                           withError:(NSError *_Nullable *_Nullable)errorPtr;

/**
 * @Verifies the BBS signature proof
 */
- (bool)verifyProof:(BbsKeyPair *_Nonnull)keyPair
           messages:(NSArray *_Nonnull)messages
              nonce:(NSData *_Nonnull)nonce
          withError:(NSError *_Nullable *_Nullable)errorPtr;

@end

#endif /* bbs_signature_proof_h */
