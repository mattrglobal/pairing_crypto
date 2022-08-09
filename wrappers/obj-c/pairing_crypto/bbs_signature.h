#ifndef bbs_signature_h
#define bbs_signature_h

#include "bbs_key_pair.h"

/** @brief BBS Signature */
@interface BbsSignature : NSObject

/** @brief signature */
@property(nonatomic, readonly) NSData *_Nonnull value;

/**
 * @brief Creates a BBS signature from the raw bytes
 */
- (nullable instancetype)initWithBytes:(NSData *_Nonnull)bytes
                             withError:(NSError *_Nullable *_Nullable)errorPtr;

/**
 * @brief Creates a BBS signature
 */
- (nullable instancetype)sign:(BbsKeyPair *_Nonnull)keyPair
                       header:(NSData *)header
                     messages:(NSArray *)messages
                    withError:(NSError *_Nullable *_Nullable)errorPtr;

/**
 * @Verifies the BBS signature
 */
- (bool)verify:(NSData *_Nonnull)publicKey
        header:(NSData *)header
      messages:(NSArray *)messages
     withError:(NSError *_Nullable *_Nullable)errorPtr;

@end

#endif /* bbs_signature_h */
