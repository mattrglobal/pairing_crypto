#ifndef bbs_key_pair_h
#define bbs_key_pair_h

/** @brief BBS key pair */
@interface BbsKeyPair : NSObject

/** @brief secret key */
@property(nonatomic, readonly) NSData *_Nullable secretKey;

/** @brief public key */
@property(nonatomic, readonly) NSData *_Nonnull publicKey;

/**
 * @brief Generates a new BBS BLS 12-381 key pair by using an IKM and optionally supplied key-info
 */
- (nullable instancetype)initWithIkm:(NSData *_Nonnull)ikm
                             keyInfo:(NSData *_Nullable)keyInfo
                           withError:(NSError *_Nullable *_Nullable)errorPtr;

@end

#endif /* bbs_key_pair_h */
