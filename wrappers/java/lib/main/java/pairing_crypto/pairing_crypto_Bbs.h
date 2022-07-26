/* DO NOT EDIT THIS FILE - it is machine generated */
#include <jni.h>
/* Header for class pairing_crypto_Bbs */

#ifndef _Included_pairing_crypto_Bbs
#define _Included_pairing_crypto_Bbs
#ifdef __cplusplus
extern "C" {
#endif
/*
 * Class:     pairing_crypto_Bbs
 * Method:    bbs_bls12381_generate_key_pair
 * Signature: ([B[B[B[B)I
 */
JNIEXPORT jint JNICALL Java_pairing_1crypto_Bbs_bbs_1bls12381_1generate_1key_1pair
  (JNIEnv *, jclass, jbyteArray, jbyteArray, jbyteArray, jbyteArray);

/*
 * Class:     pairing_crypto_Bbs
 * Method:    get_last_error
 * Signature: ()Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_pairing_1crypto_Bbs_get_1last_1error
  (JNIEnv *, jclass);

#ifdef __cplusplus
}
#endif
#endif
