/* DO NOT EDIT THIS FILE - it is machine generated */
#include <jni.h>
/* Header for class pairing_crypto_Bls12381Shake256 */

#ifndef _Included_pairing_crypto_Bls12381Shake256
#define _Included_pairing_crypto_Bls12381Shake256
#ifdef __cplusplus
extern "C" {
#endif
#undef pairing_crypto_Bls12381Shake256_SECRET_KEY_SIZE
#define pairing_crypto_Bls12381Shake256_SECRET_KEY_SIZE 32L
#undef pairing_crypto_Bls12381Shake256_PUBLIC_KEY_SIZE
#define pairing_crypto_Bls12381Shake256_PUBLIC_KEY_SIZE 96L
#undef pairing_crypto_Bls12381Shake256_SIGNATURE_SIZE
#define pairing_crypto_Bls12381Shake256_SIGNATURE_SIZE 112L
/*
 * Class:     pairing_crypto_Bls12381Shake256
 * Method:    generate_key_pair
 * Signature: ([B[B[B[B)I
 */
JNIEXPORT jint JNICALL Java_pairing_1crypto_Bls12381Shake256_generate_1key_1pair
  (JNIEnv *, jclass, jbyteArray, jbyteArray, jbyteArray, jbyteArray);

/*
 * Class:     pairing_crypto_Bls12381Shake256
 * Method:    sign_context_init
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_pairing_1crypto_Bls12381Shake256_sign_1context_1init
  (JNIEnv *, jclass);

/*
 * Class:     pairing_crypto_Bls12381Shake256
 * Method:    sign_context_set_secret_key
 * Signature: (J[B)I
 */
JNIEXPORT jint JNICALL Java_pairing_1crypto_Bls12381Shake256_sign_1context_1set_1secret_1key
  (JNIEnv *, jclass, jlong, jbyteArray);

/*
 * Class:     pairing_crypto_Bls12381Shake256
 * Method:    sign_context_set_public_key
 * Signature: (J[B)I
 */
JNIEXPORT jint JNICALL Java_pairing_1crypto_Bls12381Shake256_sign_1context_1set_1public_1key
  (JNIEnv *, jclass, jlong, jbyteArray);

/*
 * Class:     pairing_crypto_Bls12381Shake256
 * Method:    sign_context_set_header
 * Signature: (J[B)I
 */
JNIEXPORT jint JNICALL Java_pairing_1crypto_Bls12381Shake256_sign_1context_1set_1header
  (JNIEnv *, jclass, jlong, jbyteArray);

/*
 * Class:     pairing_crypto_Bls12381Shake256
 * Method:    sign_context_add_message
 * Signature: (J[B)I
 */
JNIEXPORT jint JNICALL Java_pairing_1crypto_Bls12381Shake256_sign_1context_1add_1message
  (JNIEnv *, jclass, jlong, jbyteArray);

/*
 * Class:     pairing_crypto_Bls12381Shake256
 * Method:    sign_context_finish
 * Signature: (J[B)I
 */
JNIEXPORT jint JNICALL Java_pairing_1crypto_Bls12381Shake256_sign_1context_1finish
  (JNIEnv *, jclass, jlong, jbyteArray);

/*
 * Class:     pairing_crypto_Bls12381Shake256
 * Method:    verify_context_init
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_pairing_1crypto_Bls12381Shake256_verify_1context_1init
  (JNIEnv *, jclass);

/*
 * Class:     pairing_crypto_Bls12381Shake256
 * Method:    verify_context_set_public_key
 * Signature: (J[B)I
 */
JNIEXPORT jint JNICALL Java_pairing_1crypto_Bls12381Shake256_verify_1context_1set_1public_1key
  (JNIEnv *, jclass, jlong, jbyteArray);

/*
 * Class:     pairing_crypto_Bls12381Shake256
 * Method:    verify_context_set_header
 * Signature: (J[B)I
 */
JNIEXPORT jint JNICALL Java_pairing_1crypto_Bls12381Shake256_verify_1context_1set_1header
  (JNIEnv *, jclass, jlong, jbyteArray);

/*
 * Class:     pairing_crypto_Bls12381Shake256
 * Method:    verify_context_add_message
 * Signature: (J[B)I
 */
JNIEXPORT jint JNICALL Java_pairing_1crypto_Bls12381Shake256_verify_1context_1add_1message
  (JNIEnv *, jclass, jlong, jbyteArray);

/*
 * Class:     pairing_crypto_Bls12381Shake256
 * Method:    verify_context_set_signature
 * Signature: (J[B)I
 */
JNIEXPORT jint JNICALL Java_pairing_1crypto_Bls12381Shake256_verify_1context_1set_1signature
  (JNIEnv *, jclass, jlong, jbyteArray);

/*
 * Class:     pairing_crypto_Bls12381Shake256
 * Method:    verify_context_finish
 * Signature: (J)I
 */
JNIEXPORT jint JNICALL Java_pairing_1crypto_Bls12381Shake256_verify_1context_1finish
  (JNIEnv *, jclass, jlong);

/*
 * Class:     pairing_crypto_Bls12381Shake256
 * Method:    get_proof_size
 * Signature: (I)I
 */
JNIEXPORT jint JNICALL Java_pairing_1crypto_Bls12381Shake256_get_1proof_1size
  (JNIEnv *, jclass, jint);

/*
 * Class:     pairing_crypto_Bls12381Shake256
 * Method:    proof_gen_context_init
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_pairing_1crypto_Bls12381Shake256_proof_1gen_1context_1init
  (JNIEnv *, jclass);

/*
 * Class:     pairing_crypto_Bls12381Shake256
 * Method:    proof_gen_context_set_public_key
 * Signature: (J[B)I
 */
JNIEXPORT jint JNICALL Java_pairing_1crypto_Bls12381Shake256_proof_1gen_1context_1set_1public_1key
  (JNIEnv *, jclass, jlong, jbyteArray);

/*
 * Class:     pairing_crypto_Bls12381Shake256
 * Method:    proof_gen_context_set_header
 * Signature: (J[B)I
 */
JNIEXPORT jint JNICALL Java_pairing_1crypto_Bls12381Shake256_proof_1gen_1context_1set_1header
  (JNIEnv *, jclass, jlong, jbyteArray);

/*
 * Class:     pairing_crypto_Bls12381Shake256
 * Method:    proof_gen_context_set_signature
 * Signature: (J[B)I
 */
JNIEXPORT jint JNICALL Java_pairing_1crypto_Bls12381Shake256_proof_1gen_1context_1set_1signature
  (JNIEnv *, jclass, jlong, jbyteArray);

/*
 * Class:     pairing_crypto_Bls12381Shake256
 * Method:    proof_gen_context_set_presentation_message
 * Signature: (J[B)I
 */
JNIEXPORT jint JNICALL Java_pairing_1crypto_Bls12381Shake256_proof_1gen_1context_1set_1presentation_1message
  (JNIEnv *, jclass, jlong, jbyteArray);

/*
 * Class:     pairing_crypto_Bls12381Shake256
 * Method:    proof_gen_context_add_message
 * Signature: (JZ[B)I
 */
JNIEXPORT jint JNICALL Java_pairing_1crypto_Bls12381Shake256_proof_1gen_1context_1add_1message
  (JNIEnv *, jclass, jlong, jboolean, jbyteArray);

/*
 * Class:     pairing_crypto_Bls12381Shake256
 * Method:    proof_gen_context_finish
 * Signature: (J[B)I
 */
JNIEXPORT jint JNICALL Java_pairing_1crypto_Bls12381Shake256_proof_1gen_1context_1finish
  (JNIEnv *, jclass, jlong, jbyteArray);

/*
 * Class:     pairing_crypto_Bls12381Shake256
 * Method:    proof_verify_context_init
 * Signature: ()J
 */
JNIEXPORT jlong JNICALL Java_pairing_1crypto_Bls12381Shake256_proof_1verify_1context_1init
  (JNIEnv *, jclass);

/*
 * Class:     pairing_crypto_Bls12381Shake256
 * Method:    proof_verify_context_set_public_key
 * Signature: (J[B)I
 */
JNIEXPORT jint JNICALL Java_pairing_1crypto_Bls12381Shake256_proof_1verify_1context_1set_1public_1key
  (JNIEnv *, jclass, jlong, jbyteArray);

/*
 * Class:     pairing_crypto_Bls12381Shake256
 * Method:    proof_verify_context_set_header
 * Signature: (J[B)I
 */
JNIEXPORT jint JNICALL Java_pairing_1crypto_Bls12381Shake256_proof_1verify_1context_1set_1header
  (JNIEnv *, jclass, jlong, jbyteArray);

/*
 * Class:     pairing_crypto_Bls12381Shake256
 * Method:    proof_verify_context_set_proof
 * Signature: (J[B)I
 */
JNIEXPORT jint JNICALL Java_pairing_1crypto_Bls12381Shake256_proof_1verify_1context_1set_1proof
  (JNIEnv *, jclass, jlong, jbyteArray);

/*
 * Class:     pairing_crypto_Bls12381Shake256
 * Method:    proof_verify_context_set_presentation_message
 * Signature: (J[B)I
 */
JNIEXPORT jint JNICALL Java_pairing_1crypto_Bls12381Shake256_proof_1verify_1context_1set_1presentation_1message
  (JNIEnv *, jclass, jlong, jbyteArray);

/*
 * Class:     pairing_crypto_Bls12381Shake256
 * Method:    proof_verify_context_set_total_message_count
 * Signature: (JI)I
 */
JNIEXPORT jint JNICALL Java_pairing_1crypto_Bls12381Shake256_proof_1verify_1context_1set_1total_1message_1count
  (JNIEnv *, jclass, jlong, jint);

/*
 * Class:     pairing_crypto_Bls12381Shake256
 * Method:    proof_verify_context_add_message
 * Signature: (JI[B)I
 */
JNIEXPORT jint JNICALL Java_pairing_1crypto_Bls12381Shake256_proof_1verify_1context_1add_1message
  (JNIEnv *, jclass, jlong, jint, jbyteArray);

/*
 * Class:     pairing_crypto_Bls12381Shake256
 * Method:    proof_verify_context_finish
 * Signature: (J)I
 */
JNIEXPORT jint JNICALL Java_pairing_1crypto_Bls12381Shake256_proof_1verify_1context_1finish
  (JNIEnv *, jclass, jlong);

/*
 * Class:     pairing_crypto_Bls12381Shake256
 * Method:    get_last_error
 * Signature: ()Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_pairing_1crypto_Bls12381Shake256_get_1last_1error
  (JNIEnv *, jclass);

#ifdef __cplusplus
}
#endif
#endif
