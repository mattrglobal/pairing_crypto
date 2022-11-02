#ifndef __pairing__crypto__bbs__included__
#define __pairing__crypto__bbs__included__

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#include "pairing_crypto_common.h"

#define _Nonnull
#define _Nullable
#define nullable

/** BBS BLS12-381 Secret Key Size */
#define BBS_BLS12381_SECRET_KEY_SIZE (32)

/** BBS BLS12-381 Public Key Size */
#define BBS_BLS12381_PUBLIC_KEY_SIZE (96)

/** BBS BLS12-381 Signature Size */
#define BBS_BLS12381_SIGNATURE_SIZE (112)

/* Used for receiving a pairing_crypto_byte_buffer_t from C that was allocated by either C or Rust.
 *  If Rust allocated, then the outgoing struct is `ffi_support::pairing_crypto_byte_buffer_t`
 *  Caller is responsible for calling free where applicable.
 */
typedef struct
{
  int64_t len;
  uint8_t *_Nonnull data;
} pairing_crypto_byte_buffer_t;

#ifdef __cplusplus
extern "C"
{
#endif

  /**
   * Generate a BBS BLS 12-381 curve key pair in the field.
   *
   * * ikm: UInt8Array with 32 elements
   * * key_info: UInt8Array with 32 elements
   */
  int32_t bbs_bls12_381_shake_256_generate_key_pair(pairing_crypto_byte_buffer_t ikm,
                                                    pairing_crypto_byte_buffer_t key_info,
                                                    pairing_crypto_byte_buffer_t *_Nullable secret_key,
                                                    pairing_crypto_byte_buffer_t *_Nullable public_key,
                                                    pairing_crypto_error_t *_Nullable err);

  uint64_t bbs_bls12_381_shake_256_sign_context_init(pairing_crypto_error_t *_Nullable err);

  int32_t bbs_bls12_381_shake_256_sign_context_set_secret_key(uint64_t handle,
                                                              pairing_crypto_byte_buffer_t *value,
                                                              pairing_crypto_error_t *_Nullable err);

  int32_t bbs_bls12_381_shake_256_sign_context_set_public_key(uint64_t handle,
                                                              pairing_crypto_byte_buffer_t *value,
                                                              pairing_crypto_error_t *_Nullable err);

  int32_t bbs_bls12_381_shake_256_sign_context_set_header(uint64_t handle,
                                                          pairing_crypto_byte_buffer_t *value,
                                                          pairing_crypto_error_t *_Nullable err);

  int32_t bbs_bls12_381_shake_256_sign_context_add_message(uint64_t handle,
                                                           pairing_crypto_byte_buffer_t *value,
                                                           pairing_crypto_error_t *_Nullable err);

  int32_t bbs_bls12_381_shake_256_sign_context_finish(uint64_t handle,
                                                      pairing_crypto_byte_buffer_t *_Nullable signature,
                                                      pairing_crypto_error_t *_Nullable err);

  void bbs_bls12_381_shake_256_sign_free(uint64_t v, pairing_crypto_error_t *_Nullable err);

  uint64_t bbs_bls12_381_shake_256_verify_context_init(pairing_crypto_error_t *_Nullable err);

  int32_t bbs_bls12_381_shake_256_verify_context_set_public_key(uint64_t handle,
                                                                pairing_crypto_byte_buffer_t *value,
                                                                pairing_crypto_error_t *_Nullable err);

  int32_t bbs_bls12_381_shake_256_verify_context_set_header(uint64_t handle,
                                                            pairing_crypto_byte_buffer_t *value,
                                                            pairing_crypto_error_t *_Nullable err);

  int32_t bbs_bls12_381_shake_256_verify_context_add_message(uint64_t handle,
                                                             pairing_crypto_byte_buffer_t *value,
                                                             pairing_crypto_error_t *_Nullable err);

  int32_t bbs_bls12_381_shake_256_verify_context_set_signature(uint64_t handle,
                                                               pairing_crypto_byte_buffer_t *value,
                                                               pairing_crypto_error_t *_Nullable err);

  int32_t bbs_bls12_381_shake_256_verify_context_finish(uint64_t handle, pairing_crypto_error_t *_Nullable err);

  void bbs_bls12_381_shake_256_verify_free(uint64_t v, pairing_crypto_error_t *_Nullable err);

  /**
   * Return the size of proof in bytes.
   *
   * * num_undisclosed_messages: number of undisclosed messages from orginal
   *   message set
   */
  int32_t bbs_bls12_381_shake_256_get_proof_size(uintptr_t num_undisclosed_messages);

  uint64_t bbs_bls12_381_shake_256_proof_gen_context_init(pairing_crypto_error_t *_Nullable err);

  int32_t bbs_bls12_381_shake_256_proof_gen_context_set_public_key(uint64_t handle,
                                                                      pairing_crypto_byte_buffer_t *value,
                                                                      pairing_crypto_error_t *_Nullable err);

  int32_t bbs_bls12_381_shake_256_proof_gen_context_set_header(uint64_t handle,
                                                                  pairing_crypto_byte_buffer_t *value,
                                                                  pairing_crypto_error_t *_Nullable err);

  int32_t bbs_bls12_381_shake_256_proof_gen_context_set_signature(uint64_t handle,
                                                                     pairing_crypto_byte_buffer_t *value,
                                                                     pairing_crypto_error_t *_Nullable err);

  int32_t bbs_bls12_381_shake_256_proof_gen_context_set_presentation_header(uint64_t handle,
                                                                                pairing_crypto_byte_buffer_t *value,
                                                                                pairing_crypto_error_t *_Nullable err);

  int32_t bbs_bls12_381_shake_256_proof_gen_context_add_message(uint64_t handle,
                                                                   bool reveal,
                                                                   pairing_crypto_byte_buffer_t *message,
                                                                   pairing_crypto_error_t *_Nullable err);

  int32_t bbs_bls12_381_shake_256_proof_gen_context_finish(uint64_t handle,
                                                              pairing_crypto_byte_buffer_t *_Nullable proof,
                                                              pairing_crypto_error_t *_Nullable err);

  void bbs_bls12_381_shake_256_proof_gen_free(uint64_t v, pairing_crypto_error_t *_Nullable err);

  uint64_t bbs_bls12_381_shake_256_proof_verify_context_init(pairing_crypto_error_t *_Nullable err);

  int32_t bbs_bls12_381_shake_256_proof_verify_context_set_public_key(uint64_t handle,
                                                                      pairing_crypto_byte_buffer_t *value,
                                                                      pairing_crypto_error_t *_Nullable err);

  int32_t bbs_bls12_381_shake_256_proof_verify_context_set_header(uint64_t handle,
                                                                  pairing_crypto_byte_buffer_t *value,
                                                                  pairing_crypto_error_t *_Nullable err);

  int32_t bbs_bls12_381_shake_256_proof_verify_context_set_proof(uint64_t handle,
                                                                 pairing_crypto_byte_buffer_t *value,
                                                                 pairing_crypto_error_t *_Nullable err);

  int32_t bbs_bls12_381_shake_256_proof_verify_context_set_presentation_header(uint64_t handle,
                                                                                pairing_crypto_byte_buffer_t *value,
                                                                                pairing_crypto_error_t *_Nullable err);

  int32_t bbs_bls12_381_shake_256_proof_verify_context_set_total_message_count(uint64_t handle,
                                                                               uintptr_t value,
                                                                               pairing_crypto_error_t *_Nullable err);

  int32_t bbs_bls12_381_shake_256_proof_verify_context_add_message(uint64_t handle,
                                                                   uintptr_t index,
                                                                   pairing_crypto_byte_buffer_t *message,
                                                                   pairing_crypto_error_t *_Nullable err);

  int32_t bbs_bls12_381_shake_256_proof_verify_context_finish(uint64_t handle, pairing_crypto_error_t *_Nullable err);

  void bbs_bls12_381_shake_256_proof_verify_free(uint64_t v, pairing_crypto_error_t *_Nullable err);

  /**
   * Generate a BBS BLS 12-381 curve key pair in the field.
   *
   * * ikm: UInt8Array with 32 elements
   * * key_info: UInt8Array with 32 elements
   */
  int32_t bbs_bls12_381_sha_256_generate_key_pair(pairing_crypto_byte_buffer_t ikm,
                                                  pairing_crypto_byte_buffer_t key_info,
                                                  pairing_crypto_byte_buffer_t *_Nullable secret_key,
                                                  pairing_crypto_byte_buffer_t *_Nullable public_key,
                                                  pairing_crypto_error_t *_Nullable err);

  uint64_t bbs_bls12_381_sha_256_sign_context_init(pairing_crypto_error_t *_Nullable err);

  int32_t bbs_bls12_381_sha_256_sign_context_set_secret_key(uint64_t handle,
                                                            pairing_crypto_byte_buffer_t *value,
                                                            pairing_crypto_error_t *_Nullable err);

  int32_t bbs_bls12_381_sha_256_sign_context_set_public_key(uint64_t handle,
                                                            pairing_crypto_byte_buffer_t *value,
                                                            pairing_crypto_error_t *_Nullable err);

  int32_t bbs_bls12_381_sha_256_sign_context_set_header(uint64_t handle,
                                                        pairing_crypto_byte_buffer_t *value,
                                                        pairing_crypto_error_t *_Nullable err);

  int32_t bbs_bls12_381_sha_256_sign_context_add_message(uint64_t handle,
                                                         pairing_crypto_byte_buffer_t *value,
                                                         pairing_crypto_error_t *_Nullable err);

  int32_t bbs_bls12_381_sha_256_sign_context_finish(uint64_t handle,
                                                    pairing_crypto_byte_buffer_t *_Nullable signature,
                                                    pairing_crypto_error_t *_Nullable err);

  void bbs_bls12_381_sha_256_sign_free(uint64_t v, pairing_crypto_error_t *_Nullable err);

  uint64_t bbs_bls12_381_sha_256_verify_context_init(pairing_crypto_error_t *_Nullable err);

  int32_t bbs_bls12_381_sha_256_verify_context_set_public_key(uint64_t handle,
                                                              pairing_crypto_byte_buffer_t *value,
                                                              pairing_crypto_error_t *_Nullable err);

  int32_t bbs_bls12_381_sha_256_verify_context_set_header(uint64_t handle,
                                                          pairing_crypto_byte_buffer_t *value,
                                                          pairing_crypto_error_t *_Nullable err);

  int32_t bbs_bls12_381_sha_256_verify_context_add_message(uint64_t handle,
                                                           pairing_crypto_byte_buffer_t *value,
                                                           pairing_crypto_error_t *_Nullable err);

  int32_t bbs_bls12_381_sha_256_verify_context_set_signature(uint64_t handle,
                                                             pairing_crypto_byte_buffer_t *value,
                                                             pairing_crypto_error_t *_Nullable err);

  int32_t bbs_bls12_381_sha_256_verify_context_finish(uint64_t handle, pairing_crypto_error_t *_Nullable err);

  void bbs_bls12_381_sha_256_verify_free(uint64_t v, pairing_crypto_error_t *_Nullable err);

  /**
   * Return the size of proof in bytes.
   *
   * * num_undisclosed_messages: number of undisclosed messages from orginal
   *   message set
   */
  int32_t bbs_bls12_381_sha_256_get_proof_size(uintptr_t num_undisclosed_messages);

  uint64_t bbs_bls12_381_sha_256_proof_gen_context_init(pairing_crypto_error_t *_Nullable err);

  int32_t bbs_bls12_381_sha_256_proof_gen_context_set_public_key(uint64_t handle,
                                                                    pairing_crypto_byte_buffer_t *value,
                                                                    pairing_crypto_error_t *_Nullable err);

  int32_t bbs_bls12_381_sha_256_proof_gen_context_set_header(uint64_t handle,
                                                                pairing_crypto_byte_buffer_t *value,
                                                                pairing_crypto_error_t *_Nullable err);

  int32_t bbs_bls12_381_sha_256_proof_gen_context_set_signature(uint64_t handle,
                                                                   pairing_crypto_byte_buffer_t *value,
                                                                   pairing_crypto_error_t *_Nullable err);

  int32_t bbs_bls12_381_sha_256_proof_gen_context_set_presentation_header(uint64_t handle,
                                                                              pairing_crypto_byte_buffer_t *value,
                                                                              pairing_crypto_error_t *_Nullable err);

  int32_t bbs_bls12_381_sha_256_proof_gen_context_add_message(uint64_t handle,
                                                                 bool reveal,
                                                                 pairing_crypto_byte_buffer_t *message,
                                                                 pairing_crypto_error_t *_Nullable err);

  int32_t bbs_bls12_381_sha_256_proof_gen_context_finish(uint64_t handle,
                                                            pairing_crypto_byte_buffer_t *_Nullable proof,
                                                            pairing_crypto_error_t *_Nullable err);

  void bbs_bls12_381_sha_256_proof_gen_free(uint64_t v, pairing_crypto_error_t *_Nullable err);

  uint64_t bbs_bls12_381_sha_256_proof_verify_context_init(pairing_crypto_error_t *_Nullable err);

  int32_t bbs_bls12_381_sha_256_proof_verify_context_set_public_key(uint64_t handle,
                                                                    pairing_crypto_byte_buffer_t *value,
                                                                    pairing_crypto_error_t *_Nullable err);

  int32_t bbs_bls12_381_sha_256_proof_verify_context_set_header(uint64_t handle,
                                                                pairing_crypto_byte_buffer_t *value,
                                                                pairing_crypto_error_t *_Nullable err);

  int32_t bbs_bls12_381_sha_256_proof_verify_context_set_proof(uint64_t handle,
                                                               pairing_crypto_byte_buffer_t *value,
                                                               pairing_crypto_error_t *_Nullable err);

  int32_t bbs_bls12_381_sha_256_proof_verify_context_set_presentation_header(uint64_t handle,
                                                                              pairing_crypto_byte_buffer_t *value,
                                                                              pairing_crypto_error_t *_Nullable err);

  int32_t bbs_bls12_381_sha_256_proof_verify_context_set_total_message_count(uint64_t handle,
                                                                             uintptr_t value,
                                                                             pairing_crypto_error_t *_Nullable err);

  int32_t bbs_bls12_381_sha_256_proof_verify_context_add_message(uint64_t handle,
                                                                 uintptr_t index,
                                                                 pairing_crypto_byte_buffer_t *message,
                                                                 pairing_crypto_error_t *_Nullable err);

  int32_t bbs_bls12_381_sha_256_proof_verify_context_finish(uint64_t handle, pairing_crypto_error_t *_Nullable err);

  void bbs_bls12_381_sha_256_proof_verify_free(uint64_t v, pairing_crypto_error_t *_Nullable err);

  void pairing_crypto_byte_buffer_free(pairing_crypto_byte_buffer_t v);

#ifdef __cplusplus
} // extern "C"
#endif

#endif /* __pairing__crypto__bbs__included__ */
