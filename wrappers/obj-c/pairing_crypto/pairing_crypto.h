#ifndef __pairing__crypto__included__
#define __pairing__crypto__included__

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

/* Used for receiving a bbs_signature_byte_buffer_t from C that was allocated by either C or Rust.
 *  If Rust allocated, then the outgoing struct is `ffi_support::bbs_signature_byte_buffer_t`
 *  Caller is responsible for calling free where applicable.
 */
typedef struct
{
  int64_t len;
  uint8_t *_Nonnull data;
} bbs_signature_byte_buffer_t;

typedef struct
{
  int32_t code;
  char *_Nullable message; /* note: nullable */
} bbs_signature_error_t;

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
  int32_t bbs_bls12381_generate_key_pair(bbs_signature_byte_buffer_t ikm,
                                         bbs_signature_byte_buffer_t key_info,
                                         bbs_signature_byte_buffer_t *_Nullable secret_key,
                                         bbs_signature_byte_buffer_t *_Nullable public_key,
                                         bbs_signature_error_t *_Nullable err);

  uint64_t bbs_bls12381_sign_context_init(bbs_signature_error_t *_Nullable err);

  int32_t bbs_bls12381_sign_context_set_secret_key(uint64_t handle,
                                                   bbs_signature_byte_buffer_t value,
                                                   bbs_signature_error_t *_Nullable err);

  int32_t bbs_bls12381_sign_context_set_public_key(uint64_t handle,
                                                   bbs_signature_byte_buffer_t value,
                                                   bbs_signature_error_t *_Nullable err);

  int32_t bbs_bls12381_sign_context_set_header(uint64_t handle,
                                               bbs_signature_byte_buffer_t value,
                                               bbs_signature_error_t *_Nullable err);

  int32_t bbs_bls12381_sign_context_add_message(uint64_t handle,
                                                bbs_signature_byte_buffer_t value,
                                                bbs_signature_error_t *_Nullable err);

  int32_t bbs_bls12381_sign_context_finish(uint64_t handle,
                                           bbs_signature_byte_buffer_t *_Nullable signature,
                                           bbs_signature_error_t *_Nullable err);

  void bbs_bls12381_sign_free(uint64_t v, bbs_signature_error_t *_Nullable err);

  uint64_t bbs_bls12381_verify_context_init(bbs_signature_error_t *_Nullable err);

  int32_t bbs_bls12381_verify_context_set_public_key(uint64_t handle,
                                                     bbs_signature_byte_buffer_t value,
                                                     bbs_signature_error_t *_Nullable err);

  int32_t bbs_bls12381_verify_context_set_header(uint64_t handle,
                                                 bbs_signature_byte_buffer_t value,
                                                 bbs_signature_error_t *_Nullable err);

  int32_t bbs_bls12381_verify_context_add_message(uint64_t handle,
                                                  bbs_signature_byte_buffer_t value,
                                                  bbs_signature_error_t *_Nullable err);

  int32_t bbs_bls12381_verify_context_set_signature(uint64_t handle,
                                                    bbs_signature_byte_buffer_t value,
                                                    bbs_signature_error_t *_Nullable err);

  int32_t bbs_bls12381_verify_context_finish(uint64_t handle, bbs_signature_error_t *_Nullable err);

  void bbs_bls12381_verify_free(uint64_t v, bbs_signature_error_t *_Nullable err);

  /**
   * Return the size of proof in bytes.
   *
   * * num_undisclosed_messages: number of undisclosed messages from orginal
   *   message set
   */
  int32_t bbs_bls12381_get_proof_size(uintptr_t num_undisclosed_messages);

  uint64_t bbs_bls12381_derive_proof_context_init(bbs_signature_error_t *_Nullable err);

  int32_t bbs_bls12381_derive_proof_context_set_public_key(uint64_t handle,
                                                           bbs_signature_byte_buffer_t value,
                                                           bbs_signature_error_t *_Nullable err);

  int32_t bbs_bls12381_derive_proof_context_set_header(uint64_t handle,
                                                       bbs_signature_byte_buffer_t value,
                                                       bbs_signature_error_t *_Nullable err);

  int32_t bbs_bls12381_derive_proof_context_set_signature(uint64_t handle,
                                                          bbs_signature_byte_buffer_t value,
                                                          bbs_signature_error_t *_Nullable err);

  int32_t bbs_bls12381_derive_proof_context_set_presentation_message(uint64_t handle,
                                                                     bbs_signature_byte_buffer_t value,
                                                                     bbs_signature_error_t *_Nullable err);

  int32_t bbs_bls12381_derive_proof_context_add_message(uint64_t handle,
                                                        bool reveal,
                                                        bbs_signature_byte_buffer_t message,
                                                        bbs_signature_error_t *_Nullable err);

  int32_t bbs_bls12381_derive_proof_context_finish(uint64_t handle,
                                                   bbs_signature_byte_buffer_t *_Nullable proof,
                                                   bbs_signature_error_t *_Nullable err);

  void bbs_bls12381_derive_proof_free(uint64_t v, bbs_signature_error_t *_Nullable err);

  uint64_t bbs_bls12381_verify_proof_context_init(bbs_signature_error_t *_Nullable err);

  int32_t bbs_bls12381_verify_proof_context_set_public_key(uint64_t handle,
                                                           bbs_signature_byte_buffer_t value,
                                                           bbs_signature_error_t *_Nullable err);

  int32_t bbs_bls12381_verify_proof_context_set_header(uint64_t handle,
                                                       bbs_signature_byte_buffer_t value,
                                                       bbs_signature_error_t *_Nullable err);

  int32_t bbs_bls12381_verify_proof_context_set_proof(uint64_t handle,
                                                      bbs_signature_byte_buffer_t value,
                                                      bbs_signature_error_t *_Nullable err);

  int32_t bbs_bls12381_verify_proof_context_set_presentation_message(uint64_t handle,
                                                                     bbs_signature_byte_buffer_t value,
                                                                     bbs_signature_error_t *_Nullable err);

  int32_t bbs_bls12381_verify_proof_context_set_total_message_count(uint64_t handle,
                                                                    uintptr_t value,
                                                                    bbs_signature_error_t *_Nullable err);

  int32_t bbs_bls12381_verify_proof_context_add_message(uint64_t handle,
                                                        uintptr_t index,
                                                        bbs_signature_byte_buffer_t message,
                                                        bbs_signature_error_t *_Nullable err);

  int32_t bbs_bls12381_verify_proof_context_finish(uint64_t handle, bbs_signature_error_t *_Nullable err);

  void bbs_bls12381_verify_proof_free(uint64_t v, bbs_signature_error_t *_Nullable err);

  void pairing_crypto_byte_buffer_free(bbs_signature_byte_buffer_t v);

#ifdef __cplusplus
} // extern "C"
#endif

#endif /* __pairing__crypto__included__ */
