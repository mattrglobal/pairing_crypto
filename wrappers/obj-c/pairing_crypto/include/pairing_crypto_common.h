#ifndef __pairing__crypto__common__included__
#define __pairing__crypto__common__included__

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#define _Nonnull
#define _Nullable
#define nullable

typedef struct
{
  int32_t code;
  char *_Nullable message; /* note: nullable */
} pairing_crypto_error_t;

#endif /* __pairing__crypto__common__included__ */
