_CC = clang
_GNUSTEP_LIBS = $(shell gnustep-config --base-libs)
_GNUSTEP_CFLAGS = $(shell gnustep-config --objc-flags)

_CC_FLAGS = $(_GNUSTEP_CFLAGS)
_LD_FLAGS = -L. $(_GNUSTEP_LIBS)


LIB_NAME = libpairing_crypto_obj_c.so
LIB_SRCS = bbs_key_pair.m bbs_signature.m bbs_proof.m BbsSignatureError.m

OBJ_EXT=o
LIB_OBJ_FILES=$(addsuffix .$(OBJ_EXT),$(notdir $(basename $(LIB_SRCS))))

.PHONY = clean all

all: $(LIB_NAME)

$(LIB_NAME): $(LIB_OBJ_FILES)
	$(_CC) $(_CC_FLAGS) $(LIB_OBJ_FILES) $(_LD_FLAGS) --shared  -o $(LIB_NAME)

%.$(OBJ_EXT): %.m
	$(_CC) $(_CC_FLAGS) -c $< 

clean:
	rm -rf *.o *.d *~ $(LIB_NAME)
