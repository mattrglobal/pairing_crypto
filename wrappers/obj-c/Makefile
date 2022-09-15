TARGET = pairing_crypto_obj_c

_CC = gcc
# _GNUSTEP_LIBS = $(shell gnustep-config --base-libs)
# _GNUSTEP_CFLAGS = $(shell gnustep-config --objc-flags)

OUTDIR = ./libraries
SUBDIR = pairing_crypto pairing_crypto/bbs
DIR_OBJ = ./build

INCS = $(wildcard *.h $(foreach fd, $(SUBDIR), $(fd)/*.h))
SRCS = $(wildcard *.m $(foreach fd, $(SUBDIR), $(fd)/*.m))
OBJS = $(addprefix $(DIR_OBJ)/, $(SRCS:m=o))
INC_DIRS = -I./ -Ipairing_crypto/include -Ipairing_crypto/include/bbs
FRAMEWORKS:= -framework Foundation
LIBS = -lpairing_crypto_c -lobjc
LIB_DIRS = -Llibraries

_CC_FLAGS = $(INCLUDES) $(_GNUSTEP_CFLAGS)
_LD_FLAGS = -L. $(_GNUSTEP_LIBS) $(LIB_DIRS) $(LIBS) $(FRAMEWORKS)

PHONY := $(TARGET)
$(TARGET): $(OBJS)
	$(_CC) -o $(OUTDIR)/$@ $(OBJS) $(_LD_FLAGS) --shared

$(DIR_OBJ)/%.o: %.m $(INCS)
	mkdir -p $(@D)
	$(CC) -o $@ $(_CC_FLAGS) -c $< $(INC_DIRS)

PHONY += clean
clean:
	rm -rf $(OUTDIR)/lib$(TARGET).so $(DIR_OBJ)/*

PHONY += echoes
echoes:
	@echo "INC files: $(INCS)"
	@echo "SRC files: $(SRCS)"
	@echo "OBJ files: $(OBJS)"
	@echo "LIB files: $(LIBS)"
	@echo "INC DIR: $(INC_DIRS)"
	@echo "LIB DIR: $(LIB_DIRS)"

.PHONY = $(PHONY)
