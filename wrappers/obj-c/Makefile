_CC = gcc
_GNUSTEP_LIBS = $(shell gnustep-config --base-libs)
_GNUSTEP_CFLAGS = $(shell gnustep-config --objc-flags)

PROJECT_DIR := $(realpath $(CURDIR)/..)
SOURCE_DIR := $(PROJECT_DIR)/pairing_crypto
BUILD_DIR := $(PROJECT_DIR)/build

DIRS = . bbs
SOURCE_DIRS = $(foreach dir, $(DIRS), $(addprefix $(SOURCE_DIR)/, $(dir)))
TARGET_DIRS = $(foreach dir, $(DIRS), $(addprefix $(BUILD_DIR)/, $(dir)))

INCLUDES = -I. -I$(SOURCE_DIR)/include -I$(SOURCE_DIR)/include/bbs
VPATH = $(SOURCE_DIRS)

SOURCES = $(foreach dir, $(SOURCE_DIRS), $(wildcard $(dir)/*.m))
OBJS := $(subst $(SOURCE_DIR), $(BUILD_DIR), $(SOURCES:.m=.o))
DEPS = $(OBJS:.o=.d)

$(info $(SOURCES))

_CC_FLAGS = $(INCLUDES) $(_GNUSTEP_CFLAGS)
_LD_FLAGS = -L. $(_GNUSTEP_LIBS)

LIB_NAME = libpairing_crypto_obj_c.so

# OS specific part
ifeq ($(OS),Windows_NT)
    RM = del /F /Q 
    RMDIR = -RMDIR /S /Q
    MKDIR = -mkdir
    ERRIGNORE = 2>NUL || true
    SEP=\\
else
    RM = rm -rf 
    RMDIR = rm -rf 
    MKDIR = mkdir -p
    ERRIGNORE = 2>/dev/null
    SEP=/
endif

# Remove space after separator
PSEP = $(strip $(SEP))

# Define the function that will generate each rule
define generateRules
$(1)/%.o: %.c
	@echo Building $$@
	$(HIDE)$(_CC) -c $$(_CC_FLAGS) -o $$(subst /,$$(PSEP),$$@) $$(subst /,$$(PSEP),$$<) -MMD
endef

.PHONY = clean all

all: directories $(LIB_NAME)

$(LIB_NAME): $(OBJS)
	$(_CC) $(_CC_FLAGS) $(OBJS) $(_LD_FLAGS) --shared  -o $(LIB_NAME)


# Include dependencies
-include $(DEPS)

# Generate rules
$(foreach targetdir, $(TARGET_DIRS), $(eval $(call generateRules, $(targetdir))))

directories:
	$(MKDIR) $(subst /,$(PSEP),$(TARGET_DIRS)) $(ERRIGNORE)

# Remove all objects, dependencies and executable files generated during the build
clean:
	$(RMDIR) $(subst /,$(PSEP),$(TARGET_DIRS)) $(ERRIGNORE)
	$(RM) $(LIB_NAME) $(ERRIGNORE)
	@echo Cleaning done ! 
