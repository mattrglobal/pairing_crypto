TARGET=example

CC=clang
CFLAGS+=-O0 -g -Wall -Werror 
FRAMEWORKS:= -framework Foundation

LIB_SOURCES=pairing_crypto/*.m
EXAMPLE_SOURCES=example/main.m
SOURCES= $(LIB_SOURCES) $(EXAMPLE_SOURCES)

OUTDIR = ./build/bin
SUBDIR = pairing_crypto example
DIR_OBJ = ./build/obj

INCS = $(wildcard *.h $(foreach fd, $(SUBDIR), $(fd)/*.h))
SRCS = $(wildcard *.c $(foreach fd, $(SUBDIR), $(fd)/*.m))
OBJS = $(addprefix $(DIR_OBJ)/, $(SRCS:m=o))
LIBS = -lpairing_crypto_c $(FRAMEWORKS)
LIB_DIRS = -L./../../target/debug


PHONY := $(TARGET)
$(TARGET): $(OBJS)
	mkdir -p $(OUTDIR)
	$(CC) -o $(OUTDIR)/$@ $(OBJS) $(LIB_DIRS) $(LIBS)

$(DIR_OBJ)/%.o: %.m $(INCS)
	mkdir -p $(@D)
	$(CC) -o $@ $(CFLAGS) -c $< $(INC_DIRS)

leaks: $(TARGET)
	@leaks --atExit -- ./$(OUTDIR)/$(TARGET)

PHONY += clean
clean:
	rm -rf $(OUTDIR)/* $(DIR_OBJ)/*

PHONY += echoes
echoes:
	@echo "INC files: $(INCS)"
	@echo "SRC files: $(SRCS)"
	@echo "OBJ files: $(OBJS)"
	@echo "LIB files: $(LIBS)"
	@echo "INC DIR: $(INC_DIRS)"
	@echo "LIB DIR: $(LIB_DIRS)"

.PHONY = $(PHONY)
