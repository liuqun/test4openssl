# Makefile for key generator utility using OpenSSL(libcrypto)

.PHONY: default
default: KeyGenerator_test

.PHONY: all
all: default cscope tags

#
LIBCRYPTO := $(shell pkg-config --libs libcrypto)
CFLAGS_LIBCRYPTO := $(shell pkg-config --libs libcrypto)

#
LIBS += $(LIBCRYPTO)
CFLAGS := -g -O0 -Wall $(CFLAGS_LIBCRYPTO)
CXXFLAGS := $(CFLAGS)
COMPILE_c = $(COMPILE.c)
COMPILE_cpp = $(COMPILE.cpp)

KeyGenerator_test: KeyGenerator_test.o
	$(CXX) $(LD_FLAGS) -o $@ $^ $(LIBS)

%.o: %.c %.h
	$(COMPILE_c) -o $@ $<

%.o: %.c
	$(COMPILE_c) -o $@ $<

%.o: %.cpp %.h
	$(COMPILE_cpp) -o $@ $<

%.o: %.cpp
	$(COMPILE_cpp) -o $@ $<

.PHONY: clean
clean:
	$(RM) *.o
	$(RM) cscope.files cscope.out
	$(RM) TAGS

.PHONY: cscope
cscope: cscope.out
cscope.out: cscope.files
	cscope -R -b -i $<
cscope.files: ALWAYS_UPDATE_FILE_LIST
	find . -name "*.cpp" -or -name "*.[ch]" > $@
# Always updete the file list for TAGS and cscope, so ther will update symbol table from source files
.PHONY: ALWAYS_UPDATE_FILE_LIST

.PHONY: tags
tags: TAGS
TAGS: cscope.files
	cat $^ | etags - -o $@
