# Builds cb2_c_example against an installed cb2_c through pkg-config:
#
#   PKG_CONFIG_PATH=<prefix>/lib/pkgconfig make -C bindings/c/examples

PKG_CONFIG ?= pkg-config
CFLAGS ?= -O2 -Wall -Wextra -Wpedantic
CB2_C_CFLAGS := $(shell $(PKG_CONFIG) --cflags cb2_c)
CB2_C_LIBS := $(shell $(PKG_CONFIG) --libs cb2_c)
CB2_C_LIBDIR := $(shell $(PKG_CONFIG) --variable=libdir cb2_c)

cb2_c_example: cb2_c_example.c
	$(CC) $(CFLAGS) $(CB2_C_CFLAGS) -o $@ $< $(CB2_C_LIBS) -Wl,-rpath,$(CB2_C_LIBDIR)

clean:
	rm -f cb2_c_example

.PHONY: clean
