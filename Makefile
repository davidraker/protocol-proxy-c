# protocol-proxy C port. Targets: all (library + bin/echo-proxy + bin/conformance), test (unit tests under ASan/UBSan, or valgrind
# with VALGRIND=1 when installed), self-test, conformance, clean.
CC ?= gcc
PKG_CONFIG ?= pkg-config
CSTD := -std=c11
WARN := -Wall -Wextra -Wpedantic -Wshadow -Wpointer-arith -Wstrict-prototypes -Wmissing-prototypes -Wno-unused-parameter
OPT ?= -O2 -g
CFLAGS ?= $(OPT)
CFLAGS += $(CSTD) $(WARN) -D_GNU_SOURCE -Iinclude -Isrc -Ithird_party/tomlc99 -pthread
PKGS := zlib openssl
PKG_CFLAGS := $(shell $(PKG_CONFIG) --cflags $(PKGS))
PKG_LIBS := $(shell $(PKG_CONFIG) --libs $(PKGS))
LDLIBS := $(PKG_LIBS) -pthread

SRC := src/util.c src/headers.c src/json.c src/codec.c src/log.c src/tls.c src/connector.c src/proxy.c src/selftest.c \
       src/manifest.c src/records.c src/authority.c src/manager.c src/conformance.c
THIRD := third_party/tomlc99/toml.c
OBJ := $(SRC:src/%.c=build/%.o) build/toml.o
LIB := build/libprotocolproxy.a
BIN := bin/echo-proxy
CONFORMANCE := bin/conformance

SAN_FLAGS := -fsanitize=address,undefined -fno-omit-frame-pointer -O1 -g
SAN_OBJ := $(SRC:src/%.c=build/san/%.o) build/san/toml.o
TEST_BIN := build/san/test_main
VECTORS := tests/test_vectors.json
# Override on the command line: PYTHON is an interpreter with the Python protocol-proxy installed (for the
# conformance harness), PROTOCOL_PROXY_DIR its checkout (for the shared test vectors).
PYTHON ?= python3
PROTOCOL_PROXY_DIR ?= ../protocol-proxy

.PHONY: all test self-test conformance clean

all: $(BIN) $(CONFORMANCE)

$(LIB): $(OBJ)
	ar rcs $@ $^

build/%.o: src/%.c include/ppc/ppc.h src/internal.h | build
	$(CC) $(CFLAGS) $(PKG_CFLAGS) -c $< -o $@

build/toml.o: $(THIRD) third_party/tomlc99/toml.h | build
	$(CC) $(CFLAGS) -c $< -o $@

$(BIN): tools/echo-proxy.c $(LIB) | bin
	$(CC) $(CFLAGS) $(PKG_CFLAGS) $< $(LIB) $(LDLIBS) -o $@

$(CONFORMANCE): tools/conformance.c $(LIB) | bin
	$(CC) $(CFLAGS) $(PKG_CFLAGS) $< $(LIB) $(LDLIBS) -o $@

build bin build/san:
	mkdir -p $@

# Tests: built with ASan+UBSan when their runtimes link (probed below), under valgrind with VALGRIND=1, and
# otherwise with gcc's static analyzer, _FORTIFY_SOURCE and glibc's heap checking (MALLOC_CHECK_/MALLOC_PERTURB_).
HAVE_SANITIZERS := $(shell echo 'int main(void){return 0;}' | $(CC) -x c -fsanitize=address,undefined -o /dev/null - >/dev/null 2>&1 && echo yes || echo no)
ifeq ($(VALGRIND),1)
TEST_CFLAGS := $(CFLAGS)
RUNNER := valgrind --error-exitcode=9 --leak-check=full --errors-for-leak-kinds=definite --quiet
TEST_MODE := valgrind
else ifeq ($(HAVE_SANITIZERS),yes)
TEST_CFLAGS := $(filter-out $(OPT),$(CFLAGS)) $(SAN_FLAGS)
RUNNER := env ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1
TEST_MODE := sanitizers (ASan+UBSan)
else
TEST_CFLAGS := $(filter-out $(OPT),$(CFLAGS)) -O1 -g -fanalyzer -D_FORTIFY_SOURCE=3 -fstack-protector-strong
RUNNER := env MALLOC_CHECK_=3 MALLOC_PERTURB_=165
TEST_MODE := fallback (no sanitizer runtime or valgrind installed: -fanalyzer, _FORTIFY_SOURCE=3, MALLOC_CHECK_=3)
endif

build/san/%.o: src/%.c include/ppc/ppc.h src/internal.h | build/san
	$(CC) $(TEST_CFLAGS) $(PKG_CFLAGS) -c $< -o $@

build/san/toml.o: $(THIRD) third_party/tomlc99/toml.h | build/san
	$(CC) $(TEST_CFLAGS) -c $< -o $@

$(TEST_BIN): tests/test_main.c $(SAN_OBJ) | build/san
	$(CC) $(TEST_CFLAGS) $(PKG_CFLAGS) $< $(SAN_OBJ) $(LDLIBS) -o $@

test: $(TEST_BIN) $(BIN)
	@echo "test mode: $(TEST_MODE)"
	$(RUNNER) $(TEST_BIN) $(VECTORS)

self-test: $(BIN)
	$(BIN) --self-test --vectors $(VECTORS)

conformance: $(BIN)
	cd $(PROTOCOL_PROXY_DIR) && $(PYTHON) -m protocol_proxy.conformance $(CURDIR)/proxy.toml --echo ECHO --manager-dials --tls -v

clean:
	rm -rf build bin/echo-proxy bin/conformance
