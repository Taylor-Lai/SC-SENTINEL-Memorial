# ─────────────────────────────────────────────────────────────────────────────
# Sentinel-Bench Level 1 — POSIX Makefile
#
# Targets:
#   make              normal build of every CWE microbenchmark
#   make asan         AddressSanitizer build for crash confirmation
#   make afl          AFL++ instrumented build for fuzzing
#   make test         compile + run smoke tests against seeds/default.bin
#   make clean        remove all build artifacts
#
# Per-CWE convenience targets (e.g. `make uaf`) build only that family.
# ─────────────────────────────────────────────────────────────────────────────

CC       ?= gcc
AFLCC    ?= afl-clang-fast
CFLAGS   := -Wall -Wextra -Wno-unused-parameter -Wno-unused-variable -g -I.
ASAN_FLAGS := -fsanitize=address -fno-omit-frame-pointer -O0
OPT_FLAGS  := -O2

# ── Source grouping (matches CMakeLists.txt) ─────────────────────────────────
SRCS_CWE_416 := uaf_direct.c uaf_cross_function.c uaf_array_slot.c uaf_struct_field.c
SRCS_CWE_415 := double_free_direct.c double_free_alias.c double_free_cleanup.c double_free_error_path.c
SRCS_CWE_122 := heap_overflow_strcpy.c heap_overflow_memcpy_len.c heap_overflow_off_by_one.c heap_overflow_integer_trunc.c
SRCS_CWE_121 := stack_overflow_strcpy.c stack_overflow_sprintf.c stack_overflow_index.c stack_overflow_loop.c
SRCS_CWE_134 := format_string_printf.c format_string_fprintf.c format_string_snprintf.c format_string_syslog_like.c

ALL_SRCS := $(SRCS_CWE_416) $(SRCS_CWE_415) $(SRCS_CWE_122) $(SRCS_CWE_121) $(SRCS_CWE_134)
ALL_BINS := $(ALL_SRCS:.c=)

BUILD_DIR := build

.PHONY: all normal asan afl test clean install \
        uaf double_free heap_overflow stack_overflow format_string

all: normal

normal: $(BUILD_DIR)
	@for src in $(ALL_SRCS); do                                          \
	    bin=$$(basename $$src .c);                                       \
	    echo "  CC      $$src";                                          \
	    $(CC) $(CFLAGS) $(OPT_FLAGS) -o $(BUILD_DIR)/$$bin $$src;        \
	done

asan: $(BUILD_DIR)
	@for src in $(ALL_SRCS); do                                          \
	    bin=$$(basename $$src .c);                                       \
	    echo "  ASan    $$src";                                          \
	    $(CC) $(CFLAGS) $(ASAN_FLAGS) -o $(BUILD_DIR)/$${bin}_asan $$src;\
	done

afl: $(BUILD_DIR)
	@for src in $(ALL_SRCS); do                                          \
	    bin=$$(basename $$src .c);                                       \
	    echo "  AFL++   $$src";                                          \
	    $(AFLCC) $(CFLAGS) $(ASAN_FLAGS) -o $(BUILD_DIR)/$${bin}_afl $$src; \
	done

# ── Per-CWE convenience targets ──────────────────────────────────────────────
uaf:             ; @$(MAKE) normal SRCS="$(SRCS_CWE_416)"
double_free:     ; @$(MAKE) normal SRCS="$(SRCS_CWE_415)"
heap_overflow:   ; @$(MAKE) normal SRCS="$(SRCS_CWE_122)"
stack_overflow:  ; @$(MAKE) normal SRCS="$(SRCS_CWE_121)"
format_string:   ; @$(MAKE) normal SRCS="$(SRCS_CWE_134)"

# ── Smoke test: run every normal binary against seeds/default.bin ────────────
test: normal
	@echo "Running smoke tests against seeds/default.bin..."
	@for bin in $(ALL_BINS); do                                          \
	    printf "  %-40s " $$bin;                                         \
	    timeout 5 $(BUILD_DIR)/$$bin seeds/default.bin > /dev/null 2>&1; \
	    rc=$$?;                                                          \
	    if [ $$rc -eq 124 ]; then echo "TIMEOUT"; else echo "exit=$$rc"; fi; \
	done

install:
	install -d $(DESTDIR)/usr/local/share/sentinel-bench-l1
	cp -r seeds docs *.c *.h README.md LICENSE \
	      $(DESTDIR)/usr/local/share/sentinel-bench-l1/

$(BUILD_DIR):
	@mkdir -p $(BUILD_DIR)

clean:
	rm -rf $(BUILD_DIR) *.o *.a *_asan *_afl out findings
