# CWE Detection Matrix — Sentinel-Bench Level 1

Each row is one challenge file. The "Sanitizer" column shows which
runtime sanitizer is expected to detect the bug when the program is
fed `seeds/<class>/poc.bin`.

## CWE-416 — Use-After-Free

| Challenge                  | Trigger                                            | Sanitizer |
|----------------------------|----------------------------------------------------|-----------|
| `uaf_direct.c`             | Byte `'D'` then `'S'` (free then deref) on heap note | ASan      |
| `uaf_cross_function.c`     | Helper frees object that caller still uses         | ASan      |
| `uaf_array_slot.c`         | Slot freed, then re-printed via index lookup       | ASan      |
| `uaf_struct_field.c`       | Owning struct freed; inner field dereferenced      | ASan      |

## CWE-415 — Double Free

| Challenge                    | Trigger                                            | Sanitizer |
|------------------------------|----------------------------------------------------|-----------|
| `double_free_direct.c`       | Same pointer freed in two successive blocks        | glibc / ASan |
| `double_free_alias.c`        | Two aliases of one allocation both freed           | glibc / ASan |
| `double_free_cleanup.c`      | Cleanup path frees a pointer the normal path freed | glibc / ASan |
| `double_free_error_path.c`   | Error branch frees, then fall-through frees again  | glibc / ASan |

## CWE-122 — Heap Buffer Overflow

| Challenge                            | Trigger                                       | Sanitizer |
|--------------------------------------|-----------------------------------------------|-----------|
| `heap_overflow_strcpy.c`             | `strcpy` of attacker bytes into 16-byte heap  | ASan      |
| `heap_overflow_memcpy_len.c`         | `memcpy` length from input, unchecked         | ASan      |
| `heap_overflow_off_by_one.c`         | Loop writes one byte past allocation          | ASan      |
| `heap_overflow_integer_trunc.c`      | Size truncated to 8-bit before allocation     | ASan      |

## CWE-121 — Stack Buffer Overflow

| Challenge                       | Trigger                                       | Sanitizer |
|---------------------------------|-----------------------------------------------|-----------|
| `stack_overflow_strcpy.c`       | `strcpy` of attacker bytes into 32-byte stack | ASan      |
| `stack_overflow_sprintf.c`      | `sprintf("%s", input)` into small stack buf   | ASan      |
| `stack_overflow_index.c`        | Computed index writes past stack array end    | ASan      |
| `stack_overflow_loop.c`         | Unbounded copy loop driven by input length    | ASan      |

## CWE-134 — Format String Vulnerability

| Challenge                          | Trigger                                       | Sanitizer |
|------------------------------------|-----------------------------------------------|-----------|
| `format_string_printf.c`           | `printf(user_input)`                          | static    |
| `format_string_fprintf.c`          | `fprintf(stderr, user_input)`                 | static    |
| `format_string_snprintf.c`         | `snprintf(buf, n, user_input)`                | static    |
| `format_string_syslog_like.c`      | Log macro forwards untrusted input as format  | static    |

Note: format-string bugs may not always be caught by ASan; they are
primarily detection-rate targets for the static-analysis pipeline
(Agent C).
