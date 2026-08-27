# Harness Generation Notes

Each challenge in this suite already exposes a uniform entry contract:

```c
int main(int argc, char **argv);   /* reads argv[1] as a file path */
```

The shared helper `ctf_input.h` provides:

| Helper                                  | Purpose                                  |
|-----------------------------------------|------------------------------------------|
| `read_challenge_input(argc, argv, &n)`  | Slurp up to 4 KB from file or stdin      |
| `has_byte(buf, n, c)`                   | Branch gate: does input contain byte `c` |
| `byte_or(buf, n, idx, fallback)`        | Safe positional byte read with default   |

This uniform contract means **Agent D can target one canonical harness
template** (`fuzzer_test_one_input` style wrapping `main`) without per-
challenge customization. Recommended Agent D mapping:

| CWE family | Strategy                       | Seeds folder        |
|------------|--------------------------------|---------------------|
| CWE-416    | `flag_path_trigger`            | `seeds/uaf/`        |
| CWE-415    | `flag_path_trigger`            | `seeds/double_free/`|
| CWE-122    | `oversized_string_input`       | `seeds/heap/`       |
| CWE-121    | `oversized_string_input`       | `seeds/stack/`      |
| CWE-134    | `format_string_payload`        | `seeds/fmt/`        |

When AFL++ is run via `make afl`, the produced binaries live in
`build/<name>_afl` and accept `@@` argument substitution.
