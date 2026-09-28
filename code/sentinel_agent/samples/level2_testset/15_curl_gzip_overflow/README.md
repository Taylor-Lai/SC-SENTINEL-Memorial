# gziprelay

`gziprelay` is a compact, intentionally vulnerable C99 test project for
end-to-end supply-chain and dynamic-verification testing.

## CVE provenance

The dependency manifest pins `curl/8.11.1` and `zlib/1.2.0.3`, the affected
combination described by **CVE-2025-0725**. NVD published the issue on
2025-02-05: automatic gzip decoding in libcurl can reach an integer overflow
and buffer overflow when using zlib 1.2.0.3 or older; curl 8.12.0 fixes it.

The source is a small, auditable reproduction model, not copied libcurl code.
`gziprelay_decode()` truncates its expanded-output allocation to 8 bits but
continues writing 64 bytes per input byte. The CLI passes an input file to
that function, so the vulnerable path is reachable by generated Harnesses.

## Build and trigger

```bash
make asan
python -c "open('trigger.bin','wb').write(b'GZ' + b'A' * 14)"
./gziprelay trigger.bin
```

AddressSanitizer reports a heap-buffer-overflow.
