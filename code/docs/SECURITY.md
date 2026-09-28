# Security model

SC-SENTINEL intentionally accepts and executes untrusted C/C++ source. Container isolation is therefore a security boundary, not only an operational convenience.

## Default sandbox policy

- no Linux capabilities;
- not privileged;
- default Docker seccomp profile;
- `no-new-privileges`;
- no network;
- read-only root filesystem;
- bounded writable tmpfs;
- CPU, memory, PID and wall-clock limits;
- unprivileged UID 10001.

The optional privileged eBPF mode disables part of this boundary and must only run on a disposable, dedicated host. Never enable it on an API/database host.

## Source ingestion

ZIP validation completes before extraction. The service rejects traversal paths, symbolic links, excessive file counts, excessive expanded sizes and suspicious compression ratios. Repository cloning is restricted to configured public hosting domains and disables interactive credential prompts.

## Remaining production requirements

- Put the public API behind authentication, authorization and rate limiting.
- Replace example PostgreSQL credentials.
- Terminate TLS at an ingress proxy.
- Store LLM/API credentials in a Secret manager.
- Scan container images and pin them by digest.
- Move Docker access to a narrowly scoped runner service or stronger runtime such as gVisor/Kata.
- Apply storage quotas and retention policies to uploads and reports.
