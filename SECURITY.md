# Security policy

## Scope

This repository contains security-analysis software and intentionally
vulnerable test fixtures. The fixtures are for teaching, research and
authorized testing only. Do not expose them as network services or run them on
systems containing sensitive data.

## Reporting a vulnerability

Please do not disclose a suspected vulnerability in a public issue. Report it
privately through GitHub's **Security** tab using a private vulnerability
report. Include the affected path and version, reproduction conditions,
potential impact and any suggested mitigation.

Maintainers should acknowledge a report within seven days. A fix and public
advisory will be coordinated according to severity and the risk to users.

## Deployment warning

The archived competition configuration is not a production security baseline.
Before deployment, rotate all credentials, restrict CORS and repository
allowlists, isolate the dynamic-analysis runner, keep privileged eBPF execution
on a dedicated host, and update all dependencies.
