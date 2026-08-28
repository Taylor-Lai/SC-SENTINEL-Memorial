# Third-party notices

The repository-level Apache License 2.0 applies only to SC-SENTINEL's original
code and documentation. The test fixtures listed below are excluded from that
grant pending a complete provenance review. Files or directories with their
own valid license notice remain governed by that notice.

## Bundled test components

| Path under `code/sentinel_agent/samples/` | Component | License |
|---|---|---|
| `level1_testset/` | SENTINEL level-1 vulnerability test suite | MIT |
| `level2_testset/01_textkit/` | microjson / cJSON-derived test component | MIT |
| `level2_testset/02_imagepipe/` | pngreader test component | zlib |
| `level2_testset/03_fieldbus/` | modlite test component | LGPL |
| `level2_testset/03_fieldbus_fixed/` | fixed modlite test component | LGPL |
| `level2_testset/04_astcore/` | astlite test component | MIT |
| `level2_testset/05_chunkstream/` | httpdecode test component | MIT |
| `level2_testset/06_audiodec/` | sndmini test component | LGPL |
| `level2_testset/07_imagecodec/` | minivp8 test component | BSD-3-Clause |
| `level2_testset/08_proxyroute/` | sockmini test component | MIT |
| `level2_testset/09_resolver/` | resmini test component | BSD-2-Clause |
| `level2_testset/10_authframe/` | ntlmlite test component | MIT |
| `level2_testset/11_tunnelctl/` | httptunnel test component | MIT |
| `level2_testset/12_sshscan/` | sshmini test component | BSD-2-Clause |
| `level2_testset/14_logutil/` | sudolite test component | ISC |

The `level1_testset/` and `01_textkit/` directories contain full MIT license
texts. Most other Level-2 directories currently contain only a one-line
license label rather than the complete license and attribution text. Those
labels are recorded above for audit purposes, but they are not sufficient
licensing documentation by themselves.

Before public release or redistribution, maintainers must do one of the
following for every affected directory:

1. document its upstream source, exact version, copyright holder and complete
   license text; or
2. establish that the component is wholly original and apply a license with
   consent from every contributor; or
3. remove the component from the public distribution.

Until that review is complete, do not treat the affected fixtures as granted
under Apache-2.0 and do not redistribute them independently.

## Dependency manifests

Python, JavaScript, container and C/C++ dependency manifests reference
separately distributed packages. Their respective authors retain copyright,
and each package remains subject to its own license. Before redistributing a
built product, generate a current dependency inventory and review the licenses
for the exact resolved versions.

## Archival media

The photographs, award certificate, presentation and project document
identified in `NOTICE` are not open-source software and are excluded from the
Apache-2.0 grant. Permission from the relevant rights holders may be required
for reuse.
