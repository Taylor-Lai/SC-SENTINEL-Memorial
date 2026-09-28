# Sentinel-Bench Level 2 Oracle

This directory is evaluation-only material. Do not pass it to the agent
pipeline as project input.

Each subdirectory contains the moved seed corpus, PoC inputs, vulnerability
notes, CVE/CWE metadata, and historical verification scripts for the matching
visible project under `../level2_testset`.

Use `index.json` to map neutral project names to oracle directories.

Recommended flow:

1. Submit only `../level2_testset/<project>` to the multi-agent pipeline.
2. Let the pipeline infer build steps, generate harnesses, and produce seeds.
3. Compare findings against the matching oracle entry after the pipeline
   finishes.
