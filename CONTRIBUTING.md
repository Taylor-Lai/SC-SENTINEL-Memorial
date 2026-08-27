# Contributing

SC-SENTINEL Memorial preserves a competition project while leaving room for
later teaching-oriented improvements.

## Before contributing

1. Open an issue describing the problem or proposed change.
2. Keep generated artifacts, credentials, local `.env` files and test output
   out of commits.
3. Do not add personal information, competition materials or photographs
   without permission from the relevant rights holders.
4. Preserve every third-party license and attribution notice.
5. Use vulnerability samples only in isolated, authorized environments.

## Development checks

Run the checks relevant to the area you change:

```powershell
cd code/sentinel_backend
python -m pip install -r requirements.txt
python -m pip install pytest pytest-asyncio
python -m pytest
```

```powershell
cd code/sentinel_agent
python -m pip install -r requirements.txt
python -m pytest
```

```powershell
cd code/sentinel_frontend
npm ci
npm run build
```

## License of contributions

Unless explicitly stated otherwise, a contribution intentionally submitted to
this repository is provided under Apache License 2.0, as described in section 5
of that license. Materials already governed by another license keep their
existing terms.
