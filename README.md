# Personal Data Leak Detector

A local-first web application that scans pasted text and uploaded files for common personal data and secrets. Scans run locally on the server and results are not persisted by default.

## Features

- Scan text or uploaded files (`.txt`, `.csv`, `.json`, `.log`, `.md`, and similar text files)
- Detect emails, phone numbers, credit-card-like numbers, IPv4 addresses, URLs, SSNs, API keys, JWTs, and high-entropy secrets
- Redact findings in the response
- Risk levels: low, medium, high, and critical
- JSON API and a lightweight browser interface
- No external services and no database required for the MVP

## Run locally

```bash
python -m venv .venv
# macOS/Linux
source .venv/bin/activate
# Windows: .venv\\Scripts\\activate
pip install -r backend/requirements.txt
uvicorn backend.app.main:app --reload
```

Open http://127.0.0.1:8000.

## Run with Docker

```bash
docker compose up --build
```

## API

- `GET /api/health` — health check
- `POST /api/scan` — JSON body `{ "text": "..." }`
- `POST /api/scan/file` — multipart upload with a `file` field
- `GET /docs` — OpenAPI documentation

## Privacy and limitations

The application is designed for local use. Do not send real sensitive data to a public deployment without adding authentication, encryption, access controls, and a retention policy. Pattern matching is heuristic and can produce false positives or miss unusual formats.

## License

MIT
