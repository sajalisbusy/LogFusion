# ULPF prototype

The Universal Log Pre-processing Framework (ULPF) prototype accepts perimeter device event lines, detects common log formats, maps familiar fields into a shared event envelope, and stores each normalized event with its original raw text and SHA-256 digest.

## Run locally

Requirements: Python 3.10 or newer. There are no third-party Python packages and the interface does not request remote assets.

From this directory:

```powershell
python app.py
```

Open [http://127.0.0.1:8765](http://127.0.0.1:8765), choose **Load demo bundle**, then **Normalize events**. The database is created at `data/ulpf.db`. Set `ULPF_PORT`, `ULPF_HOST`, or `ULPF_DB_PATH` to change the listener or database location. The default listener is loopback only. The local port defaults to 8765 because this machine denied binding to 8080; container deployments continue to use port 8080.

To create and pre-populate the local SQLite database without starting the web server, run:

```powershell
python seed_demo.py
```

The synthetic mixed-format input is in [samples/perimeter-demo.log](samples/perimeter-demo.log). The repository includes the seeded SQLite demo database at `data/ulpf.db`; `python seed_demo.py` adds any missing demo events by raw SHA-256. The database contains demo data only. Do not commit databases containing real or sensitive events.

## Run in a container

```powershell
docker compose up --build
```

The compose service binds port 8080 and persists SQLite data in `./data`; open `http://127.0.0.1:8080` when using the container. To stop it, press Ctrl+C. The Docker image has no runtime package installation step. For an air-gapped environment, build the image on a connected staging machine, export it with `docker save`, transfer the image archive through the approved offline process, then `docker load` it on the target and start the service with Docker Compose or `docker run`.

## Supported input and behavior

- JSON objects with common network, event, observer, endpoint, user, and rule fields.
- CEF header and common extension fields.
- LEEF with tab-delimited extension fields or space-delimited `key=value` fields.
- Syslog-style RFC 3164 / RFC 5424 lines, including CEF or LEEF embedded in the message.
- Unrecognized lines are retained as `raw` fallback events instead of being discarded.

The demo accepts one event per line. Send event strings to `/api/ingest` to preserve their exact text representation. JSON objects sent as objects are compactly serialized by the API; send their original line as a string when exact source text matters. The prototype keeps all accepted raw text in SQLite and links it to each normalized record by `event_id` and SHA-256. The HTTP ingestion endpoint does not deduplicate events; the separate demo seeder is repeat-safe by raw hash.

## Extend source coverage

Add a Python adapter under `parsers/` that defines `register(register_parser)`. Register a detector and a parser function returning a dictionary of source fields. The framework tries registered detectors and then falls back to raw retention. See [parsers/README.md](parsers/README.md) and `parsers/examples/example_vendor.py`. Local plug-ins are trusted Python code and load when the service starts.

## API

- `GET /api/health` — service and schema version.
- `GET /api/parsers` — registered parser identifiers.
- `GET /api/stats` — event counts by normalization status and source format.
- `GET /api/events?limit=100&offset=0&q=10.0.0.8&status=normalized&format=cef` — filtered event stream.
- `GET /api/events/{event_id}` — complete normalized envelope and embedded raw data.
- `GET /api/events/{event_id}/raw` — original event text as a downloadable file.
- `POST /api/ingest` — JSON `{ "events": ["raw line", "another raw line"] }` or plain text with one event per line.
- `GET /api/export` — all stored records as newline-delimited JSON.

Example:

```powershell
$body = @{ events = @('CEF:0|Acme|Edge Firewall|1.0|1001|Connection denied|8|src=10.0.0.8 dst=203.0.113.4 dpt=443 act=deny') } | ConvertTo-Json
Invoke-RestMethod -Uri http://127.0.0.1:8765/api/ingest -Method Post -ContentType 'application/json' -Body $body
```

## Prototype architecture and limits

The request handler, parser registry, normalizer, and SQLite store run as one local service. Each record contains source format and identity, common event and endpoint fields, field-mapping provenance, unmapped parsed attributes, original raw text, and its digest. See [docs/architecture.md](docs/architecture.md) for the evaluation architecture summary.

This is a functional prototype, not a billion-events-per-day deployment. SQLite and one Python process are for local demonstration. A production deployment would partition stateless parser workers behind a durable streaming layer, use a horizontally scalable event/data lake store, and batch exports to downstream SIEM systems. The prototype has no authentication or TLS; keep the default listener local or place it behind the organization's approved access controls before exposing it to a network.
