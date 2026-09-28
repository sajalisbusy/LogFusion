# Synthetic perimeter demo logs

`perimeter-demo.log` contains 11 synthetic, one-event-per-line examples for local demonstrations. It includes CEF, LEEF, RFC 5424-style Syslog, RFC 3164-style Syslog, nested and flat JSON, an unknown vendor format, and malformed JSON. All public IPs are from documentation-only ranges; device names and users are fictional.

Use **Load demo bundle** in the dashboard to try the interactive ingestion path, or run `python seed_demo.py` from the project root to populate the SQLite demo database. The seed command skips raw-event hashes already present, so it can be run again without duplicating the sample records.
