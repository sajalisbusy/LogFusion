"""Create or seed the local SQLite database with the synthetic perimeter log bundle."""

import json
from pathlib import Path

from app import DB_PATH, db, db_lock, normalize


ROOT = Path(__file__).resolve().parent
SAMPLE_PATH = ROOT / "samples" / "perimeter-demo.log"


def main() -> None:
    raw_events = [line for line in SAMPLE_PATH.read_text(encoding="utf-8").splitlines() if line.strip()]
    events = [normalize(raw) for raw in raw_events]
    with db_lock:
        known_hashes = {
            json.loads(row[0])["raw"]["sha256"]
            for row in db.execute("SELECT payload FROM events").fetchall()
        }
        new_events = [event for event in events if event["raw"]["sha256"] not in known_hashes]
        rows = [
            (
                event["event_id"],
                event["event"]["ingested"],
                event["source"]["format"],
                event["normalization"]["status"],
                event["source"]["vendor"] or event["source"]["product"] or event["source"]["device_name"] or "Unidentified",
                json.dumps(event, ensure_ascii=False, separators=(",", ":")),
            )
            for event in new_events
        ]
        db.executemany(
            "INSERT INTO events(event_id, ingested_at, source_format, status, source_label, payload) VALUES (?, ?, ?, ?, ?, ?)",
            rows,
        )
        db.commit()
        total = db.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    print(f"SQLite database: {DB_PATH}")
    print(f"Demo lines read: {len(raw_events)}; newly seeded: {len(new_events)}; total stored events: {total}")
    db.close()


if __name__ == "__main__":
    main()
