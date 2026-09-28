"""ULPF prototype: lossless event intake and normalization, using only Python stdlib."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import re
import sqlite3
import sys
import threading
import uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse


ROOT = Path(__file__).resolve().parent
STATIC = ROOT / "static"
DB_PATH = Path(os.environ.get("ULPF_DB_PATH", ROOT / "data" / "ulpf.db"))
PARSER_DIR = ROOT / "parsers"
MAX_REQUEST_BYTES = 5 * 1024 * 1024
SCHEMA_VERSION = "ulpf.event/1.0"
PARSER_VERSION = "0.1.0"

DB_PATH.parent.mkdir(parents=True, exist_ok=True)
db = sqlite3.connect(DB_PATH, check_same_thread=False)
db.row_factory = sqlite3.Row
db_lock = threading.Lock()
with db_lock:
    db.execute(
        """CREATE TABLE IF NOT EXISTS events (
            event_id TEXT PRIMARY KEY,
            ingested_at TEXT NOT NULL,
            source_format TEXT NOT NULL,
            status TEXT NOT NULL,
            source_label TEXT NOT NULL,
            payload TEXT NOT NULL
        )"""
    )
    db.execute("CREATE INDEX IF NOT EXISTS events_ingested_idx ON events(ingested_at DESC)")
    db.commit()


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def key_name(value: object) -> str:
    return re.sub(r"[^a-z0-9]", "", str(value).lower())


def unescape_delimited(value: str) -> str:
    return re.sub(r"\\([\\|= ])", r"\1", value).replace(r"\n", "\n").replace(r"\r", "\r")


def split_escaped(value: str, delimiter: str, maxsplit: int = -1) -> list[str]:
    pieces: list[str] = []
    current: list[str] = []
    escaped = False
    splits = 0
    for char in value:
        if escaped:
            current.extend(("\\", char))
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == delimiter and (maxsplit < 0 or splits < maxsplit):
            pieces.append("".join(current))
            current = []
            splits += 1
        else:
            current.append(char)
    if escaped:
        current.append("\\")
    pieces.append("".join(current))
    return pieces


def parse_kv_extension(value: str) -> dict[str, str]:
    """Parse key=value pairs, honoring escaped spaces and quoted values."""
    tokens: list[str] = []
    current: list[str] = []
    escaped = False
    quote: str | None = None
    for char in value.strip():
        if escaped:
            current.extend(("\\", char))
            escaped = False
        elif char == "\\":
            escaped = True
        elif quote:
            if char == quote:
                quote = None
            else:
                current.append(char)
        elif char in {"\"", "'"}:
            quote = char
        elif char.isspace():
            if current:
                tokens.append("".join(current))
                current = []
        else:
            current.append(char)
    if escaped:
        current.append("\\")
    if current:
        tokens.append("".join(current))
    result: dict[str, str] = {}
    for token in tokens:
        if "=" not in token:
            continue
        key, val = token.split("=", 1)
        if key:
            result[key] = unescape_delimited(val)
    return result


def parse_cef(raw: str) -> dict:
    parts = split_escaped(raw.strip(), "|", 7)
    if len(parts) < 8 or not parts[0].startswith("CEF:"):
        raise ValueError("Malformed CEF header")
    header = {
        "deviceVendor": unescape_delimited(parts[1]),
        "deviceProduct": unescape_delimited(parts[2]),
        "deviceVersion": unescape_delimited(parts[3]),
        "signatureId": unescape_delimited(parts[4]),
        "name": unescape_delimited(parts[5]),
        "severity": unescape_delimited(parts[6]),
    }
    header.update(parse_kv_extension(parts[7]))
    header["_format"] = "cef"
    return header


def parse_leef(raw: str) -> dict:
    line = raw.strip()
    parts = split_escaped(line, "|", 6)
    if len(parts) < 6 or not parts[0].startswith("LEEF:"):
        raise ValueError("Malformed LEEF header")
    fields: dict[str, str] = {
        "deviceVendor": unescape_delimited(parts[1]),
        "deviceProduct": unescape_delimited(parts[2]),
        "deviceVersion": unescape_delimited(parts[3]),
        "eventId": unescape_delimited(parts[4]),
        "_format": "leef",
    }
    # LEEF 2 includes an extension delimiter after the event ID; LEEF 1 omits it.
    if len(parts) >= 7:
        marker = unescape_delimited(parts[5]).strip()
        extension = parts[6]
        delimiter = "\t" if marker.lower() in {"09", "0x09", "\\t", "tab"} else marker
    else:
        extension = parts[5]
        delimiter = "\t" if "\t" in extension else " "
    if delimiter and delimiter in extension:
        for token in extension.split(delimiter):
            if "=" in token:
                key, value = token.split("=", 1)
                fields[key] = unescape_delimited(value)
    else:
        fields.update(parse_kv_extension(extension))
    return fields


SYSLOG_RE = re.compile(
    r"^(?:<(?P<pri>\d{1,3})>)?"
    r"(?:\d+\s+)?"
    r"(?:(?P<iso>\d{4}-\d\d-\d\d[T ][^ ]+Z?)|"
    r"(?P<bsd>[A-Z][a-z]{2}\s+\d{1,2}\s+\d\d:\d\d:\d\d))\s+"
    r"(?P<host>\S+)\s+(?P<app>[\w./-]+)(?:\[(?P<pid>\d+)\])?"
    r"(?::\s?(?P<message>.*)|\s+\S+\s+\S+\s+(?:-|\[.*\])\s+(?P<message5424>.*))$"
)


def parse_syslog(raw: str) -> dict:
    match = SYSLOG_RE.match(raw.strip())
    if not match:
        # Some appliance logs omit the timestamp but retain host and message.
        match = re.match(r"^(?P<host>[A-Za-z0-9_.:-]+)\s+(?P<app>[\w./-]+):\s?(?P<message>.*)$", raw.strip())
        if not match:
            return {"message": raw.strip(), "_format": "syslog", "_partial": True}
        return {"deviceHostName": match.group("host"), "appName": match.group("app"),
                "message": match.group("message"), "_format": "syslog"}

    body = match.group("message") or match.group("message5424") or ""
    fields: dict[str, str] = {
        "deviceHostName": match.group("host"),
        "appName": match.group("app"),
        "message": body,
        "_format": "syslog",
    }
    if match.group("pri") is not None:
        priority_name = ("emergency", "alert", "critical", "error", "warning", "notice", "informational", "debug")[int(match.group("pri")) % 8]
        fields["severity"] = priority_name
    if match.group("iso"):
        fields["eventTime"] = match.group("iso")
    elif match.group("bsd"):
        try:
            parsed = datetime.strptime(match.group("bsd"), "%b %d %H:%M:%S").replace(year=datetime.now(timezone.utc).year, tzinfo=timezone.utc)
            fields["eventTime"] = parsed.isoformat().replace("+00:00", "Z")
        except ValueError:
            pass

    if body.startswith("CEF:"):
        fields.update(parse_cef(body))
        fields["deviceHostName"] = match.group("host")
        fields["message"] = fields.get("msg") or fields.get("name") or body
        fields["_format"] = "syslog/cef"
    elif body.startswith("LEEF:"):
        fields.update(parse_leef(body))
        fields["deviceHostName"] = match.group("host")
        fields["message"] = fields.get("msg") or fields.get("name") or body
        fields["_format"] = "syslog/leef"
    else:
        fields.update(parse_kv_extension(body))
    return fields


def parse_json(raw: str) -> dict:
    parsed = json.loads(raw)
    if not isinstance(parsed, dict):
        return {"message": json.dumps(parsed, ensure_ascii=False), "_format": "json", "_partial": True}
    parsed["_format"] = "json"
    return parsed


# Parser registry: adding a format means registering a detector and parser here.
PARSER_REGISTRY: list[tuple[str, object, object]] = []


def register_parser(name: str, detector, parser) -> None:
    if not callable(detector) or not callable(parser):
        raise TypeError("Parser detector and parser must both be callable")
    PARSER_REGISTRY.append((name, detector, parser))


register_parser("json", lambda s: s.lstrip().startswith(("{", "[")), parse_json)
register_parser("cef", lambda s: s.lstrip().startswith("CEF:"), parse_cef)
register_parser("leef", lambda s: s.lstrip().startswith("LEEF:"), parse_leef)
register_parser("syslog", lambda s: bool(SYSLOG_RE.match(s.strip())) or bool(re.match(r"^[A-Za-z0-9_.:-]+\s+[\w./-]+:", s.strip())), parse_syslog)


def load_parser_plugins() -> None:
    """Load local Python parser adapters that expose register(register_parser)."""
    PARSER_DIR.mkdir(parents=True, exist_ok=True)
    for plugin_path in sorted(PARSER_DIR.glob("*.py")):
        if plugin_path.name.startswith("_"):
            continue
        module_name = f"ulpf_parser_{plugin_path.stem}"
        try:
            spec = importlib.util.spec_from_file_location(module_name, plugin_path)
            if spec is None or spec.loader is None:
                raise ImportError("Unable to load module")
            module = importlib.util.module_from_spec(spec)
            sys.modules[module_name] = module
            spec.loader.exec_module(module)
            register = getattr(module, "register")
            register(register_parser)
            print(f"Loaded parser plugin: {plugin_path.name}")
        except Exception as exc:
            print(f"Could not load parser plugin {plugin_path.name}: {exc}")


load_parser_plugins()


ALIASES = {
    "timestamp": ["eventTime", "timestamp", "@timestamp", "time", "datetime", "rt", "devTime", "eventCreated", "eventStart"],
    "vendor": ["deviceVendor", "vendor", "manufacturer", "observerVendor"],
    "product": ["deviceProduct", "product", "model", "observerProduct"],
    "version": ["deviceVersion", "version", "observerVersion"],
    "device": ["deviceHostName", "hostname", "host", "device", "deviceName", "observerName", "dhost"],
    "device_ip": ["deviceAddress", "deviceIp", "observerIp", "hostIp"],
    "process": ["appName", "processName", "process"],
    "src_ip": ["src", "srcIp", "sourceIp", "sourceAddress", "source.ip", "clientIp", "clientAddress", "shost"],
    "src_port": ["spt", "srcPort", "sourcePort", "source.port", "clientPort"],
    "src_host": ["sourceHost", "sourceHostname", "shost", "clientHost"],
    "dst_ip": ["dst", "dstIp", "destinationIp", "destinationAddress", "destination.ip", "serverIp", "dhost"],
    "dst_port": ["dpt", "dstPort", "destinationPort", "destination.port", "serverPort"],
    "dst_host": ["destinationHost", "destinationHostname", "dhost", "serverHost"],
    "protocol": ["proto", "protocol", "networkProtocol", "transport", "ipProtocol"],
    "application": ["app", "application", "service", "networkApplication"],
    "action": ["act", "action", "eventAction", "deviceAction", "disposition"],
    "severity": ["severity", "sev", "priority", "eventSeverity", "level"],
    "event_code": ["signatureId", "eventId", "eventCode", "code", "ruleId", "msgid"],
    "event_name": ["name", "eventName", "signature", "eventType", "cat"],
    "message": ["message", "msg", "description", "reason", "eventMessage"],
    "user": ["suser", "duser", "user", "username", "usrName", "accountName", "principal"],
    "rule": ["rule.name", "ruleName", "policy", "policyName", "cs1"],
    "outcome": ["outcome", "result", "status"],
}


def flatten(obj: object, prefix: str = "") -> dict[str, object]:
    result: dict[str, object] = {}
    if isinstance(obj, dict):
        for key, value in obj.items():
            if str(key).startswith("_"):
                continue
            path = f"{prefix}.{key}" if prefix else str(key)
            if isinstance(value, dict):
                result.update(flatten(value, path))
            else:
                result[path] = value
                result.setdefault(str(key), value)
    else:
        result[prefix or "value"] = obj
    return result


def as_text(value: object) -> str | None:
    if value is None or value == "":
        return None
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False)
    return str(value)


def pick(flat: dict[str, object], aliases: list[str]) -> tuple[object | None, str | None]:
    normalized = {key_name(key): (key, value) for key, value in flat.items()}
    for alias in aliases:
        found = normalized.get(key_name(alias))
        if found and found[1] is not None and found[1] != "":
            return found[1], found[0]
    return None, None


def parse_time(value: object | None) -> str | None:
    if value is None or value == "":
        return None
    try:
        if isinstance(value, (float, int)) or re.fullmatch(r"\d{10,13}(?:\.\d+)?", str(value)):
            numeric = float(value)
            if numeric > 10_000_000_000:
                numeric /= 1000
            return datetime.fromtimestamp(numeric, timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
        text = str(value).strip()
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        parsed = datetime.fromisoformat(text)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    except (ValueError, OverflowError, OSError):
        return None


def severity_value(value: object | None) -> tuple[int | None, str | None]:
    if value is None:
        return None, None
    raw = str(value).strip().lower()
    named = {"informational": (1, "informational"), "info": (1, "informational"),
             "low": (3, "low"), "medium": (5, "medium"), "moderate": (5, "medium"),
             "high": (8, "high"), "critical": (10, "critical"), "severe": (9, "critical"),
             "emergency": (10, "critical"), "alert": (9, "critical"), "error": (7, "high"),
             "warning": (4, "medium"), "notice": (2, "low")}
    if raw in named:
        return named[raw]
    try:
        numeric = float(raw)
        # CEF uses 0-10; some source formats use syslog's 0-7 priority values.
        value10 = int(round(numeric))
        if 0 <= numeric <= 10:
            label = "informational" if value10 <= 2 else "low" if value10 <= 4 else "medium" if value10 <= 6 else "high" if value10 <= 8 else "critical"
            return value10, label
    except ValueError:
        pass
    return None, raw


def normalize(raw: str) -> dict:
    parsed: dict = {}
    parser_name = "raw"
    parse_error = None
    for name, detector, parser in PARSER_REGISTRY:
        if detector(raw):
            try:
                parsed = parser(raw)
                parser_name = str(parsed.get("_format", name))
                break
            except (ValueError, json.JSONDecodeError) as exc:
                parse_error = str(exc)
                parser_name = name
                parsed = {"message": raw, "_format": name, "_parse_error": parse_error}
                break
    if not parsed:
        parsed = {"message": raw, "_format": "raw", "_partial": True}
    flat = flatten(parsed)
    mappings: dict[str, str] = {}

    def get(target: str) -> object | None:
        value, origin = pick(flat, ALIASES[target])
        if origin is not None:
            mappings[origin] = target
        return value

    event_time = parse_time(get("timestamp"))
    vendor = as_text(get("vendor"))
    product = as_text(get("product"))
    version = as_text(get("version"))
    device = as_text(get("device"))
    device_ip = as_text(get("device_ip"))
    process = as_text(get("process"))
    src_ip = as_text(get("src_ip"))
    src_port = as_text(get("src_port"))
    src_host = as_text(get("src_host"))
    dst_ip = as_text(get("dst_ip"))
    dst_port = as_text(get("dst_port"))
    dst_host = as_text(get("dst_host"))
    protocol = as_text(get("protocol"))
    application = as_text(get("application"))
    action = as_text(get("action"))
    severity_raw = get("severity")
    severity, severity_text = severity_value(severity_raw)
    event_code = as_text(get("event_code"))
    event_name = as_text(get("event_name"))
    message = as_text(get("message"))
    user = as_text(get("user"))
    rule_name = as_text(get("rule"))
    outcome = as_text(get("outcome"))

    if not outcome and action:
        action_lower = action.lower()
        if any(word in action_lower for word in ("deny", "denied", "drop", "dropped", "block", "blocked", "reject", "rejected", "fail")):
            outcome = "failure"
        elif any(word in action_lower for word in ("allow", "allowed", "accept", "permit", "permitted", "pass", "success")):
            outcome = "success"
    if action and action.lower() in {"deny", "denied", "drop", "dropped", "block", "blocked", "reject", "rejected", "allow", "allowed", "accept", "permit", "permitted", "pass"}:
        action = action.lower()
    if not message and event_name:
        message = event_name

    consumed_keys = {key_name(key) for key in mappings}
    unmapped: dict[str, object] = {}
    for key, value in flat.items():
        # Do not duplicate leaf aliases emitted by flatten().
        if "." not in key and any(key == path.rsplit(".", 1)[-1] for path in flat if "." in path):
            continue
        if key_name(key) not in consumed_keys:
            unmapped[key] = value

    extracted = bool(mappings)
    partial = bool(parsed.get("_partial") or parse_error)
    status = "normalized" if extracted and not partial else "partial" if parser_name != "raw" else "unparsed"
    ingested = utc_now()
    source_format = str(parsed.get("_format", parser_name))
    event_id = str(uuid.uuid4())
    raw_bytes = raw.encode("utf-8", errors="surrogatepass")

    normalized = {
        "schema_version": SCHEMA_VERSION,
        "event_id": event_id,
        "event": {
            "created": event_time or ingested,
            "ingested": ingested,
            "category": "network" if any((src_ip, dst_ip, protocol, action)) else "unknown",
            "kind": "event",
            "type": event_name,
            "action": action,
            "outcome": outcome,
            "severity": severity,
            "severity_text": severity_text,
            "code": event_code,
        },
        "source": {
            "format": source_format,
            "vendor": vendor,
            "product": product,
            "version": version,
            "device_name": device,
            "ip": device_ip,
            "process": process,
        },
        "source_endpoint": {"ip": src_ip, "port": src_port, "hostname": src_host},
        "destination_endpoint": {"ip": dst_ip, "port": dst_port, "hostname": dst_host},
        "network": {"protocol": protocol, "application": application},
        "principal": {"user": user},
        "rule": {"name": rule_name, "id": as_text(flat.get("ruleId"))},
        "message": message,
        "normalization": {
            "status": status,
            "parser": parser_name,
            "parser_version": PARSER_VERSION,
            "field_mappings": mappings,
            "unmapped_fields": unmapped,
            "parse_error": parse_error,
        },
        "raw": {
            "encoding": "utf-8",
            "text": raw,
            "sha256": hashlib.sha256(raw_bytes).hexdigest(),
        },
    }
    return normalized


class Handler(BaseHTTPRequestHandler):
    server_version = "ULPF/0.1"

    def log_message(self, fmt: str, *args) -> None:
        print("[%s] %s" % (self.log_date_time_string(), fmt % args))

    def send_json(self, payload: object, status: int = 200) -> None:
        body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        parsed_url = urlparse(self.path)
        path = unquote(parsed_url.path)
        params = parse_qs(parsed_url.query)
        if path == "/api/health":
            return self.send_json({"status": "ok", "schema_version": SCHEMA_VERSION})
        if path == "/api/parsers":
            return self.send_json({"parsers": [{"id": p[0], "version": PARSER_VERSION} for p in PARSER_REGISTRY] + [{"id": "raw-fallback", "version": PARSER_VERSION}]})
        if path == "/api/stats":
            with db_lock:
                total = db.execute("SELECT COUNT(*) FROM events").fetchone()[0]
                by_status = {row[0]: row[1] for row in db.execute("SELECT status, COUNT(*) FROM events GROUP BY status")}
                by_format = {row[0]: row[1] for row in db.execute("SELECT source_format, COUNT(*) FROM events GROUP BY source_format")}
                recent = db.execute("SELECT ingested_at FROM events ORDER BY ingested_at DESC LIMIT 1").fetchone()
            return self.send_json({"total": total, "by_status": by_status, "by_format": by_format, "last_ingested": recent[0] if recent else None})
        if path == "/api/events":
            limit = min(max(int(params.get("limit", ["100"])[0]), 1), 200)
            offset = max(int(params.get("offset", ["0"])[0]), 0)
            q = params.get("q", [""])[0].strip()
            status = params.get("status", [""])[0]
            fmt = params.get("format", [""])[0]
            clauses: list[str] = []
            values: list[object] = []
            if q:
                clauses.append("(payload LIKE ? OR event_id LIKE ?)")
                values.extend((f"%{q}%", f"%{q}%"))
            if status:
                clauses.append("status = ?")
                values.append(status)
            if fmt:
                clauses.append("source_format = ?")
                values.append(fmt)
            where = " WHERE " + " AND ".join(clauses) if clauses else ""
            with db_lock:
                total = db.execute("SELECT COUNT(*) FROM events" + where, values).fetchone()[0]
                rows = db.execute("SELECT payload FROM events" + where + " ORDER BY ingested_at DESC LIMIT ? OFFSET ?", [*values, limit, offset]).fetchall()
            return self.send_json({"total": total, "limit": limit, "offset": offset, "events": [json.loads(row[0]) for row in rows]})
        if path.startswith("/api/events/"):
            parts = path.strip("/").split("/")
            raw_download = len(parts) == 4 and parts[-1] == "raw"
            event_id = parts[2] if raw_download else parts[-1]
            with db_lock:
                row = db.execute("SELECT payload FROM events WHERE event_id = ?", (event_id,)).fetchone()
            if not row:
                return self.send_json({"error": "Event not found"}, 404)
            payload = json.loads(row[0])
            if raw_download:
                body = payload["raw"]["text"].encode("utf-8", errors="surrogatepass")
                self.send_response(200)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Content-Disposition", f'attachment; filename="{event_id}.log"')
                self.end_headers()
                return self.wfile.write(body)
            return self.send_json(payload)
        if path == "/api/export":
            with db_lock:
                rows = db.execute("SELECT payload FROM events ORDER BY ingested_at ASC").fetchall()
            body = "".join(row[0] + "\n" for row in rows).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/x-ndjson; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Content-Disposition", 'attachment; filename="ulpf-events.jsonl"')
            self.end_headers()
            return self.wfile.write(body)
        if path == "/" or path == "/index.html":
            return self.serve_static("index.html")
        if path == "/README.md":
            return self.serve_readme()
        if path.startswith("/static/"):
            return self.serve_static(path.removeprefix("/static/"))
        return self.send_json({"error": "Not found"}, 404)

    def serve_static(self, name: str) -> None:
        candidate = (STATIC / name).resolve()
        if STATIC.resolve() not in candidate.parents and candidate != STATIC.resolve():
            return self.send_json({"error": "Not found"}, 404)
        if not candidate.is_file():
            return self.send_json({"error": "Not found"}, 404)
        body = candidate.read_bytes()
        content_type = "text/html; charset=utf-8" if candidate.suffix == ".html" else "text/plain; charset=utf-8"
        if candidate.suffix == ".css":
            content_type = "text/css; charset=utf-8"
        elif candidate.suffix == ".js":
            content_type = "text/javascript; charset=utf-8"
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def serve_readme(self) -> None:
        candidate = ROOT / "README.md"
        if not candidate.is_file():
            return self.send_json({"error": "Not found"}, 404)
        body = candidate.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", "text/markdown; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:
        if urlparse(self.path).path != "/api/ingest":
            return self.send_json({"error": "Not found"}, 404)
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            return self.send_json({"error": "Invalid Content-Length"}, 400)
        if length < 1 or length > MAX_REQUEST_BYTES:
            return self.send_json({"error": f"Request body must be between 1 byte and {MAX_REQUEST_BYTES} bytes"}, 413)
        body = self.rfile.read(length)
        content_type = self.headers.get("Content-Type", "text/plain").split(";", 1)[0].lower()
        try:
            if content_type == "application/json":
                payload = json.loads(body.decode("utf-8"))
                items = payload.get("events", []) if isinstance(payload, dict) and "events" in payload else payload
                if isinstance(items, (str, dict)):
                    items = [items]
                if not isinstance(items, list):
                    raise ValueError("JSON body must be an event, an array, or an object with an events array")
                raws = [item if isinstance(item, str) else json.dumps(item, ensure_ascii=False, separators=(",", ":")) for item in items]
            else:
                text = body.decode("utf-8")
                raws = [line for line in text.splitlines() if line.strip()]
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            return self.send_json({"error": str(exc)}, 400)
        if not raws:
            return self.send_json({"error": "No non-empty events were provided"}, 400)
        events = [normalize(raw) for raw in raws]
        rows = [(item["event_id"], item["event"]["ingested"], item["source"]["format"], item["normalization"]["status"], item["source"]["vendor"] or item["source"]["product"] or item["source"]["device_name"] or "Unidentified", json.dumps(item, ensure_ascii=False, separators=(",", ":"))) for item in events]
        with db_lock:
            db.executemany("INSERT INTO events(event_id, ingested_at, source_format, status, source_label, payload) VALUES (?, ?, ?, ?, ?, ?)", rows)
            db.commit()
        return self.send_json({"accepted": len(events), "events": events}, 201)


def main() -> None:
    host = os.environ.get("ULPF_HOST", "127.0.0.1")
    # 8765 avoids common local reservations of port 8080 on Windows machines.
    port = int(os.environ.get("ULPF_PORT", "8765"))
    server = ThreadingHTTPServer((host, port), Handler)
    print(f"ULPF prototype listening on http://{host}:{port}")
    print(f"SQLite event store: {DB_PATH}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down ULPF")
    finally:
        server.server_close()
        with db_lock:
            db.close()


if __name__ == "__main__":
    main()
