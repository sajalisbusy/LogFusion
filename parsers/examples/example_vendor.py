"""Example adapter for a made-up KEY=value firewall format.

Example line:
EDGEFLOW|v=1|time=2026-09-29T12:00:00Z|src=10.0.0.8|dst=203.0.113.4|dpt=443|proto=tcp|act=deny
"""


def register(register_parser):
    def detects(raw):
        return raw.startswith("EDGEFLOW|")

    def parse(raw):
        fields = {"_format": "edgeflow"}
        for token in raw.split("|")[1:]:
            if "=" in token:
                key, value = token.split("=", 1)
                fields[key] = value
        return fields

    register_parser("edgeflow", detects, parse)
