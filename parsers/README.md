# Adding a parser plug-in

Create a `.py` file directly in this directory. The framework loads it at startup and calls its `register(register_parser)` function. Register a detector and a parser; the parser returns a dictionary of source fields. Map familiar keys such as `src`, `dst`, `dpt`, `proto`, `act`, `severity`, and `eventTime` to have them flow into the common event envelope. Keep source-specific fields in the returned dictionary so they remain visible as unmapped fields, and restart the service after adding or changing a plug-in.

`examples/example_vendor.py` is an executable example for the fictional EDGEFLOW format. Copy it into this directory to activate that adapter. Plug-ins are trusted local Python code and run with the framework's permissions.
