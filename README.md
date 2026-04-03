# ES API Parser

A local developer reference for the macOS [Endpoint Security](https://developer.apple.com/documentation/endpointsecurity) API. Parses the SDK headers and renders them as a searchable, navigable UI — no server, no dependencies.

## Usage

```sh
python3 parse.py   # parse SDK headers → esvis-data.js
open index.html    # open the viewer
```

Requires Xcode (for `xcrun --show-sdk-path`). Re-run `parse.py` after an SDK update.

## Features

- **Search** across event names, struct fields, types, and doc text
- **Events** — all `AUTH`, `NOTIFY`, and `RESERVED` event types with macOS availability
- **Structs & Enums** — fields, types, `@field` docs, and message version constraints
- **Type links** — click any `es_*_t` field type to navigate to its definition
- **Source view** — `</>` button shows the raw C header for any struct or enum
- **Telemetry classes** — group events by category (Process, File System, Socket, etc.)
- **Message version filter** — dim or hide fields unavailable at a given version
- **macOS version filter** — show only events available in a target OS release
- **Themes & scale** — dark / light / auto, five zoom levels, persisted via `localStorage`

## Files

| File | Description |
|------|-------------|
| `parse.py` | Parses `ESTypes.h`, `ESMessage.h`, `ESMessageCore.h` → `esvis-data.js` |
| `index.html` | Self-contained viewer; loads `esvis-data.js` via `<script src>` |
| `esvis-data.js` | Generated — not committed |
| `esvis.json` | Generated (human-readable) — not committed |
