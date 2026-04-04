# ES API Parser

A local developer reference for the macOS [Endpoint Security](https://developer.apple.com/documentation/endpointsecurity) API. Parses the SDK headers and renders them as a searchable, navigable UI — no server, no dependencies.

![ES API Parser screenshot](ES%20API%20Parser%20Screenshot.png)

## Usage

### Local (macOS)

```sh
python3 parse.py   # parse SDK headers → endpointsecurity-data.js
open index.html    # open the viewer
```

Requires Xcode (for `xcrun --show-sdk-path`). Re-run `parse.py` after an SDK update.

You can also point `parse.py` at an explicit SDK root (useful for testing extracted SDKs):

```sh
python3 parse.py --sdk-path /path/to/MacOSX.sdk
```

### Serving

The viewer is a static file — any HTTP server can serve it. Point your server's document root at the repo root (which contains `index.html` and the `generated/` folder).

`update_sdk.py` automates keeping the data current. It polls Apple's software update catalog, downloads and extracts the SDK `.pkg` if a new version is available, and re-runs `parse.py` in place. Schedule it with a cron job, systemd timer, or launchd agent at whatever interval suits you. Requires `xar` and `bsdtar` for `.pkg` extraction (`apt install xar libarchive-tools` on Debian/Ubuntu; both are available via Xcode Command Line Tools on macOS).

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
| `parse.py` | Parses `ESTypes.h`, `ESMessage.h`, `ESClient.h` → `endpointsecurity-data.js` |
| `index.html` | Self-contained viewer; loads `endpointsecurity-data.js` via `<script src>` |
| `endpointsecurity-data.js` | Generated — not committed |
| `endpointsecurity.json` | Generated (human-readable) — not committed |
| `update_sdk.py` | Polls Apple's SUCatalog, extracts SDK, re-runs `parse.py` |
