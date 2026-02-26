# Uptime Kuma HTTP Bridge

A lightweight Python HTTP bridge that exposes [Uptime Kuma](https://github.com/louislam/uptime-kuma) as a simple REST-like API. Manage monitors, tags, and status checks from any language or tool using plain HTTP — no Socket.IO client required.

## Features

- **Full monitor management** — create, edit, delete, pause, resume
- **Tag support** — add, remove, and replace tags on monitors; create new tags on the fly with custom colours
- **Bearer token authentication** — protect the bridge with a secret token
- **2FA / TOTP support** — works with Uptime Kuma accounts that have two-factor authentication enabled
- **Persistent connection** — single long-lived Socket.IO connection shared across all requests, with automatic reconnection
- **Clean shutdown** — Ctrl+C disconnects gracefully with no traceback
- **Zero extra dependencies** for basic use; `pyotp` is auto-installed if 2FA is configured

## Why use this?

Uptime Kuma's API is Socket.IO only — there is no official HTTP REST API. This bridge sits between your application and Kuma, so you can:

- Automatically create monitors when you deploy a new site
- Tag monitors by project, client, or technology stack
- Integrate with CI/CD pipelines, CRM systems, or any tool that can make HTTP requests

---

## Requirements

- Python 3.10+
- Uptime Kuma v2 (tested; may work with v1)
- Network access from the bridge host to the Kuma server

```bash
pip3 install "python-socketio[client]" websocket-client pyotp --break-system-packages
```

---

## Installation

```bash
git clone https://github.com/your-username/uptime-kuma-bridge.git
cd uptime-kuma-bridge
cp .env.example .env
# Edit .env with your settings
python3 uptime_kuma.py
```

---

## Configuration

Create a `.env` file in the same directory as the script:

```env
BRIDGE_HOST=127.0.0.1
BRIDGE_PORT=9911
BRIDGE_TOKEN=your-secret-token

KUMA_URL=http://your-kuma-server:3001
KUMA_USERNAME=admin
KUMA_PASSWORD=your-kuma-password

# Only required if your Kuma account has 2FA enabled
# This is the base32 SECRET string from the QR code — NOT a 6-digit code
KUMA_2FA_SECRET=

# Socket.IO call timeout in seconds (default 60)
KUMA_TIMEOUT=60
```

### Getting your 2FA secret

If Kuma 2FA is enabled, go to **Settings → Security → Two Factor Authentication → Setup**. The QR code encodes a URI like:

```
otpauth://totp/Uptime%20Kuma?secret=JBSWY3DPEHPK3PXP&issuer=...
```

The value after `secret=` is what goes in `KUMA_2FA_SECRET`. If you already set up 2FA without saving the secret, disable and re-enable it to retrieve it.

---

## Running

```bash
python3 uptime_kuma.py
```

Output on start:

```
[bridge] Listening  : http://127.0.0.1:9911
[bridge] Kuma URL   : http://your-kuma-server:3001
[bridge] Timeout    : 60s
[bridge] Auth token : set
[bridge] 2FA        : enabled (pyotp)
[bridge] Kuma connection established.
```

Press **Ctrl+C** to shut down cleanly.

To run as a background service, use `systemd`, `supervisor`, or `screen`.

---

## Authentication

All requests require a `Bearer` token header if `BRIDGE_TOKEN` is set:

```
Authorization: Bearer your-secret-token
```

Leave `BRIDGE_TOKEN` blank to disable authentication (not recommended for production).

---

## API Reference

All endpoints accept and return `application/json`. All responses include `"ok": true` on success or `"ok": false` with an `"error"` field on failure.

### Health Check

```
GET /health
```

Returns bridge status and configuration info.

---

### Monitors

#### List all monitors

```
POST /monitors/list
```

Returns all monitors from Kuma as a dict keyed by monitor ID.

---

#### Find a monitor by URL

```
POST /monitors/find
```

```json
{ "url": "https://example.com" }
```

Returns the first monitor whose URL matches (case-insensitive, ignores trailing slash).

---

#### Add a monitor

```
POST /monitors/add
```

```json
{
  "monitor": {
    "name": "My Website",
    "url": "https://example.com",
    "type": "http",
    "interval": 60,
    "notifications": [1, 2],
    "tags": ["#magento", 3, {"name": "#newtag", "color": "#7C3AED"}]
  }
}
```

**`notifications`** — pass a plain array of notification channel IDs; the bridge converts it to the format Kuma expects.

**`tags`** — flexible input:
- `"#tagname"` — find existing tag by name (case-insensitive), create it if not found
- `2` — link by tag ID directly
- `{"name": "#tagname", "color": "#hex"}` — find by name, or create with this colour

All Kuma monitor fields are supported. Unspecified fields use sensible defaults.

---

#### Edit a monitor

```
POST /monitors/edit
```

```json
{
  "monitor_id": 42,
  "monitor": {
    "name": "Updated Name",
    "interval": 30,
    "tags": ["#magento"]
  }
}
```

Fetches the existing monitor and merges your changes, so you only need to send the fields you want to update. If `tags` is included it replaces all existing tags on the monitor.

---

#### Delete a monitor

```
POST /monitors/delete
```

```json
{ "monitor_id": 42 }
```

---

#### Pause a monitor

```
POST /monitors/pause
```

```json
{ "monitor_id": 42 }
```

---

#### Resume a monitor

```
POST /monitors/resume
```

```json
{ "monitor_id": 42 }
```

---

#### Get monitor status / heartbeats

```
POST /monitors/status
```

```json
{ "monitor_id": 42 }
```

Returns the heartbeat list for the monitor.

---

### Tags

#### List all tag definitions

```
POST /tags/list
```

Returns all tag definitions from Kuma (id, name, colour).

---

#### Add tags to a monitor

```
POST /monitors/tags/set
```

```json
{
  "monitor_id": 42,
  "tags": ["#magento", 3]
}
```

Adds the specified tags to the monitor. Existing tags are kept unless you pass `"replace": true`.

```json
{
  "monitor_id": 42,
  "tags": ["#magento"],
  "replace": true
}
```

With `"replace": true`, all existing tags on the monitor are removed first, then the new ones are applied.

---

#### Remove tags from a monitor

```
POST /monitors/tags/delete
```

```json
{
  "monitor_id": 42,
  "tags": ["#magento"]
}
```

Removes only the specified tags. Other tags on the monitor are unaffected. Accepts tag names, IDs, or dicts.

---

### Sniff (debug)

```
POST /monitors/sniff
```

```json
{ "timeout": 60 }
```

Blocks for up to `timeout` seconds waiting for you to add a monitor through the Kuma web UI. Returns the exact raw Socket.IO payload that Kuma sent. Useful for discovering what fields your specific Kuma version expects.

---

## curl Examples

```bash
TOKEN="your-secret-token"
BASE="http://127.0.0.1:9911"

# Add a monitor with tags
curl -s -X POST $BASE/monitors/add \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"monitor": {"name": "My Site", "url": "https://example.com", "tags": ["#production"]}}'

# Edit a monitor
curl -s -X POST $BASE/monitors/edit \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"monitor_id": 42, "monitor": {"interval": 30}}'

# Add a tag to an existing monitor
curl -s -X POST $BASE/monitors/tags/set \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"monitor_id": 42, "tags": ["#magento"]}'

# Remove a tag
curl -s -X POST $BASE/monitors/tags/delete \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"monitor_id": 42, "tags": ["#magento"]}'

# Replace all tags
curl -s -X POST $BASE/monitors/tags/set \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"monitor_id": 42, "tags": ["#wordpress", "#production"], "replace": true}'

# List all monitors
curl -s -X POST $BASE/monitors/list \
  -H "Authorization: Bearer $TOKEN"

# Pause / resume
curl -s -X POST $BASE/monitors/pause \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"monitor_id": 42}'
```

---

## Technical Notes

- The bridge maintains a **single persistent Socket.IO connection** to Kuma, shared across all HTTP requests. If the connection drops it reconnects automatically on the next request.
- Tags use Kuma's `addMonitorTag` / `deleteMonitorTag` socket events with positional arguments (not a single object — this is a quirk of the Kuma Socket.IO API).
- Newly created tag definitions are cached in memory immediately so they can be found by name in subsequent requests within the same session.
- The tag cache is seeded on first use via a `getTags` socket call (Kuma does not push this automatically on connect).

---

## License

MIT
