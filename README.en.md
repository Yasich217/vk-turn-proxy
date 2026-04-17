# VK/WB TURN Proxy
[Russian version](README.md)

Proxy server for WireGuard/Hysteria traffic over VK Calls and WB Stream TURN servers. Clients encrypt traffic with DTLS 1.2 and send it in parallel streams to TURN; the server aggregates those streams, keeps one UDP backend connection to WireGuard, and fans out responses to the active DTLS peers.

## Features

- **VK Calls** — TURN credentials from VK API with automatic captcha solving.
- **WB Stream** — TURN credentials from WB Stream API.
- **Protocols** — support for `proxy_v1`, `proxy_v2`, and `proxy_v2_meta`.
- **Meta mode** — our extra client-state/webhook/script hooks are enabled only for `proxy_v2_meta`.
- **Caching** — 10 minute TTL with shared cache across streams.
- **DTLS obfuscation** — DPI bypass via DTLS tunnel.
- **Multi-stream aggregation** — multiple streams from one client are grouped by Session ID.
- **Compatibility** — legacy `v1` server flow and WB mode from the fork are preserved.

## Our additions

This branch stays compatible with the core `vk-turn-proxy` protocol while extending it for our `wireguard-turn-android` client.

- **External JSON client-state export**: the server can optionally write active client state to a JSON file for a dashboard or automation.
- **Extended client metadata**: the server accepts and keeps additional Android client fields such as connection status, TURN mode, active stream count, and network metadata like public IP.
- **Scoped hooks**: webhooks and local scripts are available only for `proxy_v2_meta`; `proxy_v1` and `proxy_v2` stay plain TURN modes.
- **No mandatory API drift**: if state export is not enabled through environment variables, the server behaves like a regular `vk-turn-proxy` build and keeps the base proxy API intact.

For educational purposes only!

## Client Structure

```
client/
├── credentials.go    # Shared credentials cache, request serialization
├── vk.go             # VK API: Token 1→4 chain, HTTP requests
├── vk_captcha.go     # VK Captcha: PoW solving, Not Robot flow
├── wb.go             # WB Stream: guest register → room → LiveKit ICE
└── main.go           # DTLS/TURN connections, CLI, main loop
```

## Setup

You will need:
1. A link to an active VK call: create your own (requires a VK account) or search for `"https://vk.com/call/join/"`. Links are valid forever unless "end call for all" is clicked.
2. A VPS with WireGuard installed.
3. For Android: Download Termux from F-Droid.

### Server

```bash
./server -listen 0.0.0.0:56000 -connect 127.0.0.1:<wg_port>
```

Supported modes:
- `proxy_v1` — old DTLS flow without `session_id` and `stream_id`.
- `proxy_v2` — DTLS flow with `session_id + stream_id`.
- `proxy_v2_meta` — our `v2` flow with extra metadata, webhooks, and scripts.

The server runs in universal mode: a single instance on one port can serve mixed `proxy_v1`, `proxy_v2`, and `proxy_v2_meta` clients at the same time without restarts. The mode is detected automatically from the first DTLS packet and, for `proxy_v2_meta`, confirmed by the `WGTM` metadata frame.

Webhooks, commands, and client-state export are enabled only for `proxy_v2_meta`. `proxy_v1` and `proxy_v2` run as plain TURN proxy modes without those hooks.

Optional client-state export can be enabled via environment variables:
- `VKTURN_STATE_JSON=/path/to/clients-state.json`
- `VKTURN_STATE_INACTIVE_GRACE=90s`

If `VKTURN_STATE_JSON` is not set, the server behaves like the standard build and does not persist external state.

Lifecycle webhooks can also be enabled through environment variables. Each event has its own variables:
- `VKTURN_WEBHOOK_ON_SESSION_CREATED_URL/METHOD/TEMPLATE/HEADERS`
- `VKTURN_WEBHOOK_ON_SESSION_UPDATED_URL/METHOD/TEMPLATE/HEADERS`
- `VKTURN_WEBHOOK_ON_SESSION_IDLE_URL/METHOD/TEMPLATE/HEADERS`
- `VKTURN_WEBHOOK_ON_SESSION_EXPIRED_URL/METHOD/TEMPLATE/HEADERS`
- `VKTURN_WEBHOOK_ON_SESSION_CLOSED_URL/METHOD/TEMPLATE/HEADERS`

Global webhook transport settings:
- `VKTURN_WEBHOOK_TIMEOUT=3s`
- `VKTURN_WEBHOOK_SSL_VERIFY=true`

Only `GET` and `POST` are supported. `POST` requires a template, while `GET` may omit it. `HEADERS` must be a JSON object. If an event config is incomplete or invalid, the server exits on startup with a clear log message.

Local commands and scripts are available through the same event-based pattern. Each event can define one command:
- `VKTURN_EXEC_ON_SESSION_CREATED_COMMAND`
- `VKTURN_EXEC_ON_SESSION_UPDATED_COMMAND`
- `VKTURN_EXEC_ON_SESSION_IDLE_COMMAND`
- `VKTURN_EXEC_ON_SESSION_EXPIRED_COMMAND`
- `VKTURN_EXEC_ON_SESSION_CLOSED_COMMAND`

Global execution settings:
- `VKTURN_EXEC_TIMEOUT=3s`
- `VKTURN_EXEC_SHELL=/bin/sh`

The command runs through a shell, so you can point it at a direct command or an executable script. The same variables are available in the command text and as environment variables: `${event}`, `${session_id}`, `${status}`, `${public_key}`, `${client_public_ip}`, `${relay_ips_csv}`, `${relay_ips_json}`, `${active_streams}`, `${persistent_keepalive}`, `${last_seen_unix}`, `${last_change_unix}`, `${ts_unix}`.

### Client

#### Android

**Recommended method:**
Use the native Android app [wireguard-turn-android](https://github.com/Yasich217/wireguard-turn-android). This is a modified WireGuard client with built-in TURN support, OTA updates, and extended client metadata reporting.

**Alternative method (via Termux):**
- In the WireGuard client config, change the server address to `127.0.0.1:9000` and set MTU to 1280.
- **Add Termux to WireGuard exceptions. Click "Save".**

In Termux:
```bash
termux-wake-lock
```
The phone will not enter deep sleep. To disable:
```bash
termux-wake-unlock
```
Copy the binary to a local folder and grant execution rights:
```bash
cp /sdcard/Download/client-android ./
chmod 777 ./client-android
```

**VK mode:**
```bash
./client-android -peer <wg_server_ip>:56000 -vk-link <VK_link> -listen 127.0.0.1:9000
```

**WB mode:**
```bash
./client-android -wb -peer <wg_server_ip>:56000 -listen 127.0.0.1:9000
```

Additional flags:
- `-session-id <hex>`: set a fixed session ID (32 hex characters).
- `-n <num>`: number of connections to TURN (default 4).
- `-udp`: use UDP for TURN (default TCP).
- `-turn <ip>`: override TURN server address.
- `-port <port>`: override TURN server port.
- `-no-dtls`: without DTLS obfuscation (may result in a ban).
- `-v1`: use v1 protocol (no session_id and stream_id sent). For legacy servers.

#### Linux

In the WireGuard client config, change the server address to `127.0.0.1:9000` and set MTU to 1280.

The script will add routes to the necessary IPs:

```bash
./client-linux -peer <wg_server_ip>:56000 -vk-link <VK_link> -listen 127.0.0.1:9000 | sudo routes.sh
```

```bash
./client-linux -wb -peer <wg_server_ip>:56000 -listen 127.0.0.1:9000 | sudo routes.sh
```

⚠️ Do not enable the VPN until the program has established a connection! Unlike Android, some requests will go through the VPN here (DNS and TURN connection requests).

#### Windows

In the WireGuard client config, change the server address to `127.0.0.1:9000` and set MTU to 1280.

In PowerShell as Administrator (so the script can add routes):

```powershell
./client.exe -peer <wg_server_ip>:56000 -vk-link <VK_link> -listen 127.0.0.1:9000 | routes.ps1
```

```powershell
./client.exe -wb -peer <wg_server_ip>:56000 -listen 127.0.0.1:9000 | routes.ps1
```

⚠️ Do not enable the VPN until the program has established a connection! Unlike Android, some requests will go through the VPN here (DNS and TURN connection requests).

### If it doesn't work

Use the `-turn` option to manually specify a TURN server address. This should be a VK, Max, or Odnoklassniki server (VK link) or WB Stream (WB mode).

If TCP doesn't work, try adding the `-udp` flag.

Add `-n 1` for a more stable single-stream connection (limited to 5 Mbps for VK).

## VK Auth Flow

1. **Token 1** — anonymous token (`login.vk.ru`)
2. **getCallPreview** — call preview (optional)
3. **Token 2** — anonymous token for the call (`api.vk.ru`)
   - On captcha → PoW solving → retry
4. **Token 3** — OK session key (`calls.okcdn.ru`)
5. **Token 4** — TURN credentials (`calls.okcdn.ru`)

## WB Auth Flow

1. **Guest register** — guest registration (`stream.wb.ru`)
2. **Create room** — create a room
3. **Join room** — join the room
4. **Get token** — get roomToken
5. **LiveKit ICE** — WebSocket to LiveKit, protobuf TURN parsing

## Caching

- TTL: **10 minutes** (safety margin 60 seconds)
- One cache per **4 streams** (`streamID / 4`)
- Fast path via `RLock`
- Fetch serialization via global `fetchMu`

## v2ray

Instead of WireGuard, you can use any V2Ray core that supports it (e.g., xray or sing-box) and any V2Ray client that uses this core (e.g., v2rayN or v2rayNG). This allows you to add more inbound interfaces (e.g., SOCKS) and implement fine-grained routing.

Example configs:

<details>

<summary>
Client
</summary>

```json
{
    "inbounds": [
        {
            "protocol": "socks",
            "listen": "127.0.0.1",
            "port": 1080,
            "settings": {
                "udp": true
            },
            "sniffing": {
                "enabled": true,
                "destOverride": [
                    "http",
                    "tls"
                ]
            }
        },
        {
            "protocol": "http",
            "listen": "127.0.0.1",
            "port": 8080,
            "sniffing": {
                "enabled": true,
                "destOverride": [
                    "http",
                    "tls"
                ]
            }
        }
    ],
    "outbounds": [
        {
            "protocol": "wireguard",
            "settings": {
                "secretKey": "<client secret key>",
                "peers": [
                    {
                        "endpoint": "127.0.0.1:9000",
                        "publicKey": "<server public key>"
                    }
                ],
                "domainStrategy": "ForceIPv4",
                "mtu": 1280
            }
        }
    ]
}
```

</details>

<details>

<summary>
Server
</summary>

```json
{
    "inbounds": [
        {
            "protocol": "wireguard",
            "listen": "0.0.0.0",
            "port": 51820,
            "settings": {
                "secretKey": "<server secret key>",
                "peers": [
                    {
                        "publicKey": "<client public key>"
                    }
                ],
                "mtu": 1280
            },
            "sniffing": {
                "enabled": true,
                "destOverride": [
                    "http",
                    "tls"
                ]
            }
        }
    ],
    "outbounds": [
        {
            "protocol": "freedom",
            "settings": {
                "domainStrategy": "UseIPv4"
            }
        }
    ]
}
```

</details>

## Direct mode

With the `-no-dtls` flag, you can send packets without DTLS obfuscation and connect to regular WireGuard servers. This may result in a ban from VK/WB.

Thanks to https://github.com/KillTheCensorship/Turnel for part of the code :)

WB Stream functionality is based on https://github.com/jaykaiperson/lionheart
