# JavaTg-Ws-Proxy

<div align="center">

**[🇷🇺 Русский](./README.md) • 🇬🇧 English**

</div>

> [!NOTE]
> ## Acknowledgments
>
> This project is a Java port of **[tg-ws-proxy]**, originally written in Python by **[Flowseal]**.
>
> - **Original Repository:** [https://github.com/Flowseal/tg-ws-proxy](https://github.com/Flowseal/tg-ws-proxy)
> - **Original License:** MIT
>
> The core logic and architecture are based on the original work. The Java implementation is a complete rewrite.

## Requirements
> [!IMPORTANT]
> Built and run using Gradle (Java 11+).

## Assembly and startup

Assembly:
```bash
./gradlew build       # Fat and thin client
./gradlew shadowJar   # Fat client only
./gradlew jar         # Thin client only (without dependencies)
./gradlew installDist # Thin client with dependencies
```

Запуск:
```bash
./gradlew run --args="--port 1443 -v" # Run via Gradle, passing an argument
java -jar build\libs\JavaTg-Ws-Proxy-1.0-all.jar --port 1443 -v # Run the "fat" client (all-in-one JAR)
build\install\JavaTg-Ws-Proxy\bin\JavaTg-Ws-Proxy.bat --port 1443 -v # Run the "thin" client on Windows
build\install\JavaTg-Ws-Proxy\bin\JavaTg-Ws-Proxy --port 1443 -v # Run the "thin" client on Linux
```

Upon startup, the core prints a banner containing its parameters and a `tg://proxy?...` link (a `dd` secret, or an `ee` link if Fake TLS is enabled).
## Flags
| Flag | Description |
|---|---|
| `--port PORT`| Listen port (default 1443) |
| `--host HOST`| Listen host (default 127.0.0.1)|
| `--secret SECRET`| MTProto proxy secret (32 hex chars). Auto-generated if not provided. |
| `--dc-ip DC:IP`| Target IP for a DC, e.g. --dc-ip 2:149.154.167.220 (repeatable; bare --dc-ip disables redirects)|
| `-v, --verbose`| Debug logging |
| `--log-file PATH`| Log to file with rotation (default: stderr only)|
| `--log-max-mb MB`| Max log file size in MB before rotation (default 5)|
| `--log-backups N`| Number of rotated log files to keep (min 1)|
| `--buf-kb KB`| Socket send/recv buffer size in KB (default 256)|
| `--pool-size N`| WS connection pool size per DC (default 4, 0 disables direct WS)|
| `--cfproxy-domain DOMAIN`| User defined Cloudflare-proxied domain for H2 media and WS fallback (repeatable)|
| `--cfproxy-worker-domain DOMAIN`|Cloudflare Worker domain for WS fallback (tried before other fallback methods, repeatable)|
| `--no-h2`| Disable HTTP/2 multiplexing for CF media (enabled by default)|
| `--no-cfproxy`| Disable Cloudflare proxy fallback|
| `--no-secure`| Use 80 port for CF-proxy and CF-worker connections|
| `--fake-tls-domain DOMAIN`| Enable Fake TLS (ee-secret) masking with the given SNI domain, e.g. example.com|
| `--force-test-dc`| Force ALL traffic to Telegram TEST datacenters|
| `--proxy-protocol`| Accept PROXY protocol v1 header|
| `-h, --help`| Show this help message and exit|

## What’s Inside

- **WS Pool** (`pool/WsPool`): Direct WebSocket connections to `kwsN.web.telegram.org/apiws` using domain fronting (SNI set to `sprinthost.ru`, Host header set to `kwsN...`). It tracks the most successful connection mode (fronting-first vs. direct-first), performs background rotation every 5 seconds, and employs an exponential backoff for connection attempts, ranging from 1 second to 1 hour.
- **CF Pool** (`pool/CfWorkerPool`): A fallback mechanism utilizing Cloudflare domains and a Cloudflare Worker.
- **H2-media** (`net/CfH2Pool`, `net/H2Channel`): Media packets are transmitted via HTTP/2 POST requests (`https://kwsN.<domain>/api`), mimicking standard web traffic.
- **Fake TLS** (`net/FakeTls`): A `ServerHello` is synthesized based on the client’s `ClientHello` (cycling through cipher suites `0x1301` → `0x1303` → `0x1302`, mirroring `X25519MLKEM768`, with 64–160 byte `AppData` payloads). It includes a replay cache to thwart active probing and introduces an 8–24 ms response delay.
- **RawWebSocket** (`net/RawWebSocket`): A `ClientHello` that includes an ALPN extension (`http/1.1` for WebSockets, `h2` for H2 transport). Without this ALPN, DPI systems will terminate the connection (resulting in a "Read timed out" error). - **Bridge** (`bridge/Bridge`): fallback order is `cf_worker → cf (H2 for media) → tcp`;
includes support for test DCs (>= 10000) and the `--force-test-dc` flag; TCP-fallback features a backoff period ranging from 30 seconds to 1 hour.
- **CF Domains**: includes a built-in, encrypted list (20 domains) plus an auto-update mechanism that fetches data from GitHub once an hour (`Flowseal/tg-ws-proxy/.github/cfproxy-domains.txt`); specifying custom domains via `--cfproxy-domain` disables this auto-update feature.

## License
[MIT License](../LICENSE.txt)