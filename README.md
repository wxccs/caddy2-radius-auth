# caddy2-radius-auth

RADIUS Authentication Module for Caddy 2

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Installation](#installation)
- [Configuration](#configuration)
- [Examples](#examples)
- [Limitations](#limitations)
- [Contributing](#contributing)
- [License](#license)

---

## Overview

`caddy2-radius-auth` is a RADIUS authentication module for **Caddy 2**.  
It authenticates HTTP requests against one or more RADIUS servers, enabling centralized credential management while keeping configuration consistent with Caddy’s built-in `basic_auth` directive.

This module is designed to be drop-in compatible with `basic_auth` usage patterns, making migration and configuration straightforward.

---

## Features

- Standard RADIUS authentication (Access-Request / Access-Accept / Access-Reject)
- Same configuration semantics as Caddy’s `basic_auth`
- Supports multiple RADIUS servers
- Configurable realm, timeout, and optional authentication cache
- Seamless integration with Caddy’s authentication chain
- Works with both **Caddyfile** and **JSON** configurations

---

## Installation

Build Caddy with this module using **xcaddy**:

```bash
xcaddy build \
  --with github.com/wxccs/caddy2-radius-auth
````

Alternatively, include it manually in your Go build:

```go
require (
    github.com/wxccs/caddy2-radius-auth v0.0.0 // replace with correct version
)

replace github.com/wxccs/caddy2-radius-auth => ../path/to/local/caddy2-radius-auth
```

---

## Configuration

This module uses the same configuration syntax as `basic_auth`, with the following parameters:

| Parameter   | Type     | Description                                                                                  |
| ----------- | -------- | -------------------------------------------------------------------------------------------- |
| `servers`   | list     | One or more RADIUS server addresses (e.g., `192.0.2.10:1812`).                               |
| `secret`    | string   | Shared secret key used to authenticate to the RADIUS server.                                 |
| `realm`     | string   | Realm name displayed in the authentication prompt.                                           |
| `timeout`   | duration | Maximum time to wait for a response from the RADIUS server.                                  |
| `cache_ttl` | duration | Optional. Duration to cache successful credentials in memory. Set to `0` to disable caching. |

There is **no retry mechanism**. If all configured servers fail to respond within `timeout`, the authentication request fails.

### Example (Caddyfile)

```caddyfile
example.com {
    route /secure/* {
        radius_auth {
            servers 192.0.2.10:1812 192.0.2.11:1812
            secret  "sharedsecret"
            realm   "Restricted Area"
            timeout 5s
            cache_ttl 1m
        }
        respond "Access granted via RADIUS authentication!" 200
    }
}
```

### Example (JSON)

```json
{
  "handler": "radius_auth",
  "servers": ["192.0.2.10:1812", "192.0.2.11:1812"],
  "secret": "sharedsecret",
  "realm": "Restricted Area",
  "timeout": "5s",
  "cache_ttl": "1m"
}
```

---

## Examples

Protect a backend application using RADIUS authentication:

```caddyfile
app.example.com {
    route /api/* {
        radius_auth {
            servers 10.0.0.1:1812
            secret  "supersecret"
            realm   "API Access"
            timeout 3s
        }
        reverse_proxy localhost:8080
    }
}
```

---

## Limitations

* No retry logic — if all servers fail to respond, authentication fails immediately.
* Does not support mapping RADIUS attributes to Caddy context.
* Does not support fallback (e.g., anonymous access).
* Only supports username/password-based RADIUS authentication.
* Large or high-latency RADIUS networks may introduce delays.

---

## Contributing

Contributions are welcome!

1. Report bugs or suggest features via GitHub Issues
2. Submit pull requests with code and documentation
3. Ensure new features include test coverage and follow Go/Caddy best practices

---

## License

Licensed under the **MIT License**.
See the [LICENSE](LICENSE) file for full details.
