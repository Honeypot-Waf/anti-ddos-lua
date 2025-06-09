![MIT License](https://img.shields.io/badge/license-MIT-blue.svg)
![Lua](https://img.shields.io/badge/language-Lua-00007b)

# Honeypot WAF – Professional L7 DDoS Protection (v3.0.0)

**Advanced Lua-based Layer 7 (HTTP) DDoS mitigation module** designed for NGINX/OpenResty environments. This module provides real-time protection against HTTP flood attacks, Slowloris behavior, abusive bots, and malicious URI patterns. It includes intelligent rate-limiting, cookie-based JS challenges, IP reputation checks, and customizable IP-based bypass logic for trusted traffic.

---

## 🔐 Key Features

- **Layer-7 HTTP flood detection**
- **Slowloris attack prevention**
- **Bot & User-Agent fingerprinting**
- **Entropy-based URI anomaly detection**
- **Dynamic IP rate-limiting and banning**
- **Cookie-based JS challenge system**
- **Smart IP bypass logic (custom CIDR ranges)**
- **Built-in metrics for monitoring and debugging**
- **Manual IP ban/unban functionality**
- **Shared dictionary support for distributed rate-limiting**

---

## 📦 Architecture Overview

This module is implemented as a standalone Lua library (`ddos_guard.lua`) and is designed to be used inside OpenResty or NGINX configurations via `access_by_lua_block` or `access_by_lua_file`. It leverages OpenResty's `ngx.shared.DICT` mechanism for shared state management — such as rate tracking, blocklists, and challenge tokens.

---

## ⚙️ Usage Example (nginx.conf)

```nginx
lua_shared_dict ddos_guard 10m;
lua_shared_dict ddos_challenge 5m;
lua_shared_dict ddos_blocked 5m;
lua_shared_dict ddos_metrics 2m;

init_by_lua_block {
    ddos_guard = require "ddos_guard"
    ddos_guard.init()
}

init_worker_by_lua_block {
    ddos_guard.init_worker()
}

server {
    listen 80;

    location / {
        access_by_lua_block {
            ddos_guard.check_request()
        }
        proxy_pass http://backend;
    }

    location = /__challenge__ {
        content_by_lua_block {
            ddos_guard.handle_challenge()
        }
    }

    location = /__ddos_status__ {
        content_by_lua_block {
            local json = require "cjson"
            ngx.say(json.encode(ddos_guard.get_status()))
        }
    }
}
