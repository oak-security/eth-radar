# ETH Radar

**Ethereum Threat Intelligence Dashboard** — Real-time security monitoring for the Ethereum ecosystem.

![ETH Radar](banner.jpg)

## Features

### 📊 Audit Findings
- Aggregated smart contract audit data
- Severity breakdown (Critical, High, Medium, Low, Informational)
- Vulnerability category analysis
- Filter by year range, firm, and category

### ⚡ Incident Data
- Historical exploit and hack data
- Total losses tracking
- Year-over-year analysis
- Top vulnerability types

### 📡 Network Health
- Live gas prices across 8 EVM networks (Ethereum, Arbitrum, Optimism, Base, Polygon, zkSync, Scroll, Linea)
- Transactions per second (TPS)
- Base fees and utilization

### 🚨 Alert Aggregator
- Real-time security alerts from:
  - @PeckShieldAlert
  - @zachxbt
  - @SlowMist_Team
  - @CertiKAlert
  - @ScamSniffer
  - Rekt News (RSS)
- No API keys required for RSS feeds

## Quick Start

### Prerequisites

- Python 3.8+
- Twitter API Bearer Token (optional, for Twitter alerts)
- Linux server with systemd

### Installation

```bash
# Clone or copy the project
cd eth-radar

# Install Python dependencies (usually none required - uses stdlib only)
# If running with venv:
python3 -m venv venv
source venv/bin/activate

# Copy and configure environment
cp .env.example .env
nano .env  # Add your Twitter Bearer Token

# Test run
python3 dashboard-eth.py
```

The dashboard will start on `http://localhost:18793`

### Production Setup

#### Using Systemd Service

Create `/etc/systemd/system/eth-radar.service`:

```ini
[Unit]
Description=ETH Radar - Ethereum Threat Intelligence Dashboard
After=network.target

[Service]
Type=simple
User=YOUR_USERNAME
WorkingDirectory=/path/to/eth-radar
ExecStart=/usr/bin/python3 /path/to/eth-radar/dashboard-eth.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Then:
```bash
sudo systemctl daemon-reload
sudo systemctl enable eth-radar
sudo systemctl start eth-radar
sudo systemctl status eth-radar
```

#### Using Reverse Proxy (Caddy)

```bash
# Install Caddy
sudo apt install -y caddy

# Configure Caddyfile
sudo nano /etc/caddy/Caddyfile
```

Add this to your Caddyfile:

```
:80 {
    reverse_proxy localhost:18793
    encode gzip
    
    header {
        X-Content-Type-Options nosniff
        X-Frame-Options DENY
        Referrer-Policy strict-origin-when-cross-origin
    }
}

# Or with custom domain and HTTPS:
# yourdomain.com {
#     reverse_proxy localhost:18793
#     encode gzip
# }

# Restart Caddy
sudo systemctl restart caddy
```

#### Using Nginx

```nginx
server {
    listen 80;
    server_name yourdomain.com;

    location / {
        proxy_pass http://127.0.0.1:18793;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        gzip on;
    }
}
```

## Configuration

### Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `TWITTER_BEARER` | No | Twitter API Bearer Token for alert aggregation |

Without the Twitter token, RSS feeds (Rekt News) will still work.

### Data Files

The dashboard uses these JSON data files:
- `findings-merged-eth.json` — Audit findings data
- `rekt-incidents-eth.json` — Historical incident data
- `stats-eth.json` — Pre-computed statistics

These are included in the repository. To update:
1. Fetch fresh data from your sources
2. Filter to Ethereum ecosystem (Solidity/EVM tech stack)
3. Save as `findings-merged-eth.json` and `rekt-incidents-eth.json`
4. Restart the service

## Architecture

```
dashboard-eth.py (Flask-like Python server)
    ├── /               → Main HTML dashboard
    ├── /logo.jpg       → Logo image
    ├── /banner.jpg     → Banner image
    ├── /data           → Aggregated stats JSON
    ├── /findings       → Paginated audit findings (SQLite)
    ├── /incidents      → Incident data JSON
    ├── /alerts         → Security alerts (Twitter API + RSS)
    └── /network        → Network health (proxied from ethgastracker.com)
```

## Security Notes

- Never commit `.env` or API keys to version control
- The Twitter Bearer Token is stored server-side only
- RSS feeds require no authentication
- Consider running behind a VPN or firewall for production

## Built With

- Python 3 (stdlib only — no external dependencies)
- Vanilla JavaScript + Canvas for charts
- Caddy web server for production reverse proxy
- [Twitter API v2](https://developer.twitter.com/en/docs/twitter-api) for alerts
- [Rekt News](https://rekt.news/) for incident analysis

## License

MIT License — See [LICENSE](LICENSE) for details.

---

Built by [Oak Security](https://oaksecurity.io/)
