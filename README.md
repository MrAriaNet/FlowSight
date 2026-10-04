# NetFlow / sFlow CLI Collector

A lightweight, **single-file** Python collector for network flow telemetry.

It receives **NetFlow v5 / v9**, **IPFIX**, and **sFlow v5** from one or many routers, shows **inbound / outbound** traffic by **IP** and **ASN**, detects simple **TCP/UDP attacks**, and can **collect reports** to disk.

No web UI. No pip packages. No virtualenv. **Python 3 standard library only.**

---

## Features

- **Protocols**
  - NetFlow v5
  - NetFlow v9 (per-exporter template cache)
  - IPFIX / NetFlow v10 (per-observation-domain template cache)
  - sFlow v5 (flow samples with IPv4/IPv6 headers)
- **Multi-router**
  - Many exporters can send to the same UDP ports
  - Friendly router names in config
  - Enable / disable routers at runtime
  - Optional allowlist for unknown exporters
- **Traffic visibility**
  - Live CLI report while collecting
  - Top talkers by IP and ASN
  - Inbound / outbound classification using local CIDRs and local ASNs
  - Per-router filtering
- **ASN enrichment**
  - Uses the [RIPEstat network-info API](https://stat.ripe.net/docs/02.data-api/network-info.html)
  - Prefix results cached locally to avoid repeated lookups
- **Attack detection**
  - TCP SYN flood / TCP flood / TCP port scan
  - UDP flood / UDP amplification heuristic
  - Alerts appended to text files
- **Report collection**
  - Manual snapshots
  - Auto-save while `run` is active
  - Final report on shutdown
  - Rolling `latest.txt` plus timestamped archive files

---

## Requirements

- Linux, Windows, or macOS
- **Python 3.10+** (3.11/3.12 recommended)
- UDP ports reachable from your routers (default `2055` for NetFlow/IPFIX, `6343` for sFlow)
- Outbound HTTPS if RIPE ASN lookup is enabled

---

## Quick start

```bash
git clone https://github.com/MrAriaNet/FlowSight.git
cd FlowSight

# Edit local networks, ASNs, and router addresses
nano config.yaml

# Start collector (live screen)
python3 collector.py run
```

That's it. There is nothing to install with `pip`.

---

## Project layout

```text
.
├── collector.py      # entire application
├── config.yaml       # listen ports, routers, thresholds
└── README.md
```

Runtime directories are created automatically:

```text
data/                 # SQLite DB, RIPE cache, router enable/disable state
alerts/               # tcp_attacks.txt, udp_attacks.txt
reports/              # collected report files
```

---

## Configuration

Edit [`config.yaml`](config.yaml).

### Listen ports

```yaml
listen:
  netflow_host: 0.0.0.0
  netflow_port: 2055
  sflow_host: 0.0.0.0
  sflow_port: 6343
```

### Local network / ASN (for inbound vs outbound)

```yaml
local_networks:
  - 203.0.113.0/24
  - 2001:db8::/32

local_asns:
  - 64500
```

Direction rules:

| Direction | Meaning |
|-----------|---------|
| `in` | source outside local, destination inside local |
| `out` | source inside local, destination outside local |
| `internal` | both sides local |
| `transit` | both sides outside local |

### Routers (exporters)

```yaml
accept_unknown_exporters: true

exporters:
  - id: edge1
    name: Edge Router 1
    address: 192.0.2.1
    enabled: true
  - id: edge2
    name: Edge Router 2
    address: 192.0.2.2
    enabled: true
    # optional per-router overrides:
    # local_networks: [198.51.100.0/24]
    # local_asns: [64501]
```

- `address` must match the UDP source IP of the exporter
- set `accept_unknown_exporters: false` to allow only listed routers
- runtime enable/disable is stored in `data/router_state.json`

### RIPE ASN lookup

```yaml
ripe:
  enabled: true
  url: https://stat.ripe.net/data/network-info/data.json
  cache_path: data/ripe_asn_cache.json
```

If a flow already contains ASN fields from the exporter, those values are preferred. Otherwise the collector queries RIPEstat in the background and caches prefixes.

### Aggregation, attacks, reports

```yaml
aggregation:
  window_seconds: 60
  retention_minutes: 120

attack:
  enabled: true
  window_seconds: 10
  tcp_syn_pps: 50000
  tcp_scan_unique_ports: 100
  udp_flood_pps: 80000
  cooldown_seconds: 60
  output_dir: alerts

reports:
  dir: reports
  auto_save_seconds: 300   # 0 disables auto-save during run
  keep_files: 48
  window_seconds: 300
  limit: 20
```

Tune attack thresholds for your traffic baseline. Defaults are intentionally high to reduce false positives on busy links.

---

## Usage

### Run the collector

```bash
python3 collector.py run
python3 collector.py -c /path/to/config.yaml run
```

Live screen includes:

- UDP / flow counters
- router state
- inbound / outbound top IPs
- inbound / outbound top ASNs

Press `Ctrl+C` to stop. A final report is saved under `reports/`.

### One-shot traffic report

```bash
python3 collector.py report
python3 collector.py report --window 300 --router edge1
python3 collector.py report --save
```

### Collect and browse saved reports

```bash
python3 collector.py collect
python3 collector.py collect --window 600 --router edge1

python3 collector.py reports
python3 collector.py reports --latest
python3 collector.py reports --show report_20261004_203000.txt
```

Saved files:

- `reports/report_YYYYMMDD_HHMMSS.txt`
- `reports/latest.txt` (always overwritten with the newest full snapshot)

### Top talkers / detail views

```bash
python3 collector.py top ip --direction in --window 60
python3 collector.py top ip --direction out --router edge1
python3 collector.py top asn --direction in --role src

python3 collector.py show ip 203.0.113.10
python3 collector.py show asn 15169 --router edge1
```

### Router management

```bash
python3 collector.py routers
python3 collector.py disable edge1
python3 collector.py enable edge1
python3 collector.py status
```

Disabled routers are ignored immediately. You do **not** need to restart `run`.

---

## Point your routers at the collector

| Protocol | Default port |
|----------|--------------|
| NetFlow / IPFIX | UDP `2055` |
| sFlow | UDP `6343` |

Make sure firewalls allow the exporter → collector path.

### Cisco IOS-XE (example)

```text
flow exporter NF-EXP
 destination <collector-ip>
 transport udp 2055
!
flow monitor NF-MON
 record netflow ipv4 original-input
 exporter NF-EXP
!
interface GigabitEthernet0/0/1
 ip flow monitor NF-MON input
 ip flow monitor NF-MON output
```

### Juniper (sFlow example)

```text
protocols {
    sflow {
        collector <collector-ip> {
            udp-port 6343;
        }
        interfaces ge-0/0/0 {
            sampling-rate 1000;
        }
    }
}
```

### MikroTik (example)

```text
/ip traffic-flow
set enabled=yes
/ip traffic-flow target
add dst-address=<collector-ip> port=2055 version=9
```

---

## Attack alerts

When thresholds are exceeded, lines are appended to:

- `alerts/tcp_attacks.txt`
- `alerts/udp_attacks.txt`

Example:

```text
2026-10-04T20:15:11Z | TCP_SYN_FLOOD | router=edge1 | exporter=192.0.2.1 | src=198.51.100.10 | dst=203.0.113.5 | pps=120000 | window=10s | proto=TCP | confidence=high
```

Detected signals:

| Type | Description |
|------|-------------|
| `TCP_SYN_FLOOD` | High SYN / TCP packet rate toward a destination |
| `TCP_FLOOD` | Generic high TCP pps fallback |
| `TCP_PORT_SCAN` | Many distinct destination ports from one source |
| `UDP_FLOOD` | High UDP pps toward a destination |
| `UDP_AMPLIFICATION` | Large response-to-request byte ratio |

This is **detection and logging only**. The collector does not push ACLs or mitigation to routers.

---

## How it works

```text
Routers / Exporters
        |  UDP 2055 / 6343
        v
   collector.py
   ├── parse NetFlow v5/v9, IPFIX, sFlow
   ├── tag router identity
   ├── enrich ASN via RIPEstat (cached)
   ├── classify direction (local CIDR / ASN)
   ├── aggregate in SQLite + live memory window
   ├── detect TCP/UDP attacks -> alerts/*.txt
   └── collect reports -> reports/*.txt
```

Important design notes:

- NetFlow v9 / IPFIX templates are cached **per exporter**, so multiple routers do not corrupt each other
- Live screen uses an in-memory window so SQLite reporting cannot stall UDP receive
- Packet parse errors are counted and logged; they do not stop the collector

---

## CLI reference

| Command | Description |
|---------|-------------|
| `run` | Start listeners and show live traffic |
| `report` | Print a traffic report (`--save` writes to disk) |
| `collect` | Save a collected report under `reports/` |
| `reports` | List / show collected reports (`--latest`, `--show`) |
| `top ip` / `top asn` | Top talkers |
| `show ip` / `show asn` | Detail for one IP or ASN |
| `routers` | List exporters and state |
| `enable` / `disable` | Toggle a router |
| `status` | Show config summary |

Global option:

```bash
python3 collector.py -c config.yaml <command>
```

---

## Operational tips

1. Set realistic `local_networks` / `local_asns` first; otherwise direction may stay `unknown` / `transit`.
2. Match each exporter `address` to the real source IP seen by the collector.
3. For high PPS environments, raise OS UDP receive buffers if needed.
4. Start with high attack thresholds, then lower them after observing normal traffic.
5. If the host has no outbound internet, set `ripe.enabled: false` and rely on ASN fields from exporters.
6. Keep collector time synchronized (NTP); report timestamps are UTC.

---

## Limitations

- CLI only (no dashboard / auth / multi-tenant UI)
- No automatic mitigation / ACL push
- No live BGP RIB feed (ASN comes from flow fields or RIPEstat)
- Not a clustered HA collector; run one instance per site or front it with your own redundancy
- sFlow support focuses on common flow-sample / IPv4 / IPv6 header records

---

## License

This project is released under the [MIT License](LICENSE).

---

## Contributing

Issues and pull requests are welcome. Please keep the project **single-file** and **stdlib-only** unless there is a strong reason to add dependencies.
