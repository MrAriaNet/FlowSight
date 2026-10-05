#!/usr/bin/env python3
"""FlowSight — NetFlow/sFlow collector + destination-ASN delivery aggregator.

Classic capabilities: multi-router NetFlow v5/v9, IPFIX, sFlow, live IP/ASN
reports, attack alerts, report collection.

AS Traffic: aggregate by destination ASN per interface (ignore source IP),
flush every N minutes, hourly/daily/monthly share reports.
"""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
import json
import socket
import sqlite3
import struct
import sys
import time
import traceback
import urllib.parse
import urllib.request
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

# NetFlow v9 / IPFIX information elements
IE_BYTES, IE_PKTS, IE_PROTO, IE_TOS, IE_TCP_FLAGS = 1, 2, 4, 5, 6
IE_SPORT, IE_SRC4, IE_IN_IF, IE_DPORT, IE_DST4 = 7, 8, 10, 11, 12
IE_OUT_IF, IE_SRC_AS, IE_DST_AS, IE_SRC6, IE_DST6 = 14, 16, 17, 27, 28
IE_SAMPLE = 34
IE_SAMPLE2 = 52
IE_SAMPLE3 = 305


def _ipv4(data: bytes) -> str:
    if len(data) < 4:
        return "0.0.0.0"
    return str(ipaddress.IPv4Address(data[:4]))


def _ipv6(data: bytes) -> str:
    if len(data) < 16:
        return "::"
    return str(ipaddress.IPv6Address(data[:16]))


def _u(data: bytes) -> int:
    return int.from_bytes(data, "big") if data else 0


def _fmt_bytes(value: int | float | None) -> str:
    n = float(value or 0)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{int(n)}B" if unit == "B" else f"{n:.1f}{unit}"
        n /= 1024
    return f"{n:.1f}TB"


def _fmt_ts(ts: float) -> str:
    if not ts:
        return "-"
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")


def _table_lines(headers: list[str], rows: list[list[Any]]) -> list[str]:
    cols = list(headers)
    data = [[str(c) for c in row] for row in rows]
    widths = [len(h) for h in cols]
    for row in data:
        for i, cell in enumerate(row):
            widths[i] = min(max(widths[i], len(cell)), 46)
    out = [
        "  ".join(h.ljust(widths[i]) for i, h in enumerate(cols)),
        "  ".join("-" * w for w in widths),
    ]
    if not data:
        out.append("(no data)")
        return out
    for row in data:
        out.append("  ".join(row[i].ljust(widths[i]) for i in range(len(cols))))
    return out


def _print_table(headers: list[str], rows: list[list[Any]]) -> None:
    for line in _table_lines(headers, rows):
        print(line)


def _scalar(text: str) -> Any:
    text = text.strip()
    if not text:
        return ""
    if text[0] in "\"'" and len(text) >= 2 and text[-1] == text[0]:
        return text[1:-1]
    low = text.lower()
    if low in ("true", "yes"):
        return True
    if low in ("false", "no"):
        return False
    if low in ("null", "~"):
        return None
    try:
        return int(text)
    except ValueError:
        return text


def load_yaml(text: str) -> Any:
    """Minimal YAML subset: maps, lists, scalars, comments."""
    lines = []
    for raw in text.splitlines():
        if "#" in raw:
            in_q = False
            out = []
            for ch in raw:
                if ch in "\"'":
                    in_q = not in_q
                if ch == "#" and not in_q:
                    break
                out.append(ch)
            raw = "".join(out)
        if raw.strip():
            lines.append(raw.rstrip())

    def parse_block(index: int, indent: int) -> tuple[Any, int]:
        mapping: dict[str, Any] = {}
        sequence: list[Any] = []
        kind = None
        while index < len(lines):
            line = lines[index]
            cur = len(line) - len(line.lstrip(" "))
            if cur < indent:
                break
            if cur > indent:
                raise ValueError(f"Bad indent: {line}")
            stripped = line.strip()
            if stripped.startswith("- "):
                if kind == "map":
                    raise ValueError("Mixed map/list")
                kind = "list"
                rest = stripped[2:]
                index += 1
                key_part = rest.split(":", 1)[0].strip()
                if ":" in rest and key_part.isidentifier():
                    key, _, val = rest.partition(":")
                    item: dict[str, Any] = {}
                    if val.strip():
                        item[key.strip()] = _scalar(val)
                    nested, index = parse_block(index, cur + 2)
                    if isinstance(nested, dict):
                        item.update(nested)
                    sequence.append(item)
                else:
                    sequence.append(_scalar(rest))
            else:
                if kind == "list":
                    break
                kind = "map"
                if stripped.endswith(":") and stripped.count(":") == 1:
                    key = stripped[:-1].strip()
                    index += 1
                    if index < len(lines):
                        nxt = lines[index]
                        ncur = len(nxt) - len(nxt.lstrip(" "))
                        if ncur > cur:
                            nested, index = parse_block(index, ncur)
                            mapping[key] = nested
                            continue
                    mapping[key] = {}
                else:
                    key, _, val = stripped.partition(":")
                    mapping[key.strip()] = _scalar(val)
                    index += 1
        if kind == "list":
            return sequence, index
        return mapping, index

    value, _ = parse_block(0, 0)
    return value


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------


@dataclass
class Exporter:
    id: str
    name: str
    address: str
    enabled: bool = True
    local_networks: list[str] = field(default_factory=list)
    local_asns: list[int] = field(default_factory=list)


@dataclass
class Config:
    netflow_host: str = "0.0.0.0"
    netflow_port: int = 2055
    sflow_host: str = "0.0.0.0"
    sflow_port: int = 6343
    accept_unknown: bool = True
    local_networks: list[str] = field(default_factory=list)
    local_asns: list[int] = field(default_factory=list)
    exporters: list[Exporter] = field(default_factory=list)
    ripe_enabled: bool = True
    ripe_url: str = "https://stat.ripe.net/data/network-info/data.json"
    ripe_cache_path: str = "data/ripe_asn_cache.json"
    router_state_path: str = "data/router_state.json"
    database_path: str = "data/collector.db"
    window_seconds: int = 60
    retention_minutes: int = 120
    attack_enabled: bool = True
    attack_window: int = 10
    tcp_syn_pps: int = 50000
    tcp_scan_ports: int = 100
    udp_flood_pps: int = 80000
    cooldown: int = 60
    alert_dir: str = "alerts"
    reports_dir: str = "reports"
    reports_auto_seconds: int = 300
    reports_keep: int = 48
    reports_window: int = 300
    reports_limit: int = 20
    # Destination-ASN delivery aggregation (high-volume path)
    as_enabled: bool = True
    as_iface_field: str = "input"  # input|output
    as_interfaces: set[int] = field(default_factory=set)
    as_flush_seconds: int = 600
    as_retention_days: int = 90


def load_config(path: str) -> Config:
    raw = load_yaml(Path(path).read_text(encoding="utf-8")) or {}
    if not isinstance(raw, dict):
        raise ValueError("config root must be a mapping")
    listen = raw.get("listen") or {}
    agg = raw.get("aggregation") or {}
    attack = raw.get("attack") or {}
    ripe = raw.get("ripe") or {}
    reports = raw.get("reports") or {}
    as_traffic = raw.get("as_traffic") or {}
    ifaces_raw = as_traffic.get("interfaces") or []
    if not isinstance(ifaces_raw, list):
        ifaces_raw = []
    iface_set: set[int] = set()
    for x in ifaces_raw:
        try:
            iface_set.add(int(x))
        except (TypeError, ValueError):
            continue
    exporters = [
        Exporter(
            id=str(item["id"]),
            name=str(item.get("name") or item["id"]),
            address=str(item["address"]),
            enabled=bool(item.get("enabled", True)),
            local_networks=list(item.get("local_networks") or []),
            local_asns=[int(a) for a in (item.get("local_asns") or [])],
        )
        for item in (raw.get("exporters") or [])
    ]
    return Config(
        netflow_host=str(listen.get("netflow_host", "0.0.0.0")),
        netflow_port=int(listen.get("netflow_port", 2055)),
        sflow_host=str(listen.get("sflow_host", "0.0.0.0")),
        sflow_port=int(listen.get("sflow_port", 6343)),
        accept_unknown=bool(raw.get("accept_unknown_exporters", True)),
        local_networks=list(raw.get("local_networks") or []),
        local_asns=[int(a) for a in (raw.get("local_asns") or [])],
        exporters=exporters,
        ripe_enabled=bool(ripe.get("enabled", True)),
        ripe_url=str(ripe.get("url") or "https://stat.ripe.net/data/network-info/data.json"),
        ripe_cache_path=str(ripe.get("cache_path") or "data/ripe_asn_cache.json"),
        router_state_path=str(raw.get("router_state_path") or "data/router_state.json"),
        database_path=str(raw.get("database_path") or "data/collector.db"),
        window_seconds=int(agg.get("window_seconds", 60)),
        retention_minutes=int(agg.get("retention_minutes", 120)),
        attack_enabled=bool(attack.get("enabled", True)),
        attack_window=int(attack.get("window_seconds", 10)),
        tcp_syn_pps=int(attack.get("tcp_syn_pps", 50000)),
        tcp_scan_ports=int(attack.get("tcp_scan_unique_ports", 100)),
        udp_flood_pps=int(attack.get("udp_flood_pps", 80000)),
        cooldown=int(attack.get("cooldown_seconds", 60)),
        alert_dir=str(attack.get("output_dir") or "alerts"),
        reports_dir=str(reports.get("dir") or "reports"),
        reports_auto_seconds=int(reports.get("auto_save_seconds", 300)),
        reports_keep=int(reports.get("keep_files", 48)),
        reports_window=int(reports.get("window_seconds", 300)),
        reports_limit=int(reports.get("limit", 20)),
        as_enabled=bool(as_traffic.get("enabled", True)),
        as_iface_field=str(as_traffic.get("iface_field", "input")).lower(),
        as_interfaces=iface_set,
        as_flush_seconds=int(as_traffic.get("flush_seconds", 600)),
        as_retention_days=int(as_traffic.get("retention_days", 90)),
    )


# ---------------------------------------------------------------------------
# Flow + routers
# ---------------------------------------------------------------------------


@dataclass
class Flow:
    timestamp: float
    exporter_ip: str
    router_id: str
    router_name: str
    protocol: int
    src_ip: str
    dst_ip: str
    src_port: int = 0
    dst_port: int = 0
    bytes: int = 0
    packets: int = 0
    src_asn: int = 0
    dst_asn: int = 0
    tcp_flags: int = 0
    sampling_rate: int = 1
    input_iface: int = 0
    output_iface: int = 0
    direction: str = "unknown"
    source: str = ""
    source_id: int = 0

    @property
    def scaled_bytes(self) -> int:
        return self.bytes * max(self.sampling_rate, 1)

    @property
    def scaled_packets(self) -> int:
        return self.packets * max(self.sampling_rate, 1)


@dataclass
class RouterStats:
    router_id: str
    router_name: str
    exporter_ip: str
    last_seen: float = 0.0
    packets_received: int = 0
    flows_received: int = 0
    template_count: int = 0
    protocols: set[str] = field(default_factory=set)


class Routers:
    def __init__(self, cfg: Config) -> None:
        self.accept_unknown = cfg.accept_unknown
        self.state_path = Path(cfg.router_state_path)
        self.by_addr = {e.address: e for e in cfg.exporters}
        self.by_id = {e.id: e for e in cfg.exporters}
        self.stats: dict[str, RouterStats] = {
            e.id: RouterStats(e.id, e.name, e.address) for e in cfg.exporters
        }
        self.enabled: dict[str, bool] = {e.id: e.enabled for e in cfg.exporters}
        self.reload_state()

    def reload_state(self) -> None:
        if not self.state_path.exists():
            return
        try:
            data = json.loads(self.state_path.read_text(encoding="utf-8"))
        except Exception:
            return
        if isinstance(data, dict):
            for key, val in data.items():
                self.enabled[str(key)] = bool(val)

    def save_state(self) -> None:
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        self.state_path.write_text(json.dumps(self.enabled, indent=2), encoding="utf-8")

    def find(self, token: str) -> Optional[str]:
        if token in self.enabled or token in self.by_id or token in self.stats:
            return token
        for exp in self.by_id.values():
            if exp.address == token or exp.name == token:
                return exp.id
        for st in self.stats.values():
            if st.exporter_ip == token or st.router_name == token:
                return st.router_id
        return None

    def is_enabled(self, rid: str) -> bool:
        return self.enabled.get(rid, True)

    def set_enabled(self, rid: str, on: bool) -> None:
        self.enabled[rid] = on
        self.save_state()

    def resolve(self, ip: str) -> Optional[tuple[str, str, Optional[Exporter]]]:
        known = self.by_addr.get(ip)
        if known:
            return known.id, known.name, known
        if not self.accept_unknown:
            return None
        rid = f"auto-{ip.replace(':', '-')}"
        name = f"Unknown ({ip})"
        self.stats.setdefault(rid, RouterStats(rid, name, ip))
        self.enabled.setdefault(rid, True)
        return rid, name, None

    def note(
        self,
        rid: str,
        name: str,
        ip: str,
        source: str,
        flows: int,
        templates: Optional[int] = None,
    ) -> None:
        st = self.stats.setdefault(rid, RouterStats(rid, name, ip))
        st.last_seen = time.time()
        st.packets_received += 1
        st.flows_received += flows
        if source:
            st.protocols.add(source)
        if templates is not None:
            st.template_count = templates


def classify(flow: Flow, cfg: Config, routers: Routers) -> str:
    exporter = routers.by_id.get(flow.router_id)
    nets = (exporter.local_networks if exporter and exporter.local_networks else cfg.local_networks)
    asns = set(exporter.local_asns if exporter and exporter.local_asns else cfg.local_asns)
    networks = []
    for item in nets:
        try:
            networks.append(ipaddress.ip_network(item, strict=False))
        except ValueError:
            pass
    if not networks and not asns:
        return "unknown"

    def is_local(ip: str, asn: int) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            addr = None
        ip_ok = addr is not None and any(addr in n for n in networks)
        asn_ok = asn > 0 and asn in asns
        return ip_ok or asn_ok

    src, dst = is_local(flow.src_ip, flow.src_asn), is_local(flow.dst_ip, flow.dst_asn)
    if src and dst:
        return "internal"
    if not src and dst:
        return "in"
    if src and not dst:
        return "out"
    return "transit"


def _public_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
    )


class RipeAsn:
    """IP to ASN via RIPEstat network-info, with prefix cache."""

    def __init__(self, cfg: Config) -> None:
        self.enabled = cfg.ripe_enabled
        self.url = cfg.ripe_url
        self.cache_path = Path(cfg.ripe_cache_path)
        self.ip_cache: dict[str, int] = {}
        self.prefixes: list[tuple[ipaddress._BaseNetwork, int]] = []
        self._pending: set[str] = set()
        self._queue: Optional[asyncio.Queue[str]] = None
        self._dirty = False
        self._last_save = 0.0
        self._load()

    def _load(self) -> None:
        if not self.cache_path.exists():
            return
        try:
            raw = json.loads(self.cache_path.read_text(encoding="utf-8"))
        except Exception:
            return
        for prefix, asn in (raw.get("prefixes") or {}).items():
            try:
                net = ipaddress.ip_network(prefix, strict=False)
                self.prefixes.append((net, int(asn)))
            except (ValueError, TypeError):
                continue

    def save(self, force: bool = False) -> None:
        if not self._dirty and not force:
            return
        now = time.time()
        if not force and now - self._last_save < 30:
            return
        self.cache_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {"prefixes": {str(net): asn for net, asn in self.prefixes}}
        self.cache_path.write_text(json.dumps(payload), encoding="utf-8")
        self._dirty = False
        self._last_save = now

    def lookup_cached(self, ip: str) -> Optional[int]:
        if ip in self.ip_cache:
            return self.ip_cache[ip]
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        for net, asn in self.prefixes:
            if addr in net:
                self.ip_cache[ip] = asn
                return asn
        return None

    def apply(self, flow: Flow) -> None:
        if not self.enabled:
            return
        for attr, ip in (("src_asn", flow.src_ip), ("dst_asn", flow.dst_ip)):
            if getattr(flow, attr) > 0:
                continue
            cached = self.lookup_cached(ip)
            if cached is not None:
                setattr(flow, attr, cached)
                continue
            self.enqueue(ip)

    def enqueue(self, ip: str) -> None:
        if not self.enabled or not _public_ip(ip):
            if not _public_ip(ip):
                self.ip_cache[ip] = 0
            return
        if ip in self.ip_cache or ip in self._pending:
            return
        self._pending.add(ip)
        if self._queue is not None:
            try:
                self._queue.put_nowait(ip)
            except asyncio.QueueFull:
                self._pending.discard(ip)

    def start(self) -> None:
        if not self.enabled:
            return
        self._queue = asyncio.Queue(maxsize=10000)
        asyncio.create_task(self._worker())
        asyncio.create_task(self._worker())

    async def _worker(self) -> None:
        assert self._queue is not None
        while True:
            ip = await self._queue.get()
            try:
                await asyncio.to_thread(self._fetch, ip)
            except Exception:
                self._pending.discard(ip)
            finally:
                self._queue.task_done()
            try:
                self.save()
            except Exception:
                pass

    def _fetch(self, ip: str) -> None:
        url = f"{self.url}?resource={urllib.parse.quote(ip)}"
        req = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": "netflow-collector/1.0"})
        try:
            with urllib.request.urlopen(req, timeout=8) as resp:
                body = json.loads(resp.read().decode("utf-8"))
        except Exception:
            self._pending.discard(ip)
            return
        data = body.get("data") or {}
        asns = data.get("asns") or []
        prefix = data.get("prefix")
        asn = 0
        if asns:
            try:
                asn = int(str(asns[0]).lstrip("AS"))
            except ValueError:
                asn = 0
        self.ip_cache[ip] = asn
        if prefix:
            try:
                net = ipaddress.ip_network(prefix, strict=False)
                key = str(net)
                if not any(str(existing) == key for existing, _ in self.prefixes):
                    self.prefixes.append((net, asn))
                    self._dirty = True
            except ValueError:
                pass
        self._pending.discard(ip)


# ---------------------------------------------------------------------------
# Parsers
# ---------------------------------------------------------------------------


def parse_v5(data: bytes, exp: str, rid: str, name: str, ts: float) -> list[Flow]:
    hdr, rec = "!HHIIIIBBH", "!IIIHHIIIIHHBBBBHHBBH"
    hs, rs = struct.calcsize(hdr), struct.calcsize(rec)
    if len(data) < hs:
        return []
    version, count, _, unix, *_rest = struct.unpack_from(hdr, data, 0)
    sampling = _rest[-1] & 0x3FFF or 1
    if version != 5:
        return []
    stamp = float(unix) if unix else ts
    out: list[Flow] = []
    off = hs
    for _ in range(count):
        if off + rs > len(data):
            break
        f = struct.unpack_from(rec, data, off)
        off += rs
        src, dst = f[0], f[1]
        out.append(
            Flow(
                timestamp=stamp,
                exporter_ip=exp,
                router_id=rid,
                router_name=name,
                protocol=f[13],
                src_ip=str(ipaddress.IPv4Address(src)),
                dst_ip=str(ipaddress.IPv4Address(dst)),
                src_port=f[9],
                dst_port=f[10],
                bytes=f[6],
                packets=f[5],
                src_asn=f[15],
                dst_asn=f[16],
                tcp_flags=f[12],
                sampling_rate=sampling,
                input_iface=int(f[3]),
                output_iface=int(f[4]),
                source="netflow_v5",
            )
        )
    return out


@dataclass
class Tmpl:
    fields: list[tuple[int, int, bool]]  # type, length, enterprise

    def fixed_size(self) -> Optional[int]:
        total = 0
        for _t, length, _e in self.fields:
            if length == 0xFFFF:
                return None
            total += length
        return total


class TemplateParser:
    """Shared NetFlow v9 + IPFIX decoder with per-exporter caches."""

    def __init__(self) -> None:
        self.templates: dict[tuple[str, int, int], Tmpl] = {}

    def count_for(self, exp: str) -> int:
        return sum(1 for k in self.templates if k[0] == exp)

    def parse_v9(self, data: bytes, exp: str, rid: str, name: str, ts: float) -> list[Flow]:
        if len(data) < 20:
            return []
        version, count, _, unix, _, source_id = struct.unpack_from("!HHIIII", data, 0)
        if version != 9:
            return []
        stamp = float(unix) if unix else ts
        return self._walk_sets(data, 20, len(data), exp, source_id, rid, name, stamp, v9=True, limit=count + 64)

    def parse_ipfix(self, data: bytes, exp: str, rid: str, name: str, ts: float) -> list[Flow]:
        if len(data) < 16:
            return []
        version, length, export_time, _, domain = struct.unpack_from("!HHIII", data, 0)
        if version != 10:
            return []
        stamp = float(export_time) if export_time else ts
        return self._walk_sets(data, 16, min(length, len(data)), exp, domain, rid, name, stamp, v9=False)

    def _walk_sets(
        self,
        data: bytes,
        offset: int,
        end: int,
        exp: str,
        sid: int,
        rid: str,
        name: str,
        ts: float,
        v9: bool,
        limit: int = 10_000,
    ) -> list[Flow]:
        flows: list[Flow] = []
        n = 0
        while offset + 4 <= end and n < limit:
            set_id, set_len = struct.unpack_from("!HH", data, offset)
            if set_len < 4 or offset + set_len > end:
                break
            body = data[offset + 4 : offset + set_len]
            tmpl_id = 0 if v9 else 2
            opt_id = 1 if v9 else 3
            if set_id == tmpl_id:
                self._read_template(body, exp, sid, ipfix=not v9)
            elif set_id == opt_id:
                self._read_options(body, exp, sid, ipfix=not v9)
            elif set_id >= 256:
                flows.extend(self._read_data(body, set_id, exp, sid, rid, name, ts, not v9))
            offset += set_len
            n += 1
        return flows

    def _read_template(self, data: bytes, exp: str, sid: int, ipfix: bool) -> None:
        off = 0
        while off + 4 <= len(data):
            tid, count = struct.unpack_from("!HH", data, off)
            off += 4
            fields: list[tuple[int, int, bool]] = []
            for _ in range(count):
                if off + 4 > len(data):
                    return
                raw, length = struct.unpack_from("!HH", data, off)
                off += 4
                ent = bool(raw & 0x8000) if ipfix else False
                ftype = raw & 0x7FFF if ipfix else raw
                if ent:
                    if off + 4 > len(data):
                        return
                    off += 4
                fields.append((ftype, length, ent))
            if tid >= 256:
                self.templates[(exp, sid, tid)] = Tmpl(fields)

    def _read_options(self, data: bytes, exp: str, sid: int, ipfix: bool) -> None:
        off = 0
        if ipfix:
            while off + 6 <= len(data):
                tid, count, _scope = struct.unpack_from("!HHH", data, off)
                off += 6
                fields: list[tuple[int, int, bool]] = []
                for _ in range(count):
                    if off + 4 > len(data):
                        return
                    raw, length = struct.unpack_from("!HH", data, off)
                    off += 4
                    ent = bool(raw & 0x8000)
                    if ent:
                        if off + 4 > len(data):
                            return
                        off += 4
                    fields.append((raw & 0x7FFF, length, ent))
                if tid >= 256:
                    self.templates[(exp, sid, tid)] = Tmpl(fields)
        else:
            while off + 6 <= len(data):
                tid, scope_len, opt_len = struct.unpack_from("!HHH", data, off)
                off += 6
                total = (scope_len + opt_len) // 4
                fields = []
                for _ in range(total):
                    if off + 4 > len(data):
                        return
                    ftype, length = struct.unpack_from("!HH", data, off)
                    off += 4
                    fields.append((ftype, length, False))
                if tid >= 256:
                    self.templates[(exp, sid, tid)] = Tmpl(fields)

    def _read_data(
        self, data: bytes, tid: int, exp: str, sid: int, rid: str, name: str, ts: float, ipfix: bool
    ) -> list[Flow]:
        tmpl = self.templates.get((exp, sid, tid))
        if not tmpl:
            return []
        flows: list[Flow] = []
        off = 0
        while off < len(data):
            values: dict[int, bytes] = {}
            cur = off
            try:
                for ftype, length, ent in tmpl.fields:
                    if length == 0xFFFF:
                        if cur >= len(data):
                            return flows
                        length = data[cur]
                        cur += 1
                        if length == 255:
                            if cur + 2 > len(data):
                                return flows
                            length = struct.unpack_from("!H", data, cur)[0]
                            cur += 2
                    if cur + length > len(data):
                        return flows
                    if not ent:
                        values[ftype] = data[cur : cur + length]
                    cur += length
            except Exception:
                break
            if cur <= off:
                break
            off = cur
            flow = values_to_flow(values, exp, rid, name, ts, sid, "ipfix" if ipfix else "netflow_v9")
            if flow:
                flows.append(flow)
            fixed = tmpl.fixed_size()
            if fixed is not None and off + fixed > len(data) and len(data) - off < 4:
                break
        return flows


def values_to_flow(
    values: dict[int, bytes], exp: str, rid: str, name: str, ts: float, sid: int, source: str
) -> Optional[Flow]:
    src = _ipv4(values[IE_SRC4]) if IE_SRC4 in values else (_ipv6(values[IE_SRC6]) if IE_SRC6 in values else "0.0.0.0")
    dst = _ipv4(values[IE_DST4]) if IE_DST4 in values else (_ipv6(values[IE_DST6]) if IE_DST6 in values else "0.0.0.0")
    if src in ("0.0.0.0", "::") and dst in ("0.0.0.0", "::"):
        return None
    sampling = _u(values.get(IE_SAMPLE, values.get(IE_SAMPLE2, values.get(IE_SAMPLE3, b"")))) or 1
    return Flow(
        timestamp=ts,
        exporter_ip=exp,
        router_id=rid,
        router_name=name,
        protocol=_u(values.get(IE_PROTO, b"")),
        src_ip=src,
        dst_ip=dst,
        src_port=_u(values.get(IE_SPORT, b"")),
        dst_port=_u(values.get(IE_DPORT, b"")),
        bytes=_u(values.get(IE_BYTES, b"")),
        packets=_u(values.get(IE_PKTS, b"")) or 1,
        src_asn=_u(values.get(IE_SRC_AS, b"")),
        dst_asn=_u(values.get(IE_DST_AS, b"")),
        tcp_flags=_u(values.get(IE_TCP_FLAGS, b"")),
        sampling_rate=sampling,
        input_iface=_u(values.get(IE_IN_IF, b"")),
        output_iface=_u(values.get(IE_OUT_IF, b"")),
        source=source,
        source_id=sid,
    )


def _ru32(data: bytes, off: int) -> tuple[int, int]:
    if off + 4 > len(data):
        raise ValueError("truncated")
    return struct.unpack_from("!I", data, off)[0], off + 4


def _parse_ip_hdr(pkt: bytes) -> Optional[tuple[str, str, int, int, int, int, int]]:
    if len(pkt) < 20:
        return None
    ver = pkt[0] >> 4
    if ver == 4:
        ihl = (pkt[0] & 0x0F) * 4
        if len(pkt) < ihl:
            return None
        proto, total = pkt[9], struct.unpack_from("!H", pkt, 2)[0]
        src = f"{pkt[12]}.{pkt[13]}.{pkt[14]}.{pkt[15]}"
        dst = f"{pkt[16]}.{pkt[17]}.{pkt[18]}.{pkt[19]}"
        l4, sport, dport, flags = pkt[ihl:], 0, 0, 0
        if proto == 6 and len(l4) >= 14:
            sport, dport = struct.unpack_from("!HH", l4, 0)
            flags = l4[13]
        elif proto == 17 and len(l4) >= 4:
            sport, dport = struct.unpack_from("!HH", l4, 0)
        return src, dst, proto, sport, dport, flags, total
    if ver == 6 and len(pkt) >= 40:
        proto, plen = pkt[6], struct.unpack_from("!H", pkt, 4)[0]
        src = str(ipaddress.IPv6Address(pkt[8:24]))
        dst = str(ipaddress.IPv6Address(pkt[24:40]))
        l4, sport, dport, flags = pkt[40:], 0, 0, 0
        if proto == 6 and len(l4) >= 14:
            sport, dport = struct.unpack_from("!HH", l4, 0)
            flags = l4[13]
        elif proto == 17 and len(l4) >= 4:
            sport, dport = struct.unpack_from("!HH", l4, 0)
        return src, dst, proto, sport, dport, flags, plen + 40
    return None


def parse_sflow(data: bytes, exp: str, rid: str, name: str, ts: float) -> list[Flow]:
    if len(data) < 28:
        return []
    try:
        version, off = _ru32(data, 0)
        if version != 5:
            return []
        atype, off = _ru32(data, off)
        off += 4 if atype == 1 else 16 if atype == 2 else 0
        _, off = _ru32(data, off)
        _, off = _ru32(data, off)
        _, off = _ru32(data, off)
        count, off = _ru32(data, off)
    except ValueError:
        return []
    flows: list[Flow] = []
    for _ in range(min(count, 512)):
        try:
            stype, off = _ru32(data, off)
            slen, off = _ru32(data, off)
            body = data[off : off + slen]
            off += slen
            if (stype >> 12) != 0:
                continue
            fmt = stype & 0xFFF
            if fmt in (1, 3):
                flows.extend(_sflow_sample(body, fmt == 3, exp, rid, name, ts))
        except ValueError:
            break
    return flows


def _sflow_sample(data: bytes, expanded: bool, exp: str, rid: str, name: str, ts: float) -> list[Flow]:
    try:
        off = 0
        _, off = _ru32(data, off)
        if expanded:
            _, off = _ru32(data, off)
            _, off = _ru32(data, off)
        else:
            _, off = _ru32(data, off)
        rate, off = _ru32(data, off)
        _, off = _ru32(data, off)
        _, off = _ru32(data, off)
        if expanded:
            _, off = _ru32(data, off)
            _, off = _ru32(data, off)
            _, off = _ru32(data, off)
            _, off = _ru32(data, off)
        else:
            _, off = _ru32(data, off)
            _, off = _ru32(data, off)
        nrec, off = _ru32(data, off)
    except ValueError:
        return []
    rate = rate or 1
    flows: list[Flow] = []
    src_as = dst_as = 0
    for _ in range(min(nrec, 64)):
        try:
            rtype, off = _ru32(data, off)
            rlen, off = _ru32(data, off)
            body = data[off : off + rlen]
            off += rlen
            if (rtype >> 12) != 0:
                continue
            fmt = rtype & 0xFFF
            if fmt == 1:
                flow = _sflow_raw(body, exp, rid, name, ts, rate, src_as, dst_as)
                if flow:
                    flows.append(flow)
            elif fmt == 3 and len(body) >= 32:
                length, proto = struct.unpack_from("!II", body, 0)
                src = str(ipaddress.IPv4Address(body[8:12]))
                dst = str(ipaddress.IPv4Address(body[12:16]))
                sport, dport, flags = struct.unpack_from("!III", body, 16)
                flows.append(
                    Flow(ts, exp, rid, name, proto, src, dst, sport, dport, length, 1, src_as, dst_as, flags & 0xFF, rate, source="sflow")
                )
            elif fmt == 1003:
                o = 0
                atype, o = _ru32(body, o)
                o += 4 if atype == 1 else 16 if atype == 2 else 0
                _, o = _ru32(body, o)
                src_as, o = _ru32(body, o)
                n, o = _ru32(body, o)
                if n > 0:
                    dst_as, o = _ru32(body, o)
        except ValueError:
            break
    if flows and (src_as or dst_as):
        if flows[-1].src_asn <= 0:
            flows[-1].src_asn = src_as
        if flows[-1].dst_asn <= 0:
            flows[-1].dst_asn = dst_as
    return flows


def _sflow_raw(data: bytes, exp: str, rid: str, name: str, ts: float, rate: int, src_as: int, dst_as: int) -> Optional[Flow]:
    try:
        proto, off = _ru32(data, 0)
        flen, off = _ru32(data, off)
        _, off = _ru32(data, off)
        hsize, off = _ru32(data, off)
        header = data[off : off + hsize]
    except ValueError:
        return None
    parsed = None
    if proto == 1 and len(header) >= 14:
        et = struct.unpack_from("!H", header, 12)[0]
        ipoff = 14
        if et == 0x8100 and len(header) >= 18:
            et = struct.unpack_from("!H", header, 16)[0]
            ipoff = 18
        parsed = _parse_ip_hdr(header[ipoff:])
    elif proto in (11, 12):
        parsed = _parse_ip_hdr(header)
    if not parsed:
        return None
    src, dst, iproto, sport, dport, flags, iplen = parsed
    return Flow(ts, exp, rid, name, iproto, src, dst, sport, dport, flen or iplen, 1, src_as, dst_as, flags, rate, source="sflow")


# ---------------------------------------------------------------------------
# Storage + attacks
# ---------------------------------------------------------------------------


class Store:
    def __init__(self, path: str, window: int, retention: int) -> None:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.window = window
        self.retention = retention
        self.conn = sqlite3.connect(path, check_same_thread=False, timeout=60)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self.conn.execute("PRAGMA busy_timeout=60000")
        self.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS agg_ip (
                window_start INTEGER, router_id TEXT, direction TEXT, ip TEXT, role TEXT,
                bytes INTEGER, packets INTEGER, flows INTEGER, tcp_packets INTEGER, udp_packets INTEGER,
                PRIMARY KEY (window_start, router_id, direction, ip, role)
            );
            CREATE TABLE IF NOT EXISTS agg_asn (
                window_start INTEGER, router_id TEXT, direction TEXT, asn INTEGER, role TEXT,
                bytes INTEGER, packets INTEGER, flows INTEGER,
                PRIMARY KEY (window_start, router_id, direction, asn, role)
            );
            CREATE TABLE IF NOT EXISTS agg_router (
                window_start INTEGER, router_id TEXT, bytes INTEGER, packets INTEGER, flows INTEGER,
                PRIMARY KEY (window_start, router_id)
            );
            CREATE TABLE IF NOT EXISTS asn_bucket (
                bucket_start INTEGER NOT NULL,
                router_id TEXT NOT NULL,
                iface INTEGER NOT NULL,
                asn INTEGER NOT NULL,
                bytes INTEGER NOT NULL DEFAULT 0,
                packets INTEGER NOT NULL DEFAULT 0,
                flows INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (bucket_start, router_id, iface, asn)
            );
            CREATE INDEX IF NOT EXISTS idx_asn_bucket_time
                ON asn_bucket(bucket_start, router_id, iface);
            """
        )
        self._last_clean = 0.0
        self._last_commit = time.time()
        self._dirty = 0

    def ingest(self, flow: Flow) -> None:
        ws = int(flow.timestamp) - (int(flow.timestamp) % self.window)
        b, p = flow.scaled_bytes, flow.scaled_packets
        tcp, udp = (p if flow.protocol == 6 else 0), (p if flow.protocol == 17 else 0)
        c = self.conn.cursor()
        c.execute(
            """INSERT INTO agg_router VALUES (?,?,?,?,1)
               ON CONFLICT(window_start, router_id) DO UPDATE SET
               bytes=bytes+excluded.bytes, packets=packets+excluded.packets, flows=flows+1""",
            (ws, flow.router_id, b, p),
        )
        for ip, role, asn in ((flow.src_ip, "src", flow.src_asn), (flow.dst_ip, "dst", flow.dst_asn)):
            c.execute(
                """INSERT INTO agg_ip VALUES (?,?,?,?,?,?,?,1,?,?)
                   ON CONFLICT(window_start, router_id, direction, ip, role) DO UPDATE SET
                   bytes=bytes+excluded.bytes, packets=packets+excluded.packets, flows=flows+1,
                   tcp_packets=tcp_packets+excluded.tcp_packets, udp_packets=udp_packets+excluded.udp_packets""",
                (ws, flow.router_id, flow.direction, ip, role, b, p, tcp, udp),
            )
            if asn > 0:
                c.execute(
                    """INSERT INTO agg_asn VALUES (?,?,?,?,?,?,?,1)
                       ON CONFLICT(window_start, router_id, direction, asn, role) DO UPDATE SET
                       bytes=bytes+excluded.bytes, packets=packets+excluded.packets, flows=flows+1""",
                    (ws, flow.router_id, flow.direction, asn, role, b, p),
                )
        self._dirty += 1
        now = time.time()
        if self._dirty >= 200 or now - self._last_commit >= 1:
            self.flush()
        if now - self._last_clean > 120:
            try:
                cut = int(now) - self.retention * 60
                for t in ("agg_ip", "agg_asn", "agg_router"):
                    c.execute(f"DELETE FROM {t} WHERE window_start < ?", (cut,))
                self.conn.commit()
            except sqlite3.Error as exc:
                print(f"cleanup skipped: {exc}", file=sys.stderr)
            self._last_clean = now

    def flush(self) -> None:
        if self._dirty:
            self.conn.commit()
            self._dirty = 0
            self._last_commit = time.time()

    def _where(self, window: Optional[int], extra: list[str], params: list[Any]) -> str:
        clauses = ["window_start >= ?"] + extra
        params.insert(0, int(time.time()) - (window or self.window))
        return " AND ".join(clauses)

    def top_ip(self, direction=None, router_id=None, window=None, limit=20, role="src"):
        extra, params = ["role = ?"], [role]
        if direction:
            extra.append("direction = ?")
            params.append(direction)
        if router_id:
            extra.append("router_id = ?")
            params.append(router_id)
        sql = f"""SELECT ip, SUM(bytes) bytes, SUM(packets) packets, SUM(flows) flows,
                  SUM(tcp_packets) tcp_packets, SUM(udp_packets) udp_packets,
                  GROUP_CONCAT(DISTINCT router_id) routers
                  FROM agg_ip WHERE {self._where(window, extra, params)}
                  GROUP BY ip ORDER BY bytes DESC LIMIT ?"""
        params.append(limit)
        return [dict(r) for r in self.conn.execute(sql, params)]

    def top_asn(self, direction=None, router_id=None, window=None, limit=20, role="src"):
        extra, params = ["role = ?", "asn > 0"], [role]
        if direction:
            extra.append("direction = ?")
            params.append(direction)
        if router_id:
            extra.append("router_id = ?")
            params.append(router_id)
        sql = f"""SELECT asn, SUM(bytes) bytes, SUM(packets) packets, SUM(flows) flows,
                  GROUP_CONCAT(DISTINCT router_id) routers
                  FROM agg_asn WHERE {self._where(window, extra, params)}
                  GROUP BY asn ORDER BY bytes DESC LIMIT ?"""
        params.append(limit)
        return [dict(r) for r in self.conn.execute(sql, params)]

    def show_ip(self, ip, router_id=None, window=None, limit=20):
        extra, params = ["ip = ?"], [ip]
        if router_id:
            extra.append("router_id = ?")
            params.append(router_id)
        where = self._where(window, extra, params)
        totals = self.conn.execute(
            f"""SELECT SUM(bytes) bytes, SUM(packets) packets, SUM(flows) flows,
                GROUP_CONCAT(DISTINCT router_id) routers, GROUP_CONCAT(DISTINCT direction) directions
                FROM agg_ip WHERE {where}""",
            params,
        ).fetchone()
        return {"ip": ip, "totals": dict(totals) if totals else {}}

    def show_asn(self, asn, router_id=None, window=None, limit=20):
        extra, params = ["asn = ?"], [asn]
        if router_id:
            extra.append("router_id = ?")
            params.append(router_id)
        where = self._where(window, extra, params)
        totals = self.conn.execute(
            f"""SELECT SUM(bytes) bytes, SUM(packets) packets, SUM(flows) flows,
                GROUP_CONCAT(DISTINCT router_id) routers, GROUP_CONCAT(DISTINCT direction) directions
                FROM agg_asn WHERE {where}""",
            params,
        ).fetchone()
        rows = self.conn.execute(
            f"""SELECT role, direction, SUM(bytes) bytes, SUM(packets) packets, SUM(flows) flows
                FROM agg_asn WHERE {where} GROUP BY role, direction ORDER BY bytes DESC LIMIT ?""",
            params + [limit],
        ).fetchall()
        return {"asn": asn, "totals": dict(totals) if totals else {}, "breakdown": [dict(r) for r in rows]}

    def router_totals(self, window=None):
        params: list[Any] = []
        where = self._where(window, [], params)
        return [
            dict(r)
            for r in self.conn.execute(
                f"SELECT router_id, SUM(bytes) bytes, SUM(packets) packets, SUM(flows) flows FROM agg_router WHERE {where} GROUP BY router_id ORDER BY bytes DESC",
                params,
            )
        ]

    def direction_bytes(self, direction: str, router_id=None, window=None) -> int:
        extra, params = ["direction = ?", "role = ?"], [direction, "src"]
        if router_id:
            extra.append("router_id = ?")
            params.append(router_id)
        where = self._where(window, extra, params)
        row = self.conn.execute(
            f"SELECT COALESCE(SUM(bytes), 0) AS bytes FROM agg_ip WHERE {where}",
            params,
        ).fetchone()
        return int(row["bytes"] if row else 0)

    def flush_asn_buckets(
        self, bucket_start: int, counters: dict[tuple[str, int, int], list[int]]
    ) -> int:
        if not counters:
            return 0
        cur = self.conn.cursor()
        n = 0
        for (router_id, iface, asn), (b, p, f) in counters.items():
            cur.execute(
                """
                INSERT INTO asn_bucket (bucket_start, router_id, iface, asn, bytes, packets, flows)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(bucket_start, router_id, iface, asn) DO UPDATE SET
                    bytes = bytes + excluded.bytes,
                    packets = packets + excluded.packets,
                    flows = flows + excluded.flows
                """,
                (bucket_start, router_id, iface, asn, b, p, f),
            )
            n += 1
        self.conn.commit()
        return n

    def cleanup_asn_buckets(self, retention_days: int) -> None:
        cut = int(time.time()) - retention_days * 86400
        self.conn.execute("DELETE FROM asn_bucket WHERE bucket_start < ?", (cut,))
        self.conn.commit()

    def asn_delivery_report(
        self,
        period: str,
        router_id: Optional[str] = None,
        iface: Optional[int] = None,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        end = int(time.time())
        start = end - {"hour": 3600, "day": 86400, "month": 30 * 86400}[period]
        clauses = ["bucket_start >= ?", "bucket_start < ?"]
        params: list[Any] = [start, end]
        if router_id:
            clauses.append("router_id = ?")
            params.append(router_id)
        if iface is not None:
            clauses.append("iface = ?")
            params.append(iface)
        where = " AND ".join(clauses)
        rows = self.conn.execute(
            f"""
            SELECT asn, SUM(bytes) AS bytes, SUM(packets) AS packets, SUM(flows) AS flows
            FROM asn_bucket WHERE {where}
            GROUP BY asn ORDER BY bytes DESC LIMIT ?
            """,
            params + [limit],
        ).fetchall()
        total_row = self.conn.execute(
            f"SELECT COALESCE(SUM(bytes), 0) AS bytes FROM asn_bucket WHERE {where}",
            params,
        ).fetchone()
        grand = int(total_row["bytes"] if total_row else 0) or 1
        out = []
        for r in rows:
            b = int(r["bytes"] or 0)
            out.append(
                {
                    "asn": int(r["asn"]),
                    "bytes": b,
                    "packets": int(r["packets"] or 0),
                    "flows": int(r["flows"] or 0),
                    "percent": round(100.0 * b / grand, 2),
                }
            )
        return out

    def asn_delivery_total(
        self, period: str, router_id: Optional[str] = None, iface: Optional[int] = None
    ) -> int:
        end = int(time.time())
        start = end - {"hour": 3600, "day": 86400, "month": 30 * 86400}[period]
        clauses = ["bucket_start >= ?", "bucket_start < ?"]
        params: list[Any] = [start, end]
        if router_id:
            clauses.append("router_id = ?")
            params.append(router_id)
        if iface is not None:
            clauses.append("iface = ?")
            params.append(iface)
        row = self.conn.execute(
            f"SELECT COALESCE(SUM(bytes), 0) AS bytes FROM asn_bucket WHERE {' AND '.join(clauses)}",
            params,
        ).fetchone()
        return int(row["bytes"] if row else 0)

    def close(self) -> None:
        try:
            self.flush()
        except Exception:
            pass
        self.conn.close()


class AsnDelivery:
    """In-memory destination-ASN aggregation; flush periodically to asn_bucket."""

    def __init__(self, cfg: Config, store: Store) -> None:
        self.cfg = cfg
        self.store = store
        self.counters: dict[tuple[str, int, int], list[int]] = defaultdict(lambda: [0, 0, 0])
        self.samples = 0
        self.flushes = 0
        self.last_flush = time.time()

    def add(self, flow: Flow) -> None:
        if not self.cfg.as_enabled:
            return
        iface = flow.output_iface if self.cfg.as_iface_field == "output" else flow.input_iface
        if self.cfg.as_interfaces and iface not in self.cfg.as_interfaces:
            return
        asn = flow.dst_asn if flow.dst_asn > 0 else 0
        key = (flow.router_id, iface, asn)
        c = self.counters[key]
        c[0] += flow.scaled_bytes
        c[1] += flow.scaled_packets
        c[2] += 1
        self.samples += 1

    def flush(self) -> int:
        if not self.counters:
            self.last_flush = time.time()
            return 0
        now = int(time.time())
        bucket = now - (now % max(self.cfg.as_flush_seconds, 1))
        snapshot = self.counters
        self.counters = defaultdict(lambda: [0, 0, 0])
        n = self.store.flush_asn_buckets(bucket, snapshot)
        self.flushes += 1
        self.last_flush = time.time()
        if self.flushes % 6 == 0:
            self.store.cleanup_asn_buckets(self.cfg.as_retention_days)
        return n

    def top_memory(self, limit: int = 15) -> list[tuple]:
        items = sorted(self.counters.items(), key=lambda kv: kv[1][0], reverse=True)[:limit]
        return items


class Detector:
    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg
        Path(cfg.alert_dir).mkdir(parents=True, exist_ok=True)
        self.tcp_dst: dict[tuple[str, str], deque] = defaultdict(deque)
        self.tcp_scan: dict[tuple[str, str], deque] = defaultdict(deque)
        self.udp_dst: dict[tuple[str, str], deque] = defaultdict(deque)
        self.udp_bytes: dict[tuple[str, str, str], deque] = defaultdict(deque)
        self.cool: dict[tuple, float] = {}

    def _purge(self, q: deque, now: float) -> None:
        cut = now - self.cfg.attack_window
        while q and q[0][0] < cut:
            q.popleft()

    def _ok(self, key: tuple, now: float) -> bool:
        return (now - self.cool.get(key, 0)) >= self.cfg.cooldown

    def _write(self, family: str, kind: str, flow: Flow, metric: str, value, conf: str, extra: str = "") -> str:
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        line = (
            f"{ts} | {kind} | router={flow.router_id} | exporter={flow.exporter_ip} "
            f"| src={flow.src_ip} | dst={flow.dst_ip} | {metric}={value} "
            f"| window={self.cfg.attack_window}s | proto={family.upper()} | confidence={conf}"
        )
        if extra:
            line += f" | {extra}"
        path = Path(self.cfg.alert_dir) / ("tcp_attacks.txt" if family == "tcp" else "udp_attacks.txt")
        with path.open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")
        return str(path)

    def process(self, flow: Flow) -> int:
        if not self.cfg.attack_enabled:
            return 0
        now = flow.timestamp or time.time()
        n = 0
        if flow.protocol == 6:
            n += self._tcp(flow, now)
        elif flow.protocol == 17:
            n += self._udp(flow, now)
        return n

    def _tcp(self, flow: Flow, now: float) -> int:
        n, pkts = 0, flow.scaled_packets
        syn = pkts if ((flow.tcp_flags & 0x02) and not (flow.tcp_flags & 0x10)) or flow.tcp_flags == 0 else 0
        q = self.tcp_dst[(flow.router_id, flow.dst_ip)]
        q.append((now, pkts, syn, pkts if flow.tcp_flags & 0x10 else 0))
        self._purge(q, now)
        syn_pps = sum(x[2] for x in q) / max(self.cfg.attack_window, 1)
        pps = sum(x[1] for x in q) / max(self.cfg.attack_window, 1)
        key = (flow.router_id, "TCP_SYN_FLOOD", flow.src_ip, flow.dst_ip)
        if syn_pps >= self.cfg.tcp_syn_pps and self._ok(key, now):
            ack = sum(x[3] for x in q)
            self._write("tcp", "TCP_SYN_FLOOD", flow, "pps", int(syn_pps), "medium" if ack > syn_pps else "high")
            self.cool[key] = now
            n += 1
        if flow.dst_port:
            sq = self.tcp_scan[(flow.router_id, flow.src_ip)]
            sq.append((now, flow.dst_port))
            self._purge(sq, now)
            ports = {x[1] for x in sq}
            skey = (flow.router_id, "TCP_PORT_SCAN", flow.src_ip, "*")
            if len(ports) >= self.cfg.tcp_scan_ports and self._ok(skey, now):
                orig_dst = flow.dst_ip
                flow.dst_ip = "*"
                self._write("tcp", "TCP_PORT_SCAN", flow, "unique_ports", len(ports), "high")
                flow.dst_ip = orig_dst
                self.cool[skey] = now
                n += 1
        fkey = (flow.router_id, "TCP_FLOOD", flow.src_ip, flow.dst_ip)
        if pps >= self.cfg.tcp_syn_pps * 1.5 and self._ok(fkey, now) and n == 0:
            self._write("tcp", "TCP_FLOOD", flow, "pps", int(pps), "medium")
            self.cool[fkey] = now
            n += 1
        return n

    def _udp(self, flow: Flow, now: float) -> int:
        n, pkts, nbytes = 0, flow.scaled_packets, flow.scaled_bytes
        q = self.udp_dst[(flow.router_id, flow.dst_ip)]
        q.append((now, pkts, nbytes))
        self._purge(q, now)
        pps = sum(x[1] for x in q) / max(self.cfg.attack_window, 1)
        key = (flow.router_id, "UDP_FLOOD", flow.src_ip, flow.dst_ip)
        if pps >= self.cfg.udp_flood_pps and self._ok(key, now):
            self._write("udp", "UDP_FLOOD", flow, "pps", int(pps), "high")
            self.cool[key] = now
            n += 1
        pair = (flow.router_id, flow.src_ip, flow.dst_ip)
        rev = (flow.router_id, flow.dst_ip, flow.src_ip)
        oq = self.udp_bytes[pair]
        oq.append((now, nbytes))
        self._purge(oq, now)
        rq = self.udp_bytes[rev]
        self._purge(rq, now)
        resp, req = sum(x[1] for x in oq), sum(x[1] for x in rq) or 1
        ratio = resp / req
        akey = (flow.router_id, "UDP_AMPLIFICATION", flow.src_ip, flow.dst_ip)
        if ratio >= 10 and resp > 1_000_000 and self._ok(akey, now):
            self._write("udp", "UDP_AMPLIFICATION", flow, "ratio", round(ratio, 2), "medium", f"resp_bytes={resp}")
            self.cool[akey] = now
            n += 1
        return n


# ---------------------------------------------------------------------------
# Engine + CLI
# ---------------------------------------------------------------------------


class LiveWindow:
    """In-memory 60s tops so the live screen never blocks on SQLite."""

    def __init__(self, seconds: int = 60) -> None:
        self.seconds = seconds
        self.reset_at = time.time()
        self.in_ip: dict[str, list[int]] = {}
        self.out_ip: dict[str, list[int]] = {}
        self.in_asn: dict[int, list[int]] = {}
        self.out_asn: dict[int, list[int]] = {}

    def _bucket(self, table: dict, key, bytes_: int, packets: int, tcp: int, udp: int) -> None:
        row = table.get(key)
        if row is None:
            table[key] = [bytes_, packets, tcp, udp, 1]
        else:
            row[0] += bytes_
            row[1] += packets
            row[2] += tcp
            row[3] += udp
            row[4] += 1

    def add(self, flow: Flow) -> None:
        now = time.time()
        if now - self.reset_at >= self.seconds:
            self.in_ip.clear()
            self.out_ip.clear()
            self.in_asn.clear()
            self.out_asn.clear()
            self.reset_at = now
        b, p = flow.scaled_bytes, flow.scaled_packets
        tcp, udp = (p if flow.protocol == 6 else 0), (p if flow.protocol == 17 else 0)
        if flow.direction == "in":
            self._bucket(self.in_ip, flow.src_ip, b, p, tcp, udp)
            if flow.src_asn > 0:
                self._bucket(self.in_asn, flow.src_asn, b, p, tcp, udp)
        elif flow.direction == "out":
            self._bucket(self.out_ip, flow.src_ip, b, p, tcp, udp)
            if flow.src_asn > 0:
                self._bucket(self.out_asn, flow.src_asn, b, p, tcp, udp)

    def top(self, table: dict, limit: int) -> list[tuple]:
        items = sorted(table.items(), key=lambda kv: kv[1][0], reverse=True)[:limit]
        return [(k, *v) for k, v in items]


class Collector:
    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg
        self.routers = Routers(cfg)
        self.store = Store(cfg.database_path, cfg.window_seconds, cfg.retention_minutes)
        self.asn_delivery = AsnDelivery(cfg, self.store)
        self.detector = Detector(cfg)
        self.templates = TemplateParser()
        self.ripe = RipeAsn(cfg)
        self.live = LiveWindow(60)
        self.packets = self.flows = self.alerts = 0
        self.dropped = 0
        self.errors = 0
        self.started = time.time()
        self.last_flow = 0.0
        self.nf_pkts = self.sf_pkts = 0
        self.nf_last = self.sf_last = 0.0

    def handle_packet(self, data: bytes, exp: str, kind: str, received: float) -> None:
        try:
            self._handle_packet(data, exp, kind, received)
        except Exception:
            self.errors += 1
            if self.errors <= 5 or self.errors % 100 == 0:
                print(f"packet error ({self.errors}): {traceback.format_exc()}", file=sys.stderr)

    def _handle_packet(self, data: bytes, exp: str, kind: str, received: float) -> None:
        self.packets += 1
        if kind == "sflow":
            self.sf_pkts += 1
            self.sf_last = received
        else:
            self.nf_pkts += 1
            self.nf_last = received
        resolved = self.routers.resolve(exp)
        if resolved is None:
            return
        rid, name, _ = resolved
        if not self.routers.is_enabled(rid):
            return
        flows: list[Flow] = []
        source = ""
        templates = None
        if kind == "sflow":
            flows = parse_sflow(data, exp, rid, name, received)
            source = "sflow"
        elif len(data) >= 2:
            ver = struct.unpack_from("!H", data, 0)[0]
            if ver == 5:
                flows = parse_v5(data, exp, rid, name, received)
                source = "netflow_v5"
            elif ver == 9:
                flows = self.templates.parse_v9(data, exp, rid, name, received)
                source, templates = "netflow_v9", self.templates.count_for(exp)
            elif ver == 10:
                flows = self.templates.parse_ipfix(data, exp, rid, name, received)
                source, templates = "ipfix", self.templates.count_for(exp)
        for flow in flows:
            self.ripe.apply(flow)
            flow.direction = classify(flow, self.cfg, self.routers)
            self.store.ingest(flow)
            self.live.add(flow)
            self.asn_delivery.add(flow)
            self.alerts += self.detector.process(flow)
            self.flows += 1
            self.last_flow = flow.timestamp
            source = flow.source or source
        self.routers.note(rid, name, exp, source, len(flows), templates)

    def close(self) -> None:
        try:
            self.asn_delivery.flush()
        except Exception:
            pass
        self.ripe.save(force=True)
        self.store.close()


class UDP(asyncio.DatagramProtocol):
    def __init__(self, kind: str, collector: Collector) -> None:
        self.kind = kind
        self.collector = collector

    def datagram_received(self, data: bytes, addr) -> None:
        self.collector.handle_packet(data, addr[0], self.kind, time.time())

    def error_received(self, exc: Exception) -> None:
        self.collector.dropped += 1


def _tune_udp(transport: asyncio.DatagramTransport) -> None:
    sock = transport.get_extra_info("socket")
    if sock is None:
        return
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 * 1024 * 1024)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    except OSError:
        pass


def open_collector(config_path: str) -> Collector:
    cfg = load_config(config_path)
    Path(cfg.database_path).parent.mkdir(parents=True, exist_ok=True)
    Path(cfg.alert_dir).mkdir(parents=True, exist_ok=True)
    Path(cfg.reports_dir).mkdir(parents=True, exist_ok=True)
    return Collector(cfg)


async def cmd_run(config_path: str) -> int:
    col = open_collector(config_path)
    cfg = col.cfg
    col.ripe.start()
    loop = asyncio.get_running_loop()
    nf_t, _ = await loop.create_datagram_endpoint(
        lambda: UDP("netflow", col), local_addr=(cfg.netflow_host, cfg.netflow_port)
    )
    sf_t, _ = await loop.create_datagram_endpoint(
        lambda: UDP("sflow", col), local_addr=(cfg.sflow_host, cfg.sflow_port)
    )
    _tune_udp(nf_t)
    _tune_udp(sf_t)
    print(f"Listening NetFlow {cfg.netflow_host}:{cfg.netflow_port}  sFlow {cfg.sflow_host}:{cfg.sflow_port}")
    if cfg.as_enabled:
        print(
            f"AS delivery: ON  iface_field={cfg.as_iface_field}  "
            f"flush={cfg.as_flush_seconds}s  filter={sorted(cfg.as_interfaces) or 'ALL'}"
        )
    if cfg.reports_auto_seconds > 0:
        print(f"Auto-collect reports every {cfg.reports_auto_seconds}s -> {cfg.reports_dir}/")
    print("Live traffic report. Ctrl+C to stop.\n")
    last_collect = time.time()
    try:
        while True:
            try:
                col.routers.reload_state()
                col.store.flush()
                if cfg.as_enabled and time.time() - col.asn_delivery.last_flush >= cfg.as_flush_seconds:
                    n = col.asn_delivery.flush()
                    print(f"\n[as-flush] wrote {n} ASN buckets", flush=True)
                print("\033[H\033[J", end="")
                print_report(col, window=60, limit=10, live=True)
                if cfg.as_enabled:
                    print("AS DELIVERY (in-memory window → destination ASN)")
                    top = col.asn_delivery.top_memory(10)
                    _print_table(
                        ["Router", "Iface", "ASN", "Bytes", "Packets", "Flows"],
                        [
                            [r, i, a if a else "unknown", _fmt_bytes(b), p, f]
                            for (r, i, a), (b, p, f) in top
                        ],
                    )
                    print(
                        f"as_samples={col.asn_delivery.samples}  "
                        f"as_flushes={col.asn_delivery.flushes}  "
                        f"next_flush~{max(0, int(cfg.as_flush_seconds - (time.time() - col.asn_delivery.last_flush)))}s\n"
                    )
                if cfg.reports_auto_seconds > 0 and time.time() - last_collect >= cfg.reports_auto_seconds:
                    path = save_collected_report(col, live=False)
                    print(f"\n[auto-collect] saved {path}", flush=True)
                    last_collect = time.time()
            except Exception as exc:
                print(f"\nreport error (collector still running): {exc}", file=sys.stderr)
            await asyncio.sleep(2)
    except (KeyboardInterrupt, asyncio.CancelledError):
        print("\nShutting down...")
        try:
            path = save_collected_report(col, live=False)
            print(f"Final report saved: {path}")
        except Exception:
            pass
    finally:
        nf_t.close()
        sf_t.close()
        col.close()
    return 0


def format_report(
    col: Collector,
    window: int = 60,
    limit: int = 15,
    router: Optional[str] = None,
    live: bool = False,
) -> str:
    lines: list[str] = []
    uptime = int(time.time() - col.started) if live else None
    lines.append("=" * 72)
    title = f"TRAFFIC REPORT  window={window}s"
    if router:
        title += f"  router={router}"
    lines.append(title)
    lines.append(f"generated={_fmt_ts(time.time())}")
    if live:
        lines.append(
            f"uptime={uptime}s  udp={col.packets}  flows={col.flows}  "
            f"alerts={col.alerts}  errors={col.errors}  netflow={col.nf_pkts}  "
            f"sflow={col.sf_pkts}  last={_fmt_ts(col.last_flow)}"
        )
    lines.append("=" * 72)

    lines.append("")
    lines.append("ROUTERS")
    rows = []
    totals: dict[str, Any] = {}
    in_bytes = out_bytes = 0
    if not live:
        try:
            totals = {r["router_id"]: r for r in col.store.router_totals(window)}
            in_bytes = col.store.direction_bytes("in", router, window)
            out_bytes = col.store.direction_bytes("out", router, window)
        except sqlite3.Error as exc:
            lines.append(f"(sqlite report skipped: {exc})")
    for st in col.routers.stats.values():
        agg = totals.get(st.router_id) or {}
        rows.append(
            [
                st.router_id,
                "ON" if col.routers.is_enabled(st.router_id) else "OFF",
                st.exporter_ip,
                _fmt_bytes(agg.get("bytes")) if agg else str(st.flows_received),
                agg.get("packets") or st.packets_received,
                ",".join(sorted(st.protocols)) or "-",
                _fmt_ts(st.last_seen),
            ]
        )
    lines.extend(_table_lines(["ID", "State", "Address", "Bytes", "Packets", "Proto", "Last seen"], rows))

    if live:
        in_bytes = sum(v[0] for v in col.live.in_ip.values())
        out_bytes = sum(v[0] for v in col.live.out_ip.values())
        lines.append("")
        lines.append(f"SUMMARY  inbound={_fmt_bytes(in_bytes)}  outbound={_fmt_bytes(out_bytes)}")
        lines.append("")
        lines.append("INBOUND  top IPs (source)")
        lines.extend(
            _table_lines(
                ["IP", "Bytes", "Packets", "TCP", "UDP"],
                [[k, _fmt_bytes(b), p, t, u] for k, b, p, t, u, _f in col.live.top(col.live.in_ip, limit)],
            )
        )
        lines.append("")
        lines.append("INBOUND  top ASNs (source)")
        lines.extend(
            _table_lines(
                ["ASN", "Bytes", "Packets", "Flows"],
                [[k, _fmt_bytes(b), p, f] for k, b, p, _t, _u, f in col.live.top(col.live.in_asn, limit)],
            )
        )
        lines.append("")
        lines.append("OUTBOUND  top IPs (source)")
        lines.extend(
            _table_lines(
                ["IP", "Bytes", "Packets", "TCP", "UDP"],
                [[k, _fmt_bytes(b), p, t, u] for k, b, p, t, u, _f in col.live.top(col.live.out_ip, limit)],
            )
        )
        lines.append("")
        lines.append("OUTBOUND  top ASNs (source)")
        lines.extend(
            _table_lines(
                ["ASN", "Bytes", "Packets", "Flows"],
                [[k, _fmt_bytes(b), p, f] for k, b, p, _t, _u, f in col.live.top(col.live.out_asn, limit)],
            )
        )
        lines.append("")
        return "\n".join(lines) + "\n"

    lines.append("")
    lines.append(f"SUMMARY  inbound={_fmt_bytes(in_bytes)}  outbound={_fmt_bytes(out_bytes)}")
    lines.append("")
    lines.append("INBOUND  top IPs (source)")
    lines.extend(
        _table_lines(
            ["IP", "Bytes", "Packets", "TCP", "UDP"],
            [
                [r["ip"], _fmt_bytes(r["bytes"]), r["packets"] or 0, r["tcp_packets"] or 0, r["udp_packets"] or 0]
                for r in col.store.top_ip("in", router, window, limit, "src")
            ],
        )
    )
    lines.append("")
    lines.append("INBOUND  top ASNs (source)")
    lines.extend(
        _table_lines(
            ["ASN", "Bytes", "Packets", "Flows"],
            [
                [r["asn"], _fmt_bytes(r["bytes"]), r["packets"] or 0, r["flows"] or 0]
                for r in col.store.top_asn("in", router, window, limit, "src")
            ],
        )
    )
    lines.append("")
    lines.append("OUTBOUND  top IPs (source)")
    lines.extend(
        _table_lines(
            ["IP", "Bytes", "Packets", "TCP", "UDP"],
            [
                [r["ip"], _fmt_bytes(r["bytes"]), r["packets"] or 0, r["tcp_packets"] or 0, r["udp_packets"] or 0]
                for r in col.store.top_ip("out", router, window, limit, "src")
            ],
        )
    )
    lines.append("")
    lines.append("OUTBOUND  top ASNs (source)")
    lines.extend(
        _table_lines(
            ["ASN", "Bytes", "Packets", "Flows"],
            [
                [r["asn"], _fmt_bytes(r["bytes"]), r["packets"] or 0, r["flows"] or 0]
                for r in col.store.top_asn("out", router, window, limit, "src")
            ],
        )
    )
    lines.append("")
    return "\n".join(lines) + "\n"


def print_report(
    col: Collector,
    window: int = 60,
    limit: int = 15,
    router: Optional[str] = None,
    live: bool = False,
) -> None:
    print(format_report(col, window=window, limit=limit, router=router, live=live), end="")


def prune_reports(reports_dir: Path, keep: int) -> None:
    if keep <= 0:
        return
    files = sorted(reports_dir.glob("report_*.txt"), key=lambda p: p.stat().st_mtime, reverse=True)
    for old in files[keep:]:
        try:
            old.unlink()
        except OSError:
            pass


def save_collected_report(
    col: Collector,
    *,
    window: Optional[int] = None,
    limit: Optional[int] = None,
    router: Optional[str] = None,
    live: bool = False,
) -> Path:
    cfg = col.cfg
    reports_dir = Path(cfg.reports_dir)
    reports_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    suffix = f"_{router}" if router else ""
    path = reports_dir / f"report_{stamp}{suffix}.txt"
    text = format_report(
        col,
        window=window if window is not None else cfg.reports_window,
        limit=limit if limit is not None else cfg.reports_limit,
        router=router,
        live=live,
    )
    path.write_text(text, encoding="utf-8")
    prune_reports(reports_dir, cfg.reports_keep)
    # Also keep a rolling "latest" copy for quick access
    latest = reports_dir / ("latest.txt" if not router else f"latest_{router}.txt")
    latest.write_text(text, encoding="utf-8")
    return path


def cmd_report(args) -> int:
    col = open_collector(args.config)
    try:
        print_report(col, window=args.window, limit=args.limit, router=args.router)
        if getattr(args, "save", False):
            path = save_collected_report(
                col, window=args.window, limit=args.limit, router=args.router
            )
            print(f"Saved: {path}")
    finally:
        col.close()
    return 0


def cmd_collect(args) -> int:
    col = open_collector(args.config)
    try:
        path = save_collected_report(
            col,
            window=args.window,
            limit=args.limit,
            router=args.router,
        )
        print(f"Collected report saved: {path}")
        print(f"Latest copy: {Path(col.cfg.reports_dir) / ('latest.txt' if not args.router else f'latest_{args.router}.txt')}")
    finally:
        col.close()
    return 0


def cmd_reports_list(args) -> int:
    cfg = load_config(args.config)
    reports_dir = Path(cfg.reports_dir)
    if not reports_dir.exists():
        print(f"No reports directory yet: {reports_dir}")
        return 0
    files = sorted(reports_dir.glob("report_*.txt"), key=lambda p: p.stat().st_mtime, reverse=True)
    if args.latest:
        latest = reports_dir / "latest.txt"
        if not latest.exists():
            print("No latest report yet. Run: python3 collector.py collect")
            return 1
        print(latest.read_text(encoding="utf-8"), end="")
        return 0
    if args.show:
        path = Path(args.show)
        if not path.is_absolute():
            path = reports_dir / path
        if not path.exists():
            print(f"Report not found: {path}")
            return 1
        print(path.read_text(encoding="utf-8"), end="")
        return 0
    rows = []
    for f in files[: args.limit]:
        size = f.stat().st_size
        mtime = datetime.fromtimestamp(f.stat().st_mtime, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")
        rows.append([f.name, mtime, f"{size}B"])
    print(f"Collected reports in {reports_dir}")
    _print_table(["File", "Saved at (UTC)", "Size"], rows)
    print("\nShow one:  python3 collector.py reports --show report_YYYYMMDD_HHMMSS.txt")
    print("Latest:    python3 collector.py reports --latest")
    return 0


def cmd_top(args) -> int:
    col = open_collector(args.config)
    try:
        if args.top_what == "ip":
            rows = col.store.top_ip(args.direction, args.router, args.window, args.limit, args.role)
            label = args.direction or "all"
            print(f"Top IPs  role={args.role}  direction={label}  window={args.window}s")
            _print_table(
                ["IP", "Bytes", "Packets", "Flows", "TCP", "UDP", "Routers"],
                [
                    [r["ip"], _fmt_bytes(r["bytes"]), r["packets"] or 0, r["flows"] or 0, r["tcp_packets"] or 0, r["udp_packets"] or 0, r["routers"] or ""]
                    for r in rows
                ],
            )
        else:
            rows = col.store.top_asn(args.direction, args.router, args.window, args.limit, args.role)
            label = args.direction or "all"
            print(f"Top ASNs  role={args.role}  direction={label}  window={args.window}s")
            _print_table(
                ["ASN", "Bytes", "Packets", "Flows", "Routers"],
                [[r["asn"], _fmt_bytes(r["bytes"]), r["packets"] or 0, r["flows"] or 0, r["routers"] or ""] for r in rows],
            )
    finally:
        col.close()
    return 0


def cmd_show(args) -> int:
    col = open_collector(args.config)
    try:
        if args.show_what == "ip":
            data = col.store.show_ip(args.value, args.router, args.window, args.limit)
            t = data.get("totals") or {}
            print(f"IP {data['ip']}")
            print(f"  bytes={_fmt_bytes(t.get('bytes'))}  packets={t.get('packets') or 0}  flows={t.get('flows') or 0}")
            print(f"  routers={t.get('routers') or '-'}  directions={t.get('directions') or '-'}")
        else:
            data = col.store.show_asn(int(args.value), args.router, args.window, args.limit)
            t = data.get("totals") or {}
            print(f"ASN {data['asn']}")
            print(f"  bytes={_fmt_bytes(t.get('bytes'))}  packets={t.get('packets') or 0}  flows={t.get('flows') or 0}")
            print(f"  routers={t.get('routers') or '-'}  directions={t.get('directions') or '-'}")
            print("\nBreakdown")
            _print_table(
                ["Role", "Direction", "Bytes", "Packets", "Flows"],
                [[r["role"], r["direction"], _fmt_bytes(r["bytes"]), r["packets"] or 0, r["flows"] or 0] for r in (data.get("breakdown") or [])],
            )
    finally:
        col.close()
    return 0


def cmd_routers(args) -> int:
    col = open_collector(args.config)
    try:
        totals = {r["router_id"]: r for r in col.store.router_totals(args.window)}
        rows = []
        for st in col.routers.stats.values():
            agg = totals.get(st.router_id) or {}
            rows.append(
                [
                    st.router_id,
                    "ON" if col.routers.is_enabled(st.router_id) else "OFF",
                    st.router_name,
                    st.exporter_ip,
                    _fmt_ts(st.last_seen),
                    ",".join(sorted(st.protocols)) or "-",
                    _fmt_bytes(agg.get("bytes")),
                ]
            )
        print("Routers")
        _print_table(["ID", "State", "Name", "Address", "Last seen", "Proto", "Bytes"], rows)
        print("\nEnable/disable:  python3 collector.py enable <id>   |   python3 collector.py disable <id>")
    finally:
        col.close()
    return 0


def cmd_set_router(args, enabled: bool) -> int:
    col = open_collector(args.config)
    try:
        rid = col.routers.find(args.router)
        if not rid:
            print(f"Unknown router: {args.router}")
            print("Known:", ", ".join(sorted(col.routers.stats) or col.routers.by_id))
            return 1
        col.routers.set_enabled(rid, enabled)
        print(f"{rid} {'enabled' if enabled else 'disabled'}")
    finally:
        col.close()
    return 0


def cmd_asn(args) -> int:
    """Destination-ASN delivery reports (hourly / daily / monthly)."""
    col = open_collector(args.config)
    try:
        if not col.cfg.as_enabled:
            print("AS traffic aggregation is disabled in config (as_traffic.enabled: false)")
            return 1
        rows = col.store.asn_delivery_report(
            period=args.period,
            router_id=args.router,
            iface=args.iface,
            limit=args.limit,
        )
        total = col.store.asn_delivery_total(args.period, args.router, args.iface)
        title = f"ASN DELIVERY  period={args.period}  total={_fmt_bytes(total)}"
        if args.router:
            title += f"  router={args.router}"
        if args.iface is not None:
            title += f"  iface={args.iface}"
        print(title)
        print(f"generated={_fmt_ts(time.time())}")
        print("Traffic sent toward destination ASNs (source IP ignored in aggregation)")
        print()
        _print_table(
            ["ASN", "Bytes", "Packets", "Flows", "Share %"],
            [
                [
                    r["asn"] if r["asn"] else "unknown",
                    _fmt_bytes(r["bytes"]),
                    r["packets"],
                    r["flows"],
                    f"{r['percent']:.2f}%",
                ]
                for r in rows
            ],
        )
        if args.save:
            out_dir = Path(col.cfg.reports_dir)
            out_dir.mkdir(parents=True, exist_ok=True)
            stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            path = out_dir / f"asn_delivery_{args.period}_{stamp}.txt"
            lines = [title, f"generated={_fmt_ts(time.time())}", "", "ASN  Bytes  Packets  Flows  Share%"]
            for r in rows:
                lines.append(
                    f"{r['asn'] if r['asn'] else 'unknown'}  {_fmt_bytes(r['bytes'])}  "
                    f"{r['packets']}  {r['flows']}  {r['percent']:.2f}%"
                )
            path.write_text("\n".join(lines) + "\n", encoding="utf-8")
            print(f"\nSaved: {path}")
    finally:
        col.close()
    return 0


def cmd_status(args) -> int:
    cfg = load_config(args.config)
    print("Config:", args.config)
    print(f"NetFlow {cfg.netflow_host}:{cfg.netflow_port}")
    print(f"sFlow   {cfg.sflow_host}:{cfg.sflow_port}")
    print(f"Alerts  {cfg.alert_dir}")
    print(f"Routers {len(cfg.exporters)}  unknown={'accept' if cfg.accept_unknown else 'reject'}")
    print(f"Local nets: {', '.join(cfg.local_networks) or '-'}")
    print(f"Local ASNs: {', '.join(str(a) for a in cfg.local_asns) or '-'}")
    print(
        f"AS delivery: {'ON' if cfg.as_enabled else 'OFF'}  "
        f"iface={cfg.as_iface_field}  flush={cfg.as_flush_seconds}s  "
        f"ifaces={sorted(cfg.as_interfaces) or 'ALL'}"
    )
    if Path(cfg.database_path).exists():
        col = Collector(cfg)
        try:
            print("\nRouter totals (300s)")
            _print_table(
                ["Router", "State", "Bytes", "Packets", "Flows"],
                [
                    [r["router_id"], "ON" if col.routers.is_enabled(r["router_id"]) else "OFF", _fmt_bytes(r["bytes"]), r["packets"] or 0, r["flows"] or 0]
                    for r in col.store.router_totals(300)
                ],
            )
            print("\nASN delivery totals")
            for period in ("hour", "day", "month"):
                print(f"  {period}: {_fmt_bytes(col.store.asn_delivery_total(period))}")
        finally:
            col.close()
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="collector",
        description="FlowSight — NetFlow/sFlow collector + destination-ASN delivery",
    )
    p.add_argument("-c", "--config", default="config.yaml")
    sub = p.add_subparsers(dest="command", required=True)
    sub.add_parser("run", help="Listen, live report, and ASN delivery aggregation")
    rep = sub.add_parser("report", help="Print inbound/outbound traffic report")
    rep.add_argument("--window", type=int, default=60)
    rep.add_argument("--limit", type=int, default=15)
    rep.add_argument("--router")
    rep.add_argument("--save", action="store_true", help="Also save report under reports/")
    asn = sub.add_parser("asn", help="Destination-ASN delivery report (hour/day/month)")
    asn.add_argument("--period", choices=["hour", "day", "month"], default="hour")
    asn.add_argument("--router")
    asn.add_argument("--iface", type=int, help="NetFlow interface index")
    asn.add_argument("--limit", type=int, default=50)
    asn.add_argument("--save", action="store_true")
    colp = sub.add_parser("collect", help="Collect/save a traffic report to reports/")
    colp.add_argument("--window", type=int, default=None)
    colp.add_argument("--limit", type=int, default=None)
    colp.add_argument("--router")
    rlist = sub.add_parser("reports", help="List or show collected reports")
    rlist.add_argument("--limit", type=int, default=20)
    rlist.add_argument("--latest", action="store_true", help="Print latest collected report")
    rlist.add_argument("--show", help="Show a saved report file name")
    top = sub.add_parser("top").add_subparsers(dest="top_what", required=True)
    for name in ("ip", "asn"):
        t = top.add_parser(name)
        t.add_argument("--direction", choices=["in", "out", "internal", "transit", "unknown"])
        t.add_argument("--router")
        t.add_argument("--window", type=int, default=60)
        t.add_argument("--limit", type=int, default=20)
        t.add_argument("--role", choices=["src", "dst"], default="src")
    show = sub.add_parser("show").add_subparsers(dest="show_what", required=True)
    ip = show.add_parser("ip")
    ip.add_argument("value")
    ashow = show.add_parser("asn")
    ashow.add_argument("value", type=int)
    for s in (ip, ashow):
        s.add_argument("--router")
        s.add_argument("--window", type=int, default=60)
        s.add_argument("--limit", type=int, default=20)
    sub.add_parser("routers").add_argument("--window", type=int, default=60)
    en = sub.add_parser("enable", help="Enable a router")
    en.add_argument("router")
    dis = sub.add_parser("disable", help="Disable a router")
    dis.add_argument("router")
    sub.add_parser("status")
    return p


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "run":
        return asyncio.run(cmd_run(args.config))
    if args.command == "report":
        return cmd_report(args)
    if args.command == "asn":
        return cmd_asn(args)
    if args.command == "collect":
        return cmd_collect(args)
    if args.command == "reports":
        return cmd_reports_list(args)
    if args.command == "top":
        return cmd_top(args)
    if args.command == "show":
        return cmd_show(args)
    if args.command == "routers":
        return cmd_routers(args)
    if args.command == "enable":
        return cmd_set_router(args, True)
    if args.command == "disable":
        return cmd_set_router(args, False)
    if args.command == "status":
        return cmd_status(args)
    return 1


if __name__ == "__main__":
    sys.exit(main())
