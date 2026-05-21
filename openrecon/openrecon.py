# 🛰️ OpenRecon — Asynchronous Reconnaissance Tool for Domain Enumeration
# python3 openrecon.py -d example.com
# 👨‍💻 Author Stanislav Istyagin (aka `@clevergod`)
import argparse
import sys
import time
import socket
import concurrent.futures
import requests
import whois
import ssl
import os
import json
import csv
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress
from rich import box
import urllib3
from . import __version__
import subprocess
from ipwhois import IPWhois
import html
from .mail_security import analyze_mail_security, render_mail_security

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
console = Console()

# -----------------
# Tuning & defaults
# -----------------
DEFAULT_PORTS = [80, 443, 40443, 8080, 8443, 8090, 445, 22, 21, 3389, 5985]
FALLBACK_SUBS = ['www', 'mail', 'vpn', 'adfs', 'telbot', 'drive', 'api', 'dev', 'test', 'sip', 'ftp', 'autodiscover', 'crm', 'vpn2', 'doc', 'owa', 'portal', 'remote', 'trade', 'admin', 'cloud']

# Timeouts / concurrency
PORT_CONNECT_TIMEOUT = 0.18
TLS_HANDSHAKE_TIMEOUT = 0.7
HTTP_TIMEOUT = 2.5
WHOIS_TIMEOUT = 8
RESOLVE_THREADS = 200
PORT_WORKERS_FULL = 300
PORT_WORKERS_DEFAULT = 80

# --------------
# Fancy banner
# --------------

def print_banner():
    """Компактный 3-строчный баннер вместо большого ASCII-art."""
    console.print(
        f"[bold cyan]┌─ OpenRecon[/] [dim]v{__version__}[/]"
        f"  [bold white]·[/]  Asynchronous Recon Toolkit"
        f"  [bold white]·[/]  [dim]by @clevergod[/]"
    )
    console.print(
        "[bold cyan]└─[/] [dim]subdomains · ports · TLS · WAF · "
        "WHOIS · mail security · security.txt[/]"
    )

# -----------------
# Helpers
# -----------------

def get_hosting_info(domain: str):
    try:
        ip = socket.gethostbyname(domain)
        whois_ip = IPWhois(ip)
        data = whois_ip.lookup_rdap()
        org = data.get('network', {}).get('name', '-')
        loc = f"{data.get('asn_country_code', '-')}, {data.get('asn_description', '-')}"
        return ip, org, loc
    except Exception:
        return '-', '-', '-'


def _whois_fetch(domain: str):
    return whois.whois(domain)


# Маппинг человеко-читаемых полей → ключи нашей нормализованной структуры.
# Обрабатываются и стандартные формы ("Domain Name", "Registrar Email"),
# и .kz-стиль с многоточием ("Domain Name............:", "Email Address......:"),
# и .ru/RIPE-стиль ("admin-c", "person").
_WHOIS_CLI_PATTERNS: list[tuple[str, list[str]]] = [
    ("domain",       [r"domain name", r"domain"]),
    ("registrar",    [r"current registar", r"sponsoring registrar", r"registrar"]),
    ("created",      [r"domain created", r"creation date", r"created on", r"created"]),
    ("expires",      [r"expir(?:y|ation)\s*date", r"registry expiry date", r"expires?",
                      r"paid-till"]),
    ("updated",      [r"last modified", r"updated date", r"updated", r"changed"]),
    ("status",       [r"domain status", r"status"]),
    ("name",         [r"registrant name", r"registrant",
                      r"organization using domain name\W+name", r"name"]),
    ("org",          [r"registrant organization", r"organization name",
                      r"organisation", r"org"]),
    ("emails",       [r"registrant email", r"email address", r"e-mail", r"email"]),
    ("country",      [r"registrant country", r"country"]),
    ("city",         [r"registrant city", r"city"]),
    ("state",        [r"registrant state(?:/province)?", r"state(?:/province)?"]),
    ("postal",       [r"registrant postal code", r"postal code", r"zip"]),
    ("dnssec",       [r"dnssec"]),
]


def _fallback_whois_via_cli(domain: str) -> dict:
    """Запасной парсер: вызывает системный `whois <domain>` и регуляркой
    извлекает основные поля. Нужен для TLD, на которых `python-whois` падает
    (например `.kz` — дата формата `2023-03-09 12:33:38 (GMT+0:00)`).
    """
    import re
    try:
        cp = subprocess.run(
            ["whois", domain], capture_output=True, text=True,
            timeout=WHOIS_TIMEOUT,
        )
        text = cp.stdout or ""
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return {}
    if not text.strip():
        return {}

    # Системный whois для многих TLD сперва возвращает ответ IANA про сам TLD
    # (например для `.kz` сверху идёт блок про домен `KZ` и его админа),
    # а ниже — данные нужного домена. Эти преамбулы загрязняют парсер.
    # Поэтому отбрасываем всё до первого маркера ответа реального whois-сервера.
    cut_markers = [
        # "Whois Server for the KZ top level domain name."
        r"(?im)^Whois Server for the [A-Z\.\-]+ top level domain name",
        # "Domain Name........: cyberone.kz" / "Domain Name: cyberone.kz"
        rf"(?im)^Domain Name[\.\s]*:\s*{re.escape(domain)}\b",
        # ".ru/.su/.рф формат: блок начинается с domain: cyberone.kz"
        rf"(?im)^domain\s*:\s*{re.escape(domain)}\b",
        # ICANN sections in gTLDs
        r"(?im)^>>> Last update of WHOIS database",
    ]
    earliest = None
    for pat in cut_markers:
        m = re.search(pat, text)
        if m and (earliest is None or m.start() < earliest):
            earliest = m.start()
    if earliest is not None and earliest > 0:
        text = text[earliest:]

    out: dict[str, list[str]] = {k: [] for k, _ in _WHOIS_CLI_PATTERNS}
    name_servers: list[str] = []

    for raw in text.splitlines():
        line = raw.rstrip()
        if not line or line.lstrip().startswith(("%", "#", ">>>")):
            continue
        # Нормализуем разделитель `Domain Name............: value` → `domain name: value`
        # Поддерживаем и `key: value`, и `key . . . : value`.
        m = re.match(r"^\s*([A-Za-z][A-Za-z0-9 /\-_]*?)[\s\.]*:\s*(.+?)\s*$", line)
        if not m:
            continue
        key_raw, value = m.group(1).strip().lower(), m.group(2).strip()
        if not value or value in ("-", "n/a"):
            continue

        # Name servers — собираем отдельно (множество вариантов имени поля)
        if re.search(r"name\s*server|nserver|primary server|secondary server", key_raw):
            ns = value.split()[0].rstrip(".")
            if ns and ns not in name_servers:
                name_servers.append(ns)
            continue

        # Иначе мапим первое совпадение по паттернам в очерёдности
        for field_name, patterns in _WHOIS_CLI_PATTERNS:
            if any(re.fullmatch(p, key_raw) for p in patterns):
                if value not in out[field_name]:
                    out[field_name].append(value)
                break

    def _first(field: str) -> str:
        return out[field][0] if out[field] else "-"

    def _join(field: str) -> str:
        return ", ".join(out[field]) if out[field] else "-"

    return {
        "domain": _first("domain") if out["domain"] else domain,
        "org": _first("org"),
        "name": _first("name"),
        "emails": _join("emails"),
        "registrar": _first("registrar"),
        "status": _join("status"),
        "created": _first("created"),
        "expires": _first("expires"),
        "updated": _first("updated"),
        "name_servers": ", ".join(name_servers) if name_servers else "-",
        "dnssec": _first("dnssec"),
        "country": _first("country"),
        "city": _first("city"),
        "state": _first("state"),
        "postal": _first("postal"),
    }


def get_whois_info(domain: str) -> dict:
    defaults = {
        'domain': domain,
        'org': '-', 'name': '-', 'emails': '-', 'registrar': '-', 'status': '-',
        'created': '-', 'expires': '-', 'updated': '-', 'name_servers': '-', 'dnssec': '-',
        'country': '-', 'city': '-', 'state': '-', 'postal': '-',
    }

    # Считаем dict «пустым» если значимые поля все прочерки.
    def _is_empty(d: dict) -> bool:
        meaningful = ('registrar', 'created', 'expires', 'updated',
                      'name_servers', 'emails', 'name', 'org')
        return all(d.get(k, '-') in ('-', '', None) for k in meaningful)

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
            fut = ex.submit(_whois_fetch, domain)
            w = fut.result(timeout=WHOIS_TIMEOUT)

        def _fmt(v):
            if v is None or v == '' or v == [] or v == ():
                return '-'
            if isinstance(v, (list, tuple, set)):
                # Чистим None/'' внутри коллекций — python-whois иногда отдаёт
                # `[datetime(...), None, None]`. Берём первый осмысленный.
                vals = [x for x in v if x not in (None, '', [])]
                if not vals:
                    return '-'
                # Для дат — первое значение (более полезно чем "list of dates")
                from datetime import datetime as _dtcls
                if all(isinstance(x, _dtcls) for x in vals):
                    return str(vals[0])
                return ", ".join(str(x) for x in vals)
            return str(v)

        def _read(wobj, candidates):
            # Supports both dict-like and attribute-like results across whois library versions
            for key in candidates:
                # Attribute access
                if not isinstance(wobj, dict) and hasattr(wobj, key):
                    val = getattr(wobj, key)
                    if val not in (None, '', []):
                        return val
                # Mapping access with common key variants
                if isinstance(wobj, dict):
                    for variant in {key, key.lower(), key.upper()}:
                        if variant in wobj and wobj[variant] not in (None, '', []):
                            return wobj[variant]
            return None

        # Convert result to a plain dict when possible to avoid surprises in later handling
        raw = w if isinstance(w, dict) else getattr(w, "__dict__", w)

        parsed = {
            'domain': _fmt(_read(raw, ['domain_name', 'domain']) or domain),
            'org': _fmt(_read(raw, ['org', 'organization', 'registrant_organization'])),
            'name': _fmt(_read(raw, ['name', 'registrant_name'])),
            'emails': _fmt(_read(raw, ['emails', 'email', 'registrant_email'])),
            'registrar': _fmt(_read(raw, ['registrar', 'sponsoring_registrar'])),
            'status': _fmt(_read(raw, ['status'])),
            'created': _fmt(_read(raw, ['creation_date', 'created', 'created_date'])),
            'expires': _fmt(_read(raw, ['expiration_date', 'expires', 'expiry_date'])),
            'updated': _fmt(_read(raw, ['updated_date', 'updated', 'modified_date'])),
            'name_servers': _fmt(_read(raw, ['name_servers', 'nameservers', 'nserver'])),
            'dnssec': _fmt(_read(raw, ['dnssec'])),
            'country': _fmt(_read(raw, ['country', 'registrant_country'])),
            'city': _fmt(_read(raw, ['city', 'registrant_city'])),
            'state': _fmt(_read(raw, ['state', 'registrant_state', 'province'])),
            'postal': _fmt(_read(raw, ['registrant_postal_code', 'postalcode', 'zip'])),
        }
        if _is_empty(parsed):
            # python-whois ничего полезного не достал (но и не упал) —
            # пробуем системный whois как fallback.
            fb = _fallback_whois_via_cli(domain)
            if fb and not _is_empty(fb):
                return {**parsed, **{k: v for k, v in fb.items()
                                     if v not in (None, '', '-')}}
        return parsed
    except Exception:
        # python-whois взорвался (типичный кейс — .kz из-за нестандартного
        # формата даты). Идём в CLI-fallback.
        fb = _fallback_whois_via_cli(domain)
        if fb and not _is_empty(fb):
            return {**defaults, **{k: v for k, v in fb.items()
                                   if v not in (None, '', '-')}}
        return defaults


def batch_lines(file_path, batch_size=5000):
    with open(file_path) as f:
        batch = []
        for line in f:
            line = line.strip()
            if not line or '*' in line or '@' in line:
                continue
            batch.append(line)
            if len(batch) >= batch_size:
                yield batch
                batch = []
        if batch:
            yield batch


def get_crtsh_subdomains(domain):
    try:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        resp = requests.get(url, timeout=10, verify=False)
        if resp.status_code != 200:
            return []
        data = resp.json()
        subs = set()
        for item in data:
            for n in item['name_value'].split('\n'):
                if domain in n:
                    subs.add(n.strip())
        return list(subs)
    except Exception:
        return []


def get_chaos_subdomains(domain):
    try:
        if subprocess.call(["which", "chaos-client"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) != 0:
            return []
        key = os.getenv("PDCP_API_KEY")
        cmd = ["chaos-client", "-d", domain]
        if key:
            cmd.insert(1, f"-key={key}")
        result = subprocess.run(cmd, capture_output=True, text=True)
        return [l.strip() for l in result.stdout.splitlines() if l.strip() and not l.startswith("[")]
    except Exception:
        return []


def resolve(domain: str):
    try:
        return socket.gethostbyname(domain)
    except Exception:
        return None


# --------- Fast port scan (concurrent) ---------

def _probe_port(ip: str, port: int) -> str | None:
    try:
        with socket.create_connection((ip, port), PORT_CONNECT_TIMEOUT):
            if port == 445:
                return "📁"
            if port in (22, 3389, 5985):
                return "🖥️"
            if port == 21:
                return "📂"
            if port == 80:
                return "80🔓"
            if port == 443:
                try:
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    with ctx.wrap_socket(socket.socket(), server_hostname=ip) as ss:
                        ss.settimeout(TLS_HANDSHAKE_TIMEOUT)
                        ss.connect((ip, 443))
                        _ = ss.getpeercert(False)
                    return "443🔒"
                except ssl.SSLError:
                    return "443🔓"
                except Exception:
                    return "443⚠️"
            return str(port)
    except Exception:
        return None


def scan_ports(ip: str, full: bool = False) -> list[str]:
    ports = (range(1, 65536) if full else DEFAULT_PORTS)
    workers = PORT_WORKERS_FULL if full else PORT_WORKERS_DEFAULT
    out = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(_probe_port, ip, p): p for p in ports}
        for fut in concurrent.futures.as_completed(futs):
            res = fut.result()
            if res:
                out.append(res)
    def _key(v: str):
        try:
            return (0, int(''.join(ch for ch in v if ch.isdigit())))
        except ValueError:
            return (1, v)
    return sorted(out, key=_key)


def check_alive(domain: str) -> str:
    try:
        r = requests.get(f"https://{domain}", timeout=HTTP_TIMEOUT, verify=False)
        if r.status_code in (200, 301, 302, 403):
            return '✅'
        if r.status_code >= 500:
            return '❌'
        return '⚠️'
    except Exception:
        try:
            r = requests.get(f"http://{domain}", timeout=HTTP_TIMEOUT, verify=False)
            if r.status_code in (200, 301, 302, 403):
                return '✅'
            if r.status_code >= 500:
                return '❌'
            return '⚠️'
        except Exception:
            return '❌'


def detect_tech(domain):
    try:
        resp = requests.get(f"https://{domain}", timeout=HTTP_TIMEOUT, verify=False)
        server = resp.headers.get('Server', '-')
        powered = resp.headers.get('X-Powered-By', '-')
        techs = set(filter(lambda t: t and t != '-' and t.lower() != 'unknown', [server, powered]))
        return ', '.join(techs) or '-'
    except Exception:
        return '-'


def detect_waf(domain):
    try:
        resp = requests.get(f"https://{domain}", timeout=HTTP_TIMEOUT, verify=False)
        headers = resp.headers
        cookies = resp.cookies.get_dict()
        if 'cloudflare' in headers.get('Server', '').lower():
            return 'Cloudflare'
        elif 'cookiesession1' in cookies:
            return 'FortiWeb'
        else:
            return '-'
    except Exception:
        return '-'


def _ip_whois(ip: str) -> dict:
    """Возвращает {'ip', 'range', 'owner'} для IP. Приватные RFC1918 помечает явно."""
    try:
        first = int(ip.split('.', 1)[0])
        second = int(ip.split('.', 2)[1])
        if first == 10:
            return {'ip': ip,
                    'range': '10.0.0.0 - 10.255.255.255',
                    'owner': 'PRIVATE-ADDRESS-ABLK-RFC1918-IANA-RESERVED'}
        if first == 172 and 16 <= second <= 31:
            return {'ip': ip,
                    'range': '172.16.0.0 - 172.31.255.255',
                    'owner': 'PRIVATE-ADDRESS-BBLK-RFC1918-IANA-RESERVED'}
        if first == 192 and second == 168:
            return {'ip': ip,
                    'range': '192.168.0.0 - 192.168.255.255',
                    'owner': 'PRIVATE-ADDRESS-CBLK-RFC1918-IANA-RESERVED'}
    except (ValueError, IndexError):
        pass
    try:
        data = IPWhois(ip).lookup_rdap(depth=1)
        net = data.get('network') or {}
        cidr = net.get('cidr') or '-'
        owner = net.get('name') or data.get('asn_description') or '-'
        return {'ip': ip, 'range': cidr, 'owner': owner}
    except Exception:
        return {'ip': ip, 'range': '-', 'owner': '-'}


def _collect_ip_whois(ips: list[str], workers: int = 16) -> list[dict]:
    """Параллельный WHOIS по списку IP — порядок сохраняется."""
    if not ips:
        return []
    results = [None] * len(ips)
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(_ip_whois, ip): i for i, ip in enumerate(ips)}
        for fut in concurrent.futures.as_completed(futs):
            i = futs[fut]
            try:
                results[i] = fut.result()
            except Exception:
                results[i] = {'ip': ips[i], 'range': '-', 'owner': '-'}
    return [r for r in results if r is not None]


def export_results(
    output_path: str,
    domain: str,
    results: list[dict],
    sources: dict[str, set[str]],
    mail_report=None,
    whois_info: dict | None = None,
):
    """Складывает все артефакты в одну папку в стиле скрипта anton.sh.

    Структура:
        <output_path>/
            all_subdomains.txt   — все уникальные сабдомены
            crtsh_subs.txt       — из crt.sh
            chaos_subs.txt       — из chaos-client (если был)
            brute_subs.txt       — из wordlist + fallback list
            alive_subdomains.txt — только живые (ответили 200/301/302/403)
            sub_ip_map.txt       — sub <TAB> ip
            unique_ips.txt       — уникальные IP резолва
            target_networks.txt  — уникальные WHOIS-диапазоны "Range | Owner"
            whois_report.txt     — per-IP WHOIS строки
            mail_security.txt    — plain-text дамп блока Mail Security
            mail_security.json   — структурированный JSON
            dkim_found.txt       — Anton-style "<selector>._domainkey.<domain> : <txt>"
            summary.csv          — табличный сводный отчёт
            summary.json         — полный JSON c результатами сканирования
            domain_whois.json    — WHOIS основного домена
    """
    os.makedirs(output_path, exist_ok=True)

    def _write(name: str, content: str):
        with open(os.path.join(output_path, name), 'w', encoding='utf-8') as fh:
            fh.write(content)

    # --- subdomains by source ---
    for fname, src_key in (
        ('crtsh_subs.txt', 'crtsh'),
        ('chaos_subs.txt', 'chaos'),
        ('brute_subs.txt', 'brute'),
    ):
        subs = sorted(sources.get(src_key, set()))
        if subs:
            _write(fname, '\n'.join(subs) + '\n')

    all_subs = sorted({s for subs in sources.values() for s in subs})
    if all_subs:
        _write('all_subdomains.txt', '\n'.join(all_subs) + '\n')

    # --- alive + sub<->ip mapping ---
    alive_lines = [r['domain'] for r in results if r.get('alive') == '✅']
    if alive_lines:
        _write('alive_subdomains.txt', '\n'.join(sorted(alive_lines)) + '\n')

    sub_ip_lines = [
        f"{r['domain']}\t{r['ip_plain']}"
        for r in results if r.get('ip_plain') and r['ip_plain'] != '-'
    ]
    if sub_ip_lines:
        _write('sub_ip_map.txt', '\n'.join(sorted(sub_ip_lines)) + '\n')

    unique_ips = sorted({
        r['ip_plain'] for r in results
        if r.get('ip_plain') and r['ip_plain'] != '-'
    })
    if unique_ips:
        _write('unique_ips.txt', '\n'.join(unique_ips) + '\n')

    # --- WHOIS по каждому уникальному IP (параллельно, RDAP) ---
    ip_whois_rows = _collect_ip_whois(unique_ips) if unique_ips else []
    if ip_whois_rows:
        whois_lines = [
            f"IP: {r['ip']}\tДиапазон: {r['range']}\tВладелец: {r['owner']}"
            for r in ip_whois_rows
        ]
        _write('whois_report.txt', '\n'.join(whois_lines) + '\n')
        # Уникальные диапазоны
        net_set = sorted({f"Диапазон: {r['range']} | Владелец: {r['owner']}"
                          for r in ip_whois_rows if r['range'] != '-'})
        if net_set:
            _write('target_networks.txt', '\n'.join(net_set) + '\n')

    # --- Mail security артефакты ---
    if mail_report is not None:
        from .mail_security import (
            report_to_text, report_to_dict, dkim_found_lines,
        )
        _write('mail_security.txt', report_to_text(mail_report))
        with open(os.path.join(output_path, 'mail_security.json'), 'w',
                  encoding='utf-8') as jf:
            json.dump(report_to_dict(mail_report), jf, indent=2, ensure_ascii=False)
        dkim_lines = dkim_found_lines(mail_report)
        if dkim_lines:
            _write('dkim_found.txt', '\n'.join(dkim_lines) + '\n')

    # --- WHOIS основного домена ---
    if whois_info:
        with open(os.path.join(output_path, 'domain_whois.json'), 'w',
                  encoding='utf-8') as jf:
            json.dump(whois_info, jf, indent=2, ensure_ascii=False, default=str)

    # --- Сводные таблицы ---
    with open(os.path.join(output_path, 'summary.json'), 'w', encoding='utf-8') as jf:
        json.dump(results, jf, indent=2, ensure_ascii=False)
    with open(os.path.join(output_path, 'summary.csv'), 'w', newline='',
              encoding='utf-8') as cf:
        writer = csv.writer(cf)
        writer.writerow(['IP', 'Domain', 'Ports', 'Alive', 'Tech', 'WAF'])
        for row in results:
            writer.writerow([
                row.get('ip_plain', '-'), row['domain'], row.get('ports', '-'),
                row.get('alive', '-'), row.get('tech', '-'), row.get('waf', '-'),
            ])


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--domain', required=True)
    parser.add_argument('-w', '--wordlist')
    parser.add_argument(
        '-t', '--threads', type=int, default=RESOLVE_THREADS,
        help=f'Параллелизм для DNS-резолва сабдоменов (по умолчанию {RESOLVE_THREADS}).',
    )
    parser.add_argument('-f', '--full', action='store_true')
    parser.add_argument('-o', '--output')
    parser.add_argument('--debug', action='store_true')
    parser.add_argument('-v', '--version', action='version', version=f'%(prog)s {__version__}')
    # --- Mail security checks (SPF/DKIM/DMARC + MTA-STS, TLS-RPT, BIMI, DNSSEC,
    #     Open Relay, security.txt) -------------------------------------------
    parser.add_argument(
        '--no-mail', action='store_true',
        help='Отключить блок Mail Security (SPF/DKIM/DMARC и сопутствующие).',
    )
    parser.add_argument(
        '--mail-verbose', action='store_true',
        help='Показывать полные сырые записи SPF / DMARC / DKIM серым цветом.',
    )
    parser.add_argument(
        '--mail-relay', action='store_true',
        help=(
            'Активная проверка open SMTP relay по 25/tcp на каждом MX-хосте '
            '(делает реальное соединение).'
        ),
    )
    args = parser.parse_args()

    # Banner & header
    print_banner()
    console.print(f"[bold green][+] Starting at:[/] {datetime.now().strftime('%d.%m.%Y %H:%M')}")
    console.print("[bold green][+] Target:[/]", args.domain)

    domain = args.domain
    start_time = time.time()
    # Пользовательский -t переопределяет дефолт пула резолвера.
    resolve_threads = max(1, args.threads if args.threads else RESOLVE_THREADS)

    # WHOIS + hosting
    whois_info = get_whois_info(domain)
    ip_host, host_org, host_loc = get_hosting_info(domain)

    whois_panel = Panel(
        f"📛 [bold]{whois_info['domain']}[/]  🏢 [bold]{html.unescape(str(whois_info['org']))}[/]\n"
        f"🌐 IP: {ip_host} 🏢 Org: {host_org} 📍 Location: {host_loc}\n"
        f"📅 Created: {whois_info['created']}  ⌛ Expires: {whois_info['expires']}  🕑 Updated: {whois_info['updated']}\n"
        f"🌍 Registrar: {whois_info['registrar']}\n"
        f"🖥️ Name Servers: {whois_info['name_servers']}\n"
        f"👤 Name: {whois_info['name']}  📧 Email: {whois_info['emails']}\n"
        f"🔒 DNSSEC: {whois_info['dnssec']}\n"
        f"🌎 Country: {whois_info['country']}  🏙️ City: {whois_info['city']}  🏴 State: {whois_info['state']}  📮 Postal: {whois_info['postal']}",
        title="[bold cyan]WHOIS Info[/]",
        box=box.DOUBLE
    )
    console.print(whois_panel)

    # --- Mail security: SPF/DKIM/DMARC + MTA-STS/TLS-RPT/BIMI/DNSSEC,
    #     security.txt + (опц.) Open SMTP Relay -----------------------------
    mail_report = None
    if not args.no_mail:
        try:
            mail_report = analyze_mail_security(
                domain,
                verbose=args.mail_verbose,
                check_relay=args.mail_relay,
            )
            render_mail_security(console, mail_report)
        except Exception as e:
            if args.debug:
                console.print(f"[red]Mail security check failed: {e}[/]")
            mail_report = None

    # --- Subdomain sources (отдельно по источникам для последующего экспорта) -
    sources: dict[str, set[str]] = {
        'crtsh': set(get_crtsh_subdomains(domain)),
        'chaos': set(get_chaos_subdomains(domain)),
        'brute': set(),
    }

    if args.wordlist:
        try:
            total = sum(1 for _ in open(args.wordlist))
            console.print(f"[blue]Loaded wordlist with {total:,} entries. Processing in batches...[/]")
            for batch in batch_lines(args.wordlist, batch_size=5000):
                sources['brute'].update(f"{line}.{domain}" for line in batch)
        except Exception as e:
            if args.debug:
                console.print(f"[red]Error loading wordlist: {e}")

    sources['brute'].update(f"{s}.{domain}" for s in FALLBACK_SUBS)

    # Объединение для последующего резолва
    subdomains = sorted({
        s for subs in sources.values() for s in subs
        if s and not s.startswith("*") and '@' not in s
    })

    # Resolve (fast) & filter unroutable
    results = []
    with Progress() as progress:
        task = progress.add_task("[cyan]Scanning...", total=1)
        with concurrent.futures.ThreadPoolExecutor(max_workers=resolve_threads) as ex:
            futs = {ex.submit(resolve, s): s for s in subdomains}
            ip_map = {}
            for fut in concurrent.futures.as_completed(futs):
                sub = futs[fut]
                try:
                    ip = fut.result()
                    if ip:
                        ip_map[sub] = ip
                except Exception:
                    pass
        progress.update(task, total=len(ip_map))

        # port/tech checks for resolved only
        for sub, ip in sorted(ip_map.items(), key=lambda x: (x[1] or 'zzz', x[0])):
            progress.advance(task)
            ip_display = f"[red]{ip}[/]" if ip.startswith(('192.', '10.', '172.')) else ip
            open_ports = scan_ports(ip, full=args.full)
            alive = check_alive(sub)
            tech = detect_tech(sub)
            waf = detect_waf(sub)
            results.append({
                'ip': ip_display,
                'ip_plain': ip,
                'domain': sub,
                'ports': ', '.join(open_ports) or '-',
                'alive': alive,
                'tech': tech,
                'waf': waf
            })

    # Table
    table = Table(title="OpenRecon Summary", box=box.DOUBLE)
    table.add_column("IP")
    table.add_column("Domain")
    table.add_column("Ports")
    table.add_column("Alive")
    table.add_column("Tech")
    table.add_column("WAF")

    for row in results:
        table.add_row(row['ip'], row['domain'], row['ports'], row['alive'], row['tech'], row['waf'])

    console.print(table)

    # Exports — Anton-style layout: одна папка `recon_<domain>` со всеми артефактами
    if args.output:
        output_base = os.path.join(
            args.output,
            f"recon_{domain}_{datetime.now().strftime('%d.%m.%Y')}",
        )
        console.print(f"[bold blue][+] Saving artefacts to:[/] {output_base}")
        export_results(
            output_base, domain, results, sources,
            mail_report=mail_report, whois_info=whois_info,
        )

    elapsed = time.time() - start_time
    console.print(f"\n✅ [bold green]Scanning complete in[/] {int(elapsed // 60):02d}:{int(elapsed % 60):02d} ({len(results)}/{len(subdomains)} subdomains processed)")
    console.print("\n[bold yellow]Legend:[/] ✅ alive, ❌ not reachable, ⚠️ unstable; 🔒 valid HTTPS, 🔓 self-signed, ⚠️ insecure HTTP; 🖥️ RDP/SSH, 📁 SMB, 📂 FTP")


if __name__ == "__main__":
    try:
        console.show_cursor(True)
        main()
    except KeyboardInterrupt:
        console.print("[red]\n[!] Interrupted by user")
        sys.exit(0)
    finally:
        # гарантированно вернём курсор, даже если rich/progress оборвало
        try:
            console.show_cursor(True)
        except Exception:
            pass