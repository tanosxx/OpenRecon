
# 🛰️ OpenRecon — Asynchronous Reconnaissance Toolkit

```
┌─ OpenRecon v1.2.0  ·  Asynchronous Recon Toolkit  ·  by @clevergod
└─ subdomains · ports · TLS · WAF · WHOIS · mail security · security.txt
```

**OpenRecon** is a high-performance asynchronous reconnaissance tool for rapid
subdomain enumeration, port scanning, CDN/WAF detection, WHOIS profiling and
**mail-security audit** (SPF, DKIM, DMARC, MTA-STS, TLS-RPT, BIMI, DNSSEC,
Open SMTP Relay, `security.txt` per RFC 9116).

![screenshot](images/OpenRecon.png)

---

## ✅ Features

### Recon core
- 🔎 Subdomain enumeration via crt.sh + Chaos + wordlist + fallback list
- 🌐 Multi-port scanning (`80`, `443`, `8080`, `8443`, `445`, `22`, `21`, …)
  with `-f` flag for full 1–65535
- 🔐 HTTPS certificate validation (🔒 valid, 🔓 self-signed, ⚠️ insecure HTTP)
- 🧱 WAF detection (Cloudflare, FortiWeb, …)
- 📡 Tech fingerprinting via headers (`Server`, `X-Powered-By`)
- 🌍 WHOIS + IP-hosting info per main domain
- 🧵 Multi-threaded resolution, port-scan and DNS probing

### Mail security audit (new in 1.1.0)
- ✓ **SPF** — record presence, `-all` enforcement, DNS-lookup limit
- ✓ **DMARC** — `p=`, `sp=`, `rua=` correctness with sub-domain protection
- ✓ **DKIM** — parallel bruteforce of 130+ common selectors (Microsoft 365,
  Google, regional `us/eu/kz`, vendor selectors, env-tagged, etc.)
- ✓ **MX + STARTTLS** transport health, **DNSSEC**, **MTA-STS**, **SMTP TLS-RPT**, **BIMI**
- ✓ **Open SMTP Relay** active probe (`--mail-relay`, opt-in)
- ✓ **`security.txt`** discovery & validation per RFC 9116 (Contact, Expires,
  HTTPS-served, etc.)
- Compact colored icons: green `✓` / red `✕` / yellow `!` / cyan `•`
- Records shown in dim gray under each block with `--mail-verbose`

### Output (new in 1.2.0)
With `-o <dir>` OpenRecon writes an Anton-style folder
`recon_<domain>_<DD.MM.YYYY>/` containing structured artefacts.

---

## ⚙️ Installation

### Recommended — `pipx`
```bash
pipx install git+https://github.com/cleverg0d/OpenRecon.git
```

### Manual
```bash
git clone https://github.com/cleverg0d/OpenRecon.git
cd OpenRecon
pip install -r requirements.txt
```

Upgrade:
```bash
pipx upgrade openrecon              # from registered git source
# или
pipx install --force /path/to/OpenRecon   # from local source
```

---

## 🚀 Usage

```bash
openrecon -d example.com
openrecon -d example.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
openrecon -d example.com -f -o ./out                       # full port-scan + export
openrecon -d example.com --mail-verbose --mail-relay       # detailed mail check + relay probe
openrecon -d example.com --no-mail                         # skip mail audit
```

### Flags

| Flag | Purpose |
|---|---|
| `-d, --domain DOMAIN` | Target domain (required) |
| `-w, --wordlist FILE` | Subdomain wordlist for brute enumeration |
| `-t, --threads N` | Resolver thread count (default `50`) |
| `-f, --full` | Full 1–65535 port scan (slower) |
| `-o, --output DIR` | Export Anton-style folder into `DIR/` |
| `--debug` | Verbose error logging |
| `-v, --version` | Print version |
| `--no-mail` | Disable Mail Security block |
| `--mail-verbose` | Show full raw SPF / DMARC / DKIM records in gray |
| `--mail-relay` | Active open SMTP relay probe on each MX host (25/tcp) |

---

## 📁 Output layout (`-o ./out`)

```
out/
└── recon_example.com_22.05.2026/
    ├── all_subdomains.txt        # All unique subdomains found
    ├── crtsh_subs.txt            # From crt.sh
    ├── chaos_subs.txt            # From chaos-client (if installed + key)
    ├── brute_subs.txt            # From wordlist + fallback list
    ├── alive_subdomains.txt      # Subdomains with HTTP 200/301/302/403
    ├── sub_ip_map.txt            # subdomain<TAB>ip
    ├── unique_ips.txt            # Unique resolved IPs
    ├── whois_report.txt          # IP<TAB>range<TAB>owner (RDAP)
    ├── target_networks.txt       # Deduped "range | owner" lines
    ├── mail_security.txt         # Plain-text Mail Security dump
    ├── mail_security.json        # Structured Mail Security JSON
    ├── dkim_found.txt            # <selector>._domainkey.<domain> : "<txt>"
    ├── domain_whois.json         # Main domain WHOIS
    ├── summary.csv               # IP/Domain/Ports/Alive/Tech/WAF table
    └── summary.json              # Full results JSON
```

The layout matches the Anton recon style and is directly consumable by
downstream tools / report generators.

---

## 🔬 Mail Security details

For each domain OpenRecon prints a single panel with checks nested logically:

```
• MX — 10 mail.example.com
  ✓ DNSSEC — включён.
  ! MTA-STS — политика не опубликована.   → recommendation…
  ! SMTP TLS Reporting — запись отсутствует.   → recommendation…

✓ SPF — присутствует и настроен корректно.

✕ DMARC — обнаружен, но настроен не корректно (sp=none).   → recommendation…
  • BIMI — запись отсутствует.

✕ DKIM — обнаружен, но настроен не корректно (mail: p= пустой).
    [>] Брутфорс 130+ популярных DKIM-селекторов…
    ✗ Найден селектор mail: "v=DKIM1; k=rsa; p="
    → recommendation…

! security.txt — файл отсутствует (HTTP 404).   → recommendation…
```

- **Without `--mail-verbose`** raw records are hidden, only verdicts and
  recommendations are shown.
- **With `--mail-verbose`** the actual SPF / DMARC / DKIM TXT records are
  printed in dim gray under each block for client reports.
- **With `--mail-relay`** OpenRecon also opens a real SMTP session on `25/tcp`
  to every MX host and tries to relay a message with sender / recipient on
  the reserved `.invalid` TLD (safe — no actual delivery is possible).

---

## 🧠 Author

Stanislav Istyagin ([@clevergod](https://t.me/clevergod))
Cybersecurity Expert · Red Teamer · SOC Analyst

## 📜 License

MIT License
