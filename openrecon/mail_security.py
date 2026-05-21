"""
mail_security — анализ почтовой безопасности домена для OpenRecon.

Проверяет:
    MX [DNSSEC, MTA-STS, SMTP TLS-RPT, Open Relay]
    → SPF
    → DMARC [BIMI]
    → DKIM (перебор популярных селекторов)
    → security.txt (RFC 9116)

Использование из OpenRecon:
    from .mail_security import analyze_mail_security, render_mail_security

    report = analyze_mail_security(
        domain="target.tld", verbose=False, check_relay=False,
    )
    render_mail_security(console, report)

Зависимости: checkdmarc, dnspython, rich (все уже в requirements.txt OpenRecon).
"""
from __future__ import annotations

import concurrent.futures
import datetime as _dt
import smtplib
import socket
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any

import checkdmarc
import dns.resolver
from rich.console import Console
from rich.panel import Panel
from rich.text import Text


# --- DKIM селекторы для авто-перебора ----------------------------------------
# Список DNS-меток, по которым публикуются DKIM-записи. Селекторы — это
# часть полного имени `<selector>._domainkey.<domain>`. При необходимости
# расширяется параметром extra_dkim_selectors.
DEFAULT_DKIM_SELECTORS: tuple[str, ...] = (
    "default", "selector1", "selector2", "sel1", "sel2",
    "s1", "s2", "s1024", "s2048",
    "key", "key1", "key2", "k", "k1", "k2", "k3",
    "dk", "dkim", "dkim1", "dkim2", "dkim3", "dkim1024", "dkim2048",
    "smtp", "smtp1", "smtp2", "smtp3", "smtpapi", "smtpout",
    "mta", "mta1", "mta2", "mta3", "mtasv",
    "mail", "mailo",
    "20161025", "20210112", "20221208", "20230601",
    "a", "b", "c", "d", "m", "n", "o", "x", "y", "z",
    "1", "2", "3", "rs1", "rs2",
    "us", "eu", "apac", "emea", "cn", "jp", "uk", "ru", "kz", "de", "fr",
    "prod", "production", "staging", "stage", "dev", "test", "qa",
    "corporate", "corp", "mxvault", "mxmta", "mxsmtp",
    "office365", "ms", "ex", "exchange", "outlook",
    "google", "amazonses", "pm", "postmark", "mandrill",
    "zoho", "zohomail", "yandex", "mail-ru", "mailru",
    "mailjet", "mailgun",
    "mimecast", "mimecastsubdomain", "mc1", "mc2",
    "proofpoint", "pps", "pps1", "pps2", "ppemail1", "ppemail2",
    "cisco", "iport", "barracuda", "forcepoint",
    "protonmail", "protonmail1", "protonmail2", "protonmail3",
    "tutanota", "transip",
    "scph0316", "scph0922", "scph1019", "scph0316a",
    "everlytickey1", "everlytickey2",
    "fd", "fd1", "fd2",
    "tm1", "tm2",
    "litmus", "sg", "sendgrid",
)


# Компактные цветные иконки.
OK = "[bold green]✓[/]"
BAD = "[bold red]✕[/]"
WARN = "[bold yellow]![/]"
INFO = "[bold cyan]•[/]"

# Отступы для вложенных проверок.
_INDENT_BODY = "    "
_INDENT_CHILD = "  "


# --- Модель результата -------------------------------------------------------

@dataclass
class Finding:
    """Одна проверка: иконка + заголовок + детали + записи + рекомендация.

    Дочерние проверки (`children`) рендерятся с отступом под родителем —
    так SPF / DMARC / DKIM остаются отдельными блоками, а вспомогательные
    проверки (DNSSEC, MTA-STS и т.п.) логически прилипают к смежному блоку.
    """
    status: str  # "ok" | "bad" | "warn" | "info"
    title: str
    detail: str = ""
    recommendation: str = ""
    records: list[str] = field(default_factory=list)
    children: list["Finding"] = field(default_factory=list)

    def render(self, indent: str = "") -> Text:
        marker = {"ok": OK, "bad": BAD, "warn": WARN, "info": INFO}[self.status]
        body_indent = indent + _INDENT_BODY

        line = Text.from_markup(f"{indent}{marker} [bold]{self.title}[/]")
        if self.detail:
            line.append(" — ")
            line.append_text(Text.from_markup(self.detail))
        for rec in self.records:
            line.append(f"\n{body_indent}")
            line.append_text(Text.from_markup(rec))
        if self.recommendation:
            line.append(f"\n{body_indent}")
            line.append_text(Text.from_markup(
                f"[dim]→ Рекомендация:[/] {self.recommendation}"
            ))
        for child in self.children:
            line.append("\n")
            line.append_text(child.render(indent + _INDENT_CHILD))
        return line


@dataclass
class DomainReport:
    domain: str
    findings: list[Finding] = field(default_factory=list)
    error: str = ""
    # Сырые структурированные данные для последующего экспорта (JSON, txt).
    # Не используется в render — только для сериализации в файлы.
    metadata: dict[str, Any] = field(default_factory=dict)

    def add(self, f: Finding) -> None:
        self.findings.append(f)


# --- DKIM перебор ------------------------------------------------------------

def _probe_one_selector(
    resolver: dns.resolver.Resolver, domain: str, sel: str,
) -> tuple[str, str] | None:
    qname = f"{sel}._domainkey.{domain}"
    try:
        answers = resolver.resolve(qname, "TXT")
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
            dns.resolver.NoNameservers, dns.exception.Timeout):
        return None
    except Exception:
        return None
    for rdata in answers:
        txt = "".join(
            s.decode() if isinstance(s, bytes) else s for s in rdata.strings
        )
        if "v=DKIM1" in txt or "k=" in txt or "p=" in txt:
            return (sel, txt)
    return None


def probe_dkim(
    domain: str,
    selectors: tuple[str, ...],
    workers: int = 16,
) -> list[tuple[str, str]]:
    """Параллельный DNS-перебор DKIM-селекторов."""
    resolver = dns.resolver.Resolver()
    resolver.timeout = 2.0
    resolver.lifetime = 3.0
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        results = list(pool.map(
            lambda s: _probe_one_selector(resolver, domain, s),
            selectors,
        ))
    return [r for r in results if r is not None]


def dkim_record_valid(txt: str) -> tuple[bool, str]:
    has_p = False
    p_empty = False
    for part in txt.split(";"):
        part = part.strip()
        if part.startswith("p="):
            has_p = True
            if not part[2:].strip():
                p_empty = True
    if not has_p:
        return False, "отсутствует обязательный параметр p="
    if p_empty:
        return False, "параметр p= пустой (ключ отозван)"
    return True, ""


# --- Анализаторы (SPF / DMARC / DKIM / MX / ...) ----------------------------

def analyze_spf(spf: dict[str, Any], verbose: bool = False) -> Finding:
    record = spf.get("record")
    if not record:
        err = spf.get("error") or "SPF-запись не обнаружена"
        return Finding(
            status="bad", title="SPF",
            detail=f"не настроен ({err}).",
            recommendation=(
                "Добавить TXT-запись для апекса домена, например: "
                '`v=spf1 include:_spf.yourprovider.com -all`. '
                "Использовать жёсткий `-all` (а не `~all` или `?all`)."
            ),
        )

    records_field = [f'[dim]"{record}"[/]'] if verbose else []
    valid = bool(spf.get("valid"))
    warnings = spf.get("warnings") or []
    parsed = spf.get("parsed") or {}
    all_action = parsed.get("all", "fail")
    lookups = spf.get("dns_lookups", 0)

    problems: list[str] = []
    if all_action in ("pass", "neutral"):
        problems.append(
            f"механизм `all` имеет действие `{all_action}` (нужно `-all` или `~all`)"
        )
    if lookups and lookups > 10:
        problems.append(f"превышен лимит DNS-запросов (10): {lookups}")
    if warnings:
        problems.extend(
            w for w in warnings
            if "permitted" in w.lower() or "void" in w.lower() or "lookup" in w.lower()
        )

    if not valid or problems:
        problem_text = "; ".join(problems) if problems else "запись невалидна"
        return Finding(
            status="bad", title="SPF",
            detail=f"присутствует, но настроен не корректно ({problem_text}).",
            recommendation=(
                "Проверить параметр `include`, при необходимости заменить "
                "`?all`/`~all` на `-all`."
            ),
            records=records_field,
        )

    return Finding(
        status="ok", title="SPF",
        detail="присутствует и настроен корректно.",
        records=records_field,
    )


def analyze_dmarc(dmarc: dict[str, Any], domain: str, verbose: bool = False) -> Finding:
    record = dmarc.get("record")
    if not record:
        err = dmarc.get("error") or "DMARC-запись не обнаружена"
        return Finding(
            status="bad", title="DMARC",
            detail=f"политика отсутствует ({err}).",
            recommendation=(
                f'Настроить DNS-запись `_dmarc.{domain}`, например: '
                f'`v=DMARC1; p=reject; sp=reject; rua=mailto:abuse@{domain}`.'
            ),
        )

    tags = dmarc.get("tags") or {}
    p = (tags.get("p") or {}).get("value", "")
    sp_tag = tags.get("sp") or {}
    sp_value = sp_tag.get("value", "")
    sp_explicit = sp_tag.get("explicit", False)
    rua = (tags.get("rua") or {}).get("value")

    problems: list[str] = []
    if p == "none":
        problems.append("параметр `p` имеет значение `none` (политика не применяется)")
    elif p == "quarantine":
        problems.append("параметр `p` имеет значение `quarantine` (рекомендуется `reject`)")
    if not sp_explicit or sp_value in ("", "none"):
        problems.append(
            "параметр `sp` не задан явно или равен `none` — поддомены не защищены"
        )
    if not rua:
        problems.append("не указан `rua` (нет получателя агрегированных отчётов)")

    records_field = [f'[dim]"{record}"[/]'] if verbose else []

    if problems:
        return Finding(
            status="bad", title="DMARC",
            detail=f"обнаружен, но настроен не корректно ({'; '.join(problems)}).",
            recommendation=(
                f'Настроить DNS-запись `_dmarc.{domain}`, например: '
                f'`v=DMARC1; p=reject; sp=reject; rua=mailto:abuse@{domain}`. '
                "Параметр `sp` регулирует политику для доменов 3+ уровня."
            ),
            records=records_field,
        )

    return Finding(
        status="ok", title="DMARC",
        detail="присутствует и настроен корректно.",
        records=records_field,
    )


def _format_dkim_record(selector: str, txt: str, verbose: bool) -> str:
    if verbose:
        return f'[bold cyan]{selector}[/]: [dim]"{txt}"[/]'
    parts = []
    for part in txt.split(";"):
        part = part.strip()
        if part.startswith("p=") and len(part) > 64:
            parts.append(part[:60] + "…")
        elif part:
            parts.append(part)
    return f'[bold cyan]{selector}[/]: "{"; ".join(parts)}"'


def analyze_dkim(
    found: list[tuple[str, str]],
    selectors_tried: tuple[str, ...],
    domain: str,
    verbose: bool = False,
) -> Finding:
    header = (
        f"[dim][>] Брутфорс {len(selectors_tried)} популярных DKIM-селекторов…[/]"
    )

    if not found:
        return Finding(
            status="bad", title="DKIM",
            detail="не обнаружен ни по одному из известных селекторов.",
            recommendation=(
                f"Настроить DKIM-подпись у почтового провайдера и опубликовать "
                f"TXT-запись `<selector>._domainkey.{domain}`."
            ),
            records=[header],
        )

    valid_count = 0
    bad_reasons: list[str] = []
    selectors_list: list[str] = []
    records_text: list[str] = [header]
    for sel, txt in found:
        ok, reason = dkim_record_valid(txt)
        selectors_list.append(sel)
        marker = "[green]✓[/]" if ok else "[red]✗[/]"
        records_text.append(
            f"{marker} Найден селектор {_format_dkim_record(sel, txt, verbose)}"
        )
        if ok:
            valid_count += 1
        else:
            bad_reasons.append(f"`{sel}`: {reason}")

    selectors_text = ", ".join(f"`{s}`" for s in selectors_list)
    if valid_count == len(found):
        return Finding(
            status="ok", title="DKIM",
            detail=f"обнаружен и настроен корректно (селектор: {selectors_text}).",
            records=records_text,
        )

    return Finding(
        status="bad", title="DKIM",
        detail=f"обнаружен, но настроен не корректно ({'; '.join(bad_reasons)}).",
        recommendation=(
            "Сгенерировать новый DKIM-ключ и опубликовать корректную запись "
            "с непустым `p=`."
        ),
        records=records_text,
    )


def analyze_mx(mx: dict[str, Any]) -> Finding:
    hosts = mx.get("hosts") or []
    if not hosts:
        return Finding(
            status="warn", title="MX",
            detail="MX-записи не обнаружены — домен не принимает почту.",
        )

    # Готовим per-host строки с пометками TLS/STARTTLS, как чек-листы.
    record_lines: list[str] = []
    weak_hosts: list[str] = []   # без STARTTLS — критично
    no_tls_hosts: list[str] = [] # без TLS-сертификата на 25/tcp

    for h in hosts:
        host = h.get("hostname", "?")
        pref = h.get("preference", "?")
        has_tls = bool(h.get("tls"))
        has_starttls = bool(h.get("starttls"))

        tls_mark = "[green]✓ TLS[/]" if has_tls else "[red]✕ TLS[/]"
        ttls_mark = "[green]✓ STARTTLS[/]" if has_starttls else "[red]✕ STARTTLS[/]"
        record_lines.append(
            f"[bold]{pref}[/] [cyan]{host}[/]   {tls_mark}   {ttls_mark}"
        )

        if not has_starttls:
            weak_hosts.append(host)
        if not has_tls:
            no_tls_hosts.append(host)

    # Маленькая «легенда» что значат столбцы — для отчётов клиентам.
    record_lines.append(
        "[dim]TLS = валидный сертификат на 25/tcp · "
        "STARTTLS = сервер объявляет шифрование (EHLO → STARTTLS)[/]"
    )

    if weak_hosts:
        if len(weak_hosts) == len(hosts):
            detail = (
                f"обнаружено {len(hosts)} MX-хост(ов) — "
                f"ни один не поддерживает STARTTLS (почта передаётся открытым текстом)."
            )
        else:
            detail = (
                f"обнаружено {len(hosts)} MX-хост(ов) — "
                f"{len(weak_hosts)} без STARTTLS: "
                f"{', '.join(f'`{h}`' for h in weak_hosts)}."
            )
        return Finding(
            status="warn", title="MX",
            detail=detail,
            records=record_lines,
            recommendation=(
                "STARTTLS защищает SMTP-сессию от подслушивания и MITM по 25/tcp. "
                "Без него содержимое писем, заголовки и список получателей "
                "передаются открытым текстом по интернету. "
                "Включить в MTA: Postfix — `smtpd_tls_security_level=may` + "
                "`smtp_tls_security_level=may`; Exim — `tls_advertise_hosts=*`; "
                "MS Exchange — Receive Connector → Authentication → Transport "
                "Layer Security."
            ),
        )

    if no_tls_hosts:
        # STARTTLS объявлен, но валидный сертификат не получен
        detail = (
            f"обнаружено {len(hosts)} MX-хост(ов) — все объявляют STARTTLS, "
            f"но {len(no_tls_hosts)} без валидного сертификата: "
            f"{', '.join(f'`{h}`' for h in no_tls_hosts)}."
        )
        return Finding(
            status="warn", title="MX",
            detail=detail,
            records=record_lines,
            recommendation=(
                "STARTTLS работает, но сертификат на 25/tcp невалиден "
                "(self-signed, expired или несоответствие имени). "
                "Установить публичный сертификат от Let's Encrypt / коммерческого CA "
                "и проверить через `openssl s_client -starttls smtp -connect "
                "<host>:25 -servername <host>`."
            ),
        )

    # Всё ок
    detail = f"обнаружено {len(hosts)} MX-хост(ов) — STARTTLS включён на всех."
    return Finding(
        status="info", title="MX",
        detail=detail,
        records=record_lines,
    )


def analyze_mta_sts(mta_sts: dict[str, Any], domain: str) -> Finding:
    if mta_sts.get("valid"):
        return Finding(status="ok", title="MTA-STS",
                       detail="политика опубликована и валидна.")
    return Finding(
        status="warn", title="MTA-STS",
        detail="политика не опубликована.",
        recommendation=(
            f"Опубликовать TXT `_mta-sts.{domain}` и HTTPS-политику "
            f"`https://mta-sts.{domain}/.well-known/mta-sts.txt` для защиты от MITM."
        ),
    )


def analyze_tls_rpt(tls_rpt: dict[str, Any], domain: str) -> Finding:
    if tls_rpt.get("valid"):
        return Finding(status="ok", title="SMTP TLS Reporting",
                       detail="запись присутствует.")
    return Finding(
        status="warn", title="SMTP TLS Reporting",
        detail="запись отсутствует.",
        recommendation=(
            f'Опубликовать TXT `_smtp._tls.{domain}` со значением '
            f'`v=TLSRPTv1; rua=mailto:tls-reports@{domain}`.'
        ),
    )


def analyze_bimi(bimi: dict[str, Any]) -> Finding:
    if bimi.get("valid"):
        return Finding(status="ok", title="BIMI", detail="запись присутствует.")
    return Finding(
        status="info", title="BIMI",
        detail="запись отсутствует (опционально, требует DMARC p=quarantine/reject).",
    )


def analyze_dnssec(enabled: bool) -> Finding:
    if enabled:
        return Finding(status="ok", title="DNSSEC", detail="включён.")
    return Finding(
        status="warn", title="DNSSEC",
        detail="не включён.",
        recommendation=(
            "Подключить DNSSEC у регистратора/DNS-провайдера для защиты от "
            "DNS-спуфинга."
        ),
    )


# --- security.txt (RFC 9116) -------------------------------------------------

_SECURITY_TXT_PATHS = ("/.well-known/security.txt", "/security.txt")
_SECURITY_TXT_UA = "OpenRecon/1.x (security.txt RFC 9116 check)"


def _parse_security_txt(text: str) -> dict[str, list[str]]:
    fields: dict[str, list[str]] = {}
    in_pgp_block = False
    for raw in text.splitlines():
        line = raw.rstrip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("-----BEGIN PGP"):
            in_pgp_block = True
            continue
        if line.startswith("-----END PGP"):
            in_pgp_block = False
            continue
        if in_pgp_block:
            continue
        if ":" not in line:
            continue
        name, _, value = line.partition(":")
        name = name.strip().lower()
        value = value.strip()
        if name and value:
            fields.setdefault(name, []).append(value)
    return fields


def check_security_txt(domain: str, timeout: float = 5.0):
    last_error = "файл не найден"
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    for scheme in ("https", "http"):
        for path in _SECURITY_TXT_PATHS:
            url = f"{scheme}://{domain}{path}"
            try:
                req = urllib.request.Request(
                    url, headers={"User-Agent": _SECURITY_TXT_UA},
                )
                with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                    if 200 <= resp.status < 300:
                        body = resp.read(64 * 1024).decode("utf-8", errors="replace")
                        return (url, body, _parse_security_txt(body))
                    last_error = f"HTTP {resp.status} по {url}"
            except urllib.error.HTTPError as e:
                last_error = f"HTTP {e.code} по {url}"
            except (urllib.error.URLError, TimeoutError, ConnectionError, OSError) as e:
                last_error = f"{url} — {e}"
                continue
    return ("", last_error, {})


def analyze_security_txt(domain: str, timeout: float = 5.0) -> Finding:
    url, body_or_err, fields = check_security_txt(domain, timeout=timeout)

    if not url:
        return Finding(
            status="warn", title="security.txt",
            detail=f"файл отсутствует ({body_or_err}).",
            recommendation=(
                f"Опубликовать `https://{domain}/.well-known/security.txt` по RFC 9116. "
                f"Минимум: поля `Contact:` (mailto или URL), `Expires:` (ISO 8601, "
                f"не более 1 года). Файл должен отдаваться по HTTPS."
            ),
        )

    contacts = fields.get("contact", [])
    expires_list = fields.get("expires", [])
    encryption = fields.get("encryption", [])
    canonical = fields.get("canonical", [])
    preferred_languages = fields.get("preferred-languages", [])

    problems: list[str] = []
    if not url.startswith("https://"):
        problems.append("отдаётся не по HTTPS")
    if not contacts:
        problems.append("отсутствует обязательное поле `Contact`")
    if not expires_list:
        problems.append("отсутствует обязательное поле `Expires`")

    expires_dt: _dt.datetime | None = None
    if expires_list:
        raw_exp = expires_list[0]
        candidates = [
            raw_exp,
            raw_exp.replace("Z", "+00:00").replace("z", "+00:00"),
        ]
        for candidate in candidates:
            try:
                expires_dt = _dt.datetime.fromisoformat(candidate)
                break
            except ValueError:
                continue
        if expires_dt is None:
            problems.append(f"некорректный формат `Expires` (`{raw_exp}`)")
        else:
            now_utc = _dt.datetime.now(_dt.timezone.utc)
            if expires_dt.tzinfo is None:
                expires_dt = expires_dt.replace(tzinfo=_dt.timezone.utc)
            if expires_dt < now_utc:
                problems.append(f"срок действия истёк ({expires_dt:%Y-%m-%d})")

    body_lines: list[str] = [f"[dim]URL:[/] {url}"]
    if contacts:
        body_lines.append(f"[dim]Contact:[/] {', '.join(contacts)}")
    if expires_list:
        body_lines.append(f"[dim]Expires:[/] {expires_list[0]}")
    if encryption:
        body_lines.append(f"[dim]Encryption:[/] {encryption[0]}")
    if canonical:
        body_lines.append(f"[dim]Canonical:[/] {canonical[0]}")
    if preferred_languages:
        body_lines.append(f"[dim]Preferred-Languages:[/] {preferred_languages[0]}")

    if problems:
        return Finding(
            status="warn", title="security.txt",
            detail=f"найден, но с замечаниями: {'; '.join(problems)}.",
            records=body_lines,
            recommendation=(
                "Привести файл к требованиям RFC 9116: указать `Contact:` "
                "(mailto/URL), `Expires:` (ISO 8601, не более 1 года вперёд), "
                "отдавать по HTTPS."
            ),
        )

    return Finding(
        status="ok", title="security.txt",
        detail="присутствует и соответствует RFC 9116.",
        records=body_lines,
    )


# --- Open SMTP relay (активная проверка по 25/tcp) -------------------------

_RELAY_FROM = "test@relay-check.invalid"
_RELAY_TO = "relay-target@relay-check-external.invalid"
_RELAY_EHLO = "relay-check.invalid"


def check_open_relay(mx_host: str, timeout: float = 6.0) -> tuple[str, str]:
    try:
        smtp = smtplib.SMTP(mx_host, 25, timeout=timeout, local_hostname=_RELAY_EHLO)
    except (socket.timeout, TimeoutError):
        return ("timeout", f"таймаут подключения к {mx_host}:25")
    except (ConnectionRefusedError, OSError) as e:
        return ("no_connect", f"не удалось подключиться к {mx_host}:25 ({e})")
    except smtplib.SMTPException as e:
        return ("error", f"SMTP ошибка: {e}")

    try:
        code, _ = smtp.ehlo(_RELAY_EHLO)
        if code >= 400:
            code, _ = smtp.helo(_RELAY_EHLO)
            if code >= 400:
                return ("error", f"EHLO/HELO отклонён (код {code})")

        try:
            if smtp.has_extn("starttls"):
                smtp.starttls()
                smtp.ehlo(_RELAY_EHLO)
        except smtplib.SMTPException:
            pass

        code, msg = smtp.mail(_RELAY_FROM)
        if code >= 400:
            msg_text = msg.decode(errors="replace") if isinstance(msg, bytes) else str(msg)
            return ("no_mail", f"MAIL FROM отклонён (код {code}: {msg_text.strip()})")

        code, msg = smtp.rcpt(_RELAY_TO)
        msg_text = msg.decode(errors="replace") if isinstance(msg, bytes) else str(msg)
        msg_text = msg_text.strip()

        if 200 <= code < 300:
            return ("open", f"RCPT TO принят (код {code}: {msg_text})")
        if code in (530, 535):
            return ("auth", f"требуется авторизация (код {code}: {msg_text})")
        if 400 <= code < 600:
            return ("closed", f"RCPT отклонён (код {code}: {msg_text})")
        return ("error", f"неожиданный код ответа {code}: {msg_text}")
    except smtplib.SMTPException as e:
        return ("error", f"SMTP ошибка: {e}")
    finally:
        try:
            smtp.quit()
        except Exception:
            try:
                smtp.close()
            except Exception:
                pass


def analyze_relay_for_hosts(hosts: list[str], timeout: float = 6.0) -> Finding:
    if not hosts:
        return Finding(status="info", title="Open Relay",
                       detail="нет MX-хостов для проверки.")

    results: list[tuple[str, str, str]] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(4, len(hosts))) as pool:
        futures = {pool.submit(check_open_relay, h, timeout): h for h in hosts}
        for fut in concurrent.futures.as_completed(futures):
            host = futures[fut]
            try:
                status, detail = fut.result()
            except Exception as e:
                status, detail = ("error", str(e))
            results.append((host, status, detail))

    order = {h: i for i, h in enumerate(hosts)}
    results.sort(key=lambda r: order.get(r[0], 1_000_000))

    any_open = any(s == "open" for _, s, _ in results)
    any_no_connect = any(s in ("no_connect", "timeout") for _, s, _ in results)
    all_closed = all(s in ("closed", "auth", "no_mail") for _, s, _ in results)

    body_lines: list[str] = []
    for host, status, detail in results:
        if status == "open":
            mark = "[bold red]✕[/]"
        elif status in ("closed", "auth", "no_mail"):
            mark = "[green]✓[/]"
        else:
            mark = "[yellow]?[/]"
        body_lines.append(f"{mark} [bold]{host}[/] — {detail}")

    if any_open:
        return Finding(
            status="bad", title="Open Relay",
            detail="ОБНАРУЖЕН открытый SMTP relay — критическая уязвимость.",
            records=body_lines,
            recommendation=(
                "Запретить ретрансляцию писем для несаутентифицированных клиентов. "
                "В Postfix — `smtpd_relay_restrictions = permit_mynetworks, "
                "permit_sasl_authenticated, reject_unauth_destination`. "
                "В Exim/MS Exchange — закрыть anonymous relay по аналогии."
            ),
        )
    if all_closed:
        return Finding(
            status="ok", title="Open Relay",
            detail="ретрансляция запрещена на всех MX-хостах.",
            records=body_lines,
        )
    if any_no_connect:
        return Finding(
            status="warn", title="Open Relay",
            detail=(
                "не удалось подключиться по 25/tcp хотя бы к одному MX "
                "(возможно, outbound 25 заблокирован провайдером)."
            ),
            records=body_lines,
        )
    return Finding(
        status="warn", title="Open Relay",
        detail="неоднозначный результат — см. ответы хостов ниже.",
        records=body_lines,
    )


# --- Публичный API -----------------------------------------------------------

def analyze_mail_security(
    domain: str,
    *,
    verbose: bool = False,
    check_relay: bool = False,
    relay_timeout: float = 6.0,
    extra_dkim_selectors: tuple[str, ...] = (),
) -> DomainReport:
    """Главный entry-point: возвращает структуру для рендера.

    Структура отчёта (порядок блоков):
        MX [DNSSEC, MTA-STS, SMTP TLS-RPT, Open Relay?] → SPF → DMARC [BIMI]
        → DKIM → security.txt
    """
    report = DomainReport(domain=domain)

    try:
        raw = checkdmarc.check_domains([domain])
        data = raw[0] if isinstance(raw, list) and raw else (raw or {})
    except Exception as e:
        report.error = f"checkdmarc упал: {e}"
        return report

    # Блок 1: MX и транспорт
    mx_data = data.get("mx") or {}
    mx_block = analyze_mx(mx_data)
    mx_block.children.append(analyze_dnssec(bool(data.get("dnssec"))))
    mx_block.children.append(analyze_mta_sts(data.get("mta_sts") or {}, domain))
    mx_block.children.append(analyze_tls_rpt(data.get("smtp_tls_reporting") or {}, domain))
    if check_relay:
        mx_hosts = [
            h.get("hostname", "") for h in (mx_data.get("hosts") or [])
            if h.get("hostname")
        ]
        mx_block.children.append(analyze_relay_for_hosts(mx_hosts, timeout=relay_timeout))
    report.add(mx_block)

    # Блок 2: SPF
    report.add(analyze_spf(data.get("spf") or {}, verbose=verbose))

    # Блок 3: DMARC + BIMI
    dmarc_block = analyze_dmarc(data.get("dmarc") or {}, domain, verbose=verbose)
    dmarc_block.children.append(analyze_bimi(data.get("bimi") or {}))
    report.add(dmarc_block)

    # Блок 4: DKIM
    selectors = tuple(dict.fromkeys((*extra_dkim_selectors, *DEFAULT_DKIM_SELECTORS)))
    dkim_found = probe_dkim(domain, selectors)
    report.add(analyze_dkim(dkim_found, selectors, domain, verbose=verbose))

    # Блок 5: security.txt — один HTTP-вызов, переиспользуем результат
    sec_url, sec_body_or_err, sec_fields = check_security_txt(domain)
    if not sec_url:
        report.add(Finding(
            status="warn", title="security.txt",
            detail=f"файл отсутствует ({sec_body_or_err}).",
            recommendation=(
                f"Опубликовать `https://{domain}/.well-known/security.txt` по RFC 9116. "
                f"Минимум: поля `Contact:` (mailto или URL), `Expires:` (ISO 8601, "
                f"не более 1 года). Файл должен отдаваться по HTTPS."
            ),
        ))
    else:
        report.add(_build_security_txt_finding(domain, sec_url, sec_fields))

    # --- Сохраняем сырые данные в metadata для экспорта в файлы --------
    report.metadata = {
        "mx_hosts": [
            {
                "preference": h.get("preference"),
                "hostname": h.get("hostname", ""),
                "addresses": h.get("addresses", []),
                "tls": h.get("tls"),
                "starttls": h.get("starttls"),
            }
            for h in (mx_data.get("hosts") or [])
        ],
        "dnssec": bool(data.get("dnssec")),
        "spf_record": (data.get("spf") or {}).get("record"),
        "spf_valid": (data.get("spf") or {}).get("valid"),
        "dmarc_record": (data.get("dmarc") or {}).get("record"),
        "dmarc_tags": (data.get("dmarc") or {}).get("tags"),
        "dkim_found": [{"selector": s, "record": t} for s, t in dkim_found],
        "dkim_selectors_tried": list(selectors),
        "mta_sts_valid": (data.get("mta_sts") or {}).get("valid", False),
        "smtp_tls_rpt_valid": (data.get("smtp_tls_reporting") or {}).get("valid", False),
        "bimi_valid": (data.get("bimi") or {}).get("valid", False),
        "security_txt_url": sec_url,
        "security_txt_fields": sec_fields,
    }

    return report


def _build_security_txt_finding(
    domain: str, url: str, fields: dict[str, list[str]],
) -> Finding:
    """Используется при двойном вызове check_security_txt, чтобы не дёргать HTTP
    дважды. Воссоздаёт логику analyze_security_txt() из готовых данных."""
    contacts = fields.get("contact", [])
    expires_list = fields.get("expires", [])
    encryption = fields.get("encryption", [])
    canonical = fields.get("canonical", [])
    preferred_languages = fields.get("preferred-languages", [])

    problems: list[str] = []
    if not url.startswith("https://"):
        problems.append("отдаётся не по HTTPS")
    if not contacts:
        problems.append("отсутствует обязательное поле `Contact`")
    if not expires_list:
        problems.append("отсутствует обязательное поле `Expires`")

    expires_dt: _dt.datetime | None = None
    if expires_list:
        raw_exp = expires_list[0]
        for candidate in (raw_exp, raw_exp.replace("Z", "+00:00").replace("z", "+00:00")):
            try:
                expires_dt = _dt.datetime.fromisoformat(candidate)
                break
            except ValueError:
                continue
        if expires_dt is None:
            problems.append(f"некорректный формат `Expires` (`{raw_exp}`)")
        else:
            now_utc = _dt.datetime.now(_dt.timezone.utc)
            if expires_dt.tzinfo is None:
                expires_dt = expires_dt.replace(tzinfo=_dt.timezone.utc)
            if expires_dt < now_utc:
                problems.append(f"срок действия истёк ({expires_dt:%Y-%m-%d})")

    body_lines: list[str] = [f"[dim]URL:[/] {url}"]
    if contacts:
        body_lines.append(f"[dim]Contact:[/] {', '.join(contacts)}")
    if expires_list:
        body_lines.append(f"[dim]Expires:[/] {expires_list[0]}")
    if encryption:
        body_lines.append(f"[dim]Encryption:[/] {encryption[0]}")
    if canonical:
        body_lines.append(f"[dim]Canonical:[/] {canonical[0]}")
    if preferred_languages:
        body_lines.append(f"[dim]Preferred-Languages:[/] {preferred_languages[0]}")

    if problems:
        return Finding(
            status="warn", title="security.txt",
            detail=f"найден, но с замечаниями: {'; '.join(problems)}.",
            records=body_lines,
            recommendation=(
                "Привести файл к требованиям RFC 9116: указать `Contact:` "
                "(mailto/URL), `Expires:` (ISO 8601, не более 1 года вперёд), "
                "отдавать по HTTPS."
            ),
        )
    return Finding(
        status="ok", title="security.txt",
        detail="присутствует и соответствует RFC 9116.",
        records=body_lines,
    )


def _finding_to_dict(f: Finding) -> dict[str, Any]:
    """Сериализует Finding (+ его children) в JSON-совместимый dict."""
    return {
        "status": f.status,
        "title": f.title,
        "detail": _strip_markup(f.detail),
        "recommendation": _strip_markup(f.recommendation),
        "records": [_strip_markup(r) for r in f.records],
        "children": [_finding_to_dict(c) for c in f.children],
    }


_MARKUP_RE = None  # lazy


def _strip_markup(s: str) -> str:
    """Убирает rich-разметку вида [bold red]...[/] из строки для plain-text/JSON."""
    global _MARKUP_RE
    if _MARKUP_RE is None:
        import re as _re
        _MARKUP_RE = _re.compile(r"\[/?[^\]]*\]")
    return _MARKUP_RE.sub("", s) if s else s


def report_to_dict(report: DomainReport) -> dict[str, Any]:
    """JSON-сериализуемая версия отчёта (для mail_security.json)."""
    return {
        "domain": report.domain,
        "error": report.error,
        "findings": [_finding_to_dict(f) for f in report.findings],
        "metadata": report.metadata,
    }


def _render_finding_text(f: Finding, indent: str = "") -> list[str]:
    """Plain-text сериализация Finding (без цвета, для mail_security.txt)."""
    mark = {"ok": "[+]", "bad": "[!]", "warn": "[?]", "info": "[i]"}[f.status]
    lines = [f"{indent}{mark} {f.title} — {_strip_markup(f.detail)}"]
    body_indent = indent + "      "
    for rec in f.records:
        lines.append(f"{body_indent}{_strip_markup(rec)}")
    if f.recommendation:
        lines.append(f"{body_indent}-> {_strip_markup(f.recommendation)}")
    for child in f.children:
        lines.extend(_render_finding_text(child, indent + "  "))
    return lines


def report_to_text(report: DomainReport) -> str:
    """Plain-text дамп для mail_security.txt — без rich-разметки."""
    if report.error:
        return f"Ошибка анализа {report.domain}: {report.error}\n"
    out: list[str] = [
        f"=== Mail Security · {report.domain} ===",
        "",
    ]
    for i, f in enumerate(report.findings):
        if i > 0:
            out.append("")
        out.extend(_render_finding_text(f))
    return "\n".join(out) + "\n"


def dkim_found_lines(report: DomainReport) -> list[str]:
    """Anton-style строки для dkim_found.txt:
    `<selector>._domainkey.<domain> : <txt>`."""
    domain = report.domain
    return [
        f'{rec["selector"]}._domainkey.{domain} : "{rec["record"]}"'
        for rec in report.metadata.get("dkim_found", [])
    ]


def render_mail_security(console: Console, report: DomainReport) -> None:
    """Печатает Panel с почтовой безопасностью в указанную rich.Console."""
    title = (
        f"[bold]Mail Security[/] · [bold cyan]{report.domain}[/]"
    )

    if report.error:
        console.print(Panel(
            Text.from_markup(f"{BAD} [bold]Ошибка анализа:[/] {report.error}"),
            title=title, border_style="red", padding=(0, 1),
        ))
        return

    body = Text()
    for i, f in enumerate(report.findings):
        if i > 0:
            body.append("\n\n")
        body.append_text(f.render())

    console.print(Panel(body, title=title, border_style="cyan", padding=(1, 2)))
