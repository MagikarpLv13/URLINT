from __future__ import annotations

import argparse
import csv
import itertools
import json
import os
import platform
import re
import shutil
import socket
import subprocess
import sys
import threading
import time
import unicodedata
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from dataclasses import asdict, dataclass, field
from html.parser import HTMLParser
from typing import Iterable

import httpx

from .tld_presets import combine_groups, group_counts, unique_preserve_order


DEFAULT_TLDS = "fr,com,org,net,io,co,xyz,ai,dev,info,biz,eu"
DEFAULT_USER_AGENT = "URLINT-osint-light/1.0"
IANA_TLDS_URL = "https://data.iana.org/TLD/tlds-alpha-by-domain.txt"
MAX_TITLE_BYTES = 65536
MAX_CONSOLE_TITLE_CHARS = 120
PROGRESS_WIDTH = 20
MAX_TABLE_DOMAIN_CHARS = 42
MAX_TABLE_SERVER_CHARS = 28
MAX_TABLE_TITLE_CHARS = 70
MAX_TABLE_IP_CHARS = 36
THREAD_LOCAL = threading.local()
DEFAULT_STOPWORDS = {
    "a",
    "and",
    "au",
    "aux",
    "d",
    "de",
    "des",
    "du",
    "en",
    "et",
    "l",
    "la",
    "le",
    "les",
    "of",
    "pour",
    "sur",
    "the",
}


@dataclass(slots=True)
class HttpProbe:
    alive: bool = False
    protocol: str | None = None
    status_code: int | None = None
    title: str | None = None
    server: str | None = None
    content_type: str | None = None
    redirect: bool = False
    redirect_location: str | None = None
    error: str | None = None
    method: str | None = None


@dataclass(slots=True)
class DomainResult:
    domain: str
    classification: str = "unreachable"
    dns_resolves: bool = False
    ips: list[str] = field(default_factory=list)
    dns_error: str | None = None
    ping_alive: bool | None = None
    ping_error: str | None = None
    http_alive: bool = False
    protocol: str | None = None
    http_status: int | None = None
    title: str | None = None
    server: str | None = None
    content_type: str | None = None
    redirect: bool = False
    redirect_location: str | None = None
    http_error: str | None = None


class TitleParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self._in_title = False
        self._chunks: list[str] = []

    def handle_starttag(self, tag: str, attrs) -> None:
        if tag.lower() == "title":
            self._in_title = True

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "title":
            self._in_title = False

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self._chunks.append(data)

    @property
    def title(self) -> str | None:
        normalized = " ".join("".join(self._chunks).split())
        return normalized or None


def strip_accents(value: str) -> str:
    normalized = unicodedata.normalize("NFKD", value)
    return "".join(ch for ch in normalized if not unicodedata.combining(ch))


def normalize_keyword(value: str) -> str | None:
    value = strip_accents(value).lower()
    value = re.sub(r"[^a-z0-9-]+", "", value)
    value = value.strip("-")
    return value or None


def parse_tlds(raw_tlds: str) -> list[str]:
    return parse_tld_values(raw_tlds.split(","))


def parse_tld_values(raw_tlds: Iterable[str]) -> list[str]:
    tlds: list[str] = []
    seen: set[str] = set()
    for raw in raw_tlds:
        tld = raw.strip().lower().lstrip(".")
        if not re.fullmatch(r"[a-z0-9-]{2,63}", tld):
            continue
        if tld not in seen:
            seen.add(tld)
            tlds.append(tld)
    return tlds


def parse_csv_values(raw_values: str | None) -> list[str]:
    if not raw_values:
        return []
    return [value.strip() for value in raw_values.split(",") if value.strip()]


def parse_iana_tlds(text: str) -> list[str]:
    values: list[str] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        values.extend(line.split())
    return parse_tld_values(values)


def fetch_iana_tlds(timeout: float, user_agent: str) -> list[str]:
    headers = {"User-Agent": user_agent, "Accept": "text/plain,*/*;q=0.2"}
    response = httpx.get(
        IANA_TLDS_URL,
        headers=headers,
        timeout=timeout,
        follow_redirects=True,
    )
    response.raise_for_status()
    text = response.text
    return parse_iana_tlds(text)


def load_tlds_file(path: str) -> list[str]:
    with open(path, "r", encoding="utf-8") as handle:
        return parse_iana_tlds(handle.read())


def normalize_keywords(keywords: Iterable[str], keep_stopwords: bool) -> list[str]:
    words = [word for item in keywords if (word := normalize_keyword(item))]
    if keep_stopwords:
        return words
    return [word for word in words if word not in DEFAULT_STOPWORDS]


def parse_excluded_words(raw_words: str | None) -> set[str]:
    if not raw_words:
        return set()
    return {
        word
        for raw in raw_words.split(",")
        if (word := normalize_keyword(raw))
    }


def label_variants(words: tuple[str, ...]) -> list[str]:
    if len(words) == 1:
        return [words[0]]
    return ["".join(words), "-".join(words)]


def generate_domain_labels(
    keywords: Iterable[str],
    keep_stopwords: bool = False,
    include_combinations: bool = True,
    include_single_words: bool = True,
    excluded_single_words: set[str] | None = None,
) -> list[str]:
    words = normalize_keywords(keywords, keep_stopwords)
    if not words:
        return []
    excluded_single_words = excluded_single_words or set()

    word_groups: list[tuple[str, ...]] = []
    if include_combinations:
        # Longest groups first keeps the full phrase high-priority, then tries
        # useful subsets before single generic words.
        min_size = 1 if include_single_words else 2
        for size in range(len(words), min_size - 1, -1):
            word_groups.extend(itertools.combinations(words, size))
    else:
        if include_single_words or len(words) > 1:
            word_groups.append(tuple(words))

    seen: set[str] = set()
    labels: list[str] = []
    for group in word_groups:
        if len(group) == 1 and group[0] in excluded_single_words:
            continue
        for label in label_variants(group):
            if label and label not in seen and len(label) <= 63:
                seen.add(label)
                labels.append(label)
    return labels


def generate_domains(
    keywords: Iterable[str],
    tlds: Iterable[str],
    max_results: int | None,
    keep_stopwords: bool = False,
    include_combinations: bool = True,
    include_single_words: bool = True,
    excluded_single_words: set[str] | None = None,
) -> list[str]:
    domains: list[str] = []
    labels = generate_domain_labels(
        keywords,
        keep_stopwords,
        include_combinations,
        include_single_words,
        excluded_single_words,
    )
    for label in labels:
        for tld in tlds:
            domains.append(f"{label}.{tld}")
            if max_results is not None and len(domains) >= max_results:
                return domains
    return domains


def resolve_dns(domain: str) -> tuple[bool, list[str], str | None]:
    try:
        infos = socket.getaddrinfo(domain, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        return False, [], f"dns_error: {exc}"
    except OSError as exc:
        return False, [], f"dns_os_error: {exc}"

    ips = sorted({info[4][0] for info in infos if info and info[4]})
    return bool(ips), ips, None if ips else "no_ip_returned"


def ping_host(domain: str, timeout: float) -> tuple[bool | None, str | None]:
    ping_bin = shutil.which("ping")
    if not ping_bin:
        return None, "ping_not_available"

    system = platform.system().lower()
    if system == "windows":
        args = [ping_bin, "-n", "1", "-w", str(max(1, int(timeout * 1000))), domain]
    elif system == "darwin":
        args = [ping_bin, "-c", "1", "-W", str(max(1000, int(timeout * 1000))), domain]
    else:
        args = [ping_bin, "-c", "1", "-W", str(max(1, int(timeout))), domain]

    try:
        completed = subprocess.run(
            args,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout + 1,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return False, "ping_timeout"
    except OSError as exc:
        return None, f"ping_error: {exc}"

    return completed.returncode == 0, None if completed.returncode == 0 else "ping_no_reply"


def get_http_client(timeout: float, user_agent: str) -> httpx.Client:
    client_key = f"{timeout}:{user_agent}"
    cached_key = getattr(THREAD_LOCAL, "client_key", None)
    cached_client = getattr(THREAD_LOCAL, "client", None)
    if cached_client is not None and cached_key == client_key:
        return cached_client

    if cached_client is not None:
        cached_client.close()

    limits = httpx.Limits(max_connections=4, max_keepalive_connections=2)
    client = httpx.Client(
        headers={
            "User-Agent": user_agent,
            "Accept": "text/html,application/xhtml+xml,*/*;q=0.2",
            "Accept-Encoding": "identity",
            "Connection": "close",
        },
        timeout=httpx.Timeout(timeout),
        limits=limits,
        follow_redirects=False,
    )
    THREAD_LOCAL.client = client
    THREAD_LOCAL.client_key = client_key
    return client


def request_root(
    url: str,
    method: str,
    timeout: float,
    user_agent: str,
) -> tuple[int | None, httpx.Headers | None, bytes, str | None]:
    client = get_http_client(timeout, user_agent)
    try:
        with client.stream(method, url, timeout=timeout) as response:
            body = b""
            if method == "GET":
                chunks: list[bytes] = []
                total = 0
                for chunk in response.iter_bytes():
                    if not chunk:
                        continue
                    remaining = MAX_TITLE_BYTES - total
                    if remaining <= 0:
                        break
                    chunks.append(chunk[:remaining])
                    total += min(len(chunk), remaining)
                    if total >= MAX_TITLE_BYTES:
                        break
                body = b"".join(chunks)
            return response.status_code, response.headers, body, None
    except httpx.TimeoutException:
        return None, None, b"", "timeout"
    except httpx.ConnectError as exc:
        return None, None, b"", f"connect_error: {exc}"
    except httpx.TransportError as exc:
        return None, None, b"", f"transport_error: {exc}"
    except httpx.HTTPError as exc:
        return None, None, b"", f"http_error: {exc}"
    except OSError as exc:
        return None, None, b"", f"os_error: {exc}"


def close_thread_http_client() -> None:
    cached_client = getattr(THREAD_LOCAL, "client", None)
    if cached_client is not None:
        cached_client.close()
        THREAD_LOCAL.client = None


def is_html_content(content_type: str | None) -> bool:
    if not content_type:
        return False
    lowered = content_type.lower()
    return "text/html" in lowered or "application/xhtml+xml" in lowered


def extract_title(body: bytes, content_type: str | None) -> str | None:
    if not body:
        return None

    charset = "utf-8"
    if content_type:
        match = re.search(r"charset=([^\s;]+)", content_type, re.I)
        if match:
            charset = match.group(1).strip("\"'")

    try:
        text = body.decode(charset, errors="replace")
    except LookupError:
        text = body.decode("utf-8", errors="replace")

    parser = TitleParser()
    parser.feed(text)
    return parser.title


def probe_http(domain: str, timeout: float, user_agent: str) -> HttpProbe:
    last_error: str | None = None

    for protocol in ("https", "http"):
        url = f"{protocol}://{domain}/"
        status, headers, _body, error = request_root(url, "HEAD", timeout, user_agent)
        if error:
            last_error = error
            continue
        if status is None or headers is None:
            continue

        content_type = headers.get("Content-Type")
        redirect = 300 <= status < 400
        location = headers.get("Location") if redirect else None
        server = headers.get("Server")
        title = None
        method = "HEAD"

        should_get_title = (
            not redirect
            and status < 500
            and (is_html_content(content_type) or status in {403, 405})
        )
        if should_get_title:
            get_status, get_headers, body, get_error = request_root(url, "GET", timeout, user_agent)
            if get_error is None and get_status is not None and get_headers is not None:
                method = "GET"
                status = get_status
                headers = get_headers
                content_type = headers.get("Content-Type") or content_type
                server = headers.get("Server") or server
                redirect = 300 <= status < 400
                location = headers.get("Location") if redirect else location
                if is_html_content(content_type):
                    title = extract_title(body, content_type)
            elif get_error:
                last_error = get_error

        return HttpProbe(
            alive=True,
            protocol=protocol,
            status_code=status,
            title=title,
            server=server,
            content_type=content_type,
            redirect=redirect,
            redirect_location=location,
            method=method,
        )

    return HttpProbe(error=last_error or "http_unreachable")


def classify_result(dns_resolves: bool, ping_alive: bool | None, http: HttpProbe) -> str:
    if http.alive and http.title:
        return "web_site"
    if http.alive:
        return "http_alive"
    if ping_alive is True:
        return "ping_only"
    if dns_resolves:
        return "dns_only"
    return "unreachable"


def inspect_domain(
    domain: str,
    timeout: float,
    do_ping: bool,
    user_agent: str,
) -> DomainResult:
    dns_resolves, ips, dns_error = resolve_dns(domain)
    ping_alive: bool | None = None
    ping_error: str | None = None
    http = HttpProbe(error="skipped_no_dns")

    if dns_resolves:
        if do_ping:
            ping_alive, ping_error = ping_host(domain, timeout)
        http = probe_http(domain, timeout, user_agent)

    classification = classify_result(dns_resolves, ping_alive, http)
    return DomainResult(
        domain=domain,
        classification=classification,
        dns_resolves=dns_resolves,
        ips=ips,
        dns_error=dns_error,
        ping_alive=ping_alive,
        ping_error=ping_error,
        http_alive=http.alive,
        protocol=http.protocol,
        http_status=http.status_code,
        title=http.title,
        server=http.server,
        content_type=http.content_type,
        redirect=http.redirect,
        redirect_location=http.redirect_location,
        http_error=http.error,
    )


def result_to_row(result: DomainResult) -> dict[str, object]:
    row = asdict(result)
    row["ips"] = ",".join(result.ips)
    return row


def write_csv(path: str, results: list[DomainResult]) -> None:
    rows = [result_to_row(result) for result in results]
    fieldnames = list(rows[0].keys()) if rows else list(result_to_row(DomainResult("")).keys())
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def should_show_progress(args: argparse.Namespace) -> bool:
    if args.no_progress:
        return False
    if args.progress:
        return True
    return not args.json and sys.stderr.isatty()


def should_show_links(args: argparse.Namespace) -> bool:
    if args.no_links:
        return False
    return not args.json and sys.stdout.isatty()


def format_elapsed(seconds: float) -> str:
    seconds = max(0, int(seconds))
    minutes, secs = divmod(seconds, 60)
    hours, minutes = divmod(minutes, 60)
    if hours:
        return f"{hours:d}h{minutes:02d}m{secs:02d}s"
    if minutes:
        return f"{minutes:d}m{secs:02d}s"
    return f"{secs:d}s"


def render_progress(current: int, total: int, domain: str, start_time: float) -> None:
    if total <= 0:
        return
    terminal_width = shutil.get_terminal_size(fallback=(80, 24)).columns
    ratio = min(1.0, max(0.0, current / total))
    filled = int(PROGRESS_WIDTH * ratio)
    bar = "#" * filled + "-" * (PROGRESS_WIDTH - filled)
    percent = int(ratio * 100)
    elapsed = format_elapsed(time.monotonic() - start_time)
    prefix = f"[{bar}] {current}/{total} {percent:3d}% {elapsed:>8}"
    available_domain_chars = max(0, terminal_width - len(prefix) - 5)
    domain_part = truncate_console(domain, min(available_domain_chars, 40)) if available_domain_chars else ""
    message = f"{prefix} {domain_part}".rstrip()
    if len(message) >= terminal_width:
        message = message[: max(0, terminal_width - 1)]
    print(f"\r\x1b[2K{message}", end="", file=sys.stderr, flush=True)


def finish_progress() -> None:
    print(file=sys.stderr, flush=True)


def format_console_title(title: str | None) -> str:
    if not title:
        return "-"
    compact = " ".join(title.split())
    if len(compact) <= MAX_CONSOLE_TITLE_CHARS:
        return compact
    return compact[: MAX_CONSOLE_TITLE_CHARS - 1].rstrip() + "..."


def truncate_console(value: object, max_chars: int) -> str:
    text = "-" if value is None or value == "" else str(value)
    text = " ".join(text.split())
    if len(text) <= max_chars:
        return text
    if max_chars <= 3:
        return text[:max_chars]
    return text[: max_chars - 3].rstrip() + "..."


def result_console_url(result: DomainResult) -> str | None:
    if result.classification == "unreachable":
        return None
    protocol = result.protocol or "https"
    return f"{protocol}://{result.domain}/"


def terminal_hyperlink(label: str, url: str | None) -> str:
    if not url:
        return label
    # OSC 8 hyperlinks are ignored by unsupported terminals and keep JSON/CSV untouched.
    clean_url = url.replace("\033", "")
    clean_label = label.replace("\033", "")
    return f"\033]8;;{clean_url}\033\\{clean_label}\033]8;;\033\\"


def console_row(result: DomainResult, verbose: bool) -> dict[str, str]:
    code = result.http_status if result.http_status is not None else "-"
    row = {
        "domain": truncate_console(result.domain, MAX_TABLE_DOMAIN_CHARS),
        "_domain_url": result_console_url(result) or "",
        "type": result.classification,
        "proto": result.protocol or "-",
        "code": str(code),
        "server": truncate_console(result.server, MAX_TABLE_SERVER_CHARS),
        "title": truncate_console(format_console_title(result.title), MAX_TABLE_TITLE_CHARS),
    }
    if verbose:
        row["ip"] = truncate_console(",".join(result.ips) if result.ips else "-", MAX_TABLE_IP_CHARS)
        errors = "; ".join(e for e in (result.dns_error, result.ping_error, result.http_error) if e)
        row["errors"] = truncate_console(errors or "-", MAX_TABLE_TITLE_CHARS)
    return row


def print_table(rows: list[dict[str, str]], headers: list[tuple[str, str]], hyperlinks: bool) -> None:
    widths: dict[str, int] = {}
    for key, label in headers:
        widths[key] = max(len(label), *(len(row[key]) for row in rows))

    header_line = " | ".join(label.ljust(widths[key]) for key, label in headers)
    separator = "-+-".join("-" * widths[key] for key, _label in headers)
    print(header_line)
    print(separator)
    for row in rows:
        cells = []
        for key, _label in headers:
            cell = row[key].ljust(widths[key])
            if hyperlinks and key == "domain":
                cell = terminal_hyperlink(cell, row.get("_domain_url"))
            cells.append(cell)
        print(" | ".join(cells))


def print_text_summary(results: list[DomainResult], hyperlinks: bool) -> None:
    found_count = sum(1 for r in results if r.classification != "unreachable")

    noun = "RESULT" if found_count == 1 else "RESULTS"
    if found_count == 1:
        first = next(r for r in results if r.classification != "unreachable")
        domain = terminal_hyperlink(first.domain, result_console_url(first)) if hyperlinks else first.domain
        print(f"1 RESULT FOUND: {domain}")
    else:
        print(f"{found_count} {noun} FOUND")


def print_text_results(results: list[DomainResult], verbose: bool, hyperlinks: bool) -> None:
    visible = results if verbose else [r for r in results if r.classification != "unreachable"]
    print_text_summary(results, hyperlinks)
    if not visible:
        return

    print()
    headers = [
        ("domain", "Domain"),
        ("type", "Type"),
        ("proto", "Proto"),
        ("code", "Code"),
        ("server", "Server"),
        ("title", "Title"),
    ]
    if verbose:
        headers.extend([("ip", "IP"), ("errors", "Errors")])
    print_table([console_row(result, verbose) for result in visible], headers, hyperlinks)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="URLINT",
        description="Reconnaissance OSINT légère et défensive sur des domaines générés depuis des mots-clés.",
    )
    parser.add_argument("keywords", nargs="*", help="Mots-clés servant à générer les domaines.")
    parser.add_argument("--json", action="store_true", help="Afficher les résultats complets en JSON.")
    parser.add_argument("--csv", metavar="FICHIER.csv", help="Exporter les résultats complets en CSV.")
    parser.add_argument(
        "--tlds",
        default=None,
        help=f"Liste de TLD séparés par virgules. Défaut: {DEFAULT_TLDS}",
    )
    parser.add_argument(
        "--tld-groups",
        metavar="GROUPES",
        help="Groupes TLD prédéfinis séparés par virgules. Exemple: global_common,france_francophone",
    )
    parser.add_argument(
        "--list-tld-groups",
        action="store_true",
        help="Lister les groupes TLD prédéfinis disponibles puis quitter.",
    )
    parser.add_argument(
        "--iana-tlds",
        action="store_true",
        help="Tester tous les TLDs actuellement autorisés par l'IANA. Mode le plus complet et le plus gourmand.",
    )
    parser.add_argument(
        "--tlds-file",
        metavar="FICHIER",
        help="Charger les TLDs depuis un fichier local de type tlds-alpha-by-domain.txt.",
    )
    parser.add_argument("--timeout", type=float, default=3.0, help="Timeout réseau par opération, en secondes.")
    parser.add_argument("--delay", type=float, default=0.0, help="Délai entre domaines testés, en secondes.")
    parser.add_argument(
        "--max-results",
        type=int,
        default=None,
        help="Nombre maximal de domaines candidats. Par défaut: aucune limite.",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=4,
        help="Nombre de domaines testés en parallèle. Défaut: 4.",
    )
    parser.add_argument("--no-ping", action="store_true", help="Désactiver le test ICMP ping.")
    parser.add_argument(
        "--no-combinations",
        action="store_true",
        help="Désactiver les sous-combinaisons et ne tester que la phrase complète.",
    )
    parser.add_argument(
        "--keep-stopwords",
        action="store_true",
        help="Conserver les mots de liaison comme 'et', 'de', 'la'.",
    )
    parser.add_argument(
        "--no-single-words",
        action="store_true",
        help="Ne pas générer de domaines à partir d'un seul mot isolé.",
    )
    parser.add_argument(
        "--exclude-words",
        metavar="MOTS",
        help="Mots isolés à ne pas tester, séparés par virgules. Exemple: meilleure,artisanale",
    )
    parser.add_argument("--dry-run", action="store_true", help="Afficher les domaines générés sans requêtes réseau.")
    parser.add_argument(
        "--progress",
        action="store_true",
        help="Forcer la progression si le terminal n'est pas détecté automatiquement.",
    )
    parser.add_argument("--no-progress", action="store_true", help="Désactiver la barre de progression.")
    parser.add_argument("--no-links", action="store_true", help="Désactiver les liens cliquables en console.")
    parser.add_argument("--verbose", action="store_true", help="Afficher les domaines injoignables et les erreurs.")
    return parser


def validate_args(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    if not args.list_tld_groups and not args.keywords:
        parser.error("au moins un mot-clé est requis.")
    if args.timeout <= 0:
        parser.error("--timeout doit être strictement positif.")
    if args.delay < 0:
        parser.error("--delay ne peut pas être négatif.")
    if args.workers <= 0:
        parser.error("--workers doit être strictement positif.")
    if args.workers > 32:
        parser.error("--workers est limité à 32 pour rester léger.")
    if args.max_results is not None and args.max_results <= 0:
        parser.error("--max-results doit être strictement positif.")
    if args.iana_tlds and args.tlds_file:
        parser.error("--iana-tlds et --tlds-file sont mutuellement exclusifs.")
    if args.iana_tlds and args.tld_groups:
        parser.error("--iana-tlds et --tld-groups sont mutuellement exclusifs.")
    if args.tld_groups:
        try:
            combine_groups(*parse_csv_values(args.tld_groups))
        except (KeyError, ValueError) as exc:
            parser.error(str(exc))
    if args.progress and args.no_progress:
        parser.error("--progress et --no-progress sont mutuellement exclusifs.")
    if args.tlds is not None and not parse_tlds(args.tlds):
        parser.error("--tlds ne contient aucun TLD valide.")


def resolve_tlds(args: argparse.Namespace) -> list[str]:
    if args.iana_tlds:
        return fetch_iana_tlds(args.timeout, DEFAULT_USER_AGENT)

    selected: list[str] = []
    if args.tlds_file:
        selected.extend(load_tlds_file(args.tlds_file))
    if args.tld_groups:
        selected.extend(combine_groups(*parse_csv_values(args.tld_groups)))
    if args.tlds:
        selected.extend(parse_tlds(args.tlds))
    if not selected:
        selected.extend(parse_tlds(DEFAULT_TLDS))
    return unique_preserve_order(selected)


def inspect_domain_task(index: int, domain: str, args: argparse.Namespace) -> tuple[int, DomainResult]:
    result = inspect_domain(
        domain=domain,
        timeout=args.timeout,
        do_ping=not args.no_ping,
        user_agent=DEFAULT_USER_AGENT,
    )
    return index, result


def inspect_domains(domains: list[str], args: argparse.Namespace) -> list[DomainResult]:
    results: list[DomainResult | None] = [None] * len(domains)
    show_progress = should_show_progress(args)
    start_time = time.monotonic()
    completed = 0
    next_index = 0

    def process_finished(future: Future[tuple[int, DomainResult]]) -> None:
        nonlocal completed
        index, result = future.result()
        results[index] = result
        completed += 1
        if show_progress:
            render_progress(completed, len(domains), result.domain, start_time)
        if args.verbose:
            print(f"Done {result.domain}: {result.classification}", file=sys.stderr)

    def submit_next(
        executor: ThreadPoolExecutor,
        pending: dict[Future[tuple[int, DomainResult]], int],
    ) -> bool:
        nonlocal next_index
        if next_index >= len(domains):
            return False
        if next_index > 0 and args.delay:
            time.sleep(args.delay)
        domain = domains[next_index]
        if args.verbose:
            print(f"Queueing {domain}...", file=sys.stderr)
        future = executor.submit(inspect_domain_task, next_index, domain, args)
        pending[future] = next_index
        next_index += 1
        return True

    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        pending: dict[Future[tuple[int, DomainResult]], int] = {}
        while len(pending) < args.workers and submit_next(executor, pending):
            pass

        while pending:
            done, _not_done = wait(pending, return_when=FIRST_COMPLETED)
            for future in done:
                pending.pop(future)
                process_finished(future)
                submit_next(executor, pending)

        cleanup_futures = [executor.submit(close_thread_http_client) for _ in range(args.workers)]
        wait(cleanup_futures)

    if show_progress:
        finish_progress()

    return [result for result in results if result is not None]


def run(args: argparse.Namespace) -> int:
    if args.list_tld_groups:
        for name, count in group_counts():
            print(f"{name} ({count})")
        return 0

    try:
        tlds = resolve_tlds(args)
    except (OSError, TimeoutError, httpx.HTTPError, KeyError, ValueError) as exc:
        print(f"Impossible de charger les TLDs: {exc}", file=sys.stderr)
        return 2
    if not tlds:
        print("Aucun TLD valide chargé.", file=sys.stderr)
        return 2

    domains = generate_domains(
        args.keywords,
        tlds,
        args.max_results,
        keep_stopwords=args.keep_stopwords,
        include_combinations=not args.no_combinations,
        include_single_words=not args.no_single_words,
        excluded_single_words=parse_excluded_words(args.exclude_words),
    )
    if not domains:
        print("Aucun domaine candidat généré.", file=sys.stderr)
        return 2

    if args.verbose:
        print(f"{len(tlds)} TLDs chargés.", file=sys.stderr)
        print(f"{len(domains)} domaines candidats générés: {', '.join(domains)}", file=sys.stderr)

    if args.dry_run:
        for domain in domains:
            print(domain)
        return 0

    results = inspect_domains(domains, args)

    if args.csv:
        write_csv(args.csv, results)

    if args.json:
        print(json.dumps([asdict(result) for result in results], ensure_ascii=False, indent=2))
    else:
        print()
        print_text_results(results, args.verbose, should_show_links(args))
        if args.csv:
            print(f"\nCSV exporté: {os.path.abspath(args.csv)}")

    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    validate_args(args, parser)
    return run(args)


if __name__ == "__main__":
    raise SystemExit(main())
