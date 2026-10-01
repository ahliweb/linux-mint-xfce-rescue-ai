"""Printer detection: USB printers on this PC, the CUPS/IPP state of their queues, opt-in local-link
network printers, and the print spooler of an installed OS (read-only).

Managed by ahlikoding.com and satpamsiber.com under ahliweb.com.
Owned by ahliweb/linux-mint-xfce-rescue-ai#57. Contract: scripts/rescue_modules/__init__.py and
docs/printer.md. USB enumeration (class 07 interfaces, port path, speed, ACPI location) comes from
usb_devices.py.

Two entry points:

  * the live-system functions (``Tools``, ``discover``, ``printer_checks``) are used by
    scripts/scan-printers.py. They look at printers attached to the machine that runs the scan.
  * ``collect_offline_target`` is the registry hook (``rescue_modules.DOMAINS``): stuck spool files and
    the print service of an installed OS mounted read-only by scripts/scan-target-os.py.

Read-only. The only commands are FIXED argv tuples:

  lpstat -r | -p | -v | -a | -o        CUPS queue state (no queue is created, enabled, paused or cancelled)
  ipptool -T N -c URI TESTFILE         one IPP Get-Printer-Attributes request from scripts/lib/ipp/
  avahi-browse -rtp _ipp._tcp|_ipps._tcp   only when the operator opted in to network discovery

Why ipptool and not a hand-written IPP client: IPP is a binary protocol; ipptool is the CUPS project's own
client, takes a fixed declarative request file (which asks only for the attributes the checks need, never a
name, URI or serial) and prints a small CSV that is parsed against an allowlist. A Python IPP encoder would be
new parsing code on data from an untrusted peer. Without ipptool the module degrades to ``lpstat`` and
reports every IPP-derived check as ``unknown``.

Safety properties:

  * the only variable argv element is the IPP URI, and it is built here from validated parts: a local CUPS
    queue name that matches ``[A-Za-z0-9._-]``, a loopback ipp-usb port in 60000-65535, or (network opt-in
    only) a private/link-local address literal, a port and a path that match a strict pattern. A name or
    address from a peer is never passed through unchecked, never to a shell, and never starts with ``-``;
  * ``stdin`` is /dev/null, every call has a timeout, output is read with a size cap, ``LC_ALL=C``, a clean
    environment (no ``CUPS_SERVER``), no network except the opt-in mDNS browse and the follow-up IPP reads;
  * everything a printer, a queue or the LAN returns is untrusted data: it is parsed into closed-set states,
    bounded numbers and an allowlisted brand and then dropped. Queue names, device URIs, IP and MAC
    addresses, host names, serial numbers, job and user names, printer-info and location strings stay in
    memory (the ``_private`` key of a printer dict) and are never put in a check, an evidence file or the
    terminal. ``public_view`` is the only way out.
"""
import csv
import hashlib
import hmac
import ipaddress
import os
import re
import select
import shutil
import stat
import subprocess
import time
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit

from . import usb_devices

ROOT = Path(__file__).resolve().parents[2]
FIXED_PATH = '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'
TOOL_SEARCH_PATH = FIXED_PATH                       # test hook: tests point it at a shim directory
IPP_TEST = ROOT / 'scripts/lib/ipp/get-printer-attributes.test'
IPP_USB_STATE = Path('/var/ipp-usb/dev')            # test hook: ipp-usb state files (vendor-product-name.state)
FIB_TRIE = Path('/proc/net/fib_trie')               # test hook: local IPv4 addresses (own shared printers are skipped)

LPSTAT_TIMEOUT = 8                                  # seconds per lpstat call
IPP_TIMEOUT = 10                                    # seconds per ipptool call (ipptool -T is 6)
IPP_NETWORK_SECONDS = 6
AVAHI_TIMEOUT = 12
MAX_OUTPUT = 1024 * 1024                            # bytes read per call
MAX_PRINTERS = 8
MAX_NETWORK = 6
MAX_QUEUES = 64

CHECK_IDS = (
    'printer-state', 'printer-media', 'printer-door', 'printer-marker-supply', 'printer-offline',
    'printer-accepting-jobs', 'printer-queued-jobs', 'printer-marker-level-min', 'printer-usb-link',
    'printer-driver',
)

# Thresholds (documented in docs/printer.md)
MARKER_WARN_PERCENT, MARKER_FAIL_PERCENT = 15, 3
LOW_SPEED_MBPS = 12                                 # below this a printer link is a cable/port problem
MAX_HUB_DEPTH = 1                                   # more hubs in a chain than this is flaky for printers
SPOOL_STUCK_WARN = 1                                # any leftover spool file is a warning
MAX_SPOOL_COUNT = 10000

USB_PRINTER_CLASS = '07'
USB_PROTOCOLS = {'01': 'unidirectional', '02': 'bidirectional', '04': 'ipp-usb'}

# Brand allowlist: USB vendor ID, and the first word of the IPP printer-make-and-model (lowercase).
VENDOR_BRANDS = {
    '03f0': 'hp', '04a9': 'canon', '04b8': 'epson', '04f9': 'brother', '04e8': 'samsung', '0924': 'xerox',
    '043d': 'lexmark', '0482': 'kyocera', '05ca': 'ricoh', '132b': 'konica-minolta', '06bc': 'oki',
    '04dd': 'sharp', '232b': 'pantum', '04cb': 'fujifilm', '413c': 'dell', '0a5f': 'zebra',
}
MAKE_WORDS = {
    'hp': 'hp', 'hewlett-packard': 'hp', 'canon': 'canon', 'epson': 'epson', 'brother': 'brother',
    'samsung': 'samsung', 'xerox': 'xerox', 'lexmark': 'lexmark', 'kyocera': 'kyocera', 'ricoh': 'ricoh',
    'konica': 'konica-minolta', 'minolta': 'konica-minolta', 'oki': 'oki', 'sharp': 'sharp', 'pantum': 'pantum',
    'fuji': 'fujifilm', 'fujifilm': 'fujifilm', 'dell': 'dell', 'zebra': 'zebra',
}
BRANDS = tuple(sorted(set(VENDOR_BRANDS.values()))) + ('other',)

# IPP printer-state-reasons (RFC 8011 + PWG 5100.x): the keyword, optionally with a severity suffix
# (-error, -warning, -report; no suffix means error). Only keywords in this table affect a check.
MEDIA_JAM = frozenset({'media-jam'})
MEDIA_OUT = frozenset({'media-empty', 'media-needed', 'input-tray-missing', 'output-area-full',
                       'output-tray-missing'})
MEDIA_LOW = frozenset({'media-low', 'output-area-almost-full'})
DOOR_OPEN = frozenset({'door-open', 'cover-open', 'interlock-open'})
SUPPLY_EMPTY = frozenset({'toner-empty', 'ink-empty', 'marker-supply-empty', 'opc-life-over', 'marker-waste-full'})
SUPPLY_LOW = frozenset({'toner-low', 'ink-low', 'marker-supply-low', 'opc-near-eol', 'marker-waste-almost-full'})
OFFLINE = frozenset({'offline-report', 'connecting-to-device', 'shutdown', 'timed-out', 'other-offline'})
PAUSED = frozenset({'paused', 'moving-to-paused'})
KNOWN_REASONS = MEDIA_JAM | MEDIA_OUT | MEDIA_LOW | DOOR_OPEN | SUPPLY_EMPTY | SUPPLY_LOW | OFFLINE | PAUSED
SEVERITIES = ('error', 'warning', 'report')

CONSUMABLE_TYPES = frozenset({'toner', 'toner-cartridge', 'ink', 'ink-cartridge', 'ink-ribbon', 'ink-tank',
                              'developer', 'opc', 'solid-wax'})

STATE_NAMES = {'idle': 'idle', 'processing': 'processing', 'stopped': 'stopped',
               '3': 'idle', '4': 'processing', '5': 'stopped'}
QUEUE_RE = re.compile(r'^[A-Za-z0-9_][A-Za-z0-9._-]{0,126}$')
REASON_RE = re.compile(r'^[a-z0-9][a-z0-9-]{0,62}$')
TYPE_RE = re.compile(r'^[a-z][a-z0-9-]{0,31}$')
IPP_FIELDS = ('printer-state', 'printer-state-reasons', 'printer-is-accepting-jobs', 'queued-job-count',
              'marker-levels', 'marker-types', 'printer-make-and-model')
RP_RE = re.compile(r'^[A-Za-z0-9._~-]{1,64}(/[A-Za-z0-9._~-]{1,64}){0,3}$')
IPP_USB_NAME = re.compile(r'^([0-9a-f]{4})-([0-9a-f]{4})-', re.I)
IPP_USB_PORTS = (60000, 65535)


# ----------------------------------------------------------------------------- running tools

def _environment(search_path):
    env = {'PATH': search_path or TOOL_SEARCH_PATH, 'LC_ALL': 'C'}
    for key in ('HOME', 'USER', 'TMPDIR'):
        if os.environ.get(key):
            env[key] = os.environ[key]
    return env          # no CUPS_SERVER, no IPP_* variables: the tools talk to this machine only


def _bounded(argv, timeout, env):
    """(returncode, text) of one command with a deadline and an output cap, or None."""
    try:
        proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, env=env)
    except OSError:
        return None
    chunks, total, ok = [], 0, False
    deadline = time.monotonic() + timeout
    try:
        fd = proc.stdout.fileno()
        while True:
            left = deadline - time.monotonic()
            if left <= 0:
                break
            ready, _, _ = select.select([fd], [], [], min(left, 1.0))
            if not ready:
                continue
            data = os.read(fd, 65536)
            if not data:
                ok = True
                break
            total += len(data)
            if total > MAX_OUTPUT:
                break
            chunks.append(data)
        if ok:
            try:
                proc.wait(timeout=max(0.2, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                ok = False
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()
        proc.stdout.close()
    if not ok:
        return None
    return proc.returncode, b''.join(chunks).decode('utf-8', 'replace')


LPSTAT_FLAGS = ('-r', '-p', '-v', '-a', '-o')
AVAHI_SERVICES = ('_ipp._tcp', '_ipps._tcp')


class Tools:
    """The only way this module talks to CUPS, ipptool and avahi: fixed argv, bounded output."""

    def __init__(self, search_path=None):
        self.search_path = search_path or TOOL_SEARCH_PATH
        self.env = _environment(self.search_path)
        self.lpstat_path = shutil.which('lpstat', path=self.search_path)
        self.ipptool_path = shutil.which('ipptool', path=self.search_path)
        self.avahi_path = shutil.which('avahi-browse', path=self.search_path)

    def lpstat(self, flag):
        """Output text of ``lpstat <flag>`` (flag from LPSTAT_FLAGS), or None when it failed or timed out."""
        if self.lpstat_path is None or flag not in LPSTAT_FLAGS:
            return None
        res = _bounded([self.lpstat_path, flag], LPSTAT_TIMEOUT, self.env)
        if res is None or res[0] not in (0, 1):      # lpstat exits 1 when there is nothing to list
            return None
        return res[1]

    def ipp(self, uri):
        """Parsed Get-Printer-Attributes answer for *uri* (see ``parse_ipp_csv``), or None."""
        if self.ipptool_path is None or not valid_ipp_uri(uri) or not IPP_TEST.is_file():
            return None
        res = _bounded([self.ipptool_path, '-T', str(IPP_NETWORK_SECONDS), '-c', uri, str(IPP_TEST)],
                       IPP_TIMEOUT, self.env)
        if res is None or res[0] != 0:
            return None
        return parse_ipp_csv(res[1])

    def avahi(self, service):
        if self.avahi_path is None or service not in AVAHI_SERVICES:
            return None
        res = _bounded([self.avahi_path, '-rtp', service], AVAHI_TIMEOUT, self.env)
        if res is None or res[0] != 0:
            return None
        return res[1]


# ------------------------------------------------------------------------------------ parsing

def valid_queue(name):
    return isinstance(name, str) and bool(QUEUE_RE.match(name))


def valid_ipp_uri(uri):
    """Only URIs this module builds: a local queue, a loopback ipp-usb endpoint, or a private-link address."""
    if not isinstance(uri, str) or len(uri) > 200 or not uri.startswith(('ipp://', 'ipps://')):
        return False
    try:
        parts = urlsplit(uri)
        host, port = parts.hostname, parts.port
    except ValueError:
        return False
    if parts.query or parts.fragment or parts.username or parts.password or not host:
        return False
    if not re.match(r'^/[A-Za-z0-9._~/-]{0,128}$', parts.path or '/'):
        return False
    if host == 'localhost':
        return True
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return False
    return _lan_address(addr) and (port is None or 0 < port < 65536)


def _lan_address(addr):
    """Loopback, private or link-local only: a peer must not make this scan talk to the Internet."""
    if addr.is_multicast or addr.is_unspecified:
        return False
    if addr.version == 6:
        # unique-local fc00::/7 or loopback only (a link-local address needs a zone ID, which is not built here;
        # Python's is_private also covers documentation and other ranges that are not a LAN)
        return addr.is_loopback or addr in ipaddress.ip_network('fc00::/7')
    return addr.is_loopback or addr.is_private or addr.is_link_local


def parse_lpstat_printers(text):
    """{queue: 'idle'|'processing'|'stopped'} from ``lpstat -p``. Names stay with the caller (never output)."""
    out = {}
    for line in (text or '').splitlines():
        m = re.match(r'^printer (\S+) (is idle|now printing|is processing|disabled since|is stopped)', line)
        if not m or not valid_queue(m.group(1)) or len(out) >= MAX_QUEUES:
            continue
        what = m.group(2)
        out[m.group(1)] = 'idle' if what == 'is idle' else 'processing' if what in ('now printing', 'is processing') \
            else 'stopped'
    return out


def parse_lpstat_devices(text):
    """{queue: device URI} from ``lpstat -v``. The URI can carry a serial or an address: internal use only."""
    out = {}
    for line in (text or '').splitlines():
        m = re.match(r'^device for ([^\s:]+): (\S{1,512})$', line.strip())
        if m and valid_queue(m.group(1)) and len(out) < MAX_QUEUES:
            out[m.group(1)] = m.group(2)
    return out


def parse_lpstat_accepting(text):
    """{queue: bool} from ``lpstat -a``."""
    out = {}
    for line in (text or '').splitlines():
        m = re.match(r'^(\S+) (accepting|not accepting) requests since', line)
        if m and valid_queue(m.group(1)) and len(out) < MAX_QUEUES:
            out[m.group(1)] = m.group(2) == 'accepting'
    return out


def parse_lpstat_jobs(text):
    """{queue: count} from ``lpstat -o`` (``queue-N user size date``; user and date are dropped)."""
    out = {}
    for line in (text or '').splitlines()[:5000]:
        tokens = line.split()
        if not tokens:
            continue
        queue, _, number = tokens[0].rpartition('-')
        if queue and number.isdigit() and valid_queue(queue):
            out[queue] = min(out.get(queue, 0) + 1, 1000000)
    return out


def scheduler_running(text):
    return None if text is None else 'scheduler is running' in text


def classify_uri(uri):
    """What kind of path a CUPS device URI is: {'kind', 'serial', 'port', 'host'}; internal use only.

    kind: usb (usb:, hp:/usb, gutenprint+usb), ipp-usb (loopback ipp(s)/http on a 60000+ port), network
    (ipp, ipps, http, https, socket, lpd, dnssd, smb, bjnp, implicitclass, hp:/net, ...), virtual (a PDF or file
    queue: not a printer, skipped), other (parallel, serial, ...)."""
    try:
        parts = urlsplit(uri or '')
        port = parts.port
    except ValueError:
        return {'kind': 'other', 'serial': None, 'port': None, 'host': None}
    scheme = (parts.scheme or '').lower()
    host = (parts.hostname or '').lower() or None
    serial = (parse_qs(parts.query).get('serial') or [None])[0]
    path = (parts.path or '').lower()
    if scheme in ('', 'file', 'cups-pdf', 'cups-brf', 'pdf') or scheme.startswith('cups-'):
        kind = 'virtual'
    elif scheme in ('usb', 'gutenprint53+usb') or (scheme in ('hp', 'hpfax') and path.startswith('/usb')):
        kind = 'usb'
    elif scheme in ('ipp', 'ipps', 'http', 'https') and host in ('localhost', '127.0.0.1', '::1') \
            and port is not None and IPP_USB_PORTS[0] <= port <= IPP_USB_PORTS[1]:
        kind = 'ipp-usb'
    elif scheme in ('ipp', 'ipps', 'http', 'https', 'socket', 'lpd', 'dnssd', 'smb', 'bjnp', 'hp', 'hpfax',
                    'mdns', 'beh', 'implicitclass'):
        kind = 'network'
    else:
        kind = 'other'
    return {'kind': kind, 'serial': serial, 'port': port, 'host': host}


def brand_from_make(text):
    """Brand token from the first word of an IPP printer-make-and-model (the text itself is dropped)."""
    words = re.findall(r'[A-Za-z][A-Za-z-]*', (text or '')[:128])
    return MAKE_WORDS.get(words[0].lower(), 'other') if words else 'other'


def _int_list(cell, low, high, limit=32):
    out = []
    for token in (cell or '').split(',')[:limit]:
        token = token.strip()
        if not re.match(r'^-?[0-9]{1,4}$', token):
            return None
        value = int(token)
        out.append(value if low <= value <= high else -1)
    return out


def parse_ipp_csv(text):
    """Allowlisted fields of one ``ipptool -c`` answer, or None when there is no data row.

    Returns ``{'state', 'reasons', 'accepting', 'queued', 'levels', 'types', 'brand'}``; a field the printer did
    not provide, or provided in an unexpected shape, is None. ``printer-make-and-model`` is reduced to a brand
    token. Any other text is dropped."""
    lines = [ln for ln in (text or '').splitlines() if ln.strip()][:3]
    if len(lines) < 2 or any(len(ln) > 8192 for ln in lines[:2]):
        return None
    try:
        header = next(csv.reader([lines[0]]))
        row = next(csv.reader([lines[1]]))
    except (csv.Error, StopIteration):
        return None
    if len(header) != len(row) or any(h not in IPP_FIELDS for h in header):
        return None
    vals = dict(zip(header, row))
    state = STATE_NAMES.get((vals.get('printer-state') or '').strip().lower())
    reasons = None
    raw = (vals.get('printer-state-reasons') or '').strip().lower()
    if raw:
        reasons = [t.strip() for t in raw.split(',')[:32]]
        reasons = [t for t in reasons if REASON_RE.match(t) and t != 'none']
    accepting = {'true': True, 'false': False}.get((vals.get('printer-is-accepting-jobs') or '').strip().lower())
    queued = None
    if re.match(r'^[0-9]{1,7}$', (vals.get('queued-job-count') or '').strip()):
        queued = min(int(vals['queued-job-count']), 1000000)
    levels = _int_list(vals.get('marker-levels'), -3, 100)
    types = [t.strip().lower() for t in (vals.get('marker-types') or '').split(',')[:32] if t.strip()]
    if not types or not all(TYPE_RE.match(t) for t in types):
        types = None
    out = {'state': state, 'reasons': reasons, 'accepting': accepting, 'queued': queued, 'levels': levels,
           'types': types, 'brand': brand_from_make(vals.get('printer-make-and-model'))}
    if state is None and reasons is None and accepting is None and queued is None and levels is None:
        return None
    return out


def split_reason(token):
    """('media-jam', 'error') from ``media-jam-error``; no suffix means error (RFC 8011). A keyword that is itself
    in the table (``offline-report`` ends in a severity word but is a keyword of its own) is never split."""
    if token in KNOWN_REASONS:
        return token, 'error'
    for severity in SEVERITIES:
        if token.endswith('-' + severity):
            return token[:-len(severity) - 1], severity
    return token, 'error'


def reason_tokens(reasons):
    """Closed-set base keywords of the reasons that matter (for the operator table), sorted; no free text."""
    return tuple(sorted({split_reason(r)[0] for r in reasons or () if split_reason(r)[0] in KNOWN_REASONS}))


def marker_minimum(levels, types):
    """Lowest consumable level in percent (0..100), or None. Waste containers and unknown (-1/-2/-3) levels are
    ignored; without ``marker-types`` no level is trusted (a waste level of 100 means *full*)."""
    if not levels or not types or len(levels) != len(types):
        return None
    usable = [lv for lv, ty in zip(levels, types)
              if ty in CONSUMABLE_TYPES and 0 <= lv <= 100]
    return min(usable) if usable else None


def _avahi_unescape(text):
    """avahi-browse -p escapes bytes as ``\\DDD`` (a space is ``\\032``)."""
    return re.sub(r'\\([0-9]{3})', lambda m: chr(int(m.group(1))) if int(m.group(1)) < 256 else '?', text)


def parse_avahi(text):
    """Services from ``avahi-browse -rtp``: dicts {'scheme','address','port','rp','host','instance','iface',
    'brand'}. Only resolved (``=``) IPv4/IPv6 lines with a LAN address survive; the instance name, host and
    address are internal (matching and the opaque ID); the TXT make-and-model is reduced to a brand."""
    out = []
    for line in (text or '').splitlines()[:2000]:
        if not line.startswith('=;'):
            continue
        f = line.split(';')
        if len(f) < 10 or f[2] not in ('IPv4', 'IPv6'):
            continue
        iface, instance, stype, host, address, port = f[1], _avahi_unescape(f[3]), f[4], f[6], f[7], f[8]
        txt = ';'.join(f[9:])
        scheme = 'ipps' if stype == '_ipps._tcp' else 'ipp' if stype == '_ipp._tcp' else None
        try:
            addr = ipaddress.ip_address(address)
            port_n = int(port)
        except ValueError:
            continue
        if scheme is None or not 0 < port_n < 65536 or not _lan_address(addr) or addr.is_loopback \
                or iface == 'lo':
            continue
        rp_m = re.search(r'"rp=([^"]{0,64})"', txt)
        rp = rp_m.group(1).strip('/') if rp_m else ''
        ty = re.search(r'"ty=([^"]{0,96})"', txt)
        out.append({'scheme': scheme, 'address': str(addr), 'port': port_n,
                    'rp': rp if rp == '' or RP_RE.match(rp) else None, 'host': host.lower()[:128],
                    'instance': instance[:128], 'iface': iface[:32], 'version': addr.version,
                    'brand': brand_from_make(ty.group(1) if ty else '')})
    return out


def network_uri(service):
    """``ipp(s)://address[:port]/rp`` for a parsed avahi service, or None when it fails validation."""
    if service.get('rp') is None:
        return None
    host = service['address']
    host = '[%s]' % host if service['version'] == 6 else host
    uri = '%s://%s:%d/%s' % (service['scheme'], host, service['port'], service['rp'])
    return uri if valid_ipp_uri(uri) else None


def local_addresses(fib_trie=None):
    """This machine's own IPv4 addresses (from /proc/net/fib_trie), to skip printers shared by this host."""
    try:
        with open(fib_trie or FIB_TRIE, encoding='ascii', errors='replace') as handle:
            text = handle.read(1 << 20)
    except OSError:
        return set()
    out, last = set(), None
    for line in text.splitlines():
        m = re.match(r'^\s*\|--\s+([0-9.]+)\s*$', line)
        if m:
            last = m.group(1)
        elif last and re.match(r'^\s*/32 host LOCAL', line):
            out.add(last)
    return out


def read_ipp_usb_endpoints(state_dir=None):
    """{(vendor_id, product_id): [port, ...]} of the ipp-usb state files (``vvvv-pppp-name.state``).

    Only the two hex IDs from the file name and the ``http-port`` number are read; the name part (a model
    string) and every other line are ignored."""
    out = {}
    base = state_dir or IPP_USB_STATE
    try:
        names = sorted(os.listdir(base))[:64]
    except OSError:
        return out
    for name in names:
        m = IPP_USB_NAME.match(name)
        if not m or not name.endswith('.state'):
            continue
        try:
            with open(os.path.join(base, name), encoding='utf-8', errors='replace') as handle:
                text = handle.read(8192)
        except OSError:
            continue
        port = re.search(r'^\s*http-port\s*=\s*([0-9]{1,5})\s*$', text, re.M)
        if port and IPP_USB_PORTS[0] <= int(port.group(1)) <= IPP_USB_PORTS[1]:
            out.setdefault((m.group(1).lower(), m.group(2).lower()), []).append(int(port.group(1)))
    return out


# --------------------------------------------------------------------------------------- USB

def usb_printers(usb_list):
    """USB printers in an inventory from ``usb_devices.list_usb_devices``: dicts {port, usb, protocols,
    ipp_usb_capable, brand}. Interface class 07 subclass 01; protocol 01 unidirectional, 02 bidirectional,
    04 IPP-over-USB. Hubs and the rescue medium are never printers."""
    out = []
    for dev in usb_list or []:
        if dev.get('is_hub') or dev.get('is_boot_media'):
            continue
        triplets = set(dev.get('interfaces') or ())
        if dev.get('device_triplet'):
            triplets.add(dev['device_triplet'])
        protocols = []
        for t in sorted(triplets):
            cls, sub, proto = (t.split('/') + ['', '', ''])[:3]
            if cls == USB_PRINTER_CLASS and sub == '01' and proto in USB_PROTOCOLS \
                    and USB_PROTOCOLS[proto] not in protocols:
                protocols.append(USB_PROTOCOLS[proto])
        if not protocols:
            continue
        out.append({'port': dev['port'], 'usb': dev, 'protocols': protocols,
                    'ipp_usb_capable': 'ipp-usb' in protocols,
                    'brand': VENDOR_BRANDS.get(dev.get('vendor_id'), 'other')})
    return out


def usb_link_status(usb):
    """printer-usb-link: ``warn`` below 12 Mbps or behind a chain of hubs, ``pass`` otherwise.

    A printer that runs at 12 Mbps is normal (many are full-speed devices) and is never flagged; the check only
    catches a link that negotiated low speed or a long hub chain, the usual cable/port faults."""
    if not usb or usb.get('speed_mbps') is None:
        return 'unknown'
    if usb['speed_mbps'] < LOW_SPEED_MBPS or usb.get('hub_depth', 0) > MAX_HUB_DEPTH:
        return 'warn'
    return 'pass'


# --------------------------------------------------------------------------------- the checks

def _c(check_id, status, kind=None, number=None):
    item = {'check_id': check_id, 'status': status}
    if kind is not None and number is not None:
        item['kind'] = kind
        item['number'] = max(0, min(int(number), 1000000))
    return item


def _worst(statuses):
    for level in ('fail', 'warn'):
        if level in statuses:
            return level
    return 'pass'


def reason_statuses(reasons):
    """{'printer-media', 'printer-door', 'printer-marker-supply', 'printer-offline'} -> status from a list of
    printer-state-reasons (None = not read, every status is then ``unknown``). Table: docs/printer.md."""
    keys = ('printer-media', 'printer-door', 'printer-marker-supply', 'printer-offline')
    if reasons is None:
        return {k: 'unknown' for k in keys}
    found = {k: set() for k in keys}
    for token in reasons:
        base, severity = split_reason(token)
        if base in MEDIA_JAM:
            found['printer-media'].add('fail')
        elif base in MEDIA_OUT:
            found['printer-media'].add('fail' if severity == 'error' else 'warn')
        elif base in MEDIA_LOW:
            found['printer-media'].add('warn')
        elif base in DOOR_OPEN:
            found['printer-door'].add('fail')
        elif base in SUPPLY_EMPTY:
            found['printer-marker-supply'].add('fail' if severity == 'error' else 'warn')
        elif base in SUPPLY_LOW:
            found['printer-marker-supply'].add('warn')
        elif base in OFFLINE:
            found['printer-offline'].add('warn')
    return {k: _worst(v) for k, v in found.items()}


def printer_checks(p, usb_known=True):
    """The ten per-printer checks (CHECK_IDS order) for one printer dict from ``discover``."""
    state = p.get('state')
    out = {}
    out['printer-state'] = _c('printer-state', {'idle': 'pass', 'processing': 'pass', 'stopped': 'fail'}.get(state, 'unknown'))
    for check_id, status in reason_statuses(p.get('reasons')).items():
        out[check_id] = _c(check_id, status)
    accepting = p.get('accepting')
    out['printer-accepting-jobs'] = _c('printer-accepting-jobs', 'unknown' if accepting is None
                                       else 'pass' if accepting else 'fail')
    queued = p.get('queued')
    if queued is None:
        out['printer-queued-jobs'] = _c('printer-queued-jobs', 'unknown')
    else:
        out['printer-queued-jobs'] = _c('printer-queued-jobs', 'warn' if queued > 0 and state == 'stopped'
                                        else 'pass', 'count', queued)
    low = p.get('marker_min')
    if low is None:
        out['printer-marker-level-min'] = _c('printer-marker-level-min', 'unknown')
    else:
        out['printer-marker-level-min'] = _c('printer-marker-level-min', 'fail' if low < MARKER_FAIL_PERCENT
                                             else 'warn' if low < MARKER_WARN_PERCENT else 'pass', 'percent', low)
    if p['connection'] in ('usb', 'ipp-over-usb') and p.get('usb'):
        out['printer-usb-link'] = _c('printer-usb-link', usb_link_status(p['usb']))
    elif p['connection'] == 'usb' and p.get('queue_without_device') and usb_known:
        out['printer-usb-link'] = _c('printer-usb-link', 'fail')    # a queue for a USB printer that is not on any port
    elif p['connection'] in ('network', 'other'):
        out['printer-usb-link'] = _c('printer-usb-link', 'not_applicable')
    else:
        out['printer-usb-link'] = _c('printer-usb-link', 'unknown')
    driver = p.get('driver')                       # True: a queue or an ipp-usb endpoint exists; None: unknown
    if p['connection'] == 'network' and not p.get('has_queue'):
        out['printer-driver'] = _c('printer-driver', 'not_applicable')   # driverless network printer: nothing to install
    else:
        out['printer-driver'] = _c('printer-driver', 'unknown' if driver is None else 'pass' if driver else 'warn')
    return [out[cid] for cid in CHECK_IDS]


def count_check(count, usb_known=True):
    """printer-count (environment check, no target_ref): ``warn`` when nothing was found, ``unknown`` when
    nothing was found and the USB list could not be read either."""
    if count == 0 and not usb_known:
        return _c('printer-count', 'unknown')
    return _c('printer-count', 'pass' if count else 'warn', 'count', count)


# ------------------------------------------------------------------------------- discovery

def opaque_seed():
    """Salt for the opaque printer ID: the host's machine-id (never emitted), as the other collectors do."""
    for path in ('/etc/machine-id', '/var/lib/dbus/machine-id'):
        try:
            with open(path, encoding='ascii') as handle:
                mid = handle.read().strip()
            if mid:
                return 'machine-id:' + mid
        except (OSError, UnicodeDecodeError):
            pass
    return 'fallback:' + hashlib.sha256(b'rescue-printer').hexdigest()


def opaque_id(material, seed=None):
    """``target-`` + 16 hex of HMAC-SHA256 keyed with the host seed over a private identity string.

    The identity is the USB serial (or port plus vendor:product), or for a network printer its mDNS instance
    name; none of it is emitted, and the keyed hash stops anyone from confirming a guess against the evidence."""
    key = (seed or opaque_seed()).encode('utf-8')
    digest = hmac.new(key, b'printer-target:' + material.encode('utf-8', 'replace'), hashlib.sha256).hexdigest()
    return 'target-' + digest[:16]


def _empty_record(connection):
    return {'connection': connection, 'port': None, 'usb': None, 'brand': 'other', 'ipp_usb_capable': False,
            'protocols': [], 'has_queue': False, 'driver': None, 'queue_without_device': False,
            'state': None, 'reasons': None, 'accepting': None, 'queued': None, 'levels': None, 'types': None,
            'marker_min': None, 'ipp_read': False, 'detection': 'usb-enumerated', 'access': 'usb-only',
            'opaque_id': None, '_private': {}}


def _apply_ipp(record, attrs):
    if not attrs:
        return
    record['ipp_read'] = True
    for key in ('state', 'reasons', 'accepting', 'queued'):
        if attrs.get(key) is not None:
            record[key] = attrs[key]
    record['levels'], record['types'] = attrs.get('levels'), attrs.get('types')
    record['marker_min'] = marker_minimum(attrs.get('levels'), attrs.get('types'))
    if record['brand'] == 'other' and attrs.get('brand') in BRANDS:
        record['brand'] = attrs['brand']


def _match_queues(printers, queues):
    """Pair local CUPS queues (dicts with ``_uri`` info) with USB printers. Returns {queue: printer index}.

    Order: the ipp-usb port in the queue URI, then the USB serial in a usb:// URI, then the one remaining
    USB queue with the one remaining USB printer. Anything ambiguous stays unpaired (and is reported so)."""
    paired = {}
    for q in queues:
        info = q['info']
        if info['kind'] == 'ipp-usb':
            for i, p in enumerate(printers):
                if info['port'] in p['_private'].get('endpoints', ()) and i not in paired.values():
                    paired[q['name']] = i
                    break
    for q in queues:
        info = q['info']
        if q['name'] in paired or info['kind'] != 'usb' or not info['serial']:
            continue
        for i, p in enumerate(printers):
            if i not in paired.values() and p['_private'].get('serial') == info['serial']:
                paired[q['name']] = i
                break
    left_q = [q for q in queues if q['name'] not in paired and q['info']['kind'] in ('usb', 'ipp-usb')]
    left_p = [i for i in range(len(printers)) if i not in paired.values()]
    if len(left_q) == 1 and len(left_p) == 1:
        paired[left_q[0]['name']] = left_p[0]
    return paired


def _group(record):
    """Numbering order: printers on a USB port, queues of unplugged/other printers, network printers."""
    if record['usb']:
        return 0
    return {'usb': 1, 'ipp-over-usb': 1, 'other': 2, 'network': 3}.get(record['connection'], 2)


def discover(usb_list, tools, network=False, seed=None, serial_reader=None, fib_trie=None, ipp_usb_state=None):
    """Printers on this machine: USB printers, local CUPS queues, ipp-usb endpoints and (opt-in) mDNS.

    Returns ``(printers, status)``. *printers*: dicts numbered ``prn-0``... (USB by port order, then queue-only
    printers, then network printers, each by opaque ID; at most 8). Public keys: ref, connection, port, usb,
    brand, ipp_usb_capable, protocols, has_queue, driver, queue_without_device, state, reasons, accepting,
    queued, levels, types, marker_min, ipp_read, detection, access, opaque_id. ``_private`` holds the queue
    name, the device-URI facts and the serial for in-process use only (docs/printer.md: Phase 2 resolves
    ``prn-N`` to a queue through it); ``public_view`` strips it. *status*: lpstat, ipptool, scheduler, avahi,
    network, network_found, ipp_attempts and ipp_answers."""
    reader = serial_reader or usb_devices.read_serial
    status = {'lpstat': tools.lpstat_path is not None, 'ipptool': tools.ipptool_path is not None,
              'scheduler': None, 'avahi': tools.avahi_path is not None, 'network': bool(network),
              'network_found': 0, 'ipp_attempts': 0, 'ipp_answers': 0}

    def query(uri):
        status['ipp_attempts'] += 1
        attrs = tools.ipp(uri)
        if attrs:
            status['ipp_answers'] += 1
        return attrs

    # ---- USB printers (class 07) and their ipp-usb endpoints
    endpoints = read_ipp_usb_endpoints(ipp_usb_state)
    found = usb_printers(usb_list)
    records = []
    for item in found:
        r = _empty_record('usb')
        r.update(port=item['port'], usb=item['usb'], brand=item['brand'], ipp_usb_capable=item['ipp_usb_capable'],
                 protocols=item['protocols'])
        vid_pid = (item['usb']['vendor_id'], item['usb']['product_id'])
        twins = [x for x in found if (x['usb']['vendor_id'], x['usb']['product_id']) == vid_pid]
        ports = endpoints.get(vid_pid, []) if len(twins) == 1 else []     # two identical printers: ambiguous
        r['_private'] = {'serial': reader(item['port']),
                         'endpoints': tuple(ports) if item['ipp_usb_capable'] else ()}
        records.append(r)
    usb_count = len(records)

    # ---- local CUPS queues (names stay in memory)
    queues = []
    if tools.lpstat_path:
        status['scheduler'] = scheduler_running(tools.lpstat('-r'))
        if status['scheduler']:
            states = parse_lpstat_printers(tools.lpstat('-p'))
            devices = parse_lpstat_devices(tools.lpstat('-v'))
            accepting = parse_lpstat_accepting(tools.lpstat('-a'))
            jobs = parse_lpstat_jobs(tools.lpstat('-o'))
            for name in sorted(set(states) | set(devices))[:MAX_QUEUES]:
                info = classify_uri(devices.get(name))
                if info['kind'] == 'virtual':
                    continue                  # PDF/file queues are not printers
                queues.append({'name': name, 'info': info, 'state': states.get(name),
                               'accepting': accepting.get(name), 'queued': jobs.get(name, 0)})
    paired = _match_queues(records, queues)
    free_devices = usb_count - len(set(paired.values()))
    loose_usb_queues = 0
    for q in queues:
        i = paired.get(q['name'])
        kind = q['info']['kind']
        if i is None:
            r = _empty_record('ipp-over-usb' if kind == 'ipp-usb' else kind if kind in ('usb', 'network') else 'other')
            if kind in ('usb', 'ipp-usb'):
                loose_usb_queues += 1
                # A queue for a USB printer that is on no port: only certain when no unpaired USB printer exists.
                r['queue_without_device'] = free_devices == 0
            records.append(r)
        else:
            r = records[i]
            if kind == 'ipp-usb':
                r['connection'] = 'ipp-over-usb'
        r['has_queue'] = True
        r['driver'] = True
        r['state'], r['accepting'], r['queued'] = q['state'], q['accepting'], q['queued']
        r['_private'].update({'queue': q['name'], 'device_uri': q['info']})
        r['access'] = 'cups-only'
        r['detection'] = 'usb-cups' if r['connection'] in ('usb', 'ipp-over-usb') else 'network-ipp'
    if status['scheduler']:
        for r in records[:usb_count]:
            if r['has_queue']:
                continue
            if loose_usb_queues:
                r['driver'] = None          # a queue we could not pair may belong to this printer: unknown
            elif r['ipp_usb_capable']:
                r['driver'] = bool(r['_private'].get('endpoints'))     # driverless through ipp-usb, or not yet
            else:
                r['driver'] = False
    records = records[:MAX_PRINTERS]

    # ---- IPP attributes: through the queue, else the ipp-usb endpoint
    for r in records:
        queue = r['_private'].get('queue')
        attrs = None
        if queue and valid_queue(queue):
            attrs = query('ipp://localhost/printers/%s' % queue)
        elif not r['has_queue'] and r['_private'].get('endpoints'):
            attrs = query('ipp://localhost:%d/ipp/print' % r['_private']['endpoints'][0])
            if attrs is not None:
                r['connection'], r['detection'], r['driver'] = 'ipp-over-usb', 'ipp-usb', True
        if attrs is not None:
            _apply_ipp(r, attrs)
            r['access'] = 'ipp-read'
            if r['has_queue']:
                r['detection'] = 'usb-ipp' if r['connection'] in ('usb', 'ipp-over-usb') else 'network-ipp'

    # ---- network printers: only when the operator opted in
    if network:
        text = ''.join(t for t in (tools.avahi('_ipp._tcp'), tools.avahi('_ipps._tcp')) if t)
        mine = local_addresses(fib_trie)
        known = set()
        for x in records:
            info = x['_private'].get('device_uri') or {}
            if info.get('host'):
                known.add(unquote(info['host']).lower())
        seen = set()
        room = min(MAX_NETWORK, MAX_PRINTERS - len(records))
        for svc in parse_avahi(text):
            key = svc['instance'].lower()
            if status['network_found'] >= room:
                break
            if key in seen or svc['address'] in mine or svc['address'] in known or svc['host'] in known \
                    or any(h.startswith(key) for h in known):
                continue
            seen.add(key)
            r = _empty_record('network')
            r.update(brand=svc['brand'], detection='network-ipp', access='ipp-unavailable')
            r['_private'] = {'instance': svc['instance']}
            uri = network_uri(svc)
            attrs = query(uri) if uri else None
            if attrs is not None:
                _apply_ipp(r, attrs)
                r['access'] = 'ipp-read'
            records.append(r)
            status['network_found'] += 1

    # ---- identity, order and numbering
    for r in records:
        pr = r['_private']
        if r['usb']:
            material = pr.get('serial') or '%s|%s:%s' % (r['port'], r['usb'].get('vendor_id', '-'),
                                                         r['usb'].get('product_id', '-'))
        elif pr.get('queue'):
            material = 'queue:' + pr['queue']
        else:
            material = 'network:' + pr.get('instance', '-')
        r['opaque_id'] = opaque_id(material, seed)
    records.sort(key=lambda r: (_group(r), usb_devices.port_key(r['port']) if r['port'] else (0, ()),
                                r['opaque_id']))
    for n, r in enumerate(records):
        r['ref'] = 'prn-%d' % n
    return records, status


def public_view(record):
    """The record without its ``_private`` data (queue name, device URI facts, serial, instance name)."""
    return {k: v for k, v in record.items() if k != '_private'}


def resolve_ref(printers, ref):
    """The in-process printer dict for ``prn-N``, or None. Phase 2 repair engines use this to find the queue;
    the queue name is never read from evidence or from a model."""
    for r in printers:
        if r['ref'] == ref:
            return r
    return None


def collect_target_checks(printers, status, usb_known=True):
    """{ref: [check dicts]} for every printer."""
    return {p['ref']: printer_checks(p, usb_known) for p in printers}


# ------------------------------------------------------------------ installed OS (offline)

def _lookup(cur, name):
    if os.path.lexists(os.path.join(cur, name)):
        return name
    try:
        entries = os.listdir(cur)
    except OSError:
        return None
    wanted = name.casefold()
    for entry in entries:
        if entry.casefold() == wanted:
            return entry
    return None


def _path(root, rel):
    """REL below ROOT, case-insensitive, or None. Any symlink on the way makes it None."""
    cur = os.path.realpath(root)
    for part in [p for p in rel.split('/') if p]:
        name = _lookup(cur, part)
        if name is None:
            return None
        cur = os.path.join(cur, name)
        if os.path.islink(cur):
            return None
    return cur


def _count_files(root, rel, pattern):
    """Number of regular files (symlinks are not followed or counted) in a directory whose name matches
    *pattern*, capped at MAX_SPOOL_COUNT; None when the directory is missing or unreadable."""
    path = _path(root, rel)
    if path is None:
        return None
    n = 0
    try:
        with os.scandir(path) as it:
            for entry in it:
                if entry.is_file(follow_symlinks=False) and pattern.match(entry.name):
                    n += 1
                    if n >= MAX_SPOOL_COUNT:
                        break
    except OSError:
        return None
    return n


def _stuck(check_id, count):
    if count is None:
        return _c(check_id, 'unknown')
    return _c(check_id, 'warn' if count >= SPOOL_STUCK_WARN else 'pass', 'count', count)


WINDOWS_SPOOL = re.compile(r'^[^/]{1,64}\.(spl|shd)$', re.I)
CUPS_SPOOL = re.compile(r'^(c[0-9]{5,}|d[0-9]{5,}-[0-9]{3})$')
CUPS_WANTS = ('etc/systemd/system/printer.target.wants', 'etc/systemd/system/sockets.target.wants',
              'etc/systemd/system/multi-user.target.wants')
CUPS_UNITS = ('cups.service', 'cups.socket', 'cups.path')


def _cups_installed(root):
    return any(_path(root, rel) is not None for rel in
               ('usr/sbin/cupsd', 'usr/lib/systemd/system/cups.service', 'usr/lib/cups/daemon/cups-deviced'))


def _cups_service(root):
    """printer-target-cups-service from the unit symlinks of the installed Linux (never followed, never run)."""
    if not _cups_installed(root):
        return _c('printer-target-cups-service', 'not_applicable')
    system_dir = _path(root, 'etc/systemd/system')
    if system_dir is None:
        return _c('printer-target-cups-service', 'unknown')
    mask = os.path.join(system_dir, 'cups.service')
    try:
        if os.path.islink(mask) and os.readlink(mask) == '/dev/null':
            return _c('printer-target-cups-service', 'fail')            # masked: it can never start
    except OSError:
        return _c('printer-target-cups-service', 'unknown')
    for rel in CUPS_WANTS:
        wants = _path(root, rel)
        if wants is None:
            continue
        for unit in CUPS_UNITS:
            if os.path.lexists(os.path.join(wants, unit)):
                return _c('printer-target-cups-service', 'pass')
    return _c('printer-target-cups-service', 'warn')                    # installed but not enabled


def collect_offline_target(ctx, root, target):
    """Printing subsystem of one installed OS mounted read-only at *root* (registry hook)."""
    family = (target or {}).get('family')
    if family == 'windows':
        # The Spooler start type lives in the SYSTEM registry hive; this project has no hive parser, so the
        # honest answer is unknown (docs/printer.md).
        return [_stuck('printer-target-spool-stuck', _count_files(root, 'Windows/System32/spool/PRINTERS', WINDOWS_SPOOL)),
                _c('printer-target-spooler-service', 'unknown')]
    if family in ('linuxmint', 'linux-other'):
        count = _count_files(root, 'var/spool/cups', CUPS_SPOOL)
        if count is None and not _cups_installed(root):
            stuck = _c('printer-target-spool-stuck', 'not_applicable')
        else:
            stuck = _stuck('printer-target-spool-stuck', count)
        return [stuck, _cups_service(root)]
    return []
