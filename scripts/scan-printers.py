#!/usr/bin/env python3
"""Read-only printer scan: USB printers on this PC, their CUPS/IPP state, and (opt-in) local-link network printers.

Lists every printer with its USB port, speed, physical location, brand, state, the mapped state reasons, the
lowest ink/toner level and the queued jobs, with bilingual (Bahasa Indonesia / English) guidance per problem,
and (with --output) writes schema 1.3 evidence (rescue-ai/v1) with each printer as ``prn-N``, the ``usb_ports``
inventory, a closed-set ``printers`` list and the read-only printer checks. Nothing is written to a printer or
to CUPS (no queue is created, enabled, paused or cancelled, nothing is printed); the only file written is the
evidence (private 0600, atomic).

Privacy (see docs/printer.md and docs/security-model.md): queue names, device URIs, IP and MAC addresses, host
names, serial numbers, job and user names and printer-info/location strings never reach the evidence, the
terminal output or any file. The printer identity is an opaque ``target-`` id (a keyed hash). The terminal may
show the brand (from an allowlist), the USB port and closed-set state words, never a name.

Network discovery is OFF unless --network is given: then ``avahi-browse -rtp _ipp._tcp`` and ``_ipps._tcp`` run
on the local link with a timeout (no subnet scan, no SNMP, no credentials) and each answer is read with one
IPP Get-Printer-Attributes request to a private/link-local address.

Managed by ahlikoding.com and satpamsiber.com under ahliweb.com.

Usage: scan-printers.py (--list | --output FILE) [--network] [--source-platform live-linux|linux-host]
                        [--printer prn-N] [--provider-ready]
  --list       print a bilingual table of the printers found and what to do about each; with --output the
               evidence is written as well
  --network    also look for network printers by mDNS/DNS-SD on the local link (opt-in, per run)
  --output     write validated evidence (exit 1 when it does not validate)
  --printer    only this printer (numbering is by USB port order, then queues, then network printers)
  --fixture-root DIR, --tool-path DIR  are TEST hooks (fake sysfs/proc tree, directory holding fake lpstat/ipptool/
               avahi-browse)
Exit codes: 0 done, 1 fatal error (nothing can be read, printer not found, evidence invalid), 2 usage error.
"""
import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent / 'lib'))
import scan_common  # noqa: E402
from rescue_modules import printer, usb_devices  # noqa: E402

SOURCE = 'collector-allowlist'
MODEL_ID = 'mimo-v2.6-flash'
MAX_CHECKS = 160
REF_RE = re.compile(r'^prn-[0-7]$')

CONNECTION_LABEL = {'usb': 'USB', 'ipp-over-usb': 'IPP-over-USB', 'network': 'jaringan/network', 'other': 'lain/other'}
STATE_LABEL = {'idle': 'idle', 'processing': 'processing', 'stopped': 'stopped'}


# --------------------------------------------------------------------------- operator text

def speed_text(dev):
    speed = (dev or {}).get('speed_mbps')
    return '%s Mbps' % speed if speed is not None else '-'


def reasons_cell(p):
    if not p['ipp_read'] and p['reasons'] is None:
        return '?'
    return ','.join(printer.reason_tokens(p['reasons']))[:34] or '-'


def marks(p, boot_ports):
    out = []
    usb = p.get('usb')
    if usb and usb['hub_depth'] > 0:
        out.append('[HUB]')
    if usb and shares_hub(usb, boot_ports):
        out.append('[USB RESCUE]')
    return ' '.join(out) or '-'


def shares_hub(usb, boot_ports):
    """The printer sits on the same hub as the rescue USB (unplugging that hub would drop both)."""
    if usb['hub_depth'] < 1:
        return False
    parent = usb['port'].rpartition('.')[0]
    return any(b.rpartition('.')[0] == parent for b in boot_ports if '.' in b)


def render_table(printers, boot_ports):
    header = ('REF', 'KONEKSI / CONNECTION', 'PORT', 'LOKASI / LOCATION', 'KECEPATAN / SPEED', 'MEREK / BRAND',
              'STATUS / STATE', 'ALASAN / REASONS', 'TINTA% / MARKER MIN', 'ANTRIAN / JOBS', 'TANDA / MARKS')
    rows = []
    for p in printers:
        usb = p.get('usb')
        rows.append((p['ref'], CONNECTION_LABEL[p['connection']], p['port'] or '-',
                     scan_common.location_cell(usb) if usb else '-', speed_text(usb), p['brand'],
                     STATE_LABEL.get(p['state'], '-'), reasons_cell(p),
                     '%d%%' % p['marker_min'] if p['marker_min'] is not None else '-',
                     str(p['queued']) if p['queued'] is not None else '-', marks(p, boot_ports)))
    widths = [max(len(str(r[i])) for r in [header] + rows) for i in range(len(header))]
    lines = ['  '.join(str(v).ljust(widths[i]) for i, v in enumerate(row)).rstrip() for row in [header] + rows]
    lines.insert(1, '  '.join('-' * w for w in widths))
    return lines


def guidance(printers, boot_ports, status, usb_known):
    """List of (bahasa_indonesia, english) operator messages about the printers."""
    out = []
    rescue = sorted(boot_ports)
    if rescue:
        out.append(('Jangan cabut perangkat USB rescue (port %s): itu USB rescue, bukan printer.' % ', '.join(rescue),
                    'Do not unplug the rescue USB (port %s): it is the rescue medium, not a printer.' % ', '.join(rescue)))
    if not status['lpstat']:
        out.append(('lpstat tidak ditemukan (paket "cups-client"): status antrean tidak dapat dibaca.',
                    'lpstat not found (package "cups-client"): the queue state cannot be read.'))
    elif status['scheduler'] is False:
        out.append(('Layanan CUPS tidak berjalan: nyalakan CUPS dari sesi ini bila perlu (tidak dilakukan pemindaian).',
                    'The CUPS service is not running: start CUPS from this session if needed (the scan does not do it).'))
    if status['lpstat'] and not status['ipptool']:
        out.append(('ipptool tidak ditemukan (paket "cups-ipp-utils"): alasan status, tinta, dan penerimaan pekerjaan dilewati (unknown).',
                    'ipptool not found (package "cups-ipp-utils"): state reasons, ink levels and job acceptance are skipped (unknown).'))
    if not printers:
        out.append(('Tidak ada printer terdeteksi.', 'No printer detected.'))
        out.append(('Periksa: printer menyala dan siap, kabel USB adalah kabel data (bukan hanya pengisi daya), colok langsung ke port komputer tanpa hub, '
                    'dan coba port lain. Printer jaringan tidak dicari kecuali Anda memakai --network (mDNS di link lokal saja).',
                    'Check: the printer is on and ready, the USB cable is a data cable, plug it straight into a computer port without a hub, and try another port. '
                    'Network printers are not searched unless you use --network (mDNS on the local link only).'))
        if not usb_known:
            out.append(('Sysfs USB tidak terbaca: daftar USB tidak tersedia.', 'The USB sysfs is unreadable: no USB list.'))
        return out
    for p in printers:
        usb = p.get('usb')
        tokens = printer.reason_tokens(p['reasons'])
        if p['connection'] in ('usb', 'ipp-over-usb') and p['port']:
            loc = scan_common.panel_text(usb) if usb else None
            where_id = 'port USB %s%s, %s' % (p['port'], ' (%s)' % loc[0] if loc else '', speed_text(usb))
            where_en = 'USB port %s%s, %s' % (p['port'], ' (%s)' % loc[1] if loc else '', speed_text(usb))
        elif p['connection'] in ('usb', 'ipp-over-usb'):
            where_id, where_en = 'tidak terlihat di port USB mana pun', 'not seen on any USB port'
        else:
            where_id, where_en = 'lewat jaringan atau jenis antrean lain', 'over the network or another queue type'
        out.append(('Printer %s: %s, merek %s.' % (p['ref'], where_id, p['brand']),
                    'Printer %s: %s, brand %s.' % (p['ref'], where_en, p['brand'])))
        if p.get('queue_without_device') and usb_known:
            out.append(('Antrean untuk printer USB ada, tetapi printernya tidak terlihat di port USB: nyalakan printer, periksa kabel data dan daya, lalu colok ulang.',
                        'A queue for a USB printer exists but the printer is not on any USB port: switch it on, check the data and power cables, and replug.'))
        if usb and printer.usb_link_status(usb) == 'warn':
            out.append(('Koneksi USB lemah (%s, kedalaman hub %d): colok langsung ke port komputer dengan kabel lain.'
                        % (speed_text(usb), usb['hub_depth']),
                        'Weak USB link (%s, hub depth %d): plug it straight into a computer port with another cable.'
                        % (speed_text(usb), usb['hub_depth'])))
        if usb and shares_hub(usb, boot_ports):
            out.append(('Printer ada di hub yang sama dengan USB rescue: jangan cabut hub itu.',
                        'The printer is on the same hub as the rescue USB: do not unplug that hub.'))
        if 'media-jam' in tokens:
            out.append(('Kertas macet: matikan printer, buka penutup, tarik kertas pelan-pelan searah jalur kertas tanpa merobek, lalu tutup dan nyalakan lagi.',
                        'Paper jam: switch the printer off, open the covers, pull the paper out gently along the paper path without tearing it, close up and switch on again.'))
        if tokens and set(tokens) & printer.DOOR_OPEN:
            out.append(('Penutup atau pintu printer terbuka: tutup sampai terdengar klik.',
                        'A printer cover or door is open: close it until it clicks.'))
        if tokens and set(tokens) & (printer.MEDIA_OUT | printer.MEDIA_LOW):
            out.append(('Kertas habis atau baki hilang: isi kertas dan pasang baki dengan benar.',
                        'Out of paper or tray missing: load paper and seat the tray properly.'))
        if tokens and set(tokens) & (printer.SUPPLY_LOW | printer.SUPPLY_EMPTY):
            level = ' (terendah %d%%)' % p['marker_min'] if p['marker_min'] is not None else ''
            level_en = ' (lowest %d%%)' % p['marker_min'] if p['marker_min'] is not None else ''
            out.append(('Toner atau tinta rendah/habis%s: ganti kartrid atau isi ulang tinta asli sesuai model.' % level,
                        'Toner or ink is low or empty%s: replace the cartridge or refill with ink for this model.' % level_en))
        elif p['marker_min'] is not None and p['marker_min'] < printer.MARKER_WARN_PERCENT:
            out.append(('Tingkat tinta/toner terendah %d%%: siapkan kartrid pengganti.' % p['marker_min'],
                        'The lowest ink/toner level is %d%%: have a replacement cartridge ready.' % p['marker_min']))
        if tokens and set(tokens) & printer.OFFLINE:
            out.append(('Printer offline: periksa kabel USB dan daya, nyalakan printer, tunggu siap, dan colok ulang. Printer jaringan: pastikan terhubung ke jaringan yang sama.',
                        'The printer is offline: check the USB cable and power, switch it on, wait until ready, and replug. Network printer: make sure it is on the same network.'))
        if p['state'] == 'stopped' or (tokens and set(tokens) & printer.PAUSED):
            out.append(('Antrean berhenti atau dijeda: lanjutkan antrean dari Pengaturan Printer. Melanjutkan antrean otomatis adalah tindakan katalog fase 2 (Planned).',
                        'The queue is stopped or paused: resume it from Printer Settings. Resuming the queue by the toolkit is a phase 2 catalog action (Planned).'))
        if p['accepting'] is False:
            out.append(('Antrean menolak pekerjaan baru: aktifkan "Terima pekerjaan" di Pengaturan Printer (tindakan katalog fase 2, Planned).',
                        'The queue is not accepting jobs: enable "Accept jobs" in Printer Settings (phase 2 catalog action, Planned).'))
        if p['queued'] and p['state'] == 'stopped':
            out.append(('Ada %d pekerjaan menumpuk di antrean yang berhenti: batalkan pekerjaan macet dari Pengaturan Printer (tindakan katalog fase 2, Planned).' % p['queued'],
                        '%d job(s) are stuck in the stopped queue: cancel the stuck jobs from Printer Settings (phase 2 catalog action, Planned).' % p['queued']))
        if p['connection'] == 'usb' and p['driver'] is False:
            out.append(('Printer terdeteksi tetapi belum ada antrean (driver): tambahkan di Pengaturan Printer (driverless/IPP Everywhere atau driver pabrikan); membuat antrean driverless adalah tindakan fase 2 (Planned).',
                        'The printer is detected but has no queue (driver): add it in Printer Settings (driverless/IPP Everywhere or the vendor driver); creating a driverless queue is a phase 2 action (Planned).'))
        if p['access'] in ('cups-only', 'usb-only') and status['ipptool'] and p['has_queue'] and not p['ipp_read']:
            out.append(('Antrean ada tetapi tidak menjawab IPP: status rinci (kertas, tinta, pintu) tidak diketahui.',
                        'The queue exists but did not answer IPP: detailed state (paper, ink, door) is unknown.'))
    if not status['network']:
        out.append(('Printer jaringan tidak dicari (opt-in): jalankan dengan --network untuk mencari lewat mDNS di link lokal.',
                    'Network printers were not searched (opt-in): run with --network to look for them by mDNS on the local link.'))
    elif status['avahi'] is False:
        out.append(('avahi-browse tidak ditemukan (paket "avahi-utils"): pencarian jaringan dilewati.',
                    'avahi-browse not found (package "avahi-utils"): network discovery is skipped.'))
    elif status['network_found'] == 0:
        out.append(('Pencarian jaringan tidak menemukan printer IPP di link lokal (avahi-daemon harus berjalan).',
                    'Network discovery found no IPP printer on the local link (avahi-daemon must be running).'))
    return out


# --------------------------------------------------------------------------- evidence

def build_evidence(usb_list, printers, per_printer, count_total, now, platform_name, provider_ready=False):
    """Schema 1.3 evidence. *per_printer* maps ref -> [check dicts]."""
    stamp = scan_common.iso(now)

    def emit(c, ref=None):
        item = {'check_id': c['check_id'], 'status': c['status'], 'source': SOURCE, 'observed_at': stamp}
        if ref:
            item['target_ref'] = ref
        if c.get('kind') is not None:
            item['value'] = {'kind': c['kind'], 'number': c['number']}
        return item

    ports = {d['port'] for d in usb_list or []}
    env = []
    if usb_list is None:
        env.append({'check_id': 'usb-device-count', 'status': 'unknown'})
    else:
        env.append({'check_id': 'usb-device-count', 'status': 'pass', 'kind': 'count',
                    'number': len([d for d in usb_list if not d['is_hub']])})
    env.append(printer.count_check(count_total, usb_list is not None))
    checks = [emit(c) for c in env]
    target_systems, listed = [], []
    for p in printers:
        p_checks = per_printer.get(p['ref'], [])
        if len(checks) + len(p_checks) > MAX_CHECKS:
            break
        entry = {'ref': p['ref'], 'family': 'printer', 'detection': p['detection'], 'encryption': 'unknown',
                 'access': p['access'], 'opaque_id': p['opaque_id']}
        item = {'ref': p['ref'], 'connection': p['connection'], 'brand': p['brand'],
                'ipp_usb_capable': bool(p['ipp_usb_capable'])}
        if p['port'] in ports and p['connection'] in ('usb', 'ipp-over-usb'):
            entry['usb_port'] = p['port']
            item['usb_port'] = p['port']
        target_systems.append(entry)
        listed.append(item)
        checks.extend(emit(c, p['ref']) for c in p_checks)
    host_id = 'target-' + scan_common.digest(printer.opaque_seed())[:16]
    device_id = target_systems[0]['opaque_id'] if len(target_systems) == 1 else host_id
    live = platform_name == 'live-linux'
    report = {
        'schema_version': '1.3',
        'run_id': 'rescue-' + now.strftime('%Y%m%d-%H%M%S'),
        'source_platform': 'linux-mint-xfce-live' if live else 'linux-host',
        'boot_mode': scan_common.boot_mode(),
        'collected_at': stamp,
        'target_device_opaque_id': device_id,
        'ventoy_version': None,
        'linux_release': scan_common.live_release() if live else None,
        'target_systems': target_systems,
        'printers': listed,
        'checks': checks,
        'evidence_manifest': {'entry_count': len(checks),
                              'manifest_sha256': scan_common.digest(json.dumps(checks, sort_keys=True)),
                              'storage_class': 'usb-rescue-state'},
        'ai_provider': {'provider_id': 'opencode-go', 'model_id': MODEL_ID, 'authenticated': bool(provider_ready),
                        'destination_class': 'cloud' if provider_ready else 'unknown'},
        'ai_analysis_status': 'not_run',
        'mutation_status': 'none',
        'verification': {'hashes_verified': False, 'read_back_verified': False, 'status': 'not_applicable'},
        'classification': 'confidential',
        'source_references': ['opencode-go:provider', 'nist:sp-800-86'],
        'repair_policy': 'detect-only',
    }
    if usb_list is not None:
        report['usb_ports'] = scan_common.usb_ports_entries(usb_list)
    return report


# ------------------------------------------------------------------------------ main

def main(argv=None):
    parser = argparse.ArgumentParser(description='Read-only printer scan (USB, CUPS/IPP, opt-in local-link network).')
    parser.add_argument('--list', action='store_true', help='print the printers found and what to do about each')
    parser.add_argument('--network', action='store_true',
                        help='also look for network printers by mDNS on the local link (opt-in; no subnet scan)')
    parser.add_argument('--output', metavar='FILE', help='write schema 1.3 evidence (0600, atomic, validated)')
    parser.add_argument('--source-platform', choices=('live-linux', 'linux-host'), default='live-linux')
    parser.add_argument('--printer', metavar='prn-N', help='scan only this printer (numbering by port order)')
    parser.add_argument('--provider-ready', action='store_true',
                        help='the launcher has a usable OPENCODE_GO_API_KEY and will send this evidence')
    parser.add_argument('--fixture-root', metavar='DIR', help=argparse.SUPPRESS)
    parser.add_argument('--tool-path', metavar='DIR', help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    if not args.list and not args.output:
        parser.error('give --list and/or --output FILE / beri --list dan/atau --output FILE')
    if args.printer is not None and not REF_RE.match(args.printer):
        parser.error('--printer must look like prn-0 / --printer harus berbentuk prn-0')

    if args.fixture_root:
        root = Path(args.fixture_root)
        usb_devices.SYSFS_USB = root / 'sys/bus/usb/devices'
        usb_devices.SYS_ROOT = root / 'sys'
        usb_devices.MOUNTINFO = root / 'proc/self/mountinfo'
        usb_devices.BY_LABEL = root / 'dev/disk/by-label'
        printer.IPP_USB_STATE = root / 'var/ipp-usb/dev'
        printer.FIB_TRIE = root / 'proc/net/fib_trie'
    if args.tool_path:
        printer.TOOL_SEARCH_PATH = args.tool_path

    usb_list = usb_devices.list_usb_devices()
    tools = printer.Tools()
    if usb_list is None and tools.lpstat_path is None and not args.network:
        print('scan-printers: cannot read the USB sysfs and lpstat is missing / tidak dapat membaca sysfs USB dan lpstat tidak ada.',
              file=sys.stderr)
        return 1
    printers, status = printer.discover(usb_list, tools, network=args.network)
    boot_ports = {d['port'] for d in usb_list or [] if d['is_boot_media']}

    if args.list:
        if printers:
            print('\n'.join(render_table([printer.public_view(p) for p in printers], boot_ports)))
            print()
        for text_id, text_en in guidance([printer.public_view(p) for p in printers], boot_ports, status,
                                         usb_list is not None):
            print('  ' + text_id)
            print('  (%s)' % text_en)

    if not args.output:
        return 0

    chosen = printers if args.printer is None else [p for p in printers if p['ref'] == args.printer]
    if args.printer is not None and not chosen:
        print('scan-printers: the selected printer was not found / printer yang dipilih tidak ditemukan.', file=sys.stderr)
        return 1
    now = scan_common.utc_now()
    chosen_views = [printer.public_view(p) for p in chosen]
    per_printer = {p['ref']: printer.printer_checks(p, usb_list is not None) for p in chosen_views}
    report = build_evidence(usb_list, chosen_views, per_printer, len(printers), now, args.source_platform,
                            args.provider_ready)
    problems = scan_common.validation_problems(report)
    if problems:
        print('scan-printers: evidence did not validate, nothing written / evidence tidak valid, tidak ditulis:',
              file=sys.stderr)
        for problem in problems:
            print('  - %s' % problem, file=sys.stderr)
        return 1
    scan_common.write_atomic(report, args.output)
    print(args.output)
    print('scan-printers: %d printer(s), %d USB device(s), %d checks / printer: %d, perangkat USB: %d'
          % (len(report['target_systems']), len(usb_list or []), len(report['checks']),
             len(report['target_systems']), len(usb_list or [])))
    for system in report['target_systems']:
        item = next(x for x in report['printers'] if x['ref'] == system['ref'])
        print('  %s connection=%s brand=%s port=%s access=%s' % (system['ref'], item['connection'], item['brand'],
                                                                 item.get('usb_port', '-'), system['access']))
    return 0


if __name__ == '__main__':
    sys.exit(main())
