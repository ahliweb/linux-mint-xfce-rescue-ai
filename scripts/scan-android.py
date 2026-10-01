#!/usr/bin/env python3
"""Read-only USB inventory and Android target scan (phone or tablet attached over USB).

Lists every USB device with its port path, speed, physical location and Android connection mode,
marks the rescue USB so it is never confused with the repair target, and (with --output) writes
schema 1.3 evidence (rescue-ai/v1) with the Android target(s) as ``and-N``, the ``usb_ports``
inventory and the read-only ADB checks. No network, no root needed, nothing is written to the
phone or to any disk except the evidence file (private 0600, atomic).

Privacy (see docs/android.md and docs/security-model.md): USB serial numbers (the Android serial),
manufacturer/product strings, account names, package names, phone numbers, IMEI and Wi-Fi/Bluetooth
addresses never reach the evidence, the terminal output or any file. The target identity is an
opaque ``target-`` id (a keyed hash of the serial). The terminal may show the vendor brand and the
USB port, never the serial.

Managed by ahlikoding.com and satpamsiber.com under ahliweb.com.

Usage: scan-android.py (--list-usb | --count-android | --output FILE) [--source-platform live-linux|linux-host]
                       [--device and-N | --port BUS-PORT[.PORT]...] [--provider-ready]
                       [--repair-policy detect-only|approve-each|auto-safe]
  --list-usb   print a bilingual (Bahasa Indonesia / English) table of ALL USB devices and where
               the Android target(s) are; with --output the scan then runs as well
  --count-android  print only the number of Android phones/tablets seen on USB (the live launcher uses it)
  --output     write validated evidence (exit 1 when it does not validate); it carries scope ["android"],
               the repair policy and the catalog-trigger proposals (action IDs only) like scan-target-os.py
  --device / --port  scan only one phone when several are attached (and-N numbering is by port order)
  --fixture-root DIR, --adb-path DIR  are TEST hooks (fake sysfs/proc tree, directory holding a fake adb)
Exit codes: 0 done, 1 fatal error (USB sysfs unreadable, device not found, evidence invalid), 2 usage error.
"""
import argparse
import hashlib
import importlib.util
import json
import os
import platform
import re
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent / 'lib'))
from rescue_modules import android, usb_devices  # noqa: E402
import repair_catalog  # noqa: E402

SOURCE = 'collector-allowlist'
MODEL_ID = 'mimo-v2.6-flash'
MAX_CHECKS = 160
REF_RE = re.compile(r'^and-[0-7]$')

MODE_LABEL = {
    'none': '-', 'adb': 'ADB', 'fastboot': 'fastboot', 'mtp-ptp': 'MTP/PTP', 'rndis': 'RNDIS',
    'qualcomm-edl': 'Qualcomm EDL', 'mediatek-brom': 'MediaTek preloader/BROM',
    'samsung-download': 'Samsung Download (Odin)', 'spreadtrum-download': 'Unisoc download',
}
PANEL_ID = {'left': 'kiri', 'right': 'kanan', 'top': 'atas', 'bottom': 'bawah', 'front': 'depan', 'back': 'belakang'}
HORIZONTAL_ID = {'left': 'kiri', 'center': 'tengah', 'right': 'kanan'}
HORIZONTAL_EN = {'left': 'left', 'center': 'center', 'right': 'right'}


# --------------------------------------------------------------------------------- helpers

def utc_now():
    return datetime.now(timezone.utc).replace(microsecond=0)


def iso(dt):
    return dt.isoformat().replace('+00:00', 'Z')


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


def live_release():
    try:
        with open('/etc/os-release', encoding='utf-8') as handle:
            for line in handle:
                if line.startswith('PRETTY_NAME='):
                    text = line.split('=', 1)[1].strip().strip('"\'')
                    cleaned = re.sub(r'[^A-Za-z0-9 ._+()/-]', '', text).strip()[:48].rstrip()
                    return cleaned if re.match(r'^[A-Za-z0-9][A-Za-z0-9 ._+()/-]{0,63}$', cleaned) else None
    except OSError:
        pass
    return None


def boot_mode():
    if os.path.exists('/sys/firmware/efi'):
        return 'uefi'
    return 'legacy-bios' if platform.machine().lower() in ('x86_64', 'amd64', 'i386', 'i686') else 'unknown'


def write_atomic(report, out):
    directory = os.path.dirname(os.path.abspath(out))
    os.makedirs(directory, mode=0o700, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix='.evidence-', suffix='.tmp', dir=directory)
    try:
        # mkstemp already creates the file 0600; FAT/exFAT state partitions may reject chmod/chown.
        try:
            os.fchmod(fd, 0o600)
            sudo_uid, sudo_gid = os.environ.get('SUDO_UID', ''), os.environ.get('SUDO_GID', '')
            if os.geteuid() == 0 and sudo_uid.isdigit() and sudo_gid.isdigit():
                os.fchown(fd, int(sudo_uid), int(sudo_gid))
        except OSError:
            pass
        with os.fdopen(fd, 'w', encoding='utf-8') as handle:
            json.dump(report, handle, indent=2)
            handle.write('\n')
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, out)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def validation_problems(report):
    """Schema and semantic problems of *report* (same logic as validate-evidence.py), [] when valid."""
    path = Path(__file__).resolve().with_name('validate-evidence.py')
    spec = importlib.util.spec_from_file_location('rescue_validate_evidence', path)
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except SystemExit:
        return ['python3-jsonschema is not installed; refusing to write unvalidated evidence']
    schema = json.loads(module.SCHEMA_PATH.read_text(encoding='utf-8'))
    validator = module.jsonschema.Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(report), key=lambda e: [str(p) for p in e.absolute_path])
    if errors:
        return ['%s at %s' % (e.message[:200], module.format_path(e)) for e in errors[:5]]
    return module.semantic_errors(report)


# ---------------------------------------------------------------------- operator text

def panel_text(dev):
    """(id, en) location of a device's port from the ACPI physical location, or None."""
    if dev.get('panel'):
        text_id, text_en = 'panel %s' % PANEL_ID[dev['panel']], '%s panel' % dev['panel']
        if dev.get('horizontal_position') and dev['horizontal_position'] != 'center':
            text_id += ', sisi %s' % HORIZONTAL_ID[dev['horizontal_position']]
            text_en += ', %s side' % HORIZONTAL_EN[dev['horizontal_position']]
        return text_id, text_en
    if dev.get('horizontal_position'):
        return 'sisi %s' % HORIZONTAL_ID[dev['horizontal_position']], '%s side' % HORIZONTAL_EN[dev['horizontal_position']]
    return None


def location_cell(dev):
    if dev.get('connect_type') == 'hardwired':
        return 'internal'
    parts = []
    if dev.get('panel'):
        parts.append('%s/%s' % (dev['panel'], PANEL_ID[dev['panel']]))
    if dev.get('horizontal_position'):
        parts.append(dev['horizontal_position'])
    return ' '.join(parts) or '-'


def speed_text(dev):
    speed = dev.get('speed_mbps')
    return '%s Mbps' % speed if speed is not None else '-'


def render_table(usb_list, refs):
    """Bilingual table of all USB devices; *refs* maps port -> and-N."""
    header = ('PORT', 'LOKASI / LOCATION', 'KECEPATAN / SPEED', 'USB', 'KELAS / CLASS', 'MEREK / BRAND',
              'MODE ANDROID', 'TANDA / MARKS')
    rows = []
    for dev in usb_list:
        marks = []
        if dev['is_boot_media']:
            marks.append('[USB RESCUE]')
        if dev['is_hub']:
            marks.append('[HUB]')
        if dev['port'] in refs:
            marks.append('[%s]' % refs[dev['port']])
        rows.append((dev['port'], location_cell(dev), speed_text(dev), dev['usb_version'] or '-',
                     ','.join(dev['class_summary'])[:28] or '-', dev['brand'],
                     MODE_LABEL[dev['android_mode']], ' '.join(marks) or '-'))
    widths = [max(len(str(r[i])) for r in [header] + rows) for i in range(len(header))]
    lines = ['  '.join(str(v).ljust(widths[i]) for i, v in enumerate(row)).rstrip() for row in [header] + rows]
    lines.insert(1, '  '.join('-' * w for w in widths))
    return lines


def guidance(usb_list, targets, adb_available):
    """List of (bahasa_indonesia, english) operator messages about the Android target(s)."""
    out = []
    rescue = [d['port'] for d in usb_list if d['is_boot_media']]
    if rescue:
        out.append(('Jangan cabut perangkat bertanda [USB RESCUE] (port %s): itu USB rescue, bukan target.' % ', '.join(rescue),
                    'Do not unplug the device marked [USB RESCUE] (port %s): it is the rescue USB, not the target.' % ', '.join(rescue)))
    if not targets:
        out.append(('Tidak ada ponsel/tablet Android terdeteksi.',
                    'No Android phone or tablet detected.'))
        out.append(('Periksa: kabel hanya-pengisi daya (tanpa jalur data) tidak terlihat sama sekali; pakai kabel data asli dan colok langsung ke port komputer. '
                    'Di ponsel pilih "Transfer file (MTP)" pada notifikasi USB. Aktifkan Opsi pengembang (Pengaturan > Tentang ponsel > ketuk Nomor build 7 kali), lalu USB debugging.',
                    'Check: a charge-only cable has no data lines and is invisible; use a real data cable straight into the computer. '
                    'On the phone choose "File transfer (MTP)" in the USB notification. Enable Developer options (Settings > About phone > tap Build number 7 times), then USB debugging.'))
        return out
    for t in targets:
        usb = t['usb']
        where_id = 'port tidak diketahui' if t['port'] is None else 'port %s' % t['port']
        where_en = 'unknown port' if t['port'] is None else 'port %s' % t['port']
        details_id, details_en = [], []
        if usb:
            loc = panel_text(usb)
            if loc:
                details_id.append(loc[0])
                details_en.append(loc[1])
            if usb['speed_mbps'] is not None:
                details_id.append('%s Mbps' % usb['speed_mbps'])
                details_en.append('%s Mbps' % usb['speed_mbps'])
        suffix_id = ' (%s)' % ', '.join(details_id) if details_id else ''
        suffix_en = ' (%s)' % ', '.join(details_en) if details_en else ''
        label = MODE_LABEL.get(t['mode'], '-')
        out.append(('Ponsel %s terdeteksi di %s%s, merek %s, mode %s.' % (t['ref'], where_id, suffix_id, t['brand'], label),
                    'Phone %s detected on %s%s, brand %s, mode %s.' % (t['ref'], where_en, suffix_en, t['brand'], label)))
        if t['access'] == 'adb-authorized':
            out.append(('USB debugging aktif dan disetujui: pemeriksaan ADB read-only bisa dijalankan.',
                        'USB debugging is on and authorized: read-only ADB checks can run.'))
        elif t['access'] == 'adb-unauthorized':
            out.append(('Buka kunci ponsel dan setujui "Izinkan USB debugging" (RSA) di layar ponsel, lalu jalankan ulang pemindaian.',
                        'Unlock the phone and accept "Allow USB debugging" (RSA prompt) on its screen, then run the scan again.'))
        elif t['access'] == 'adb-unavailable':
            out.append(('Status ADB "%s": cabut dan colok ulang kabel, buka kunci layar, dan pilih boot Android normal (bukan recovery/bootloader).' % t['adb_state'],
                        'ADB state "%s": replug the cable, unlock the screen and boot Android normally (not recovery/bootloader).' % t['adb_state']))
        elif t['mode'] in usb_devices.LOW_LEVEL_MODES:
            out.append(('Ponsel berada di mode tingkat rendah (%s), bukan Android yang berjalan. Toolkit ini hanya mendeteksi; tidak melakukan flashing atau unbrick.' % label,
                        'The phone is in a low-level mode (%s), not a running Android. This toolkit only detects it; it never flashes or unbricks.' % label))
        elif not adb_available:
            out.append(('adb belum terpasang (paket "adb"), sehingga pemeriksaan ADB dilewati.',
                        'adb is not installed (package "adb"), so the ADB checks are skipped.'))
        else:
            out.append(('USB debugging belum aktif: aktifkan Opsi pengembang (Pengaturan > Tentang ponsel > ketuk Nomor build 7 kali) lalu USB debugging, dan pilih "Transfer file".',
                        'USB debugging is off: enable Developer options (Settings > About phone > tap Build number 7 times) then USB debugging, and choose "File transfer".'))
        if usb and usb['speed_mbps'] is not None and usb['speed_mbps'] < android.FULL_SPEED_MBPS:
            out.append(('Kecepatan hanya %s Mbps: ganti kabel data atau pakai port USB lain.' % usb['speed_mbps'],
                        'Only %s Mbps negotiated: use another data cable or another USB port.' % usb['speed_mbps']))
        if usb and usb['hub_depth'] > 0:
            out.append(('Ponsel terhubung lewat hub: colok langsung ke port komputer bila koneksi bermasalah.',
                        'The phone is behind a hub: plug it straight into a computer port if the connection is flaky.'))
    return out


# --------------------------------------------------------------------------- evidence

def usb_ports_entries(usb_list):
    out = []
    for dev in usb_list[:64]:
        item = {'port': dev['port'], 'is_hub': dev['is_hub'], 'is_boot_media': dev['is_boot_media'],
                'android_mode': dev['android_mode'], 'vendor_brand': dev['brand'], 'hub_depth': dev['hub_depth']}
        if dev['speed_mbps'] is not None:
            item['speed_mbps'] = dev['speed_mbps']
        if dev['usb_version']:
            item['usb_version'] = dev['usb_version']
        if dev['android_modes']:
            item['android_modes'] = list(dev['android_modes'])
        for key in ('panel', 'horizontal_position'):
            if dev.get(key):
                item[key] = dev[key]
        out.append(item)
    return out


def build_evidence(usb_list, targets, per_target, now, platform_name, provider_ready=False, policy='detect-only'):
    """Schema 1.3 evidence. *per_target* maps ref -> (checks, props)."""
    stamp = iso(now)

    def emit(c, ref=None):
        item = {'check_id': c['check_id'], 'status': c['status'], 'source': SOURCE, 'observed_at': stamp}
        if ref:
            item['target_ref'] = ref
        if c.get('kind') is not None:
            item['value'] = {'kind': c['kind'], 'number': c['number']}
        return item

    ports = {d['port'] for d in usb_list}
    checks = [emit(c) for c in android.usb_inventory_checks(usb_list)]
    target_systems = []
    for t in targets:
        t_checks, props = per_target.get(t['ref'], ([], {}))
        if len(checks) + len(t_checks) > MAX_CHECKS:
            break
        entry = {'ref': t['ref'], 'family': 'android', 'release': android.release_label(props),
                 'architecture': android.architecture(props), 'detection': t['detection'],
                 'encryption': 'unknown', 'access': t['access'], 'opaque_id': t['opaque_id']}
        if t['port'] in ports:
            entry['usb_port'] = t['port']
        target_systems.append(entry)
        checks.extend(emit(c, t['ref']) for c in t_checks)
    host_id = 'target-' + digest(android.opaque_seed())[:16]
    device_id = target_systems[0]['opaque_id'] if len(target_systems) == 1 else host_id
    live = platform_name == 'live-linux'
    return {
        'schema_version': '1.3',
        'run_id': 'rescue-' + now.strftime('%Y%m%d-%H%M%S'),
        'source_platform': 'linux-mint-xfce-live' if live else 'linux-host',
        'boot_mode': boot_mode(),
        'collected_at': stamp,
        'target_device_opaque_id': device_id,
        'ventoy_version': None,
        'linux_release': live_release() if live else None,
        'target_systems': target_systems,
        'usb_ports': usb_ports_entries(usb_list),
        'checks': checks,
        'evidence_manifest': {'entry_count': len(checks), 'manifest_sha256': digest(json.dumps(checks, sort_keys=True)),
                              'storage_class': 'usb-rescue-state'},
        'ai_provider': {'provider_id': 'opencode-go', 'model_id': MODEL_ID, 'authenticated': bool(provider_ready),
                        'destination_class': 'cloud' if provider_ready else 'unknown'},
        'ai_analysis_status': 'not_run',
        'mutation_status': 'none',
        'verification': {'hashes_verified': False, 'read_back_verified': False, 'status': 'not_applicable'},
        'classification': 'confidential',
        'source_references': ['opencode-go:provider', 'nist:sp-800-86'],
        'scope': ['android'],
        'repair_policy': policy,
    }


def add_proposals(report, catalog_dir=None):
    """Attach catalog-trigger proposals (action IDs only). A broken catalog never breaks the scan."""
    try:
        catalog = repair_catalog.load(catalog_dir or repair_catalog.CATALOG_DIR)
    except (repair_catalog.CatalogError, OSError, ValueError) as exc:
        print('warning: repair catalog unusable, no proposals added: %s' % exc, file=sys.stderr)
        return report
    proposals = repair_catalog.triggered(catalog, report, ('android',))[:32]
    if proposals:
        report['repair_proposals'] = proposals
    return report


# ------------------------------------------------------------------------------ main

def select_targets(targets, device, port):
    if device is not None:
        return [t for t in targets if t['ref'] == device]
    if port is not None:
        return [t for t in targets if t['port'] == port]
    return targets


def main(argv=None):
    parser = argparse.ArgumentParser(description='Read-only USB inventory and Android target scan.')
    parser.add_argument('--list-usb', action='store_true', help='print every USB device and where the phone is')
    parser.add_argument('--count-android', action='store_true',
                        help='print only the number of Android phones/tablets seen on USB')
    parser.add_argument('--output', metavar='FILE', help='write schema 1.3 evidence (0600, atomic, validated)')
    parser.add_argument('--repair-policy', choices=('detect-only', 'approve-each', 'auto-safe'), default='detect-only',
                        help='the policy the repair engine will use; recorded in the evidence')
    parser.add_argument('--source-platform', choices=('live-linux', 'linux-host'), default='live-linux')
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--device', metavar='and-N', help='scan only this Android target (numbering by port order)')
    group.add_argument('--port', metavar='PORT', help='scan only the Android target on this USB port (e.g. 3-2.1)')
    parser.add_argument('--provider-ready', action='store_true',
                        help='the launcher has a usable OPENCODE_GO_API_KEY and will send this evidence')
    parser.add_argument('--fixture-root', metavar='DIR', help=argparse.SUPPRESS)
    parser.add_argument('--adb-path', metavar='DIR', help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    if not args.list_usb and not args.output and not args.count_android:
        parser.error('give --list-usb, --count-android and/or --output FILE / beri --list-usb, --count-android dan/atau --output FILE')
    if args.count_android and (args.list_usb or args.output):
        parser.error('--count-android stands alone / --count-android berdiri sendiri')
    if args.device is not None and not REF_RE.match(args.device):
        parser.error('--device must look like and-0 / --device harus berbentuk and-0')
    if args.port is not None and not usb_devices.valid_port(args.port):
        parser.error('--port must look like 3-2.1 / --port harus berbentuk 3-2.1')

    if args.fixture_root:
        root = Path(args.fixture_root)
        usb_devices.SYSFS_USB = root / 'sys/bus/usb/devices'
        usb_devices.SYS_ROOT = root / 'sys'
        usb_devices.MOUNTINFO = root / 'proc/self/mountinfo'
        usb_devices.BY_LABEL = root / 'dev/disk/by-label'
    if args.adb_path:
        android.ADB_SEARCH_PATH = args.adb_path

    usb_list = usb_devices.list_usb_devices()
    if usb_list is None:
        print('scan-android: cannot read the USB sysfs / tidak dapat membaca sysfs USB.', file=sys.stderr)
        return 1
    if args.count_android:
        print(len([d for d in usb_list if d['is_android']]))
        return 0
    program = android.find_adb()
    adb = android.Adb(program) if program else None
    live = args.source_platform == 'live-linux'
    try:
        targets = android.discover(usb_list, adb, adb is not None)
        refs = {t['port']: t['ref'] for t in targets if t['port']}

        if args.list_usb:
            print('\n'.join(render_table(usb_list, refs)))
            print()
            for text_id, text_en in guidance(usb_list, targets, adb is not None):
                print('  ' + text_id)
                print('  (%s)' % text_en)
            if adb is None:
                print('  adb tidak ditemukan; pemeriksaan ADB tidak tersedia / adb not found; ADB checks unavailable.')

        if not args.output:
            return 0

        chosen = select_targets(targets, args.device, args.port)
        if (args.device is not None or args.port is not None) and not chosen:
            print('scan-android: the selected Android target was not found / target Android yang dipilih tidak ditemukan.',
                  file=sys.stderr)
            return 1
        now = utc_now()
        per_target = {}
        for t in chosen:
            per_target[t['ref']] = android.collect_target_checks(adb, t, adb is not None,
                                                                 today=now.date())
        report = add_proposals(build_evidence(usb_list, chosen, per_target, now, args.source_platform,
                                              args.provider_ready, args.repair_policy))
        problems = validation_problems(report)
        if problems:
            print('scan-android: evidence did not validate, nothing written / evidence tidak valid, tidak ditulis:',
                  file=sys.stderr)
            for problem in problems:
                print('  - %s' % problem, file=sys.stderr)
            return 1
        write_atomic(report, args.output)
        print(args.output)
        print('scan-android: %d Android target(s), %d USB device(s), %d checks / target Android: %d, perangkat USB: %d'
              % (len(report['target_systems']), len(usb_list), len(report['checks']),
                 len(report['target_systems']), len(usb_list)))
        for system in report['target_systems']:
            t = next(x for x in chosen if x['ref'] == system['ref'])
            print('  %s brand=%s mode=%s port=%s access=%s' % (system['ref'], t['brand'], t['mode'],
                                                               t['port'] or '-', system['access']))
        return 0
    finally:
        if live:
            android.stop_server(adb)


if __name__ == '__main__':
    sys.exit(main())
