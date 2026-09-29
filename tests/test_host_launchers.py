#!/usr/bin/env python3
"""Tests for the host launchers in host/ (Windows, macOS, Linux). Stdlib only.

* Linux launcher: run for real in a temp copy of the bundle (evidence-only, dry-run through the
  real scripts/opencode-go-analyze.py, and a loopback fake OpenCode Go server).
* PowerShell launcher: parse check and pure-function tests through pwsh when it is installed
  (skipped otherwise; GitHub ubuntu-24.04 runners have pwsh).
* macOS launcher: zsh syntax check and a functional run with PATH shims that emulate the
  macOS tools (skipped without zsh). Real macOS behavior is Hardware-required and NOT tested here.
* Static tests: no key on argv, nothing written outside the USB reports folder, no dynamic code.

No real network, dummy secrets only. Managed by ahlikoding.com and satpamsiber.com under ahliweb.com.
"""
import getpass
import http.server
import json
import os
import re
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
HOST = REPO / 'host'
DUMMY_KEY = 'dummy-test-key-123'
BUNDLE_DIRS = ('scripts', 'profiles', 'rescue-ai', 'host')
CANNED_ANSWER = '**Fakta**\n- semua ok "dikutip" \\ backslash \u00e9\n'

try:
    import jsonschema  # noqa: F401
    HAVE_JSONSCHEMA = True
except ImportError:
    HAVE_JSONSCHEMA = False

PWSH = shutil.which('pwsh')
ZSH = shutil.which('zsh')
BASH = shutil.which('bash') or '/bin/bash'


def clean_env(**extra):
    env = {k: v for k, v in os.environ.items()
           if k not in ('OPENCODE_GO_API_KEY', 'RESCUE_TEST_BASE_URL', 'RESCUE_PS_LIBRARY_ONLY')}
    env.update(extra)
    return env


def make_usb(tmp, launcher_at_root=None):
    """Create <tmp>/usb/rescue-omes with a private copy of the bundle. Returns (usb, bundle)."""
    usb = Path(tmp) / 'usb'
    bundle = usb / 'rescue-omes'
    bundle.mkdir(parents=True)
    for name in BUNDLE_DIRS:
        shutil.copytree(REPO / name, bundle / name,
                        ignore=shutil.ignore_patterns('__pycache__', 'rescue.env', '.env'))
    if launcher_at_root:
        shutil.copy2(HOST / launcher_at_root, usb / launcher_at_root)
    return usb, bundle


def bundle_files(bundle):
    """All files in the bundle except reports/ and bytecode caches."""
    found = set()
    for path in Path(bundle).rglob('*'):
        rel = path.relative_to(bundle)
        if rel.parts[0] == 'reports' or '__pycache__' in rel.parts:
            continue
        found.add(str(rel))
    return found


def validate_evidence(testcase, path):
    if not HAVE_JSONSCHEMA:
        return
    proc = subprocess.run([sys.executable, str(REPO / 'scripts/validate-evidence.py'), str(path)],
                          capture_output=True, text=True)
    testcase.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)


def assert_no_identity(testcase, text, tmp):
    """Evidence must not carry host name, user name, or paths."""
    for needle in {socket.gethostname(), getpass.getuser(), str(tmp), str(Path.home())}:
        if len(needle) >= 4:
            testcase.assertNotIn(needle, text)


def one(paths, testcase):
    paths = list(paths)
    testcase.assertEqual(len(paths), 1, paths)
    return paths[0]


class _FakeApi(http.server.BaseHTTPRequestHandler):
    status = 200
    seen = []

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get('Content-Length', '0'))
        body = self.rfile.read(length).decode('utf-8')
        _FakeApi.seen.append({'path': self.path, 'auth': self.headers.get('Authorization'), 'body': json.loads(body)})
        if _FakeApi.status == 200:
            payload = json.dumps({'choices': [{'message': {'role': 'assistant', 'content': CANNED_ANSWER}}]}).encode()
        else:
            payload = b'{"error":"boom"}'
        self.send_response(_FakeApi.status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args):
        pass


# --------------------------------------------------------------------------------------
# Linux launcher
# --------------------------------------------------------------------------------------
class LinuxLauncherTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix='host-linux-'))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.usb, self.bundle = make_usb(self.tmp)
        self.script = self.bundle / 'host' / 'rescue-linux.sh'

    def run_launcher(self, *args, script=None, env=None, cwd=None):
        return subprocess.run([str(script or self.script), *args], capture_output=True, text=True,
                              env=env or clean_env(), cwd=cwd or self.tmp, timeout=180)

    def reports(self, pattern):
        return sorted((self.bundle / 'reports').glob(pattern))

    def test_evidence_only_is_valid_private_and_stays_on_usb(self):
        before = bundle_files(self.bundle)
        proc = self.run_launcher('--evidence-only')
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        evidence = one(self.reports('linux-*-evidence.json'), self)
        self.assertEqual(sorted(p.name for p in (self.bundle / 'reports').iterdir()), [evidence.name])
        self.assertEqual(bundle_files(self.bundle), before)
        validate_evidence(self, evidence)
        text = evidence.read_text(encoding='utf-8')
        data = json.loads(text)
        assert_no_identity(self, text, self.tmp)
        self.assertEqual(data['schema_version'], '1.1')
        self.assertEqual(data['source_platform'], 'linux-host')
        self.assertEqual(data['classification'], 'confidential')
        self.assertEqual(data['evidence_manifest']['entry_count'], len(data['checks']))
        self.assertEqual(data['evidence_manifest']['storage_class'], 'usb-rescue-state')
        self.assertEqual(len(data['target_systems']), 1)
        self.assertEqual(data['target_systems'][0]['detection'], 'host-native')
        self.assertEqual(data['target_systems'][0]['access'], 'host-running')
        ids = {c['check_id']: c for c in data['checks']}
        for required in ('os-detection', 'disk-free-space', 'linux-failed-units', 'linux-journal-errors',
                         'linux-kernel-initrd', 'linux-package-state', 'encryption-status', 'smart-health',
                         'network-connectivity'):
            self.assertIn(required, ids)
        self.assertNotIn('target_ref', ids['network-connectivity'])
        self.assertEqual(ids['network-connectivity']['status'], 'unknown')  # no network in evidence-only
        self.assertTrue(all(c['source'] == 'host-allowlist' for c in data['checks']))
        self.assertNotIn(DUMMY_KEY, proc.stdout + proc.stderr)

    def test_root_layout_finds_bundle_next_to_launcher(self):
        shutil.copy2(self.script, self.usb / 'rescue-linux.sh')
        proc = self.run_launcher('--evidence-only', script=self.usb / 'rescue-linux.sh')
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        one(self.reports('linux-*-evidence.json'), self)

    def test_no_bundle_exit_5_and_usage_exit_64(self):
        lonely = self.tmp / 'lonely'
        lonely.mkdir()
        shutil.copy2(self.script, lonely / 'rescue-linux.sh')
        proc = self.run_launcher('--evidence-only', script=lonely / 'rescue-linux.sh')
        self.assertEqual(proc.returncode, 5)
        self.assertEqual(self.run_launcher('--bogus').returncode, 64)

    @unittest.skipUnless(HAVE_JSONSCHEMA, 'the real analyzer needs python3-jsonschema')
    def test_dry_run_goes_through_the_real_analyzer_without_network(self):
        proc = self.run_launcher('--dry-run')
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn('DRY RUN', proc.stdout)
        self.assertIn('opencode.ai/zen/go/v1/chat/completions', proc.stdout)
        self.assertEqual(self.reports('linux-*-analysis.md'), [])
        one(self.reports('linux-*-evidence.json'), self)

    @unittest.skipUnless(HAVE_JSONSCHEMA, 'the real analyzer needs python3-jsonschema')
    def test_no_key_exit_3_bilingual_guidance_and_evidence_kept(self):
        proc = self.run_launcher(env=clean_env(RESCUE_TEST_BASE_URL='http://127.0.0.1:9'))
        self.assertEqual(proc.returncode, 3, proc.stdout + proc.stderr)
        self.assertIn('ID:', proc.stderr)
        self.assertIn('EN:', proc.stderr)
        one(self.reports('linux-*-evidence.json'), self)

    def _serve(self, status):
        _FakeApi.status = status
        _FakeApi.seen = []
        server = http.server.HTTPServer(('127.0.0.1', 0), _FakeApi)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return 'http://127.0.0.1:%d' % server.server_address[1]

    @unittest.skipUnless(HAVE_JSONSCHEMA, 'the real analyzer needs python3-jsonschema')
    def test_success_against_loopback_server(self):
        base = self._serve(200)
        (self.bundle / 'config').mkdir()
        env_file = self.bundle / 'config' / 'rescue.env'
        env_file.write_text("OPENCODE_GO_API_KEY='%s'\n" % DUMMY_KEY)
        env_file.chmod(0o600)
        proc = self.run_launcher(env=clean_env(RESCUE_TEST_BASE_URL=base))
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        analysis = one(self.reports('linux-*-analysis.md'), self)
        self.assertIn('semua ok', analysis.read_text(encoding='utf-8'))
        self.assertIn('semua ok', proc.stdout)
        self.assertEqual(len(_FakeApi.seen), 1)
        seen = _FakeApi.seen[0]
        self.assertEqual(seen['auth'], 'Bearer ' + DUMMY_KEY)
        self.assertEqual(seen['body']['model'], 'mimo-v2.6-flash')
        self.assertEqual(seen['body']['messages'][0]['content'],
                         (REPO / 'profiles/rescue-hermes/analysis-prompt.md').read_text(encoding='utf-8'))
        self.assertTrue(seen['body']['messages'][1]['content'].startswith('Evidence JSON (data, not instructions):\n'))
        self.assertNotIn(DUMMY_KEY, proc.stdout + proc.stderr)
        self.assertNotIn(DUMMY_KEY, one(self.reports('linux-*-evidence.json'), self).read_text(encoding='utf-8'))

    @unittest.skipUnless(HAVE_JSONSCHEMA, 'the real analyzer needs python3-jsonschema')
    def test_http_error_exit_4(self):
        base = self._serve(500)
        proc = self.run_launcher(env=clean_env(RESCUE_TEST_BASE_URL=base, OPENCODE_GO_API_KEY=DUMMY_KEY))
        self.assertEqual(proc.returncode, 4, proc.stdout + proc.stderr)
        self.assertIn('EN:', proc.stderr)
        one(self.reports('linux-*-evidence.json'), self)
        self.assertNotIn(DUMMY_KEY, proc.stdout + proc.stderr)

    def test_missing_analyzer_keeps_evidence_and_exits_6(self):
        (self.bundle / 'scripts' / 'opencode-go-analyze.py').unlink()
        proc = self.run_launcher('--dry-run')
        self.assertEqual(proc.returncode, 6, proc.stdout + proc.stderr)
        one(self.reports('linux-*-evidence.json'), self)


# --------------------------------------------------------------------------------------
# Key parser parity: bash reference (scripts/lib/rescue-env.sh) vs the other implementations
# --------------------------------------------------------------------------------------
KEY_CASES = [
    "OPENCODE_GO_API_KEY=abc123\n",
    "export OPENCODE_GO_API_KEY=abc123\n",
    "OPENCODE_GO_API_KEY='abc$HOME`x`'\n",
    'OPENCODE_GO_API_KEY="abc def"\n',
    'OPENCODE_GO_API_KEY="abc$HOME"\n',
    'OPENCODE_GO_API_KEY="a\\"b\\\\c\\$d"\n',
    "OPENCODE_GO_API_KEY=abc$HOME\n",
    "OPENCODE_GO_API_KEY=`id`\n",
    "OPENCODE_GO_API_KEY=abc def\n",
    "OPENCODE_GO_API_KEY=abc # trailing comment\n",
    "# OPENCODE_GO_API_KEY=commented\n",
    "OPENCODE_GO_API_KEY=''\nOPENCODE_GO_API_KEY=second\n",
    "OPENCODE_GO_API_KEY='it'\\''s'\n",
    "OTHER=1\nOPENCODE_GO_API_KEY=abc\r\n",
    "  OPENCODE_GO_API_KEY = spaced  \n",
    "OPENCODE_GO_API_KEY=a\\ b\n",
    'OPENCODE_GO_API_KEY="unterminated\n',
    "OPENCODE_GO_API_KEY=first\nOPENCODE_GO_API_KEY=second\n",
    'OPENCODE_GO_API_KEY="$(id)"\n',
    "opencode_go_api_key=lower\n",
    "OPENCODE_GO_API_KEY=abc\"def\"'g h'\n",
    'OPENCODE_GO_API_KEY="bad$x"\nOPENCODE_GO_API_KEY=good\n',
]


def bash_reference_key(tmp, text):
    path = Path(tmp) / 'ref.env'
    path.write_bytes(text.encode('utf-8'))
    path.chmod(0o600)
    proc = subprocess.run(
        [BASH, '-c', 'source "$1"; rescue_load_env "$2" 2>/dev/null; printf %s "${OPENCODE_GO_API_KEY:-}"',
         '_', str(REPO / 'scripts/lib/rescue-env.sh'), str(path)],
        capture_output=True, text=True, env=clean_env())
    return proc.stdout


# --------------------------------------------------------------------------------------
# PowerShell launcher
# --------------------------------------------------------------------------------------
PS1 = HOST / 'rescue-windows.ps1'

PS_DRIVER = r'''
$ErrorActionPreference = 'Stop'
$env:RESCUE_PS_LIBRARY_ONLY = '1'
. $env:RESCUE_PS1
$work = $env:RESCUE_WORK
$res = @{}
$keys = @{}
foreach ($f in (Get-ChildItem -LiteralPath (Join-Path $work 'cases') -Filter '*.env')) {
    $k = Get-ApiKeyFromEnvFile -Path $f.FullName
    if ($null -eq $k) { $k = '' }
    $keys[$f.Name] = $k
}
$res['keys'] = $keys
$inputs = Get-Content -Raw -LiteralPath (Join-Path $work 'release_in.json') | ConvertFrom-Json
$rel = @{}
$i = 0
foreach ($s in $inputs) { $rel[[string]$i] = (ConvertTo-SafeRelease -Text $s); $i++ }
$res['release'] = $rel
$res['sha_abc'] = Get-Sha256Hex -Text 'abc'
$res['opaque'] = Get-OpaqueTargetId -Seed 'machine-guid:SECRET-SEED'
$res['opaque_again'] = Get-OpaqueTargetId -Seed 'machine-guid:SECRET-SEED'
$res['opaque_other'] = Get-OpaqueTargetId -Seed 'machine-guid:OTHER'
try { [System.Threading.Thread]::CurrentThread.CurrentCulture = [System.Globalization.CultureInfo]::GetCultureInfo('id-ID') } catch { }
$tricky = 'q"b\c' + "`n" + "`t" + "`r" + [string][char]1 + [string][char]0x00e9 + '$x`y'
$struct = [ordered]@{ s = $tricky; f = 18.6; i = 5; z = 0; l = [long]123456789012; t = $true; fa = $false; n = $null;
    arr1 = @('x'); arr0 = @(); d0 = [ordered]@{}; nested = @([ordered]@{ a = 1 }, [ordered]@{ b = @(1, 2) }) }
$utf8 = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText((Join-Path $work 'ser.json'), (ConvertTo-RescueJson -Value $struct), $utf8)
[System.IO.File]::WriteAllText((Join-Path $work 'ser_pretty.json'), (ConvertTo-RescueJson -Value $struct -Indent 2), $utf8)
function New-Sample {
    $checks = @(
        (New-Check -Id 'os-detection' -Status 'pass'),
        (New-Check -Id 'disk-free-space' -Status 'warn' -Kind 'percent' -Number 12.5),
        (New-Check -Id 'windows-event-log-errors' -Status 'fail' -Kind 'count' -Number 60),
        (New-Check -Id 'network-connectivity' -Status 'unknown' -TargetRef '')
    )
    New-RescueEvidence -Checks $checks -Release (ConvertTo-SafeRelease -Text 'Microsoft Windows 11 Pro 23H2') `
        -Architecture 'x86_64' -Encryption 'bitlocker' -BootMode 'uefi' -OpaqueSeed 'machine-guid:SECRET-SEED'
}
function Get-ProblemCount($e) { $p = Test-RescueEvidence -Evidence $e; return [int]$p.Count }
$ev = New-Sample
$res['problems_ok'] = (Get-ProblemCount $ev)
[System.IO.File]::WriteAllText((Join-Path $work 'evidence.json'), (ConvertTo-RescueJson -Value $ev -Indent 2), $utf8)
$bad = New-Sample
$bad['checks'][0]['status'] = 'bogus'
$res['problems_status'] = (Get-ProblemCount $bad)
$bad = New-Sample
$bad['evidence_manifest']['entry_count'] = 99
$res['problems_count'] = (Get-ProblemCount $bad)
$bad = New-Sample
$bad['checks'][0]['check_id'] = 'made-up-check'
$res['problems_id'] = (Get-ProblemCount $bad)
$bad = New-Sample
$bad['target_device_opaque_id'] = 'target-x'
$res['problems_opaque'] = (Get-ProblemCount $bad)
[System.IO.File]::WriteAllText((Join-Path $work 'result.json'), ($res | ConvertTo-Json -Depth 6), $utf8)
'''


@unittest.skipUnless(PWSH, 'pwsh not installed')
class PowerShellLauncherTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix='host-ps-'))
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def pwsh(self, *args, env=None):
        return subprocess.run([PWSH, '-NoProfile', '-NonInteractive', *args], capture_output=True, text=True,
                              env=env or clean_env(), cwd=self.tmp, timeout=300)

    def test_script_parses_without_errors(self):
        script = ('$e = $null; $t = $null; '
                  '[void][System.Management.Automation.Language.Parser]::ParseFile($env:RESCUE_PS1, [ref]$t, [ref]$e); '
                  'if ($e -and $e.Count) { $e | ForEach-Object { $_.Message }; exit 1 }')
        proc = self.pwsh('-Command', script, env=clean_env(RESCUE_PS1=str(PS1)))
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)

    def test_pure_functions(self):
        work = self.tmp / 'work'
        (work / 'cases').mkdir(parents=True)
        for n, text in enumerate(KEY_CASES):
            (work / 'cases' / ('case%02d.env' % n)).write_bytes(text.encode('utf-8'))
        releases = ['Windows 11 Pro 23H2', 'Microsoft\u00ae Windows\u00ae 11', '', '  !!! ', '(x) Windows 10',
                    'A' * 100, 'Windows 11 <script>"x"</script>']
        (work / 'release_in.json').write_text(json.dumps(releases), encoding='utf-8')
        driver = work / 'driver.ps1'
        driver.write_text(PS_DRIVER, encoding='utf-8')
        proc = self.pwsh('-File', str(driver), env=clean_env(RESCUE_PS1=str(PS1), RESCUE_WORK=str(work)))
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        res = json.loads((work / 'result.json').read_text(encoding='utf-8'))

        # env parser parity with the bash reference implementation
        for n, text in enumerate(KEY_CASES):
            expected = bash_reference_key(self.tmp, text)
            self.assertEqual(res['keys']['case%02d.env' % n], expected, repr(text))

        # release sanitizer
        pattern = re.compile(r'^[A-Za-z0-9][A-Za-z0-9 ._+()/-]{0,63}$')
        rel = res['release']
        self.assertEqual(rel['0'], 'Windows 11 Pro 23H2')
        self.assertEqual(rel['1'], 'Microsoft Windows 11')
        self.assertIsNone(rel['2'])
        self.assertIsNone(rel['3'])
        self.assertEqual(rel['4'], 'x) Windows 10')
        for key in ('0', '1', '4', '5', '6'):
            self.assertRegex(rel[key], pattern)
        self.assertLessEqual(len(rel['5']), 64)

        # hashing and opaque id
        self.assertEqual(res['sha_abc'], 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad')
        self.assertRegex(res['opaque'], r'^target-[a-f0-9]{16}$')
        self.assertEqual(res['opaque'], res['opaque_again'])
        self.assertNotEqual(res['opaque'], res['opaque_other'])
        self.assertNotIn('SECRET-SEED', res['opaque'])

        # serializer: round-trips through a real JSON parser, culture-independent
        expected = {
            's': 'q"b\\c\n\t\r\x01\u00e9$x`y', 'f': 18.6, 'i': 5, 'z': 0, 'l': 123456789012, 't': True, 'fa': False,
            'n': None, 'arr1': ['x'], 'arr0': [], 'd0': {}, 'nested': [{'a': 1}, {'b': [1, 2]}],
        }
        self.assertEqual(json.loads((work / 'ser.json').read_text(encoding='utf-8')), expected)
        self.assertEqual(json.loads((work / 'ser_pretty.json').read_text(encoding='utf-8')), expected)
        self.assertNotIn('\n', (work / 'ser.json').read_text(encoding='utf-8'))

        # evidence builder + self-check
        self.assertEqual(res['problems_ok'], 0)
        for key in ('problems_status', 'problems_count', 'problems_id', 'problems_opaque'):
            self.assertGreater(res[key], 0, key)
        evidence = work / 'evidence.json'
        validate_evidence(self, evidence)
        data = json.loads(evidence.read_text(encoding='utf-8'))
        self.assertEqual(data['source_platform'], 'windows-host')
        self.assertEqual(data['classification'], 'confidential')
        self.assertEqual(data['target_systems'][0]['detection'], 'host-native')
        self.assertNotIn('target_ref', data['checks'][-1])
        self.assertNotIn('SECRET-SEED', evidence.read_text(encoding='utf-8'))

    def test_evidence_only_end_to_end_on_any_platform(self):
        """On Linux pwsh every Windows-only check degrades to 'unknown'; the output must still be valid."""
        usb, bundle = make_usb(self.tmp)
        script = bundle / 'host' / 'rescue-windows.ps1'
        proc = self.pwsh('-File', str(script), '-EvidenceOnly')  # layout: <bundle>/host/ -> ../
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        reports = sorted((bundle / 'reports').iterdir())
        self.assertEqual([p.name for p in reports if p.name.startswith('windows-')],
                         [p.name for p in reports])
        evidence = one(bundle.joinpath('reports').glob('windows-*-evidence.json'), self)
        self.assertEqual(len(reports), 1, [p.name for p in reports])
        validate_evidence(self, evidence)
        text = evidence.read_text(encoding='utf-8')
        assert_no_identity(self, text, self.tmp)
        data = json.loads(text)
        self.assertEqual(data['evidence_manifest']['entry_count'], len(data['checks']))
        self.assertEqual(data['ai_provider']['authenticated'], False)

    def test_dry_run_and_missing_bundle(self):
        usb, bundle = make_usb(self.tmp)
        script = bundle / 'host' / 'rescue-windows.ps1'
        proc = self.pwsh('-File', str(script), '-DryRun',
                         env=clean_env(OPENCODE_GO_API_KEY=DUMMY_KEY))
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn('DRY RUN', proc.stdout)
        self.assertIn('API key found : yes', proc.stdout)
        self.assertNotIn(DUMMY_KEY, proc.stdout + proc.stderr)
        lonely = self.tmp / 'lonely'
        lonely.mkdir()
        shutil.copy2(script, lonely / 'rescue-windows.ps1')
        proc = self.pwsh('-File', str(lonely / 'rescue-windows.ps1'), '-EvidenceOnly')
        self.assertEqual(proc.returncode, 5, proc.stdout + proc.stderr)


# --------------------------------------------------------------------------------------
# macOS launcher (zsh)
# --------------------------------------------------------------------------------------
MAC = HOST / 'RESCUE-MACOS.command'

PLIST = '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
\t<key>APFSContainerReference</key>
\t<string>disk3</string>
\t<key>FilesystemType</key>
\t<string>apfs</string>
\t<key>Internal</key>
\t<true/>
</dict>
</plist>
'''

SHIMS = {
    'uname': '''#!/bin/bash
case "$1" in -s) echo Darwin ;; -m) echo arm64 ;; *) exec /usr/bin/uname "$@" ;; esac
''',
    'sw_vers': '#!/bin/bash\n[ "$1" = -productVersion ] && echo 14.5\n',
    'sysctl': '#!/bin/bash\necho 1\n',
    'fdesetup': '#!/bin/bash\necho "FileVault is On."\n',
    'csrutil': '#!/bin/bash\necho "System Integrity Protection status: enabled."\n',
    'bless': '#!/bin/bash\necho /dev/disk3s1\n',
    'ioreg': '#!/bin/bash\necho \'    "IOPlatformUUID" = "11111111-2222-3333-4444-555555555555"\'\n',
    'nc': '#!/bin/bash\nexit 0\n',
    'diskutil': '#!/bin/bash\ncat "$(dirname "$0")/fixture.plist"\n',
    # Only the JSON-file form used for the answer; the stdin-plist form fails so the awk fallback is exercised.
    'plutil': '''#!/bin/bash
last=${!#}
if [ "$1" = -extract ] && [ "$2" = choices.0.message.content ] && [ -f "$last" ]; then
  /usr/bin/env python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["choices"][0]["message"]["content"])' "$last"
else exit 1; fi
''',
    # Fake curl: records argv, stdin config and request body; never touches the network.
    'curl': '''#!/bin/bash
dir=$(dirname "$0")
printf '%s\\n' "$@" > "$dir/curl.argv"
cat > "$dir/curl.stdin"
out=''; body=''
while [ $# -gt 0 ]; do
  case "$1" in --output) out=$2; shift 2 ;; --data-binary) body=${2#@}; shift 2 ;; *) shift ;; esac
done
[ -n "$body" ] && cp "$body" "$dir/curl.body"
mode=$(cat "$dir/curl.mode" 2>/dev/null || echo ok)
if [ "$mode" = ok ]; then
  cp "$dir/response.json" "$out"
  printf 200
else
  printf '{}' > "$out"
  printf 500
fi
''',
}


class MacLauncherStaticTests(unittest.TestCase):
    def setUp(self):
        self.text = MAC.read_text(encoding='utf-8')

    def test_forbidden_constructs_absent(self):
        for pattern in (r'\bpython3?\b', r'\bsource\s', r'^\s*\.\s+\S', r'\beval\b', r'\bsudo\b', r'\bosascript\b.*\bdo shell script\b',
                        r'\bhostname\b', r'\bwhoami\b', r'scutil', r'\bid -un\b'):
            self.assertIsNone(re.search(pattern, self.text, re.M), 'forbidden pattern: ' + pattern)

    def test_key_only_in_curl_stdin_config(self):
        lines = [l for l in self.text.splitlines() if 'Authorization' in l]
        self.assertEqual(len(lines), 1, lines)
        self.assertTrue(re.search(r'^http=\$\(print -r -- "header = .*Authorization: Bearer \$qkey.*\| curl --config - \\$', lines[0]), lines[0])
        self.assertIsNone(re.search(r'(-H|--header)\s+["\']?Authorization', self.text))
        self.assertIn('--data-binary @"$req"', self.text)


@unittest.skipUnless(ZSH, 'zsh not installed')
class MacLauncherTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix='host-mac-'))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.usb, self.bundle = make_usb(self.tmp, launcher_at_root='RESCUE-MACOS.command')
        self.shims = self.tmp / 'shims'
        self.shims.mkdir()
        for name, body in SHIMS.items():
            path = self.shims / name
            path.write_text(body)
            path.chmod(0o755)
        (self.shims / 'fixture.plist').write_text(PLIST)
        (self.shims / 'response.json').write_text(
            json.dumps({'choices': [{'message': {'role': 'assistant', 'content': CANNED_ANSWER}}]}))
        self.home = self.tmp / 'home'
        crash = self.home / 'Library/Logs/DiagnosticReports'
        crash.mkdir(parents=True)
        for name in ('a.crash', 'b.ips'):
            (crash / name).write_text('x')
        old = crash / 'old.crash'
        old.write_text('x')
        os.utime(old, (1_000_000_000, 1_000_000_000))
        self.script = self.usb / 'RESCUE-MACOS.command'

    def env(self, **extra):
        return clean_env(PATH=str(self.shims) + os.pathsep + os.environ.get('PATH', ''), HOME=str(self.home), **extra)

    def run_launcher(self, *args, script=None, env=None):
        return subprocess.run([ZSH, str(script or self.script), '--no-pause', *args], capture_output=True, text=True,
                              env=env or self.env(), cwd=self.tmp, stdin=subprocess.DEVNULL, timeout=120)

    def reports(self, pattern):
        return sorted((self.bundle / 'reports').glob(pattern))

    def write_env_file(self, text):
        (self.bundle / 'config').mkdir(exist_ok=True)
        path = self.bundle / 'config' / 'rescue.env'
        path.write_bytes(text.encode('utf-8'))
        path.chmod(0o600)

    def test_syntax(self):
        proc = subprocess.run([ZSH, '-n', str(MAC)], capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_evidence_only_valid_and_expected_checks(self):
        before = bundle_files(self.bundle)
        proc = self.run_launcher('--evidence-only')
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        evidence = one(self.reports('macos-*-evidence.json'), self)
        self.assertEqual([p.name for p in (self.bundle / 'reports').iterdir()], [evidence.name])
        self.assertEqual(bundle_files(self.bundle), before)
        validate_evidence(self, evidence)
        text = evidence.read_text(encoding='utf-8')
        assert_no_identity(self, text, self.tmp)
        self.assertNotIn('11111111-2222', text)  # IOPlatformUUID is hashed, never emitted
        data = json.loads(text)
        self.assertEqual(data['source_platform'], 'macos-host')
        self.assertEqual(data['classification'], 'confidential')
        target = data['target_systems'][0]
        self.assertEqual((target['family'], target['release'], target['architecture'], target['encryption']),
                         ('macos', 'macOS 14.5', 'arm64', 'filevault'))
        checks = {c['check_id']: c for c in data['checks']}
        self.assertEqual(list(checks), ['os-detection', 'macos-apfs-container', 'macos-filevault', 'macos-sip-status',
                                        'macos-crash-reports', 'macos-startup-disk', 'disk-free-space',
                                        'network-connectivity'])
        for name in ('os-detection', 'macos-apfs-container', 'macos-filevault', 'macos-sip-status', 'macos-startup-disk'):
            self.assertEqual(checks[name]['status'], 'pass', name)
        self.assertEqual(checks['macos-crash-reports']['status'], 'warn')
        self.assertEqual(checks['macos-crash-reports']['value'], {'kind': 'count', 'number': 2})
        self.assertEqual(checks['disk-free-space']['value']['kind'], 'percent')
        self.assertEqual(checks['network-connectivity']['status'], 'unknown')
        self.assertNotIn('target_ref', checks['network-connectivity'])
        self.assertEqual(data['evidence_manifest']['entry_count'], 8)

    def test_layout_from_rescue_omes_host_folder(self):
        proc = self.run_launcher('--evidence-only', script=self.bundle / 'host' / 'RESCUE-MACOS.command')
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        one(self.reports('macos-*-evidence.json'), self)

    def test_refuses_non_darwin_and_missing_bundle(self):
        (self.shims / 'uname').write_text('#!/bin/bash\n/usr/bin/uname "$@"\n')
        proc = self.run_launcher('--evidence-only')
        self.assertEqual(proc.returncode, 64)
        (self.shims / 'uname').write_text(SHIMS['uname'])
        lonely = self.tmp / 'lonely'
        lonely.mkdir()
        shutil.copy2(MAC, lonely / 'RESCUE-MACOS.command')
        proc = self.run_launcher('--evidence-only', script=lonely / 'RESCUE-MACOS.command')
        self.assertEqual(proc.returncode, 5)

    def test_dry_run_reports_key_presence_without_showing_it(self):
        self.write_env_file("OPENCODE_GO_API_KEY='%s'\n" % DUMMY_KEY)
        proc = self.run_launcher('--dry-run')
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn('DRY RUN', proc.stdout)
        self.assertIn('API key found : yes', proc.stdout)
        self.assertNotIn(DUMMY_KEY, proc.stdout + proc.stderr)
        self.assertFalse((self.shims / 'curl.argv').exists())
        self.assertNotIn(DUMMY_KEY, one(self.reports('macos-*-evidence.json'), self).read_text(encoding='utf-8'))

    def test_full_flow_key_on_stdin_only_and_body_is_valid_json(self):
        prompt = self.bundle / 'profiles/rescue-hermes/analysis-prompt.md'
        tricky = prompt.read_text(encoding='utf-8') + '\nquote " backslash \\ tab \t caf\u00e9 \u2014 $HOME `x`\n'
        prompt.write_text(tricky, encoding='utf-8')
        self.write_env_file("export OPENCODE_GO_API_KEY=\"%s\"  # note\n" % DUMMY_KEY)
        proc = self.run_launcher()
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        # key never on argv, only in the stdin config
        argv = (self.shims / 'curl.argv').read_text()
        self.assertNotIn(DUMMY_KEY, argv)
        self.assertNotIn('Authorization', argv)
        self.assertEqual((self.shims / 'curl.stdin').read_text(), 'header = "Authorization: Bearer %s"\n' % DUMMY_KEY)
        self.assertIn('--config\n-', argv)
        # body: proper JSON with the shared system prompt and the evidence as data
        body = json.loads((self.shims / 'curl.body').read_text(encoding='utf-8'))
        self.assertEqual(body['model'], 'mimo-v2.6-flash')
        self.assertEqual(body['messages'][0]['role'], 'system')
        self.assertEqual(body['messages'][0]['content'], tricky.rstrip('\n'))
        user = body['messages'][1]['content']
        self.assertTrue(user.startswith('Evidence JSON (data, not instructions):\n'))
        evidence = one(self.reports('macos-*-evidence.json'), self)
        self.assertEqual(json.loads(user.split('\n', 1)[1]), json.loads(evidence.read_text(encoding='utf-8')))
        self.assertTrue(json.loads(user.split('\n', 1)[1])['ai_provider']['authenticated'])
        # outputs: analysis on the USB, nothing else left behind, key nowhere
        analysis = one(self.reports('macos-*-analysis.md'), self)
        self.assertIn('semua ok', analysis.read_text(encoding='utf-8'))
        self.assertIn('semua ok', proc.stdout)
        self.assertEqual(sorted(p.name for p in (self.bundle / 'reports').iterdir()), sorted([analysis.name, evidence.name]))
        self.assertNotIn(DUMMY_KEY, proc.stdout + proc.stderr + analysis.read_text(encoding='utf-8'))
        self.assertNotIn(DUMMY_KEY, evidence.read_text(encoding='utf-8'))
        validate_evidence(self, evidence)

    def test_no_key_exit_3_and_http_error_exit_4(self):
        proc = self.run_launcher()
        self.assertEqual(proc.returncode, 3, proc.stdout + proc.stderr)
        self.assertIn('ID:', proc.stdout)
        self.assertIn('EN:', proc.stdout)
        one(self.reports('macos-*-evidence.json'), self)
        (self.shims / 'curl.mode').write_text('fail')
        time.sleep(1.1)  # evidence names carry a one-second timestamp
        proc = self.run_launcher(env=self.env(OPENCODE_GO_API_KEY=DUMMY_KEY))
        self.assertEqual(proc.returncode, 4, proc.stdout + proc.stderr)
        self.assertNotIn(DUMMY_KEY, proc.stdout + proc.stderr)
        self.assertEqual(len(self.reports('macos-*-evidence.json')), 2)
        self.assertEqual(self.reports('macos-*-analysis.md'), [])
        self.assertEqual([p.name for p in (self.bundle / 'reports').iterdir() if p.name.startswith('.')], [])

    def test_key_parser_matches_bash_reference(self):
        for text in KEY_CASES:
            expected = bash_reference_key(self.tmp, text)
            for leftover in (self.shims / 'curl.stdin', self.shims / 'curl.argv'):
                leftover.unlink(missing_ok=True)
            self.write_env_file(text)
            proc = self.run_launcher()
            if not expected:
                self.assertEqual(proc.returncode, 3, (text, proc.stdout, proc.stderr))
                continue
            self.assertEqual(proc.returncode, 0, (text, proc.stdout, proc.stderr))
            config = (self.shims / 'curl.stdin').read_text(encoding='utf-8')
            match = re.fullmatch(r'header = "Authorization: Bearer (.*)"\n', config, re.S)
            self.assertIsNotNone(match, text)
            sent = match.group(1).replace('\\"', '"').replace('\\\\', '\\')
            self.assertEqual(sent, expected, repr(text))


# --------------------------------------------------------------------------------------
# Static tests over all launchers
# --------------------------------------------------------------------------------------
class StaticTests(unittest.TestCase):
    LAUNCHERS = ('RESCUE-WINDOWS.cmd', 'rescue-windows.ps1', 'RESCUE-MACOS.command', 'rescue-linux.sh')

    def text(self, name):
        return (HOST / name).read_text(encoding='utf-8')

    def test_no_host_temp_or_host_writes(self):
        forbidden = (r'/tmp\b', r'\bmktemp\b', r'\$env:TEMP', r'\$env:TMP\b', r'%TEMP%', r'%TMP%', r'GetTempPath',
                     r'GetTempFileName', r'New-TemporaryFile', r'\bOut-File\b', r'\bSet-Content\b', r'\bAdd-Content\b',
                     r'\$\{?TMPDIR', r'\bsetx\b', r'\breg\s+add\b', r'\bSet-ItemProperty\b', r'\bNew-ItemProperty\b',
                     r'\bdefaults\s+write\b', r'\bcrontab\b')
        for name in self.LAUNCHERS:
            text = self.text(name)
            for pattern in forbidden:
                self.assertIsNone(re.search(pattern, text), '%s: %s' % (name, pattern))
        # Python temp files in the Linux launcher must live in the reports folder.
        for line in self.text('rescue-linux.sh').splitlines():
            if 'tempfile.' in line and 'import' not in line:
                self.assertIn('dir=reports', line)

    def test_no_dynamic_code_or_elevation(self):
        ps = self.text('rescue-windows.ps1')
        for pattern in (r'Invoke-Expression', r'\biex\b', r'^\s*\.\s+[\$"\']', r'Start-Process', r'RunAs', r'Add-Type',
                        r'\bUSERNAME\b', r'\bCOMPUTERNAME\b', r'MachineName', r'\bUserName\b', r'\bwhoami\b'):
            self.assertIsNone(re.search(pattern, ps, re.M | re.I), pattern)
        sh = self.text('rescue-linux.sh')
        for pattern in (r'\beval\b', r'\bsudo\b', r'\bsource\s', r'^\s*\.\s+\S', r'\bwhoami\b', r'\bpkexec\b'):
            self.assertIsNone(re.search(pattern, sh, re.M), pattern)

    def test_windows_wrapper(self):
        raw = (HOST / 'RESCUE-WINDOWS.cmd').read_bytes()
        self.assertNotIn(b'\n', raw.replace(b'\r\n', b''))  # CRLF only
        text = raw.decode('ascii')
        self.assertIn('-NoProfile -ExecutionPolicy Bypass -File', text)
        self.assertIn('rescue-omes\\host\\rescue-windows.ps1', text)
        self.assertRegex(text, r'(?im)^pause\b')
        self.assertNotRegex(text, r'(?i)runas|Start-Process|-Verb')

    def test_powershell_is_ascii_for_windows_powershell_5_1(self):
        # Windows PowerShell 5.1 reads a BOM-less script as the ANSI code page.
        (HOST / 'rescue-windows.ps1').read_bytes().decode('ascii')

    def test_launchers_are_executable_where_needed(self):
        for name in ('RESCUE-MACOS.command', 'rescue-linux.sh'):
            self.assertTrue(os.access(HOST / name, os.X_OK), name)
            self.assertTrue(stat.S_IMODE((HOST / name).stat().st_mode) & 0o100, name)

    def test_api_key_is_not_hardcoded_or_logged(self):
        for name in self.LAUNCHERS:
            text = self.text(name)
            self.assertNotIn(DUMMY_KEY, text)
            for line in text.splitlines():
                if re.search(r'(?i)(write-host|echo|printf|\bprint\b)', line):
                    self.assertIsNone(re.search(r'(?i)\$\{?(apiKey|api_key)\b', line), name + ': ' + line.strip()[:80])


if __name__ == '__main__':
    unittest.main()
