#!/usr/bin/env python3
"""Verified Hermes skill update: newest owner-signed skills bundle, skill text only, fail closed.

Managed by ahlikoding.com and satpamsiber.com under ahliweb.com. Design and threat model: docs/skill-update.md.

  update-skills.py --hermes-home DIR [--reports-dir DIR] [--toolkit-root DIR] [--mode auto|off] [--offline] [--json]

The launchers call this right before Hermes opens. It never blocks Hermes: the exit code is only a signal and
every launcher ignores it. The pinned allowed_signers file is read from the INSTALLED toolkit
(<toolkit-root>/config/skills-allowed-signers), never from a download.

Exit codes: 0 updated, current, or deliberately skipped (off, no ssh-keygen, offline, toolkit too old)
            1 refused or failed (placeholder signers, bad signature, rollback, bad bundle, install error)
            2 usage error
Test-only options (the launchers never pass them): --release-api-base, --release-download-base, --allowed-signers.
"""
import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts' / 'lib'))
import skills_update as su  # noqa: E402


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--hermes-home', required=True)
    ap.add_argument('--reports-dir')
    ap.add_argument('--toolkit-root', default=str(ROOT))
    ap.add_argument('--mode', choices=['auto', 'off'])
    ap.add_argument('--offline', action='store_true', help='record "offline" without touching the network')
    ap.add_argument('--json', action='store_true', help='print one JSON line instead of the operator message')
    ap.add_argument('--release-api-base', help=argparse.SUPPRESS)
    ap.add_argument('--release-download-base', help=argparse.SUPPRESS)
    ap.add_argument('--allowed-signers', help=argparse.SUPPRESS)
    args = ap.parse_args(argv)
    fetcher = None
    if args.release_api_base or args.release_download_base:
        fetcher = su.Fetcher(api_base=args.release_api_base or su.DEFAULT_API_BASE,
                             download_base=args.release_download_base or su.DEFAULT_DOWNLOAD_BASE)
    result = su.run_update(
        Path(args.toolkit_root), Path(args.hermes_home), Path(args.reports_dir) if args.reports_dir else None,
        mode=args.mode, offline=args.offline, fetcher=fetcher,
        signers_path=Path(args.allowed_signers) if args.allowed_signers else None)
    if args.json:
        print(json.dumps({'status': result.status, 'reason': result.reason, 'bundle_version': result.bundle_version,
                          'installed_version': result.installed_version, 'signer': result.signer,
                          'skills': result.skills}, sort_keys=True))
    else:
        print(result.message)
    return 0 if result.ok else 1


if __name__ == '__main__':
    sys.exit(main())
