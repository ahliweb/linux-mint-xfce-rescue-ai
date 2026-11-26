#!/usr/bin/env python3
"""Build and check the deterministic signed-skills bundle (never signs; see scripts/sign-skills-bundle.sh).

Managed by ahlikoding.com and satpamsiber.com under ahliweb.com.

  build-skills-bundle.py build [--output-dir DIR]     write rescue-skills-<V>.tar.gz and .manifest.json
  build-skills-bundle.py check --manifest FILE [--tarball FILE]
                                                      validate the format and every hash, in memory
  build-skills-bundle.py signers-status [--file FILE] print placeholder, pinned or invalid

Exit codes: 0 ok | 1 refused (bad bundle, placeholder or invalid signers) | 2 usage error
"""
import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts' / 'lib'))
import skills_bundle as sb  # noqa: E402


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest='cmd', required=True)
    b = sub.add_parser('build')
    b.add_argument('--output-dir', default=str(ROOT / 'dist'))
    b.add_argument('--skills-dir', default=str(ROOT / 'profiles' / 'rescue-hermes' / 'skills'))
    b.add_argument('--version-file', default=str(ROOT / 'VERSION'))
    b.add_argument('--min-toolkit-file', default=str(ROOT / 'config' / 'skills-min-toolkit'))
    c = sub.add_parser('check')
    c.add_argument('--manifest', required=True)
    c.add_argument('--tarball')
    s = sub.add_parser('signers-status')
    s.add_argument('--file', default=str(ROOT / 'config' / 'skills-allowed-signers'))
    args = ap.parse_args(argv)
    try:
        if args.cmd == 'build':
            version = Path(args.version_file).read_text(encoding='utf-8').strip()
            min_toolkit = Path(args.min_toolkit_file).read_text(encoding='utf-8').strip()
            tar_path, man_path = sb.build(Path(args.skills_dir), version, min_toolkit, Path(args.output_dir))
            sb.check_bundle(man_path, tar_path)
            print(f'built {tar_path}\nbuilt {man_path}')
        elif args.cmd == 'check':
            man = Path(args.manifest)
            manifest = sb.parse_manifest(man.read_bytes())
            tar_path = Path(args.tarball) if args.tarball else man.parent / manifest['tarball']['name']
            manifest = sb.check_bundle(man, tar_path)
            print(f"bundle ok: version {manifest['bundle_version']}, {len(manifest['files'])} skills, "
                  f"min toolkit {manifest['min_toolkit_version']}")
        else:
            state, detail = sb.allowed_signers_state(Path(args.file).read_text(encoding='utf-8'))
            print(f'{state}: {detail}')
            return 0 if state == 'pinned' else 1
    except (sb.BundleError, OSError) as exc:
        print(f'refused: {exc}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
