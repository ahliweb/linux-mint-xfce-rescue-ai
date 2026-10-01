"""Quarantine manifest on the rescue USB: append-only JSONL of events, read helpers.

Managed by ahlikoding.com and satpamsiber.com under ahliweb.com. Design: docs/malware.md.

``<state>/quarantine/manifest.jsonl`` (0600) records one JSON object per line:

  {"event": "quarantine", "id": "q-...", "time": "...Z", "root_kind": "host|target", "rel": "...",
   "sha256": "...", "size": N, "mode": "0644", "uid": N, "gid": N, "mtime_ns": N}
  {"event": "restore", "id": "q-...", "time": "...Z"}

A quarantined item is *active* until a later restore event names its id. Stuck print-spool files moved by the printer action
``printer.target-quarantine-spool`` (docs/printer.md) are recorded the same way plus ``"kind": "spool"``, a ``"batch": "s-..."``
shared by the files of one run and the device number ``"dev"`` of the target mount; they are not malware, so ``count_active``
(the ``malware-quarantine`` check) does not count them. The moved bytes live in
``<state>/quarantine/blobs/<id>`` (0600, never executable). Paths appear here, so the directory is
as private as the detection list: never share it.
"""
from __future__ import annotations

import fcntl
import json
import os
import re
import stat
from datetime import datetime, timezone

MANIFEST = 'manifest.jsonl'
BLOBS = 'blobs'
ID_RE = re.compile(r'^q-[a-f0-9]{12}$')
BATCH_RE = re.compile(r'^s-[a-f0-9]{12}$')
MAX_MANIFEST = 32 * 1024 * 1024


def utc_now():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def events(qdir):
    """Manifest events in order; unreadable or malformed lines are skipped (never trusted for paths)."""
    path = os.path.join(qdir, MANIFEST)
    out = []
    try:
        st = os.lstat(path)
        if not stat.S_ISREG(st.st_mode) or st.st_size > MAX_MANIFEST:
            return out
        with open(path, 'rb') as handle:
            for raw in handle:
                try:
                    item = json.loads(raw.decode('utf-8'))
                except ValueError:
                    continue
                if isinstance(item, dict) and item.get('event') in ('quarantine', 'restore') \
                        and ID_RE.match(str(item.get('id'))):
                    out.append(item)
    except OSError:
        pass
    return out


def active(qdir):
    """Quarantine events that were not restored, oldest first."""
    restored = {e['id'] for e in events(qdir) if e['event'] == 'restore'}
    return [e for e in events(qdir) if e['event'] == 'quarantine' and e['id'] not in restored]


def count_active(qdir):
    """Malware items currently quarantined (spool files are a different kind and are not counted)."""
    return len([e for e in active(qdir) if e.get('kind') != 'spool'])


def spool_batch(qdir):
    """(batch id, [active spool events of that batch]) for the latest spool batch that still has active files, else (None, [])."""
    items = [e for e in active(qdir) if e.get('kind') == 'spool' and BATCH_RE.match(str(e.get('batch')))]
    if not items:
        return None, []
    batch = items[-1]['batch']
    return batch, [e for e in items if e['batch'] == batch]


def append(qdir, record):
    os.makedirs(qdir, mode=0o700, exist_ok=True)
    fd = os.open(os.path.join(qdir, MANIFEST), os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        os.write(fd, (json.dumps(record, sort_keys=True, separators=(',', ':')) + '\n').encode('utf-8'))
        os.fsync(fd)
    finally:
        os.close(fd)
