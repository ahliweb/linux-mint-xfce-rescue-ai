"""Terminal progress bars for the rescue tools (stdlib only).

Managed by ahlikoding.com and satpamsiber.com under ahliweb.com.
Owned by ahliweb/linux-mint-xfce-rescue-ai#67. Behavior: docs/target-os-scan.md.

Progress is drawn ONLY on the controlling terminal (/dev/tty), never on stdout or stderr, because the
launchers tee those into a log file. It is disabled (every call is a silent no-op) when RESCUE_PROGRESS=0,
when TERM=dumb, or when the terminal cannot be opened. No function here raises: I/O errors disable drawing.

Test hook (tests only): RESCUE_PROGRESS_TTY=/path/to/file replaces /dev/tty so a test can read what would
have been drawn. Operators never set it.
"""
from __future__ import annotations

import os
import shutil
import threading
import time

BAR_WIDTH = 20
REFRESH_SECONDS = 0.5
TTY_ENV = 'RESCUE_PROGRESS_TTY'


def _open_tty():
    """A text handle for the terminal, or None when progress is disabled or unavailable."""
    try:
        if os.environ.get('RESCUE_PROGRESS') == '0' or os.environ.get('TERM') == 'dumb':
            return None
        path = os.environ.get(TTY_ENV) or '/dev/tty'
        return open(path, 'a', encoding='ascii', errors='replace')
    except Exception:
        return None


def _columns(handle):
    try:
        return max(20, os.get_terminal_size(handle.fileno()).columns)
    except Exception:
        try:
            return max(20, int(os.environ.get('COLUMNS', '')))
        except ValueError:
            return max(20, shutil.get_terminal_size((80, 24)).columns)


def _clock(seconds):
    seconds = max(0, int(seconds))
    return '%02d:%02d' % (seconds // 60, seconds % 60)


def _ascii(text):
    return ''.join(c if 32 <= ord(c) < 127 else '?' for c in str(text if text is not None else ''))


def _line(fraction, label, elapsed, columns, tail=None):
    fraction = min(1.0, max(0.0, fraction))
    filled = int(round(fraction * BAR_WIDTH))
    bar = '[' + '#' * filled + '-' * (BAR_WIDTH - filled) + ']'
    suffix = '  ' + (tail if tail is not None else _clock(elapsed))
    head = '%s %3d%%  ' % (bar, int(fraction * 100))
    room = columns - 1 - len(head) - len(suffix)
    label = _ascii(label)
    if room < 4:
        label = ''
    elif len(label) > room:
        label = label[:room - 3] + '...'
    return (head + label + suffix)[:columns - 1]


class _Drawer:
    """One terminal line redrawn with \\r. Thread-safe enough for one bar at a time."""

    def __init__(self):
        self.tty = _open_tty()
        self.lock = threading.Lock()
        self.drawn = False
        self.width = 0

    @property
    def enabled(self):
        return self.tty is not None

    def draw(self, text, newline=False):
        with self.lock:
            if self.tty is None:
                return
            try:
                pad = ' ' * max(0, self.width - len(text))
                self.tty.write('\r' + text + pad + ('\n' if newline else ''))
                self.tty.flush()
                self.drawn = not newline
                self.width = 0 if newline else len(text)
            except Exception:
                self.tty = None

    def finish(self):
        """End the line (if one is open) and release the terminal."""
        with self.lock:
            tty, self.tty = self.tty, None
        if tty is None:
            return
        try:
            if self.drawn:
                tty.write('\n')
            tty.flush()
        except Exception:
            pass
        try:
            tty.close()
        except Exception:
            pass


class Progress:
    """A determinate bar: total units of work, advanced by the caller."""

    def __init__(self, total, label=''):
        try:
            self.total = max(1, int(total))
        except Exception:
            self.total = 1
        self.done = 0
        self.label = label
        self.start = time.monotonic()
        self._d = _Drawer()
        self._render()

    def _render(self, final=False):
        try:
            if not self._d.enabled:
                return
            cols = _columns(self._d.tty)
            self._d.draw(_line(self.done / self.total, self.label, time.monotonic() - self.start, cols),
                         newline=final)
        except Exception:
            pass

    def set(self, done, label=None):
        try:
            self.done = max(0, min(self.total, int(done)))
            if label is not None:
                self.label = label
            self._render()
        except Exception:
            pass

    def advance(self, n=1, label=None):
        try:
            self.set(self.done + int(n), label)
        except Exception:
            pass

    def close(self, final_label=None):
        try:
            if final_label is not None:
                self.label = final_label
            self.done = self.total
            self._render(final=True)
            self._d.finish()
        except Exception:
            pass

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        self.close()
        return False


class Budget:
    """Elapsed time against a time budget for an opaque long step; capped at 99% until closed."""

    def __init__(self, label, budget_seconds):
        try:
            self.budget = max(1.0, float(budget_seconds))
        except Exception:
            self.budget = 1.0
        self.label = label
        self.start = time.monotonic()
        self._d = _Drawer()
        self._stop = threading.Event()
        self._thread = None
        self._closed = False
        if self._d.enabled:
            try:
                self._tick()
                self._thread = threading.Thread(target=self._run, name='rescue-progress', daemon=True)
                self._thread.start()
            except Exception:
                self._thread = None

    def _tick(self, final=False):
        try:
            if not self._d.enabled:
                return
            elapsed = time.monotonic() - self.start
            fraction = 1.0 if final else min(0.99, elapsed / self.budget)
            tail = _clock(elapsed) + '/' + _clock(self.budget)
            self._d.draw(_line(fraction, self.label, elapsed, _columns(self._d.tty), tail), newline=final)
        except Exception:
            pass

    def _run(self):
        while not self._stop.wait(REFRESH_SECONDS):
            self._tick()

    def close(self, final_label=None):
        try:
            if self._closed:
                return
            self._closed = True
            self._stop.set()
            if self._thread is not None:
                self._thread.join(2)
            if final_label is not None:
                self.label = final_label
            self._tick(final=True)
            self._d.finish()
        except Exception:
            pass

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        self.close()
        return False


def step(n, total, label):
    """Print a phase header such as '[3/7] label' to the terminal."""
    handle = _open_tty()
    if handle is None:
        return
    try:
        handle.write('[%s/%s] %s\n' % (_ascii(n), _ascii(total), _ascii(label)))
        handle.flush()
    except Exception:
        pass
    finally:
        try:
            handle.close()
        except Exception:
            pass
