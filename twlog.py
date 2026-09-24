"""One log file per server, capped in size.  Standard library only.

    python tools/twlog.py            # self-test

`lobbyd` logs every frame it sends and receives, and nothing ever trimmed
that: a five-minute two-player session wrote 33 KB, and under `tw04.sh` the
same lines were written twice -- once by lobbyd to its own file and once more
through stdout into the supervisor's.  This writes each line once, to one file,
and when that file passes `max_bytes` it rolls over:

    lobbyd.log  ->  lobbyd.log.1  ->  lobbyd.log.2 ... up to `keep`

so the disk used is bounded by `max_bytes * (keep + 1)`.  No logrotate, no
cron job, nothing installed -- the same rule as the rest of the server.

`echo` also prints each line, for running by hand in a terminal.  Under a
supervisor that already sends stdout to the same file, turn it off (`--quiet`)
or every line lands twice again.
"""
import os
import sys
import threading

DEFAULT_MAX_MB = 10
DEFAULT_KEEP = 3


class Log:
    def __init__(self, path='', max_bytes=DEFAULT_MAX_MB << 20,
                 keep=DEFAULT_KEEP, echo=True):
        self.path = os.path.abspath(path) if path else ''
        self.max_bytes = max(int(max_bytes), 64 << 10)   # not absurdly small
        self.keep = max(int(keep), 1)
        self.echo = echo
        self.lock = threading.Lock()
        if self.path:
            os.makedirs(os.path.dirname(self.path), exist_ok=True)

    def write(self, line):
        """Write one line (no trailing newline needed).  Never raises: a full
        disk must not take the server down with it."""
        with self.lock:
            if self.echo:
                try:
                    print(line, flush=True)
                except (OSError, ValueError):
                    pass
            if not self.path:
                return
            try:
                with open(self.path, 'a', encoding='utf-8') as f:
                    f.write(line + '\n')
                    size = f.tell()
                if size >= self.max_bytes:
                    self._rotate()
            except OSError as exc:
                try:
                    sys.stderr.write('log: cannot write %s: %s\n'
                                     % (self.path, exc))
                except (OSError, ValueError):
                    pass

    def _rotate(self):
        """lobbyd.log.(keep-1) -> .keep, ..., lobbyd.log -> .1.  The oldest
        falls off the end.  Called with the lock held."""
        for n in range(self.keep - 1, 0, -1):
            older = '%s.%d' % (self.path, n)
            if os.path.exists(older):
                os.replace(older, '%s.%d' % (self.path, n + 1))
        os.replace(self.path, self.path + '.1')

    def files(self):
        """The log and its rolled-over copies that exist, newest first."""
        out = [self.path] if os.path.exists(self.path) else []
        out += ['%s.%d' % (self.path, n) for n in range(1, self.keep + 1)
                if os.path.exists('%s.%d' % (self.path, n))]
        return out


def _selftest():
    import tempfile
    fails = []
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, 'logs', 'test.log')
        log = Log(path, max_bytes=64 << 10, keep=2, echo=False)
        line = 'x' * 99                        # 100 bytes with the newline
        for i in range(3000):                  # ~300 KB through a 64 KB cap
            log.write('%05d %s' % (i, line[6:]))
        files = log.files()
        sizes = [os.path.getsize(f) for f in files]
        print('files: %s' % ', '.join('%s %d' % (os.path.basename(f), s)
                                      for f, s in zip(files, sizes)))
        if [os.path.basename(f) for f in files] != ['test.log', 'test.log.1',
                                                     'test.log.2']:
            fails.append('expected the log plus two rolled copies, got %r'
                         % files)
        if any(s > (64 << 10) + 100 for s in sizes):
            fails.append('no file may pass the cap by more than a line: %r'
                         % sizes)
        with open(path, encoding='utf-8') as f:
            last = f.read().splitlines()[-1]
        if not last.startswith('02999 '):
            fails.append('the newest line belongs in the live file, got %r'
                         % last[:10])
        with open(path + '.2', encoding='utf-8') as f:
            first = int(f.readline()[:5])
        if first < 3000 - 3 * 700:
            fails.append('older copies than `keep` should have been dropped')
    if fails:
        for f in fails:
            print('FAIL %s' % f)
        return 1
    print('\nok: the log rolls over at its cap, keeps `keep` old copies, and '
          'the\n    newest lines are always in the live file')
    return 0


if __name__ == '__main__':
    sys.exit(_selftest())
