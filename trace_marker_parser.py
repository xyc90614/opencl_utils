#!/usr/bin/env python3
"""
Systrace / atrace Tracing Marker Parser for HarmonyOS / Android
Parses tracing_mark_write events from systrace output files.

Events parsed:
  B|pid|name      - Begin slice
  E|pid           - End slice
  C|pid|name|val  - Counter
  S|pid|name      - Async begin
  F|pid|name      - Async end
  T|pid|name|val  - Integer trace marker
"""

import re
import json
import csv
import sys
import argparse
from collections import defaultdict
from pathlib import Path


class TraceEvent:
    __slots__ = ('pid', 'cpu', 'timestamp', 'type', 'args', 'process_name')

    def __init__(self, pid: int, cpu: int, timestamp: float,
                 marker_type: str, args: list[str]):
        self.pid = pid
        self.cpu = cpu
        self.timestamp = timestamp
        self.type = marker_type
        self.args = args
        self.process_name = ''

    def __repr__(self):
        return (f"TraceEvent({self.type}, pid={self.pid}, cpu={self.cpu}, "
                f"ts={self.timestamp:.6f}, args={self.args})")


class TracingMarkerParser:
    """
    Parser for systrace tracing_mark_write events.
    Supports text ftrace format, HTML systrace, and JSON trace format.
    """
    _FTRACE_RE = re.compile(
        r'^\s*(?P<comm>\S+?)-?(?P<pid>\d+)\s+'
        r'\(?\s*(?P<tid>\d+)\)?\s+'
        r'\[(?P<cpu>\d+)\]\s+[\d.]+\s+'
        r'(?P<ts>\d+\.\d+):\s+tracing_mark_write:\s+'
        r'(?P<type>[BECSFTP])\|(?P<args>.*)$'
    )
    _MARKER_RE = re.compile(r'(?P<type>[BECSFTP])\|(?P<args>.+)$')

    def __init__(self):
        self.events: list[TraceEvent] = []
        self._b_stack: dict[int, list[tuple[str, float]]] = defaultdict(list)
        self._async_map: dict[tuple[int, str], float] = {}

    def parse_file(self, path: str) -> list[TraceEvent]:
        raw = Path(path).read_text(encoding='utf-8', errors='replace')
        stripped = raw.strip()
        if stripped.startswith('<!DOCTYPE html') or '<html' in stripped[:256]:
            self._parse_html(raw)
        else:
            self._parse_text(raw)
        return self.events

    # ------------------------------------------------------------------
    # HTML
    # ------------------------------------------------------------------
    def _parse_html(self, content: str):
        m = re.search(
            r'<script[^>]*>\s*traceData\s*=\s*({.*?})\s*</script>',
            content, re.DOTALL
        )
        if m:
            try:
                data = json.loads(m.group(1))
                self._parse_json_trace(data)
                return
            except json.JSONDecodeError:
                pass
        m = re.search(
            r'<textarea[^>]*id="trace-data"[^>]*>(.*?)</textarea>',
            content, re.DOTALL
        )
        if m:
            self._parse_text(m.group(1))
        else:
            self._parse_text(content)

    # ------------------------------------------------------------------
    # JSON / Catapult
    # ------------------------------------------------------------------
    def _parse_json_trace(self, data: dict):
        for ev in data.get('traceEvents', []):
            ph = ev.get('ph')
            if ph not in ('B', 'E', 'C', 'S', 'F', 'T', 'X'):
                continue
            pid = ev.get('pid', 0)
            cpu = ev.get('cpu', 0)
            ts = ev.get('ts', 0) / 1e6
            name = ev.get('name', '')
            cat = ev.get('cat', '')

            if ph == 'B':
                te = TraceEvent(pid, cpu, ts, 'B', [str(pid), name])
                te.process_name = cat
                self.events.append(te)
                self._b_stack[pid].append((name, ts))
            elif ph == 'E':
                te = TraceEvent(pid, cpu, ts, 'E', [str(pid)])
                te.process_name = cat
                self.events.append(te)
            elif ph == 'X':
                dur = ev.get('dur', 0) / 1e6
                te = TraceEvent(pid, cpu, ts, 'X', [str(pid), name, f'{dur:.6f}'])
                te.process_name = cat
                te._dur = dur
                self.events.append(te)
            elif ph == 'C':
                val = ev.get('args', {}).get('value', 0)
                te = TraceEvent(pid, cpu, ts, 'C', [str(pid), name, str(val)])
                te.process_name = cat
                self.events.append(te)
            elif ph == 'S':
                te = TraceEvent(pid, cpu, ts, 'S', [str(pid), name])
                te.process_name = cat
                self.events.append(te)
                self._async_map[(pid, name)] = ts
            elif ph == 'F':
                te = TraceEvent(pid, cpu, ts, 'F', [str(pid), name])
                te.process_name = cat
                self.events.append(te)

    # ------------------------------------------------------------------
    # Plain text
    # ------------------------------------------------------------------
    def _parse_text(self, content: str):
        for line in content.splitlines():
            line = line.strip()
            if not line or 'tracing_mark_write:' not in line:
                continue
            m = self._FTRACE_RE.match(line)
            if m:
                self._add_from_ftrace(m)
                continue
            m = self._MARKER_RE.search(line)
            if m:
                self._add_from_marker(m)

    def _add_from_ftrace(self, m: re.Match):
        te = TraceEvent(
            pid=int(m.group('pid')),
            cpu=int(m.group('cpu')),
            timestamp=float(m.group('ts')),
            marker_type=m.group('type'),
            args=m.group('args').split('|'),
        )
        te.process_name = m.group('comm')
        self.events.append(te)

    def _add_from_marker(self, m: re.Match):
        te = TraceEvent(
            pid=0, cpu=0, timestamp=0.0,
            marker_type=m.group('type'),
            args=m.group('args').split('|'),
        )
        self.events.append(te)

    # ------------------------------------------------------------------
    # Analysis helpers
    # ------------------------------------------------------------------
    def get_slices(self) -> list[dict]:
        slices, stack = [], defaultdict(list)
        for ev in self.events:
            if ev.type == 'B' and len(ev.args) >= 2:
                stack[ev.pid].append((ev.args[1], ev.timestamp))
            elif ev.type == 'E' and stack[ev.pid]:
                name, start = stack[ev.pid].pop()
                slices.append(dict(
                    pid=ev.pid, name=name,
                    start=start, end=ev.timestamp,
                    duration=ev.timestamp - start,
                    process_name=ev.process_name,
                ))
        return slices

    def get_counters(self) -> list[dict]:
        return [
            dict(pid=ev.pid, name=ev.args[1], value=ev.args[2],
                 timestamp=ev.timestamp, process_name=ev.process_name)
            for ev in self.events
            if ev.type == 'C' and len(ev.args) >= 3
        ]

    def get_async_slices(self) -> list[dict]:
        starts: dict[tuple[int, str], float] = {}
        slices = []
        for ev in self.events:
            if ev.type == 'S' and len(ev.args) >= 2:
                starts[(ev.pid, ev.args[1])] = ev.timestamp
            elif ev.type == 'F' and len(ev.args) >= 2:
                key = (ev.pid, ev.args[1])
                if key in starts:
                    s = starts.pop(key)
                    slices.append(dict(
                        pid=ev.pid, name=ev.args[1],
                        start=s, end=ev.timestamp,
                        duration=ev.timestamp - s,
                        process_name=ev.process_name,
                    ))
        return slices

    def summary(self) -> dict:
        by_type: dict[str, int] = defaultdict(int)
        by_proc: dict[str, int] = defaultdict(int)
        for ev in self.events:
            by_type[ev.type] += 1
            by_proc[ev.process_name or f'pid:{ev.pid}'] += 1
        return dict(
            total=len(self.events),
            by_type=dict(by_type),
            by_process=dict(sorted(by_proc.items(), key=lambda x: -x[1])),
        )

    # ------------------------------------------------------------------
    # Export
    # ------------------------------------------------------------------
    def export_csv(self, path: str):
        with open(path, 'w', newline='', encoding='utf-8') as f:
            w = csv.writer(f)
            w.writerow(['Timestamp', 'CPU', 'PID', 'Process', 'Type', 'Args'])
            for e in self.events:
                w.writerow([f'{e.timestamp:.6f}', e.cpu, e.pid,
                            e.process_name, e.type, '|'.join(e.args)])

    def export_json(self, path: str):
        def _ev(e: TraceEvent) -> dict:
            return dict(timestamp=e.timestamp, cpu=e.cpu, pid=e.pid,
                        process_name=e.process_name, type=e.type, args=e.args)
        payload = dict(
            events=[_ev(e) for e in self.events],
            slices=self.get_slices(),
            counters=self.get_counters(),
            async_slices=self.get_async_slices(),
        )
        Path(path).write_text(
            json.dumps(payload, indent=2, ensure_ascii=False), encoding='utf-8')

    # ------------------------------------------------------------------
    # Pretty print
    # ------------------------------------------------------------------
    def print_slices(self):
        slices = self.get_slices()
        if not slices:
            print('  (no B/E slices found)')
            return
        by_pid: dict[int, list[dict]] = defaultdict(list)
        for s in slices:
            by_pid[s['pid']].append(s)
        for pid in sorted(by_pid):
            items = sorted(by_pid[pid], key=lambda x: x['start'])
            name = items[0].get('process_name') or f'Process {pid}'
            print(f'\n  {"=" * 56}')
            print(f'  {name}  (PID {pid})')
            print(f'  {"=" * 56}')
            for s in items:
                print(f'  [{s["start"]:.6f} - {s["end"]:.6f}]  '
                      f'{s["duration"] * 1000:9.3f} ms  {s["name"]}')

    def print_counters(self, limit=40):
        counters = self.get_counters()
        if not counters:
            print('  (no counter events found)')
            return
        print(f'\n  {"=" * 56}')
        print('  Counter Events')
        print(f'  {"=" * 56}')
        for c in counters[:limit]:
            print(f'  [{c["timestamp"]:.6f}]  {c["name"]} = {c["value"]}  '
                  f'(pid {c["pid"]})')
        if len(counters) > limit:
            print(f'  ... and {len(counters) - limit} more')

    def print_async(self, limit=30):
        slices = self.get_async_slices()
        if not slices:
            print('  (no async S/F events found)')
            return
        print(f'\n  {"=" * 56}')
        print(f'  Async Slices  ({len(slices)} total)')
        print(f'  {"=" * 56}')
        for s in slices[:limit]:
            print(f'  [{s["start"]:.6f} - {s["end"]:.6f}]  '
                  f'{s["duration"] * 1000:9.3f} ms  {s["name"]}  '
                  f'(pid {s["pid"]})')
        if len(slices) > limit:
            print(f'  ... and {len(slices) - limit} more')

    def print_events(self, limit=80):
        for i, e in enumerate(self.events[:limit]):
            print(f'  [{e.timestamp:.6f}]  CPU:{e.cpu}  PID:{e.pid}  '
                  f'{e.process_name or "?":24s}  {e.type} | {"|".join(e.args)}')
        if len(self.events) > limit:
            print(f'  ... and {len(self.events) - limit} more')


# ======================================================================
def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog='trace_marker_parser',
        description='Parse tracing_mark_write events from systrace / atrace.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Examples:
              %(prog)s trace.txt                        # summary
              %(prog)s trace.html --slices --async      # slices + async
              %(prog)s trace.txt --json out.json        # export JSON
              %(prog)s trace.txt --csv out.csv          # export CSV
              %(prog)s trace.txt -v                     # raw events
        """),
    )
    p.add_argument('file', help='Input trace file (text / HTML / JSON)')
    g = p.add_argument_group('Display')
    g.add_argument('-s', '--slices', action='store_true', help='Show B/E slice tree')
    g.add_argument('-c', '--counters', action='store_true', help='Show C counter events')
    g.add_argument('-a', '--async', action='store_true', dest='show_async',
                   help='Show S/F async slices')
    g.add_argument('-v', '--verbose', action='store_true', help='Show raw event list')
    g.add_argument('--summary', action='store_true', help='Show summary statistics')
    g = p.add_argument_group('Export')
    g.add_argument('--json', metavar='FILE', help='Export to JSON')
    g.add_argument('--csv', metavar='FILE', help='Export to CSV')
    return p


def main():
    import textwrap
    args = _build_parser().parse_args()

    want = [args.slices, args.counters, args.show_async,
            args.verbose, args.summary, args.json, args.csv]
    if not any(want):
        args.summary = True

    try:
        parser = TracingMarkerParser()
        events = parser.parse_file(args.file)
    except FileNotFoundError:
        print(f'Error: file not found: {args.file}', file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f'Error: {e}', file=sys.stderr)
        sys.exit(1)

    print(f'Parsed {len(events)} tracing_mark_write events from {args.file}\n')

    if args.summary:
        s = parser.summary()
        label = dict(B='Begin (B)', E='End (E)', C='Counter (C)',
                     S='Async Begin (S)', F='Async End (F)',
                     T='Trace Int (T)', X='Complete (X)')
        print(f'  Total events  : {s["total"]}')
        print(f'  By type       :')
        for t in sorted(s['by_type']):
            print(f'    {label.get(t, t)}: {s["by_type"][t]}')
        if s['by_process']:
            print(f'  Top processes :')
            for name, cnt in list(s['by_process'].items())[:12]:
                print(f'    {name:<30s} {cnt}')

    if args.slices:
        print(f'\n--- B/E Slices ---')
        parser.print_slices()

    if args.counters:
        print(f'\n--- Counters ---')
        parser.print_counters()

    if args.show_async:
        print(f'\n--- Async Slices ---')
        parser.print_async()

    if args.verbose:
        print(f'\n--- Raw Events (first 80) ---')
        parser.print_events()

    if args.json:
        parser.export_json(args.json)
        print(f'\n  Exported: {args.json}')

    if args.csv:
        parser.export_csv(args.csv)
        print(f'\n  Exported: {args.csv}')


if __name__ == '__main__':
    main()
