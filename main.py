#!/usr/bin/env python3
"""monitor-dnsqueries: I read DNS query logs that already exist on
your machine and tell you what has been asking for what, and which
of those patterns I do not like the look of.

The README this replaces promised live capture. I do not do that,
and I want the boundary in writing: nothing here sniffs packets,
nothing needs root, and nothing leaves the machine. I read local
log files (dnsmasq and Pi-hole style, BIND 9 query logs, and a
plain CSV form), count honestly, and flag the shapes that usually
mean trouble: one client hammering one name, crowds of unique
subdomains under a single parent, labels long enough to smuggle
data, and TXT-heavy traffic.

A log with no parseable queries is a run that processed nothing:
exit 2, no report dressed up as a clean bill of health.
"""

import argparse
import csv
import io
import json
import math
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

DNSMASQ_RE = re.compile(
    r"query\[(?P<type>[A-Z0-9]+)\]\s+(?P<name>\S+)\s+from\s+(?P<client>\S+)")
BIND_RE = re.compile(
    r"client\s+\S+\s+(?P<client>\d+\.\d+\.\d+\.\d+)#\d+\s+"
    r"\((?P<name>[^)]+)\):\s+query:\s+\S+\s+IN\s+(?P<type>[A-Z0-9]+)")
TYPES = {"A", "AAAA", "CNAME", "MX", "TXT", "NS", "PTR", "SRV",
         "SOA", "NULL", "HTTPS", "SVCB", "DS", "DNSKEY", "CAA"}


def parse_line(line):
    """One log line in, one (client, name, type) out, or None."""
    m = DNSMASQ_RE.search(line)
    if m:
        return m.group("client"), m.group("name").lower(), m.group("type")
    m = BIND_RE.search(line)
    if m:
        return m.group("client"), m.group("name").lower(), m.group("type")
    if "," in line or "\t" in line:
        parts = next(csv.reader(io.StringIO(line)))
        parts = [p.strip() for p in parts if p.strip()]
        # I accept time, client, name, type in that order, and the
        # shorter client, name, type. Anything else is not a CSV log
        # line I understand, and I will not guess.
        if len(parts) == 4:
            _, client, name, qtype = parts
        elif len(parts) == 3:
            client, name, qtype = parts
        else:
            return None
        if qtype.upper() in TYPES and "." in name:
            return client, name.lower(), qtype.upper()
    return None


def parent_of(name):
    """The registered-looking parent: last two labels. (Public
    suffixes like co.uk exist; for pattern counting on a home or
    office log this is the grouping that surfaces abuse.)"""
    labels = name.split(".")
    return ".".join(labels[-2:]) if len(labels) >= 2 else name


def entropy(text):
    if not text:
        return 0.0
    counts = Counter(text)
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def analyze(lines, args):
    entries = []
    skipped = 0
    for line in lines:
        got = parse_line(line)
        if got:
            entries.append(got)
        elif line.strip():
            skipped += 1
    if not entries:
        return None, skipped
    per_domain = Counter()
    per_client = Counter()
    per_type = Counter()
    pair_counts = Counter()
    subs = defaultdict(set)
    for client, name, qtype in entries:
        per_domain[name] += 1
        per_client[client] += 1
        per_type[qtype] += 1
        pair_counts[(client, name)] += 1
        subs[parent_of(name)].add(name)
    flags = []
    for (client, name), count in pair_counts.most_common():
        if count >= args.burst:
            flags.append({
                "kind": "burst",
                "detail": f"{client} asked for {name} {count} times "
                          f"(threshold {args.burst}); a stuck resolver, "
                          f"a retry loop, or a beacon all look like this"})
    for parent, names in sorted(subs.items()):
        if len(names) >= args.subdomains:
            flags.append({
                "kind": "subdomain crowd",
                "detail": f"{len(names)} distinct names under {parent} "
                          f"(threshold {args.subdomains}); data can "
                          f"ride out one subdomain at a time"})
    long_names = [n for n in per_domain
                  if max(len(label) for label in n.split(".")) >= args.long_label]
    for name in sorted(long_names)[:10]:
        flags.append({
            "kind": "long label",
            "detail": f"{name} carries a label of "
                      f"{max(len(l) for l in name.split('.'))} characters "
                      f"(threshold {args.long_label}); long labels are "
                      f"where tunneling hides"})
    odd = [n for n in per_domain
           if len(n.split(".")[-2] if "." in n else n) >= 12
           and entropy(n.split(".")[-2] if "." in n else n) >= 4.2]
    for name in sorted(odd)[:10]:
        flags.append({
            "kind": "random-looking",
            "detail": f"{name} has a high-entropy second-level label; "
                      f"generated names are a DGA habit"})
    if per_type.get("TXT", 0) >= args.txt_heavy:
        flags.append({
            "kind": "TXT-heavy",
            "detail": f"{per_type['TXT']} TXT queries "
                      f"(threshold {args.txt_heavy}); TXT answers are "
                      f"roomy enough to carry payloads"})
    report = {
        "queries": len(entries), "lines_skipped": skipped,
        "unique_domains": len(per_domain),
        "top_domains": per_domain.most_common(args.top),
        "top_clients": per_client.most_common(args.top),
        "by_type": dict(per_type.most_common()),
        "flags": flags,
    }
    return report, skipped


def render_text(report):
    lines = [f"Read {report['queries']} DNS queries "
             f"({report['unique_domains']} distinct names, "
             f"{report['lines_skipped']} lines not understood)"]
    lines.append("\nTop domains:")
    for name, count in report["top_domains"]:
        lines.append(f"  {count:>6}  {name}")
    lines.append("\nTop clients:")
    for client, count in report["top_clients"]:
        lines.append(f"  {count:>6}  {client}")
    lines.append("\nBy type: " + ", ".join(
        f"{t}={c}" for t, c in report["by_type"].items()))
    if report["flags"]:
        lines.append(f"\nPatterns I flag ({len(report['flags'])}):")
        for flag in report["flags"]:
            lines.append(f"  [{flag['kind']}] {flag['detail']}")
    else:
        lines.append("\nNo pattern crossed a flag threshold.")
    return "\n".join(lines) + "\n"


def run(args):
    path = Path(args.logfile)
    if not path.is_file():
        print(f"error: no such file: {path}", file=sys.stderr)
        return 2
    report, skipped = analyze(
        path.read_text(errors="replace").splitlines(), args)
    if report is None:
        print(f"error: no DNS queries parsed from {path} "
              f"({skipped} lines not understood)", file=sys.stderr)
        return 2
    text = json.dumps(report, indent=2) + "\n" if args.json \
        else render_text(report)
    if args.output:
        out = Path(args.output)
        if out.resolve() == path.resolve():
            print("error: --output resolves to the log file; "
                  "refusing to overwrite the evidence", file=sys.stderr)
            return 2
        out.write_text(text)
    else:
        sys.stdout.write(text)
    return 0


def build_parser():
    parser = argparse.ArgumentParser(
        prog="monitor-dnsqueries",
        description="Summarize a DNS query log and flag unusual "
                    "patterns. Reads local files only.")
    parser.add_argument("logfile",
                        help="dnsmasq/Pi-hole, BIND 9, or CSV query log")
    parser.add_argument("--top", type=int, default=10,
                        help="rows in each top list (default 10)")
    parser.add_argument("--burst", type=int, default=50,
                        help="same client and name count that earns a "
                             "burst flag (default 50)")
    parser.add_argument("--subdomains", type=int, default=20,
                        help="distinct names under one parent that "
                             "earn a crowd flag (default 20)")
    parser.add_argument("--long-label", type=int, default=30,
                        help="label length that earns a long-label "
                             "flag (default 30)")
    parser.add_argument("--txt-heavy", type=int, default=10,
                        help="TXT query count that earns a TXT-heavy "
                             "flag (default 10)")
    parser.add_argument("--json", action="store_true",
                        help="emit JSON instead of text")
    parser.add_argument("--output", help="write the report to this file")
    return parser


def main(argv=None):
    return run(build_parser().parse_args(argv))


if __name__ == "__main__":
    sys.exit(main())
