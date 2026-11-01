![Banner](banner.png)

# monitor-dnsqueries

I read DNS query logs that already exist on your machine and tell
you what has been asking for what, and which patterns I do not like
the look of.

An earlier version of this README promised live capture of system
DNS queries. That is not what this tool does, and the difference
matters: nothing here sniffs packets, nothing needs root, and
nothing leaves the machine. I read local log files, count honestly,
and flag suspicious shapes.

## What I read

- dnsmasq logs, including Pi-hole style output
  (`query[A] name from client`)
- BIND 9 query logs (`client ... query: name IN A`)
- Plain CSV lines, either `time, client, name, type` or
  `client, name, type`

Lines I cannot parse are counted and reported as not understood,
never guessed at.

## What I flag

- **Burst**: one client asking for one name over and over. A stuck
  resolver, a retry loop, or a beacon all look like this.
- **Subdomain crowd**: many distinct names under one parent domain.
  Data can ride out of a network one subdomain at a time.
- **Long label**: a single DNS label long enough to smuggle data.
- **Random-looking names**: a high-entropy second-level label, the
  habit of domain generation algorithms.
- **TXT-heavy traffic**: TXT answers are roomy enough to carry
  payloads, so a pile of TXT queries earns a look.

Every threshold is a parameter, because your network's normal is
not mine to decide.

## Install

```bash
git clone https://github.com/ShadowGuard-AI/monitor-dnsqueries.git
cd monitor-dnsqueries
```

Python 3, standard library only. There is nothing to install. (The
old requirements.txt listed standard library modules as if they
were downloads; it is gone.)

## Usage

```bash
python3 main.py /var/log/dnsmasq.log
```

Abridged from this tool's own test fixture, a synthetic log with a
burst and a tunneling pattern planted in ordinary traffic:

```
Read 85 DNS queries (29 distinct names, 2 lines not understood)

Top domains:
      55  update.example.net
       2  example.org

By type: A=61, TXT=22, MX=1, AAAA=1

Patterns I flag (13):
  [burst] 192.168.1.50 asked for update.example.net 55 times (threshold 50); a stuck resolver, a retry loop, or a beacon all look like this
  [subdomain crowd] 22 distinct names under example-cdn.com (threshold 20); data can ride out one subdomain at a time
  [long label] 0123456789abcdefghijklmnopqrstuvwxyz.tunneldata.example-cdn.com carries a label of 36 characters (threshold 30); long labels are where tunneling hides
  [TXT-heavy] 22 TXT queries (threshold 10); TXT answers are roomy enough to carry payloads
```

## Parameters

- `logfile`: the query log to read.
- `--top`: rows in each top list. Default 10.
- `--burst`: same client and name count that earns a burst flag.
  Default 50.
- `--subdomains`: distinct names under one parent that earn a
  crowd flag. Default 20.
- `--long-label`: label length that earns a long-label flag.
  Default 30.
- `--txt-heavy`: TXT query count that earns a TXT-heavy flag.
  Default 10.
- `--json`: emit the report as JSON instead of text.
- `--output`: write the report to this file. If it resolves to the
  log file itself, I refuse: the log is the evidence.

## Exit codes

- `0`: the log was read and the report delivered.
- `2`: nothing was processed (missing file, or no parseable DNS
  queries in it), or the refused in-place output.

## License

MIT. See [LICENSE](LICENSE).
Copyright (c) Gavin K (@Epsilon0xCell).
