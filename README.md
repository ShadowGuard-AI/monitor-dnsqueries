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

Every flag threshold except the random-looking rule is a parameter, because your network's normal is not mine to decide. The random-looking rule is fixed in code: a second-level label at least 12 characters long with Shannon entropy at least 4.2.

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

Verified run on a synthetic log with a burst and a tunneling pattern planted in ordinary traffic:

```
Read 80 DNS queries (25 distinct names, 2 lines not understood)

Top domains:
      55  update.example.net
       2  example.org
       1  sub0.example-cdn.com
       1  sub1.example-cdn.com
       1  sub2.example-cdn.com
       1  sub3.example-cdn.com
       1  sub4.example-cdn.com
       1  sub5.example-cdn.com
       1  sub6.example-cdn.com
       1  sub7.example-cdn.com

Top clients:
      55  192.168.1.50
      23  192.168.1.60
       2  192.168.1.70

By type: A=55, TXT=23, MX=1, AAAA=1

Patterns I flag (4):
  [burst] 192.168.1.50 asked for update.example.net 55 times (threshold 50); a stuck resolver, a retry loop, or a beacon all look like this
  [subdomain crowd] 23 distinct names under example-cdn.com (threshold 20); data can ride out one subdomain at a time
  [long label] 0123456789abcdefghijklmnopqrstuvwxyz.tunneldata.example-cdn.com carries a label of 36 characters (threshold 30); long labels are where tunneling hides
  [TXT-heavy] 23 TXT queries (threshold 10); TXT answers are roomy enough to carry payloads
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
