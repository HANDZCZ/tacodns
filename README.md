# TacoDNS

Developer-friendly authoritative DNS server written in Rust.

## Example

### Docker Compose

```
version: "3.7"
services:
  tacodns:
    restart: always
    image: registry.gitlab.com/chris13524/tacodns
    ports:
      - 53:53/udp
      - 53:53/tcp
    command: --config-env TACODNS
    environment:
      TACODNS: |
        ttl: 30m
        zones:
          example.com:
            A: 10.10.10.10
```

### Cargo

```
cat >tacodns.yml <<EOF
ttl: 30m
zones:
  example.com:
    A: 10.10.10.10
EOF

cargo run -- --config tacodns.yml
```

## Usage

See `config.example.yml` and `tacodns --help`.

## Features

  - Configuration is done via YAML format. No more of those ugly
    BIND-style zone files!
  - Supports ANAME/ALIAS records.
  - Supports more advanced matching than regular DNS wildcards such as
    single, double, and triple wildcards, regular expressions, and
    fall-though zones.
  - RNS (Recursive NS) record: TacoDNS queries another DNS server for
    the results. Supports record types that TacoDNS does not.
  - TRPP (TacoDNS Record Provider Protocol) record: TacoDNS will query
    a JSON HTTP server for the results
    (e.g. [TacoDNS ACME](https://gitlab.com/chris13524/tacodns-acme)).
    Only supports A, AAAA, MX, and TXT records.

### Supported record types

  - A
  - AAAA
  - MX
  - TXT
  - NS
  - CNAME & ANAME

Unsupported types can be provided by an upstream DNS server connected via RNS.

### Planned features

  - SRV records
  - CAA records
  - DNSSEC
  - environment variables in config
  - URL records (resolves address records to itself and does HTTP redirect)

## Spec compliance

This server is mostly spec compliant. There are some semantic cases
where this server isn't fully compliant, but I haven't encountered any
actual real-world problems with them. TacoDNS has production usage at
chris.smith.xyz and fathomstudio.com.

Known incompatibilities:

  - does not support BIND-style zone files
  - does not support zone transfers or master/slave
  - never returns NXDOMAIN, only empty NOERROR's (functional requirement
    due to powerful fall-though nature of TacoDNS zones)
  - SOA record is generated for every request, and may not be accurate
  - EDNS compliance: https://ednscomp.isc.org/ednscomp/cf51805c31
