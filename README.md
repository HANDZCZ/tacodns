# TacoDNS

Next-gen developer-friendly authoritative DNS server. TacoDNS supports
powerful features that make managing your DNS simple and powerful.

# Example usage

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

Note: rather than providing your configuration through an environment
variable, you can mount your YAML file at `/etc/tacodns.yml` or pass the
`--config` flag to change the location.

# Features

  - Configuration is done via YAML format. No more of those ugly
    BIND-style zone files!
  - Supports ANAME/ALIAS records.
  - Supports more advanced matching than regular DNS wildcards such as
    single, double, and triple wildcards, and regular expressions.
  - RNS (Recursive NS) record: TacoDNS queries another DNS server for
    the results
  - TRPP (TacoDNS Record Provider Protocol) record: TacoDNS will query
    another JSON-enabled server for the results
    (e.g. [TacoDNS ACME](https://gitlab.com/chris13524/tacodns-acme))
 
## Planned

  - DNSSEC
  - environment variables
  - URL records
  - DynamicDNS sidecar
  - GeoDNS
