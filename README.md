# TacoDNS

Developer-friendly DNS server.

```
version: "3.5"
services:
  tacodns:
    restart: always
    image: registry.gitlab.com/chris13524/tacodns
    ports:
      - 53:53/udp
    command: --config-env TACODNS
    environment:
      TACODNS: |
        authority: ns1.example.com
        zones:
          example.com:
            A: 10.10.10.10
```
