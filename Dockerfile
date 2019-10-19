FROM rust:1.38.0-slim
WORKDIR /usr/src/tacodns
COPY . .
RUN cargo build --release

FROM ubuntu:bionic
RUN apt-get update && apt-get install -y dumb-init && rm -rf /var/lib/apt/lists/*
COPY --from=0 /usr/src/tacodns/target/release/tacodns /usr/local/bin/tacodns
ENTRYPOINT ["dumb-init", "--", "tacodns"]
EXPOSE 53/udp
