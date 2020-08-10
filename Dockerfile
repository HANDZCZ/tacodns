FROM rust:1-slim
RUN apt-get update && apt-get install -y libssl-dev pkg-config && rm -rf /var/lib/apt/lists/*
WORKDIR /usr/src/tacodns
COPY . .
RUN cargo build --release

FROM ubuntu:bionic
RUN apt-get update && apt-get install -y dumb-init libssl-dev pkg-config && rm -rf /var/lib/apt/lists/*
COPY --from=0 /usr/src/tacodns/target/release/tacodns /usr/local/bin/tacodns
ENTRYPOINT ["dumb-init", "--", "tacodns"]
EXPOSE 53/udp
EXPOSE 53/tcp
