FROM rust:slim AS build

WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --locked --release

FROM debian:stable-slim

RUN useradd --system --create-home --uid 10001 ddos
COPY --from=build /src/target/release/ddos /usr/local/bin/ddos
USER ddos
ENTRYPOINT ["/usr/local/bin/ddos"]
