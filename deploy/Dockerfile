# veil-relay container image.
#
#   docker build -f deploy/Dockerfile -t veil-relay .        (from the repository root)
#
# Multi-stage: compile in the official Rust image, run from distroless as uid 65532 with no
# shell, no package manager and (via docker-compose.yml) a read-only root filesystem. Base images
# are pinned by multi-arch index digest, so the same file builds for amd64 and arm64 (Raspberry Pi).

FROM docker.io/library/rust:1.97.0-slim-bookworm@sha256:6d220bf85c74e842a79da63997af8d2e74455c0b8847d8bb3a5888572334991d AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
# --locked: build exactly the reviewed dependency graph (Cargo.lock, cargo-vet/deny audited).
RUN cargo build --release --locked -p veil-relay --bin veil-relay \
 && install -D -m 0755 target/release/veil-relay /out/veil-relay \
 && install -d -m 0700 -o 65532 -g 65532 /out/data

FROM gcr.io/distroless/cc-debian12:nonroot@sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f
COPY --from=build /out/veil-relay /usr/local/bin/veil-relay
# Owned by the runtime user so a fresh named volume mounted here inherits uid 65532 / mode 0700.
COPY --from=build --chown=65532:65532 /out/data /data
USER 65532:65532
ENV VEIL_RELAY_DATA=/data \
    VEIL_RELAY_LISTEN=0.0.0.0:8443
VOLUME ["/data"]
EXPOSE 8443/tcp
ENTRYPOINT ["/usr/local/bin/veil-relay"]
CMD ["serve"]
