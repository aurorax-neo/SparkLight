# Stage 1: Build binary using cached rust:bookworm
FROM rust:bookworm AS builder
ENV CARGO_REGISTRIES_CRATES_IO_PROTOCOL=sparse
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY frontend/dist ./frontend/dist
RUN cargo build --release --bin sparklight

# Stage 2: Runtime image
FROM debian:bookworm-slim AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl tini \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10001 sparklight \
    && useradd --system --uid 10001 --gid sparklight --home-dir /app sparklight
WORKDIR /app
COPY --from=builder /app/target/release/sparklight /usr/local/bin/sparklight
COPY frontend/dist /app/frontend/dist
RUN mkdir -p /data && chown -R sparklight:sparklight /data /app
USER sparklight
ENV SPARK_HOST=0.0.0.0 \
    SPARK_PORT=8080 \
    SPARK_DATA_DIR=/data \
    RUST_LOG=info
EXPOSE 8080
VOLUME ["/data"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -fsS -o /dev/null http://127.0.0.1:8080/api/v1/system/health || exit 1
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["sparklight"]
