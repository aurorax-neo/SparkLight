ARG BASE_IMAGE=alpine:latest
ARG BUILDER_IMAGE=rust:alpine
ARG NODE_IMAGE=node:22-alpine

# Stage 1: Build frontend static assets
FROM ${NODE_IMAGE} AS frontend-builder
WORKDIR /app/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

# Stage 2: Build Rust binaries
FROM ${BUILDER_IMAGE} AS builder
RUN apk add --no-cache musl-dev gcc
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --locked --release --bin sparklight --bin native_session_import

# Stage 3: Runtime image
FROM ${BASE_IMAGE}
WORKDIR /app
RUN apk add --no-cache ca-certificates tzdata curl tini libgcc && \
    ln -snf /usr/share/zoneinfo/Asia/Shanghai /etc/localtime && \
    echo "Asia/Shanghai" > /etc/timezone && \
    addgroup -g 10001 -S sparklight && \
    adduser -u 10001 -S -G sparklight -h /app sparklight
COPY --from=builder /app/target/release/sparklight /usr/local/bin/sparklight
COPY --from=builder /app/target/release/native_session_import /usr/local/bin/native_session_import
COPY --from=frontend-builder /app/frontend/dist /app/frontend/dist
RUN chmod +x /usr/local/bin/sparklight /usr/local/bin/native_session_import && \
    mkdir -p /data && \
    chown -R sparklight:sparklight /data /app
USER sparklight
ENV TZ=Asia/Shanghai \
    SPARK_HOST=0.0.0.0 \
    SPARK_PORT=8080 \
    SPARK_DATA_DIR=/data \
    RUST_LOG=info
EXPOSE 8080
VOLUME ["/data"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -fsS -o /dev/null http://127.0.0.1:8080/api/v1/system/health || exit 1
ENTRYPOINT ["/sbin/tini", "--"]
CMD ["sparklight"]
