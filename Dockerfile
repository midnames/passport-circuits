# Build stage
FROM rust:1.91.1-bookworm AS builder

WORKDIR /app
COPY . .
RUN cargo build --release -p server

# Runtime stage
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libssl3 \
 && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/server /usr/local/bin/server

EXPOSE 3000
CMD ["server"]
