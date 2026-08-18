# ========================
# Build Stage
# ========================
FROM rust:1.89.0-alpine3.20 AS builder

# Build platform argument (x86_64 or aarch64) (default: x86_64)
RUN echo "TARGETARCH: $TARGETARCH"

# Install build dependencies, including static OpenSSL libraries
RUN apk add --no-cache \
    musl-dev \
    openssl-dev \
    openssl-libs-static \
    pkgconfig \
    build-base \
    curl

# Set cross-compiler environment variables:
# Always set ARM64 variables - safe since unused when targeting x86_64.
# Create environment setup script for x86_64 variables - only when host is ARM so we don't override the native compiler on x86 hosts.
# Set PATH to include both cross-compiler directories (non-existent paths are ignored)
# Set environment variables for static linking with OpenSSL
ENV OPENSSL_STATIC=yes
ENV OPENSSL_LIB_DIR=/usr/lib
ENV OPENSSL_INCLUDE_DIR=/usr/include

# Set the working directory
WORKDIR /usr/src/app

# Copy over Cargo.toml and Cargo.lock for dependency caching
COPY Cargo.toml Cargo.lock ./

# Copy over all the source code
COPY . .

# Add build argument for binary selection (homeserver or testnet)
ARG BUILD_TARGET=testnet

# Build the project in release mode for the MUSL target
# Only apply environment setup script only when host is ARM so we don't override the native compiler on x86 hosts
RUN cargo build --release --bin pubky-$BUILD_TARGET

# Strip the binary to reduce size
RUN strip target/release/pubky-$BUILD_TARGET

# ========================
# Runtime Stage
# ========================
FROM alpine:3.20

ARG TARGETARCH
ARG BUILD_TARGET=testnet

# Install runtime dependencies (only ca-certificates)
RUN apk add --no-cache ca-certificates

# Copy the compiled binary from the builder stage
COPY --from=builder /usr/src/app/target/release/pubky-$BUILD_TARGET /usr/local/bin/pubky-homeserver

# Set the working directory
WORKDIR /usr/local/bin

# Expose the port the homeserver listens on (should match that of config.toml)
EXPOSE 6287

# Run the binary by default and pass docker run arguments to it.
ENTRYPOINT ["pubky-homeserver"]
