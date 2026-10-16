# ========================
# Build Stage
# ========================
FROM rust:1.91.1-alpine3.20 AS builder

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
ARG BUILD_TARGET=homeserver

# Build in release mode by default; use debug for faster development builds.
ARG BUILD_PROFILE=release

# Cargo calls the debug profile "dev", but writes its artifacts to target/debug.
RUN case "$BUILD_PROFILE" in \
      release) cargo build --release --bin "pubky-$BUILD_TARGET" && \
               strip "target/release/pubky-$BUILD_TARGET" ;; \
      debug) cargo build --bin "pubky-$BUILD_TARGET" ;; \
      *) echo "Invalid BUILD_PROFILE: $BUILD_PROFILE (expected debug or release)" >&2; exit 1 ;; \
    esac && \
    mkdir -p /out && \
    cp "target/$BUILD_PROFILE/pubky-$BUILD_TARGET" /out/homeserver

# ========================
# Runtime Stage
# ========================
FROM alpine:3.20

ARG TARGETARCH

# Install runtime dependencies (only ca-certificates)
RUN apk add --no-cache ca-certificates

# Copy the compiled binary from the builder stage
COPY --from=builder /out/homeserver /usr/local/bin/homeserver

# Set the working directory
WORKDIR /usr/local/bin

# Expose the port the homeserver listens on (should match that of config.toml)
EXPOSE 6287

# Set the default command to run the binary
CMD ["homeserver"]
