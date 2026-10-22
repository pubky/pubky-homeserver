# ========================
# Toolchain Stage
# ========================
FROM rust:1.91.1-alpine3.23 AS chef

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

# cargo-chef builds the dependencies in a layer of their own, so a change to
# the source code reuses the cached dependencies and rebuilds only the
# workspace crates.
RUN cargo install cargo-chef --locked --version 0.1.78

# Set the working directory
WORKDIR /usr/src/app

# ========================
# Recipe Stage
# ========================
# The recipe lists the dependencies, so it changes only when they do.
FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# ========================
# Build Stage
# ========================
FROM chef AS builder

# Add build argument for binary selection (homeserver or testnet)
ARG BUILD_TARGET=homeserver

# Build in release mode by default; use debug for faster development builds.
ARG BUILD_PROFILE=release

# Cargo calls the debug profile "dev", but writes its artifacts to target/debug.
RUN case "$BUILD_PROFILE" in \
      release) echo release ;; \
      debug) echo dev ;; \
      *) echo "Invalid BUILD_PROFILE: $BUILD_PROFILE (expected debug or release)" >&2; exit 1 ;; \
    esac > /cargo-profile

# Build the dependencies of the binary. The recipe leaves out the crates the
# workspace excludes, but cargo still reads the test utilities the workspace
# crates depend on.
COPY --from=planner /usr/src/app/recipe.json recipe.json
COPY test_utils test_utils
RUN cargo chef cook --profile "$(cat /cargo-profile)" --bin "pubky-$BUILD_TARGET" \
      --recipe-path recipe.json

# Copy over all the source code and build the binary
COPY . .
RUN cargo build --profile "$(cat /cargo-profile)" --bin "pubky-$BUILD_TARGET" && \
    if [ "$BUILD_PROFILE" = release ]; then strip "target/release/pubky-$BUILD_TARGET"; fi && \
    mkdir -p /out && \
    cp "target/$BUILD_PROFILE/pubky-$BUILD_TARGET" /out/homeserver

# ========================
# Runtime Stage
# ========================
FROM alpine:3.23

ARG TARGETARCH

# Install runtime dependencies (only ca-certificates)
RUN apk upgrade --no-cache && apk add --no-cache ca-certificates

# Copy the compiled binary from the builder stage
COPY --from=builder /out/homeserver /usr/local/bin/homeserver

# Set the working directory
WORKDIR /usr/local/bin

# Expose the port the homeserver listens on (should match that of config.toml)
EXPOSE 6287

# Set the default command to run the binary
CMD ["homeserver"]
