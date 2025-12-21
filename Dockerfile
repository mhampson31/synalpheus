# Rust as the base image
FROM rust:1-slim-bullseye AS build

# Create a new empty shell project
RUN USER=root cargo new --bin synalpheus
WORKDIR /synalpheus

# Copy our manifests
COPY ./Cargo.lock ./Cargo.lock
COPY ./Cargo.toml ./Cargo.toml
COPY ./entity ./entity
COPY ./migration ./migration

RUN apt-get update \
    && apt-get install --no-install-recommends -y libssl-dev pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Build only the dependencies to cache them
RUN cargo build --release
RUN rm src/*.rs

# Copy the source code
COPY ./src ./src
COPY ./templates ./templates
COPY ./entity ./entity
COPY ./migration ./migration
COPY ./assets ./assets

# Build for release.
RUN rm ./target/release/deps/synalpheus*
RUN cargo build --release

# The final base image
FROM debian:bullseye-slim

# Copy from the previous build
COPY --from=build /synalpheus/target/release/synalpheus /synalpheus/synalpheus
# COPY --from=build /synalpheus/target/release/synalpheus/target/x86_64-unknown-linux-musl/release/synalpheus .

COPY --from=build /synalpheus/templates /synalpheus/templates
COPY --from=build /synalpheus/assets /synalpheus/assets

ENV RUST_LOG=error,poem=debug,synalpheus=trace

RUN apt-get update \
    && apt-get install --no-install-recommends -y ca-certificates libssl-dev pkg-config curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /synalpheus
# Run the binary
CMD ["./synalpheus"]
