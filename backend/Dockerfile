# Use the Rust base image
FROM rust:slim-bookworm

# Install system dependencies needed for OpenSSL and pkg-config
RUN apt-get update && \
    apt-get install -y --no-install-recommends pkg-config libssl-dev && \
    rm -rf /var/lib/apt/lists/*

# Set the working directory inside the container
WORKDIR /app

# Copy your backend project files
COPY backend /app/backend

# Set the entry point for your application (Start Command)
# This matches your previous start command logic, adjusted for the WORKDIR setup.
CMD ["/app/backend/target/release/xum-google-oauth"]

# Expose the port your application listens on
EXPOSE 8080