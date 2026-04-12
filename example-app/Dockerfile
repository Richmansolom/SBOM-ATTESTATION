FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    make \
    zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .

RUN make

# libpng produces static/shared libs under build/; no single demo binary required for SBOM CI.
CMD ["sh", "-c", "ls -la build/ 2>/dev/null || true"]
