# ===========================================================================
# Stage 1 – Go-based tools: subfinder, amass, gobuster, assetfinder
# ===========================================================================
FROM golang:latest AS go-builder

RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install github.com/owasp-amass/amass/v4/...@latest && \
    go install github.com/OJ/gobuster/v3@latest && \
    go install github.com/tomnomnom/assetfinder@latest && \
    go install github.com/ffuf/ffuf/v2@latest

# ===========================================================================
# Stage 2 – Python runtime with all tools installed
# ===========================================================================
FROM python:slim

LABEL org.opencontainers.image.title="subdomainenum" \
      org.opencontainers.image.description="Passive & active subdomain enumeration CLI" \
      org.opencontainers.image.source="https://github.com/t0kubetsu/subdomainenum"

# System runtime deps: git (for SecLists sparse checkout + dnsrecon source clone),
# curl, unzip, libssl-dev. Build toolchain (build-essential, libffi-dev, etc.) is
# installed transiently inside the dnsrecon step and purged afterwards to keep
# the runtime image small.
RUN apt-get update && apt-get install -y --no-install-recommends \
        git \
        curl \
        unzip \
        libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy Go-compiled binaries first so the dnsrecon step (below) doesn't
# invalidate this cheap layer when DNSRECON_REF changes.
COPY --from=go-builder /go/bin/subfinder    /usr/local/bin/subfinder
COPY --from=go-builder /go/bin/amass        /usr/local/bin/amass
COPY --from=go-builder /go/bin/gobuster     /usr/local/bin/gobuster
COPY --from=go-builder /go/bin/assetfinder  /usr/local/bin/assetfinder
COPY --from=go-builder /go/bin/ffuf         /usr/local/bin/ffuf

# ---------------------------
# dnsrecon – install from source (github.com/darkoperator/dnsrecon)
#
# Tracks upstream master with automatic Docker layer cache invalidation:
# the ADD below fetches the GitHub "latest commit on ${DNSRECON_REF}" JSON.
# Its body (commit SHA + timestamp) changes whenever the ref moves, which
# changes the ADD layer hash and forces the following RUN to re-clone and
# re-install. When the ref hasn't moved, Docker reuses the cached layer.
#
# Mirrors upstream Dockerfile: pip install . from a cloned checkout.
# Build deps are installed, used, and purged in the same layer so no
# toolchain bloat ships in the final image. Override DNSRECON_REF to pin
# to a tag or commit SHA if a reproducible build is needed.
# ---------------------------
ARG DNSRECON_REF=master
ADD https://api.github.com/repos/darkoperator/dnsrecon/commits/${DNSRECON_REF} \
    /tmp/dnsrecon.commit.json
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        libffi-dev \
        libxml2-dev \
        libxslt1-dev \
    && git clone --depth=1 --branch ${DNSRECON_REF} \
        https://github.com/darkoperator/dnsrecon.git /opt/dnsrecon \
    && python -m pip install --upgrade pip \
    && pip install --no-cache-dir /opt/dnsrecon \
    && rm -rf /opt/dnsrecon /tmp/dnsrecon.commit.json \
    && apt-get purge -y --auto-remove \
        build-essential \
        libffi-dev \
        libxml2-dev \
        libxslt1-dev \
    && rm -rf /var/lib/apt/lists/*

# findomain – download pre-built Linux binary from GitHub releases
# (package was removed from crates.io)
RUN curl -sL \
        "https://github.com/Findomain/Findomain/releases/latest/download/findomain-linux-i386.zip" \
        -o /tmp/findomain.zip && \
    unzip /tmp/findomain.zip -d /tmp && \
    mv /tmp/findomain /usr/local/bin/findomain && \
    chmod +x /usr/local/bin/findomain && \
    rm /tmp/findomain.zip

# ---------------------------
# SecLists – sparse checkout (DNS + Web-Content only, avoids 1.5 GB clone)
# ---------------------------
ARG SECLISTS_REF=master
RUN git clone --filter=blob:none --no-checkout --depth=1 \
        https://github.com/danielmiessler/SecLists.git /opt/SecLists && \
    cd /opt/SecLists && \
    git sparse-checkout init --cone && \
    git sparse-checkout set Discovery/DNS Discovery/Web-Content && \
    git checkout ${SECLISTS_REF} && \
    rm -rf /opt/SecLists/.git

# ---------------------------
# Install the subdomainenum package
# ---------------------------
WORKDIR /app
COPY pyproject.toml ./
COPY subdomainenum/ ./subdomainenum/

RUN pip install --no-cache-dir -e "."

# Output directory for saved reports
RUN mkdir /reports

VOLUME ["/reports"]

ENTRYPOINT ["subdomainenum"]
CMD ["--help"]
