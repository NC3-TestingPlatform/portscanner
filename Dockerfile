# portscanner container: nmap (required) + rustscan (optional) + the package.
# Both scanners use TCP connect scans here, so the container needs no extra
# capabilities (no NET_RAW / root-only raw sockets).
FROM python:slim

# nmap (required) + cargo/toolchain to build rustscan.
RUN apt-get update \
    && apt-get install -y --no-install-recommends nmap ca-certificates cargo build-essential \
    && rm -rf /var/lib/apt/lists/*

# rustscan (optional, for --rustscan): install from crates.io via cargo.
ENV CARGO_HOME=/opt/cargo PATH=/opt/cargo/bin:$PATH
RUN cargo install rustscan \
    && rm -rf /opt/cargo/registry

WORKDIR /app
COPY . /app
RUN pip install --no-cache-dir .

# Saved reports land in a mountable volume (matches the platform convention of
# mounting ./reports).
VOLUME ["/reports"]
WORKDIR /reports

ENTRYPOINT ["portscanner"]
CMD ["--help"]
