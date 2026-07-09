# portscanner container: nmap (required) + rustscan (optional) + the package.
# Both scanners use TCP connect scans here, so the container needs no extra
# capabilities (no NET_RAW / root-only raw sockets).
FROM python:slim

ARG RUSTSCAN_VERSION=2.4.1

# nmap (required) + a build toolchain to compile rustscan from cargo.
RUN apt-get update \
    && apt-get install -y --no-install-recommends nmap ca-certificates curl build-essential \
    && rm -rf /var/lib/apt/lists/*

# rustscan (optional, for --rustscan): install from crates.io via cargo.
ENV RUSTUP_HOME=/opt/rustup CARGO_HOME=/opt/cargo PATH=/opt/cargo/bin:$PATH
RUN curl -fsSL https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain stable \
    && cargo install rustscan --version "${RUSTSCAN_VERSION}" --locked \
    && rm -rf /opt/cargo/registry /opt/rustup

WORKDIR /app
COPY . /app
RUN pip install --no-cache-dir .

# Saved reports land in a mountable volume (matches the platform convention of
# mounting ./reports).
VOLUME ["/reports"]
WORKDIR /reports

ENTRYPOINT ["portscanner"]
CMD ["--help"]
