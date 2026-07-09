# portscanner container: nmap (required) + rustscan (optional) + the package.
# Both scanners use TCP connect scans here, so the container needs no extra
# capabilities (no NET_RAW / root-only raw sockets).
FROM python:3.12-slim

ARG RUSTSCAN_VERSION=2.4.1

RUN apt-get update \
    && apt-get install -y --no-install-recommends nmap ca-certificates curl unzip \
    && rm -rf /var/lib/apt/lists/*

# rustscan is optional (only used by --rustscan). Best-effort install from the
# GitHub release; the image still builds (nmap-only) if this step fails.
RUN set -eux; \
    ( curl -fsSL -o /tmp/rustscan.deb.zip \
        "https://github.com/RustScan/RustScan/releases/download/${RUSTSCAN_VERSION}/rustscan.deb.zip" \
      && unzip -o /tmp/rustscan.deb.zip -d /tmp \
      && dpkg -i /tmp/rustscan*.deb ) \
    || echo "rustscan install skipped — image will run nmap-only"; \
    rm -f /tmp/rustscan.deb.zip /tmp/rustscan*.deb || true

WORKDIR /app
COPY . /app
RUN pip install --no-cache-dir .

# Saved reports land in a mountable volume (matches the platform convention of
# mounting ./reports).
VOLUME ["/reports"]
WORKDIR /reports

ENTRYPOINT ["portscanner"]
CMD ["--help"]
