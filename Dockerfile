# RedKit — authorized-use-only pentesting tool.
# Run it in a container against lab targets you are permitted to test.

FROM python:3.12-slim

LABEL org.opencontainers.image.title="RedKit" \
      org.opencontainers.image.description="Modular web application red-teaming framework" \
      org.opencontainers.image.source="https://github.com/K4os-1534/redkit" \
      org.opencontainers.image.licenses="MIT"

WORKDIR /app

# Build from source; README.md and LICENSE are part of the package metadata
COPY pyproject.toml README.md LICENSE ./
COPY src ./src

RUN pip install --no-cache-dir . && \
    useradd --create-home --shell /bin/bash redkit

# Run as an unprivileged user; reports/sessions are written to the mounted CWD
USER redkit
WORKDIR /workdir

ENTRYPOINT ["redkit"]
CMD ["--help"]
