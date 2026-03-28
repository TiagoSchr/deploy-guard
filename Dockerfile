FROM python:3.12-slim

LABEL maintainer="Deploy Guard Contributors"
LABEL description="Pre-deploy security scanner with LGPD compliance"

WORKDIR /app

# Install deploy-guard
COPY pyproject.toml README.md LICENSE ./
COPY src/ ./src/

RUN pip install --no-cache-dir . && \
    pip install --no-cache-dir pdfplumber

# Create non-root user for security
RUN useradd --create-home --shell /bin/bash scanner
USER scanner

WORKDIR /scan

ENTRYPOINT ["deploy-guard"]
CMD ["--help"]
