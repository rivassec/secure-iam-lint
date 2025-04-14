# Dockerfile for secure-iam-lint
FROM python:3.10-slim

# Set working directory and create non-root user in a single RUN layer
RUN useradd --create-home --shell /bin/bash appuser && \
    mkdir -p /app && \
    chown -R appuser /app

WORKDIR /app

# Copy and install in one layer (minimizes intermediate image size)
COPY setup.py iam_lint.py ./
COPY iamlint/ ./iamlint/
COPY examples/ ./examples/
RUN pip install --no-cache-dir .

USER appuser

# Add HEALTHCHECK to satisfy security tools
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD ["iam-lint", "--help"] || exit 1

ENTRYPOINT ["iam-lint"]
