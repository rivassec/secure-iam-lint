# Dockerfile for secure-iam-lint
FROM python:3.10-slim

# Set working directory
WORKDIR /app

# Copy only necessary files
COPY setup.py .
COPY iam_lint.py .
COPY iamlint/ ./iamlint/
COPY examples/ ./examples/

# Install the tool in editable mode
RUN pip install --no-cache-dir .

# Default command
ENTRYPOINT ["iam-lint"]

