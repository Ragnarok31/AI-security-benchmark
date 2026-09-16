# ============================================================
# AI Security Benchmark Suite — Scanner Docker Image
# ============================================================
# This image contains all three security scanners
# (Bandit, Semgrep, pip-audit) in an isolated environment.
#
# WHY DOCKER?
# When scanning untrusted code, we don't want a malicious
# file to affect the host machine. Running scanners inside
# a container means even if something goes wrong, it stays
# contained.
#
# BUILD:
#   docker build -t ai-security-benchmark -f docker/Dockerfile .
#
# RUN BENCHMARK IN SANDBOX:
#   python run.py --sandboxed
# ============================================================

# Use official Python slim image as base
# slim = smaller size, fewer attack surface
FROM python:3.11-slim

# Set working directory inside container
WORKDIR /app

# Set environment variables
# PYTHONDONTWRITEBYTECODE: no .pyc files (cleaner)
# PYTHONUNBUFFERED: logs appear immediately (no buffering)
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Install system dependencies
# git is needed by some semgrep rules
# curl is needed for health checks
RUN apt-get update && apt-get install -y \
    git \
    curl \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first (Docker layer caching)
# This means pip install only reruns when
# requirements.txt changes — not on every build
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir \
    bandit \
    semgrep \
    pip-audit \
    pyyaml \
    rich

# Copy project files into container
COPY . .

# Create results directory
RUN mkdir -p results

# Default command — runs the benchmark
CMD ["python", "run.py"]