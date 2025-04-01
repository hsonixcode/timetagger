# Use Python 3.9 slim image
FROM python:3.9-slim

# Install git and other dependencies
RUN apt-get update && apt-get install -y \
    git \
    gcc \
    libpq-dev \
    postgresql-client \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements first to leverage Docker cache
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code
COPY . .

# Make entrypoint script executable
RUN chmod +x /app/docker-entrypoint.sh

# Install the package in editable mode
RUN pip install -e .

# Create non-root user
RUN useradd -m -u 1000 timetagger && \
    mkdir -p /home/timetagger/.timetagger && \
    chown -R timetagger:timetagger /home/timetagger

# Switch to non-root user
USER timetagger

# Set environment variables
ENV PYTHONPATH=/app
ENV PATH="/home/timetagger/.local/bin:${PATH}"

# Expose port
EXPOSE 8000

# Use our custom entrypoint script
ENTRYPOINT ["/app/docker-entrypoint.sh"] 