# Use Python 3.9 slim image
FROM python:3.9-slim

# Install git and other dependencies
RUN apt-get update && apt-get install -y \
    git \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Clone the repository with submodules
RUN git clone --recursive https://github.com/hsonixcode/timetagger.git .

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

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

# Run the application
CMD ["python", "-m", "timetagger"] 