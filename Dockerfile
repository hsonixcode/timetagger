FROM python:3.9-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first to leverage Docker cache
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application
COPY . .

# Create a non-root user and set up data directory
RUN useradd -m -u 1000 timetagger && \
    mkdir -p /home/timetagger/.timetagger/users && \
    chown -R timetagger:timetagger /home/timetagger/.timetagger

USER timetagger

# Expose the port TimeTagger runs on
EXPOSE 8000

# Run TimeTagger
CMD ["python", "-m", "timetagger"] 