#!/bin/bash
set -e

echo "Waiting for PostgreSQL to be ready..."
# Wait for PostgreSQL to be ready (max 60 seconds)
MAX_TRIES=60
COUNT=0
while [ $COUNT -lt $MAX_TRIES ]; do
    if pg_isready -h postgres; then
        echo "PostgreSQL is ready!"
        break
    fi
    COUNT=$((COUNT+1))
    echo "Waiting for PostgreSQL... ($COUNT/$MAX_TRIES)"
    sleep 1
done

if [ $COUNT -eq $MAX_TRIES ]; then
    echo "Error: PostgreSQL did not become ready in time"
    exit 1
fi

# The application now handles database initialization on startup
echo "Starting TimeTagger with built-in database initialization..."
exec python -m timetagger 