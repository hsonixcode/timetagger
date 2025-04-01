# PostgreSQL Database Configuration for TimeTagger

TimeTagger now supports PostgreSQL as a database backend, offering improved performance, reliability, and concurrency for multi-user environments.

## Why PostgreSQL?

While SQLite is excellent for single-user setups or smaller deployments, PostgreSQL offers several advantages for larger or production environments:

- **Concurrency**: Multiple users can write to the database simultaneously without locking
- **Reliability**: Built-in features for data integrity and crash recovery
- **Scalability**: Better performance as your data and user base grows
- **Advanced Features**: Full SQL support, robust indexing, and query optimization

## Setting Up PostgreSQL

### Option 1: Docker Compose (Recommended)

The easiest way to set up TimeTagger with PostgreSQL is using Docker Compose:

1. Create or modify your `.env` file with PostgreSQL configuration:

```
# PostgreSQL Configuration
POSTGRES_USER=timetagger
POSTGRES_PASSWORD=your_secure_password
POSTGRES_DB=timetagger
POSTGRES_HOST=postgres
POSTGRES_PORT=5432

# TimeTagger Database URL
TIMETAGGER_DB_URL=postgresql://timetagger:your_secure_password@postgres:5432/timetagger
```

2. Update your `docker-compose.yml` to include PostgreSQL:

```yaml
version: '3'

services:
  postgres:
    image: postgres:15
    environment:
      - POSTGRES_USER=${POSTGRES_USER}
      - POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
      - POSTGRES_DB=${POSTGRES_DB}
    volumes:
      - postgres_data:/var/lib/postgresql/data
    restart: unless-stopped
    
  timetagger:
    image: timetagger/timetagger:latest
    # Or build from local source
    # build: .
    depends_on:
      - postgres
    environment:
      - TIMETAGGER_DB_URL=${TIMETAGGER_DB_URL}
      - TIMETAGGER_BIND=0.0.0.0:8000
      - TIMETAGGER_CREDENTIALS=${TIMETAGGER_CREDENTIALS}
    ports:
      - "8000:8000"
    volumes:
      - timetagger_data:/app/data
    restart: unless-stopped

volumes:
  postgres_data:
  timetagger_data:
```

3. Launch the services:

```bash
docker-compose up -d
```

### Option 2: Manual Setup

If you prefer to manage PostgreSQL separately:

1. Install PostgreSQL on your system or use a hosted PostgreSQL service

2. Create a database and user for TimeTagger:

```sql
CREATE DATABASE timetagger;
CREATE USER timetagger WITH PASSWORD 'your_secure_password';
GRANT ALL PRIVILEGES ON DATABASE timetagger TO timetagger;
```

3. Configure TimeTagger to use PostgreSQL by setting the environment variable:

```bash
export TIMETAGGER_DB_URL=postgresql://timetagger:your_secure_password@localhost:5432/timetagger
```

Or add it to your `.env` file if using Docker.

## Migrating from SQLite to PostgreSQL

If you're transitioning from SQLite to PostgreSQL, TimeTagger provides a migration script:

1. Make sure PostgreSQL is running and configured

2. Run the migration script:

```bash
python scripts/migrate_to_postgres.py --all --login-db --validate
```

This script will:
- Initialize the PostgreSQL database
- Migrate all user data from SQLite to PostgreSQL
- Migrate the login tracking database
- Validate that the migration was successful

### Migration Options

The script supports the following options:

- `--username USERNAME`: Migrate a specific user only
- `--all`: Migrate all users (recommended)
- `--login-db`: Migrate the central login database
- `--validate`: Verify migration success by comparing record counts

## Troubleshooting

### Connection Issues

If TimeTagger cannot connect to PostgreSQL:

1. Verify PostgreSQL is running and accessible
2. Check the database URL format: `postgresql://username:password@host:port/database`
3. Ensure network connectivity between TimeTagger and PostgreSQL
4. Check PostgreSQL logs for connection errors

### Migration Problems

If you encounter issues during migration:

1. Check the migration log file (`migration.log`)
2. Ensure the PostgreSQL user has sufficient permissions
3. Try migrating a single user first with `--username` to identify specific issues
4. Verify SQLite databases exist and are not corrupted

## Backup and Restore

Always backup your data before and after migration:

### Backup PostgreSQL

```bash
pg_dump -U timetagger -d timetagger -F c -f timetagger_backup.dump
```

### Restore PostgreSQL

```bash
pg_restore -U timetagger -d timetagger -c timetagger_backup.dump
```

### Backup SQLite (for reference)

```bash
# Copy the entire users directory
cp -r /path/to/timetagger/data/users /backup/location
```

## Performance Tuning

For larger deployments, consider these PostgreSQL optimizations:

```
# Add to postgresql.conf
shared_buffers = 1GB
work_mem = 32MB
maintenance_work_mem = 256MB
effective_cache_size = 2GB
```

Adjust values based on your server resources and usage patterns. 