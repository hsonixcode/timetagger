"""
Database utilities for TimeTagger PostgreSQL integration.

This module provides common database functions and models used
throughout the TimeTagger application for PostgreSQL support.
"""

import os
import time
import logging
from typing import Dict, Any, Optional
from sqlalchemy import create_engine, Column, Integer, String, Float, Text, Boolean, MetaData, Table
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.sql import text

# Set up logger
logger = logging.getLogger("timetagger.server.db_utils")

# Create base model class
Base = declarative_base()

# Define models
class Record(Base):
    """Model for time records"""
    __tablename__ = 'records'
    
    id = Column(Integer, primary_key=True)
    key = Column(String, nullable=False, index=True)
    username = Column(String, nullable=False, index=True)
    t1 = Column(Float, nullable=False, index=True)
    t2 = Column(Float, nullable=True, index=True)
    mt = Column(Float, nullable=False)
    st = Column(Float, nullable=False)
    ds = Column(Text)
    tags = Column(Text)
    
    def __repr__(self):
        return f"<Record(key='{self.key}', username='{self.username}')>"

class Settings(Base):
    """Model for user settings"""
    __tablename__ = 'settings'
    
    id = Column(Integer, primary_key=True)
    key = Column(String, nullable=False, index=True)
    username = Column(String, nullable=False, index=True)
    value = Column(Text)
    mt = Column(Float, nullable=False)
    st = Column(Float, nullable=False)
    
    def __repr__(self):
        return f"<Settings(key='{self.key}', username='{self.username}')>"

class UserInfo(Base):
    """Model for user information"""
    __tablename__ = 'user_info'
    
    id = Column(Integer, primary_key=True)
    username = Column(String, nullable=False, index=True)
    role = Column(String, default="user")
    is_allowed = Column(Boolean, default=True)
    user_metadata = Column(JSONB, default={})
    
    # Add key and value as Python properties to make compatible with existing code
    # These are not actual columns in the database but virtual properties
    _key = None
    _value = None
    _mt = None
    _st = None
    
    @property
    def key(self):
        return self._key
        
    @key.setter
    def key(self, value):
        self._key = value
        
    @property
    def value(self):
        return self._value
        
    @value.setter
    def value(self, value):
        self._value = value
        
    @property
    def mt(self):
        return self._mt
        
    @mt.setter
    def mt(self, value):
        self._mt = value
        
    @property
    def st(self):
        return self._st
        
    @st.setter
    def st(self, value):
        self._st = value
    
    def __repr__(self):
        return f"<UserInfo(username='{self.username}', role='{self.role}')>"

# Model mapping for use in queries
MODEL_MAP = {
    "records": Record,
    "settings": Settings,
    "userinfo": UserInfo
}

def get_database_url() -> str:
    """
    Get the database URL from environment variables.
    
    Returns:
        str: The database URL for SQLAlchemy
    """
    # Check if a direct DB URL is provided
    db_url = os.environ.get("TIMETAGGER_DB_URL")
    if db_url:
        logger.info("Using database URL from TIMETAGGER_DB_URL environment variable")
        return db_url
    
    # Otherwise construct from components
    host = os.environ.get("POSTGRES_HOST", "postgres")
    port = os.environ.get("POSTGRES_PORT", "5432")
    user = os.environ.get("POSTGRES_USER", "timetagger")
    password = os.environ.get("POSTGRES_PASSWORD", "timetagger")
    db = os.environ.get("POSTGRES_DB", "timetagger")
    
    # Construct and return the URL
    url = f"postgresql://{user}:{password}@{host}:{port}/{db}"
    logger.info(f"Constructed database URL for {user}@{host}:{port}/{db}")
    return url

def get_engine():
    """
    Get or create the SQLAlchemy engine.
    
    Returns:
        Engine: The SQLAlchemy engine
    """
    # Get the database URL
    db_url = get_database_url()
    
    try:
        # Create the engine
        engine = create_engine(db_url)
        logger.info("Database engine created successfully")
        return engine
    except Exception as e:
        logger.error(f"Error creating database engine: {e}")
        raise

def get_session() -> Session:
    """
    Get a new database session.
    
    Returns:
        Session: A new SQLAlchemy session
    """
    engine = get_engine()
    Session = sessionmaker(bind=engine)
    return Session()

def initialize_database():
    """
    Initialize the database, creating all tables.
    """
    engine = get_engine()
    # Only create tables that don't exist yet
    Base.metadata.create_all(engine)
    logger.info("Database initialized with all tables created")
    
    # Run migration to update existing tables if needed
    migrate_database()

def migrate_database():
    """
    Migrate the database schema to match the current models.
    """
    engine = get_engine()
    
    try:
        # Use raw SQL to check if columns exist and add them if they don't
        with engine.connect() as connection:
            # Create userinfo_key_value table for storing key-value pairs
            connection.execute(text("""
                CREATE TABLE IF NOT EXISTS userinfo_key_value (
                    id SERIAL PRIMARY KEY,
                    username VARCHAR NOT NULL,
                    key VARCHAR NOT NULL,
                    value TEXT,
                    mt FLOAT,
                    st FLOAT,
                    UNIQUE(username, key)
                )
            """))
            
            connection.execute(text("""
                CREATE INDEX IF NOT EXISTS idx_userinfo_key_value_username_key 
                ON userinfo_key_value (username, key)
            """))
            
            # Add initial webtoken_seed if it doesn't exist
            connection.execute(text("""
                INSERT INTO userinfo_key_value (username, key, value, mt, st)
                SELECT 'admin', 'webtoken_seed', md5(random()::text), extract(epoch from now()), extract(epoch from now())
                WHERE NOT EXISTS (
                    SELECT 1 FROM userinfo_key_value WHERE username = 'admin' AND key = 'webtoken_seed'
                )
            """))
            
            connection.commit()
            logger.info("Database migration completed successfully")
            
    except Exception as e:
        logger.error(f"Error migrating database: {e}")
        raise

# Create custom wrapper for UserInfo access
class UserInfoKeyValue:
    """Manual model for userinfo_key_value table"""
    __tablename__ = 'userinfo_key_value'
    
    def __init__(self, username=None, key=None, value=None, mt=None, st=None):
        self.username = username
        self.key = key
        self.value = value
        self.mt = mt or time.time()
        self.st = st or time.time()
    
    @staticmethod
    def ensure_table_exists():
        """Ensure the userinfo_key_value table exists"""
        engine = get_engine()
        with engine.connect() as connection:
            # Create table if it doesn't exist
            connection.execute(text("""
                CREATE TABLE IF NOT EXISTS userinfo_key_value (
                    id SERIAL PRIMARY KEY,
                    username VARCHAR NOT NULL,
                    key VARCHAR NOT NULL,
                    value TEXT,
                    mt FLOAT,
                    st FLOAT,
                    UNIQUE(username, key)
                )
            """))
            
            connection.execute(text("""
                CREATE INDEX IF NOT EXISTS idx_userinfo_key_value_username_key 
                ON userinfo_key_value (username, key)
            """))
            
            # Add initial webtoken_seed if it doesn't exist
            connection.execute(text("""
                INSERT INTO userinfo_key_value (username, key, value, mt, st)
                SELECT 'admin', 'webtoken_seed', md5(random()::text), extract(epoch from now()), extract(epoch from now())
                WHERE NOT EXISTS (
                    SELECT 1 FROM userinfo_key_value WHERE username = 'admin' AND key = 'webtoken_seed'
                )
            """))
            
            connection.commit()
            logger.info("UserInfoKeyValue table created or verified")
        
    @staticmethod
    def get_by_username_and_key(username, key):
        """Get a record by username and key"""
        # Ensure table exists
        UserInfoKeyValue.ensure_table_exists()
        
        engine = get_engine()
        with engine.connect() as connection:
            result = connection.execute(text(
                "SELECT * FROM userinfo_key_value WHERE username = :username AND key = :key"
            ), {"username": username, "key": key})
            row = result.fetchone()
            if row:
                obj = UserInfoKeyValue()
                obj.username = row.username
                obj.key = row.key
                obj.value = row.value
                obj.mt = row.mt
                obj.st = row.st
                return obj
            return None
            
    @staticmethod
    def save(obj):
        """Save or update a record"""
        # Ensure table exists
        UserInfoKeyValue.ensure_table_exists()
        
        engine = get_engine()
        with engine.connect() as connection:
            # Check if record exists
            result = connection.execute(text(
                "SELECT id FROM userinfo_key_value WHERE username = :username AND key = :key"
            ), {"username": obj.username, "key": obj.key})
            row = result.fetchone()
            
            if row:
                # Update
                connection.execute(text(
                    "UPDATE userinfo_key_value SET value = :value, mt = :mt, st = :st "
                    "WHERE username = :username AND key = :key"
                ), {
                    "username": obj.username, 
                    "key": obj.key, 
                    "value": obj.value,
                    "mt": obj.mt,
                    "st": obj.st
                })
            else:
                # Insert
                connection.execute(text(
                    "INSERT INTO userinfo_key_value (username, key, value, mt, st) "
                    "VALUES (:username, :key, :value, :mt, :st)"
                ), {
                    "username": obj.username, 
                    "key": obj.key, 
                    "value": obj.value,
                    "mt": obj.mt,
                    "st": obj.st
                })
            
            connection.commit()
            
    def __repr__(self):
        return f"<UserInfoKeyValue(username='{self.username}', key='{self.key}')>" 