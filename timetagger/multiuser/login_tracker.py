"""
Centralized login tracking for TimeTagger.

This module provides functionality for tracking user logins in a central database,
unifying login data for both local and Azure users.
"""

import os
import logging
import json
import time
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime

from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text, Index, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.sql import select, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.exc import SQLAlchemyError

from timetagger.server.db_utils import get_database_url, get_engine

logger = logging.getLogger("timetagger.multiuser.login_tracker")

# Define the SQLAlchemy model
Base = declarative_base()

class LoginUser(Base):
    __tablename__ = 'login_users'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    email = Column(String(255), unique=True, nullable=False)
    username = Column(String(255), nullable=False)
    role = Column(String(50), default='user')
    last_login = Column(DateTime)
    user_type = Column(String(10), default='local')
    access = Column(String(20), default='allowed')
    source_db = Column(String(255))
    user_metadata = Column(JSONB)
    
    # Define indices
    __table_args__ = (
        Index('idx_email', email),
        Index('idx_username', username),
        Index('idx_user_type', user_type),
        Index('idx_last_login', last_login),
    )
    
    def to_dict(self):
        """Convert model to dictionary"""
        return {
            'id': self.id,
            'email': self.email,
            'username': self.username,
            'role': self.role,
            'last_login': self.last_login.timestamp() if self.last_login else None,
            'user_type': self.user_type,
            'access': self.access,
            'source_db': self.source_db,
            'metadata': self.user_metadata
        }

class LoginTracker:
    """
    Tracks user logins in a central database.
    """
    
    def __init__(self):
        """
        Initialize the LoginTracker.
        """
        self._engine = get_engine()
        self._Session = sessionmaker(bind=self._engine)
        self._ensure_db_exists()
    
    def _ensure_db_exists(self):
        """
        Ensure the central login database exists with the required schema.
        """
        try:
            # Create tables if they don't exist
            Base.metadata.create_all(self._engine)
            logger.info("Login database tables initialized")
        except Exception as e:
            logger.error(f"Error ensuring login database exists: {str(e)}")
    
    async def record_login(self, user_data: Dict[str, Any]) -> bool:
        """
        Record a user login in the central database.
        
        Args:
            user_data: Dictionary containing user information.
                Required keys: email, username, user_type
                Optional keys: role, access, source_db, metadata
                
        Returns:
            bool: True if the login was recorded successfully, False otherwise.
        """
        try:
            # Ensure required fields
            email = user_data.get("email")
            if not email:
                logger.warning("Cannot record login: email is required")
                return False
            
            username = user_data.get("username")
            if not username:
                logger.warning("Cannot record login: username is required")
                return False
            
            user_type = user_data.get("user_type", "local")
            if user_type not in ("local", "azure"):
                user_type = "local"  # Default to local if invalid
            
            # Optional fields with defaults
            role = user_data.get("role", "user")
            access = "allowed" if user_data.get("is_allowed", True) else "not allowed"
            source_db = user_data.get("source_db", "")
            user_metadata = user_data.get("metadata", {})
            if not isinstance(user_metadata, dict):
                user_metadata = {}
            
            # Set last_login to current timestamp
            last_login = datetime.utcfromtimestamp(time.time())
            
            # Create a new session
            session = self._Session()
            
            try:
                # Check if user exists
                existing_user = session.query(LoginUser).filter_by(email=email).first()
                
                if existing_user:
                    # Update existing user
                    existing_user.username = username
                    existing_user.role = role
                    existing_user.last_login = last_login
                    existing_user.user_type = user_type
                    existing_user.access = access
                    existing_user.source_db = source_db
                    existing_user.user_metadata = user_metadata
                    logger.info(f"Updated login record for user {email}")
                else:
                    # Insert new user
                    new_user = LoginUser(
                        email=email,
                        username=username,
                        role=role,
                        last_login=last_login,
                        user_type=user_type,
                        access=access,
                        source_db=source_db,
                        user_metadata=user_metadata
                    )
                    session.add(new_user)
                    logger.info(f"Created new login record for user {email}")
                
                session.commit()
                return True
                
            except Exception as e:
                session.rollback()
                logger.error(f"Database error recording login for {email}: {str(e)}")
                return False
                
            finally:
                session.close()
                
        except Exception as e:
            logger.error(f"Error recording login for user {user_data.get('email')}: {str(e)}")
            return False
    
    def get_all_logins(self, 
                      user_type: Optional[str] = None, 
                      role: Optional[str] = None,
                      access: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Get all logins from the central database, with optional filtering.
        
        Args:
            user_type: Optional filter by user type ('local' or 'azure')
            role: Optional filter by role (e.g., 'admin', 'user')
            access: Optional filter by access ('allowed' or 'not allowed')
            
        Returns:
            List of user dictionaries.
        """
        try:
            # Create a new session
            session = self._Session()
            
            try:
                # Build the query with potential filters
                query = session.query(LoginUser)
                
                if user_type:
                    query = query.filter(LoginUser.user_type == user_type)
                
                if role:
                    query = query.filter(LoginUser.role == role)
                
                if access:
                    query = query.filter(LoginUser.access == access)
                
                # Execute the query and convert results to dictionaries
                users = [user.to_dict() for user in query.all()]
                
                return users
                
            finally:
                session.close()
                
        except Exception as e:
            logger.error(f"Error retrieving logins: {str(e)}")
            return []
    
    def get_user_by_email(self, email: str) -> Optional[Dict[str, Any]]:
        """
        Get a user by email address.
        
        Args:
            email: The email address to look up
            
        Returns:
            User dictionary or None if not found
        """
        try:
            # Create a new session
            session = self._Session()
            
            try:
                # Query for the user
                user = session.query(LoginUser).filter_by(email=email).first()
                
                if user:
                    return user.to_dict()
                return None
                
            finally:
                session.close()
                
        except Exception as e:
            logger.error(f"Error retrieving user by email {email}: {str(e)}")
            return None
    
    def get_login_by_email(self, email: str) -> Optional[Dict[str, Any]]:
        """
        Alias for get_user_by_email for backward compatibility.
        
        Args:
            email: The email address to look up
            
        Returns:
            User dictionary or None if not found
        """
        logger.debug(f"Using deprecated method get_login_by_email for {email}, use get_user_by_email instead")
        return self.get_user_by_email(email)
    
    def update_user_role(self, email: str, new_role: str) -> bool:
        """
        Update a user's role.
        
        Args:
            email: The email address of the user to update
            new_role: The new role to assign
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            # Create a new session
            session = self._Session()
            
            try:
                # Find the user
                user = session.query(LoginUser).filter_by(email=email).first()
                
                if not user:
                    logger.warning(f"Cannot update role: user with email {email} not found")
                    return False
                
                # Update the role
                user.role = new_role
                session.commit()
                
                logger.info(f"Updated role for user {email} to {new_role}")
                return True
                
            except Exception as e:
                session.rollback()
                logger.error(f"Database error updating role for {email}: {str(e)}")
                return False
                
            finally:
                session.close()
                
        except Exception as e:
            logger.error(f"Error updating role for user {email}: {str(e)}")
            return False
    
    def update_user_access(self, email: str, allowed: bool) -> bool:
        """
        Update a user's access status.
        
        Args:
            email: The email address of the user to update
            allowed: Whether the user is allowed access
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            # Create a new session
            session = self._Session()
            
            try:
                # Find the user
                user = session.query(LoginUser).filter_by(email=email).first()
                
                if not user:
                    logger.warning(f"Cannot update access: user with email {email} not found")
                    return False
                
                # Update the access
                user.access = "allowed" if allowed else "not allowed"
                session.commit()
                
                logger.info(f"Updated access for user {email} to {user.access}")
                return True
                
            except Exception as e:
                session.rollback()
                logger.error(f"Database error updating access for {email}: {str(e)}")
                return False
                
            finally:
                session.close()
                
        except Exception as e:
            logger.error(f"Error updating access for user {email}: {str(e)}")
            return False
    
    def get_login_stats(self) -> Dict[str, Any]:
        """
        Get login statistics.
        
        Returns:
            Dictionary with statistics
        """
        try:
            # Create a new session
            session = self._Session()
            
            try:
                stats = {
                    "total_users": session.query(func.count(LoginUser.id)).scalar(),
                    "local_users": session.query(func.count(LoginUser.id)).filter_by(user_type="local").scalar(),
                    "azure_users": session.query(func.count(LoginUser.id)).filter_by(user_type="azure").scalar(),
                    "admin_users": session.query(func.count(LoginUser.id)).filter_by(role="admin").scalar(),
                    "users_with_access": session.query(func.count(LoginUser.id)).filter_by(access="allowed").scalar(),
                    "users_without_access": session.query(func.count(LoginUser.id)).filter_by(access="not allowed").scalar(),
                }
                
                return stats
                
            finally:
                session.close()
                
        except Exception as e:
            logger.error(f"Error getting login stats: {str(e)}")
            return {
                "total_users": 0,
                "local_users": 0,
                "azure_users": 0,
                "admin_users": 0,
                "users_with_access": 0,
                "users_without_access": 0,
                "error": str(e)
            } 