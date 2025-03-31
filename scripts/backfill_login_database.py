#!/usr/bin/env python3
"""
Backfill script for the central login database.

This script scans existing user databases and populates the central login database
with user information, including login timestamps.
"""

import os
import sys
import argparse
import logging
from pathlib import Path

# Add the parent directory to the path so we can import TimeTagger modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from timetagger.multiuser.login_tracker import LoginTracker
from timetagger.server._utils import ROOT_USER_DIR

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("backfill_login_database")

def main():
    """Run the backfill operation."""
    parser = argparse.ArgumentParser(description="Backfill the central login database from existing user databases.")
    parser.add_argument("--dry-run", action="store_true", help="Print what would be done without actually modifying the database.")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output.")
    args = parser.parse_args()
    
    # Set log level
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    # Print informational message
    logger.info("Starting backfill operation")
    logger.info(f"User directory: {ROOT_USER_DIR}")
    
    # Check if user directory exists
    if not os.path.exists(ROOT_USER_DIR):
        logger.error(f"User directory does not exist: {ROOT_USER_DIR}")
        sys.exit(1)
    
    # Get user database files
    user_dbs = list(Path(ROOT_USER_DIR).glob("*.db"))
    logger.info(f"Found {len(user_dbs)} user database files")
    
    # Skip if in dry run mode
    if args.dry_run:
        logger.info("Dry run mode - not making any changes")
        return
    
    # Create login tracker and run backfill
    login_tracker = LoginTracker()
    
    logger.info("Starting backfill...")
    success_count, error_count = login_tracker.backfill_from_user_databases()
    
    # Print results
    logger.info(f"Backfill operation completed")
    logger.info(f"Successfully processed {success_count} users")
    logger.info(f"Failed to process {error_count} users")
    
    # Return exit code based on success
    return 0 if error_count == 0 else 1

if __name__ == "__main__":
    sys.exit(main()) 