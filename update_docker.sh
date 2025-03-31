#!/bin/bash
# Copy updated files to the container
docker cp timetagger/pages/users.md timetagger-timetagger-1:/app/timetagger/pages/users.md
docker cp timetagger/__main__.py timetagger-timetagger-1:/app/timetagger/__main__.py
docker cp timetagger/multiuser/api.py timetagger-timetagger-1:/app/timetagger/multiuser/api.py

# Restart timetagger container
docker restart timetagger-timetagger-1
