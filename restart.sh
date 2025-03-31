#!/bin/bash
echo "Stopping TimeTagger server..."
pkill -f "python3 -m timetagger"
sleep 1
echo "Starting TimeTagger server..."
cd /Users/hsonixcode/Projects/timetagger
python3 -m timetagger &
echo "Server restarted!"
