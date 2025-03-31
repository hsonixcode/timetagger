docker exec $(docker ps -q --filter name=timetagger) bash -c "cd /app && git pull && supervisorctl restart all"
