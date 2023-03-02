#
# Deployment script for the Redis server used by signservice services
#
#!/bin/bash

REDIS_PORT=6379
echo Pulling Redis docker image ...
docker pull redis

echo Undeploying Redis container ...
docker rm signservice-redis --force

echo Redeploying Redis docker container signservice-redis ...
docker run -d --name signservice-redis --restart=always \
  -p ${REDIS_PORT}:6379 \
  -v /opt/docker/signservice-redis:/data \
  redis

REDIS_CONTAINER_IP=`docker inspect -f "{{ .NetworkSettings.IPAddress }}" signservice-redis`

echo "Redis container started - IP: ${REDIS_CONTAINER_IP}"
