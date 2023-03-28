#!/bin/bash

#
# Deployment script for the eduSign SignService in the Sandbox environment
#

REDIS_PORT=6379
SIGNSERVICE_HTTPS_PORT=9070
SIGNSERVICE_AJP_PORT=9079

REDIS_CONTAINER_IP=`docker inspect -f "{{ .NetworkSettings.IPAddress }}" signservice-redis`

if [ -n "$REDIS_CONTAINER_IP" ]; then
  echo "Will connect to Redis at: ${REDIS_CONTAINER_IP}"
else
  echo "Redis is not started. Start it by invoking signservice-redis-deploy.sh"
  exit 1
fi

echo Pulling edusign-signservice docker image ...
docker pull docker.eidastest.se:5000/edusign-signservice

echo Undeploying edusign-signservice container ...
docker rm edusign-signservice --force

SS_HOME=/opt/edusign-signservice

echo Redeploying docker container edusign-signservice ...
docker run -d --name edusign-signservice --restart=always \
  -p ${SIGNSERVICE_AJP_PORT}:8009 \
  -p ${SIGNSERVICE_HTTPS_PORT}:8443 \
  -e SPRING_CONFIG_LOCATION=${SS_HOME}/config/application.yml \
  -e SIGNSERVICE_HOME=${SS_HOME} \
  -e SPRING_REDIS_HOST=${REDIS_CONTAINER_IP} \
  -e SPRING_REDIS_PORT=${REDIS_PORT} \
  -e SPRING_SESSION_STORE_TYPE=redis \
  -e SPRING_SESSION_REDIS_NAMESPACE=signservice:session \
  -e SPRING_SESSION_REDIS_FLUSH_MODE="immediate" \
  -e SPRING_SESSION_REDIS_SAVE_MODE="on-set-attribute" \
  -e "TZ=Europe/Stockholm" \
  -v /etc/localtime:/etc/localtime:ro \
  -v /opt/docker/edusign-signservice:${SS_HOME} \
  docker.eidastest.se:5000/edusign-signservice

echo Done!

