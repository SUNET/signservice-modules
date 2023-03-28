#!/bin/bash

#
# Deployment script for the eduSign SignService
#

REDIS_PORT=6379
SIGNSERVICE_HTTPS_PORT=9070

if [ "$SIGNSERVICE_DIR" == "" ]; then
  echo "Variable SIGNSERVICE_DIR must be set"
  exit 1
fi

if [ ! -d ${SIGNSERVICE_DIR}/config ]; then
  echo "Directory ${SIGNSERVICE_DIR}/config must exist and contain the SignService configuration"
  exit 1
fi

SS_HOME=/opt/edusign-signservice

echo Starting docker container edusign-signservice ...
docker run -d --name edusign-signservice --restart=always \
  -p ${SIGNSERVICE_HTTPS_PORT}:8443 \
  -e SIGNSERVICE_HOME=${SS_HOME} \
  -e SPRING_CONFIG_LOCATION=${SS_HOME}/config/application.yml \
#  -e SPRING_PROFILES_ACTIVE=qa \
#  -e SERVER_SERVLET_CONTEXT_PATH="/edusign-signservice" \  
  -e "TZ=Europe/Stockholm" \
  -v /etc/localtime:/etc/localtime:ro \
  -v ${SIGNSERVICE_DIR}:${SS_HOME} \
  edusign-signservice

echo Done!

