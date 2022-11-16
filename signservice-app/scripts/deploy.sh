#!/bin/bash

#
# Deployment script for the Sandbox environment
#

SIGNSERVICE_HTTPS_PORT=9030
SIGNSERVICE_AJP_PORT=9039

echo Pulling signservice-sandbox docker image ...
docker pull docker.eidastest.se:5000/signservice-sandbox

echo Undeploying signservice-sandbox container ...
docker rm signservice-sandbox --force

SS_HOME=/opt/signservice
# -e SPRING_CONFIG_ADDITIONAL_LOCATION=${SS_HOME}/config \

echo Redeploying docker container signservice-sandbox ...
docker run -d --name signservice-sandbox --restart=always \
  -p ${SIGNSERVICE_AJP_PORT}:8009 \
  -p ${SIGNSERVICE_HTTPS_PORT}:8443 \
  -e SPRING_PROFILES_ACTIVE=sandbox \
  -e SERVER_SERVLET_CONTEXT_PATH=signservice \
  -e SIGNSERVICE_HOME=${SS_HOME} \
  -e SIGNSERVICE_CLIENT_CONFIG_DIRECTORY=${SS_HOME}/clients \
  -e "TZ=Europe/Stockholm" \
  -v /etc/localtime:/etc/localtime:ro \
  -v /opt/docker/signservice:${SS_HOME} \
  docker.eidastest.se:5000/signservice-sandbox

echo Done!

