#!/bin/bash

#
# Deployment script for the eduSign SignService in the Sandbox environment
#

SIGNSERVICE_HTTPS_PORT=9070
SIGNSERVICE_AJP_PORT=9079

echo Pulling edusign-signservice docker image ...
docker pull docker.eidastest.se:5000/edusign-signservice

echo Undeploying edusign-signservice container ...
docker rm edusign-signservice --force

SS_HOME=/opt/edusign-signservice
# -e SPRING_CONFIG_ADDITIONAL_LOCATION=${SS_HOME}/config \

echo Redeploying docker container edusign-signservice ...
docker run -d --name edusign-signservice --restart=always \
  -p ${SIGNSERVICE_AJP_PORT}:8009 \
  -p ${SIGNSERVICE_HTTPS_PORT}:8443 \
  -e SPRING_PROFILES_ACTIVE=sandbox \
  -e SPRING_CONFIG_ADDITIONAL_LOCATION=${SS_HOME}/config/ \
  -e SERVER_SERVLET_CONTEXT_PATH="/edusign-signservice" \
  -e SIGNSERVICE_HOME=${SS_HOME} \
  -e SIGNSERVICE_CLIENT_CONFIG_DIRECTORY=${SS_HOME}/clients \
  -e "TZ=Europe/Stockholm" \
  -v /etc/localtime:/etc/localtime:ro \
  -v /opt/docker/edusign-signservice:${SS_HOME} \
  docker.eidastest.se:5000/edusign-signservice

echo Done!

