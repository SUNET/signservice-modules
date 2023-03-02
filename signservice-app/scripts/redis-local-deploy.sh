#!/bin/bash

#
# Deployment script for using Redis locally ...
#

echo Pulling Redis docker image ...
docker pull redis

echo Undeploying ...
docker rm signservice-redis --force

echo Redeploying Redis docker container signservice-redis ...

docker run --name signservice-redis -p 6379:6379 -v ${DEV_ROOT}/sunet/data/redis:/data -d redis redis-server --save 60 1 --loglevel debug 
