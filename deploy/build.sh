#!/bin/bash

#
# Builds the SignService application 
#

usage() {
    echo "Usage: $0 [options...]" >&2
    echo
    echo "   -i, --image            Name of image to create (default is edusign-signservice)"
    echo "   -t, --tag              Optional docker tag for image"
    echo "   -h, --help             Prints this help"
    echo
}

DEPLOY_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

IMAGE_NAME=""
DOCKER_TAG=""

while :
do
    case "$1" in
  -h | --help)
      usage
      exit 0
      ;;
  -i | --image)
      IMAGE_NAME="$2"
      shift 2
      ;;
  -t | --tag)
      DOCKER_TAG="$2"
      shift 2
      ;;
  --)
      shift
      break;
      ;;
  -*)
      echo "Error: Unknown option: $1" >&2
      usage
      exit 0
      ;;
  *)
      break
      ;;
    esac
done

if [ "$IMAGE_NAME" == "" ]; then
    IMAGE_NAME=edusign-signservice
    echo "Docker image name not given, defaulting to $IMAGE_NAME" >&1
fi

echo
echo "Building SignService source ..."
echo

mvn -f ${DEPLOY_DIR}/../pom.xml clean install

if [ "$DOCKER_TAG" != "" ]; then
    IMAGE_NAME="$IMAGE_NAME:$DOCKER_TAG"
fi

echo
echo "Building Docker image ${IMAGE_NAME} ..."
echo


docker build -f ${DEPLOY_DIR}/Dockerfile -t ${IMAGE_NAME} ${DEPLOY_DIR}/../signservice-app


