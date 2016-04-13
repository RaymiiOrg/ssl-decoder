#!/bin/bash
APPNAME="ssl-decoder"
IMGNAME="php-7.0-apache-2.4-openssl-1.1.0"
FOLDERHERE="/home/remy/repo/ssl-decoder/"
FOLDERTHERE="/var/www/html"

DOCKER_ID="$(docker ps -a 2>&1 | grep "${APPNAME}" | awk '{print $1}')"
if [[ ! -z ${DOCKER_ID} ]]; then
  docker stop "${DOCkER_ID}"
  docker rm "${DOCKER_ID}"
fi

docker build -t "${IMGNAME}" .
docker run --name "${APPNAME}" -v ${FOLDERHERE}:${FOLDERTHERE} ${IMGNAME}
