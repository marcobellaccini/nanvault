#!/bin/bash
#
# script to automatically compile statically-linked bin
#

if [ "$1" = "debug" ] || [ "$1" = "release" ]
then
    BUILD_TYPE=$1
else
    echo "Usage: ./build.sh [debug/release]"
    exit 1
fi

if [ BUILD_TYPE = "release" ]
then
    PRODOPT="--production"
else
    PRODOPT=""
fi

docker run --rm -it -v $PWD:/workspace -w /workspace crystallang/crystal:latest-alpine \
    shards build $PRODOPT --static

if [ "$?" -ne "0" ]
then
    echo "Build failed"
    exit 1
fi

exit 0
