#!/bin/bash -e
set -xv
APP=certmin
BIN_DIR=/var/tmp/$APP
BASE_NAME="$BIN_DIR/$APP"
PLATFORMS=("windows/amd64" "darwin/amd64" "darwin/amd64" "linux/amd64")
SRC_DIR=$(pwd)
BUILD_CMD="go build -a -installsuffix cgo -ldflags -s"

function build {
    GOOS=$1
    GOARCH=$2
    OUTPUT="${BASE_NAME}-${GOOS}-${GOARCH}"
    if [ $GOOS = "windows" ]; then
        OUTPUT+='.exe'
    fi
    GOOS=$GOOS GOARCH=$GOARCH CGO_ENABLED=0 $BUILD_CMD -o $OUTPUT
    cd $BIN_DIR
    sha512sum $OUTPUT > $OUTPUT.sha512
    cat $OUTPUT.sha512
    cd $SRC_DIR
}

mkdir -p $BIN_DIR
for i in ${PLATFORMS[@]}; do
    PLATFORMS_SPLIT=(${i//\// })
    GOOS=${PLATFORMS_SPLIT[0]}
    GOARCH=${PLATFORMS_SPLIT[1]}
    build $GOOS $GOARCH
done
