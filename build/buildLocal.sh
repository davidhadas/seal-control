#!/bin/bash
set -e
set -o pipefail

function catch()
{
    echo "Exiting with error code $1 on line $2"
    rm ./seal ./egg.txt ./seal-wrap > /dev/null
}

trap 'catch $? $LINENO' ERR

if [ "$#" -ne 3 ]; then
    echo "Usage: build.sh <workloadname> <image> <repo>"
    REPO="quay.io/dhadas"
    IMAGE="ubuntu"
    WORKLOAD="test"
else
    WORKLOAD="${1}"
    IMAGE="${2}"
    REPO="${3}"
fi


cd `git rev-parse --show-toplevel`
cd build/
pwd

#cross compile seal wrap to linux/amd64 
echo "building seal wrap"
GOARCH="amd64" GOOS="linux"  go build ../cmd/seal-wrap

echo "building seal"
go build ../cmd/seal

echo "creating an egg"
./seal wl "${WORKLOAD}" egg > ./egg.txt

echo "building image"
# docker build . -t quay.io/dhadas/wrap-ubuntu --platform linux/amd64
podman build . -f Dockerfile.Local -t "${REPO}/${IMAGE}.${WORKLOAD}.seal" --build-arg IMAGE="${IMAGE}"

echo "pushing image"
#podman push "${REPO}/${IMAGE}.${WORKLOAD}.seal" --encryption-key private.pem
podman push "${REPO}/${IMAGE}.${WORKLOAD}.seal"
rm ./seal ./egg.txt ./seal-wrap
