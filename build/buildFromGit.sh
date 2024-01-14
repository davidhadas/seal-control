#!/bin/bash
set -e
set -o pipefail

function catch()
{
    echo "Exiting with error code $1 on line $2"
    rm ./kubeconfig > /dev/null
}

trap 'catch $? $LINENO' ERR

if [ "$#" -ne 3 ]; then
    echo "Usage: build.sh <workloadname> <image> <repo>"
    REPO="quay.io/dhadas"
    IMAGE="ubuntu"
    WORKLOAD="test"
    echo "Defaults to: build.sh ${WORKLOAD} ${IMAGE} ${REPO}"
else
    WORKLOAD="${1}"
    IMAGE="${2}"
    REPO="${3}"
fi

cp ~/.kube/config ./kubeconfig

echo "building image"
podman build . -f Dockerfile.FromGit -t "${REPO}/${IMAGE}.${WORKLOAD}.seal" --build-arg WORKLOAD=${WORKLOAD} --build-arg IMAGE=${IMAGE}

echo "pushing image"
podman push "${REPO}/${IMAGE}.${WORKLOAD}.seal"

rm ./kubeconfig
