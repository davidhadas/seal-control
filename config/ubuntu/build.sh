#GOARCH="amd64" GOOS=linux go build ../../cmd/seal-wrap/wrap.go
#docker build . -t quay.io/dhadas/wrap-ubuntu --platform linux/amd64
cp ~/.kube/config config/ubuntu/kubeconfig
docker build config/ubuntu/. -t quay.io/dhadas/wrap-ubuntu --build-arg workloadname=test
docker push quay.io/dhadas/wrap-ubuntu
