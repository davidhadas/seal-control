GOARCH="amd64" GOOS=linux go build ../../cmd/seal-wrap/wrap.go
docker build . -t quay.io/dhadas/wrap-ubuntu --platform linux/amd64
docker push quay.io/dhadas/wrap-ubuntu
