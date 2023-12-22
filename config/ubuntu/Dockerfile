FROM  golang:alpine AS build
RUN apk update && apk add git
WORKDIR /
RUN git clone https://github.com/davidhadas/seal-control.git
WORKDIR /seal-control

# cross compile a seal-wrap for linux/amd64
RUN GOARCH="amd64" GOOS="linux"  go build ./cmd/seal-wrap

# Create an egg (localy)
ARG workloadname=test
RUN go build ./cmd/seal
COPY kubeconfig /root/.kube/config
RUN ./seal wl ${workloadname} egg > /egg.txt

# Create a linux/amd64 ubuntu image 
FROM --platform=linux/amd64 ubuntu
COPY --from=build /seal-control/seal-wrap /bin/seal-wrap
COPY --from=build /egg.txt /egg.txt

# RUN CGO_ENABLED=0 GOOS=linux go build cmd/seal-wrap/wrap.go
# cli: GOARCH="amd64" GOOS=linux go build ../../cmd/seal-wrap/wrap.go
# COPY wrap /bin/seal-wrap
# COPY egg.txt /

