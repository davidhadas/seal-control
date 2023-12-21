FROM ubuntu

# RUN CGO_ENABLED=0 GOOS=linux go build cmd/seal-wrap/wrap.go
# cli: GOARCH="amd64" GOOS=linux go build ../../cmd/seal-wrap/wrap.go
COPY wrap /bin/seal-wrap
COPY egg.txt /

