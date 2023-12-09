#!/bin/bash 
#
echo
echo "Connect to remote server using mTLS and self signed certificates"
echo
# curl
echo "Try Curl:"
echo
set -x
curl -v https://myapp-default.myos-e621c7d733ece1fad737ff54a8912822-0000.us-south.containers.appdomain.cloud  --key prk.pem --cert cert.pem --cacert ca.pem
set +x
echo
# wget
echo "Try Wget:"
echo
set -x
wget -d https://myapp-default.myos-e621c7d733ece1fad737ff54a8912822-0000.us-south.containers.appdomain.cloud  --private-key prk.pem --certificate cert.pem --ca-certificate ca.pem
set +x
echo

