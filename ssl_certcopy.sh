#!/bin/bash 

#copy ssl cert from sites

read site
read port

openssl s_client -connect $site:$port -showcerts </dev/null 2>/dev/null|openssl x509 -outform PEM >certfile.pem

#wget https:/server.edu:443/somepage --ca-certificate=mycertfile.pem
