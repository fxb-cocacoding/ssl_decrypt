#!/bin/bash
openssl genrsa -out MyRootCA.key 2048
openssl req -x509 -new -nodes -key MyRootCA.key -sha256 -days 1024 -out MyRootCA.pem
openssl genrsa -out MyClient1.key 2048
openssl req -new -key MyClient1.key -out MyClient1.csr
openssl x509 -req -in MyClient1.csr -CA MyRootCA.pem -CAkey MyRootCA.key -CAcreateserial -out MyClient1.pem -days 1024 -sha256
