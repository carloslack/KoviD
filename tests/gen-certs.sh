#!/usr/bin/env bash

#socat
openssl req -newkey rsa:2048 -nodes -keyout server.key -x509 -days 30 -out server.crt
cat server.key server.crt > server.pem

#s_server
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes
