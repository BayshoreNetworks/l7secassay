#!/bin/bash

echo "Content-Type: application/json";
echo ""
echo '{ "uptime": "'`uptime`'", "kernel": "'`uname -a`'"} '

