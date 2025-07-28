#!/bin/bash
sleep 5
insmod=$(which insmod)
$insmod "$1" >/dev/null 2>&1
