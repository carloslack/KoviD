#!/bin/bash
insmod=$(which insmod)
$insmod "$1" >/dev/null 2>&1
