#!/bin/sh

insmod kovid.ko
dmesg
rmmod kovid.ko
