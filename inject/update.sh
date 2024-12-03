#!/bin/bash
xxd -i ../kovid.ko  |grep ^" "|while read l ; do echo "    .byte $l"|sed 's/,$//' ; done >kv_embed.inc
