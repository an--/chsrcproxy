#!/bin/sh

./chsrcproxy listenPort=1270 -mode=relay -remoteAddr= -remotePort= -cacertpem= -certpem= -prikeypem= > /tmp/chsrcproxy.log 2>&1