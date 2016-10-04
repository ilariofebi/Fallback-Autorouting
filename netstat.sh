#!/usr/bin/env bash

NETSTATFILE=$(mktemp /tmp/XXXXX)
netstat -nr > $NETSTATFILE

DEF=$(awk '$1 ~ /default/ {print "DEFAULT="$2}' $NETSTATFILE)
VPN=$(awk '$1 ~ /2.228.74.179/ {print "IP1="$2}' $NETSTATFILE)
VOIP=$(awk '$1 ~ /2.228.74.180/ {print "IP1="$2}' $NETSTATFILE)

echo -n $DEF' '$VPN' '$VOIP