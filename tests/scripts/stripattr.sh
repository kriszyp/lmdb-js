#! /bin/sh
#
# Strip attribute from LDIF
#
awk '/^'$1'/ {getline; while (substr($0,1,1) == " ") getline;} /.*/ {print $0}'
