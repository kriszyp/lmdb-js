#! /bin/sh
#
# Expunge extra stuff resulting from diff -u
# strip everything, including leading '-', except leading '+' to force errors
#
awk '/^-/ {if (substr($0,1,3) != "---") print substr($0,2,length($0))} /^+/ {if (substr($0,1,3) != "+++") print $0}'
