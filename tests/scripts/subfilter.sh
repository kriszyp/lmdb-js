#! /bin/sh
#
# Strip entries that belong to subtree $1
#
awk "/^dn:/&&!/$1\$/ {while (\$1!=\"\") {print \$0;getline} print \"\"}"

