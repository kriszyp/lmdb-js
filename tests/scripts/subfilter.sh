#! /bin/sh
#
# Strip entries that belong to subtree $2 (if any)
#
if test $# == 0 ; then
	exit 1
else
	awk "/^dn:/&&!/$1\$/ {while (\$1!=\"\") {print \$0;getline} print \"\"}"
fi

