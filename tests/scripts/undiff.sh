#! /bin/sh
#
# Expunge "< " and "> " resulting from diff
#
awk '!/^[0-9]/ {print $0}' | \
	sed "s/^< \|^> \|^- \|^+ //" | \
	awk '/.+/ {print $0}'

