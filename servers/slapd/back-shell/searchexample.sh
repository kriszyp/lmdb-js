#! /bin/sh
# $OpenLDAP$
## Copyright 1998-2000 The OpenLDAP Foundation, All Rights Reserved.
## COPYING RESTRICTIONS APPLY, see COPYRIGHT file

while [ 1 ]; do
	read TAG VALUE
	if [ $? -ne 0 ]; then
		break
	fi
	case "$TAG" in
		base:)
		BASE=$VALUE
		;;
		filter:)
		FILTER=$VALUE
		;;
		# include other parameters here
	esac
done

LOGIN=`echo $FILTER | sed -e 's/.*=\(.*\))/\1/'`

PWLINE=`grep -i "^$LOGIN" /etc/passwd`

sleep 60
# if we found an entry that matches
if [ $? = 0 ]; then
	echo $PWLINE | awk -F: '{
		printf("dn: cn=%s,%s\n", $1, base);
		printf("objectclass: top\n");
		printf("objectclass: person\n");
		printf("cn: %s\n", $1);
		printf("cn: %s\n", $5);
		printf("sn: %s\n", $1);
		printf("uid: %s\n", $1);
	}' base="$BASE"
	echo ""
fi

# result
echo "RESULT"
echo "code: 0"

exit 0
