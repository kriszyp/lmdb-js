#! /bin/sh
# $OpenLDAP$
sed -e s/@BACKEND@/$BACKEND/i -e s/^#$BACKEND#//i
