#! /bin/sh
# $OpenLDAP$
if [ x"$MONITORDB" = x"yes" ] ; then
	MON=monitor
else
	MON=nomonitor
fi
sed -e "s/@BACKEND@/$BACKEND/" -e "s/^#$BACKEND#//"  -e "s/^#$MON#//" \
	-e "s/@PORT@/9009/" -e "s/@SLAVEPORT@/9010/"
