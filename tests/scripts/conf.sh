#! /bin/sh
# $OpenLDAP$
if [ x"$MONITORDB" = x"yes" ] ; then
	MON=monitor
else
	MON=nomonitor
fi
sed -e "s/@BACKEND@/${BACKEND}/"	\
	-e "s/^#${BACKEND}#//"			\
	-e "s/^#${MON}#//"				\
	-e "s/@PORT@/${PORT}/"			\
	-e "s/@SLAVEPORT@/${SLAVEPORT}/"
