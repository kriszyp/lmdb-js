#! /bin/sh
# $OpenLDAP$
if [ x"$MONITORDB" = x"yes" ] ; then
	MON=monitor
else
	MON=nomonitor
fi
if [ x"$BACKENDTYPE" = x"mod" ]; then
	MODULELOAD="moduleload	back_${BACKEND}.la"
fi
sed -e "s/@BACKEND@/${BACKEND}/"	\
	-e "s/@MODULELOAD@/${MODULELOAD}/" \
	-e "s/^#${BACKEND}#//"			\
	-e "s/^#${MON}#//"				\
	-e "s/@PORT@/${PORT}/"			\
	-e "s/@SLAVEPORT@/${SLAVEPORT}/" \
	-e "s/@CACHETTL@/${CACHETTL}/"   \
	-e "s/@ENTRY_LIMIT@/${CACHE_ENTRY_LIMIT}/"   
