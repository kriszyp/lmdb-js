# $OpenLDAP$

BACKEND=bdb
if test $# -ge 1 ; then
        BACKEND=$1; shift
fi

SYNCREPL=no
if test $# -ge 1 ; then
	SYNCREPL=$1; shift
fi

WAIT=0
if test $# -ge 1 ; then
        WAIT=1; shift
fi
