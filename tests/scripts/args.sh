# $OpenLDAP$

BACKEND=bdb
if test $# -ge 1 ; then
        BACKEND=$1; shift
fi

BACKENDTYPE=yes
if test $# -ge 1 ; then
        BACKENDTYPE=$1; shift
fi

MONITORDB=no
if test $# -ge 1 ; then
        MONITORDB=$1; shift
fi

PROXYCACHE=no
if test $# -ge 1 ; then
        PROXYCACHE=$1; shift
fi

SYNCREPL=no
if test $# -ge 1 ; then
	SYNCREPL=$1; shift
fi

WAIT=0
if test $# -ge 1 ; then
        WAIT=1; shift
fi
