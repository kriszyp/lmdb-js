/*
 * Copyright 1998-1999 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "portable.h"

#include <stdio.h>

#include <ac/ctype.h>
#include <ac/stdarg.h>
#include <ac/string.h>
#include <ac/time.h>

#include "ldap-int.h"

/*
 * ldap log 
 */

static int ldap_log_check( LDAP *ld, int loglvl )
{
	int errlvl;

	if(ld == NULL) {
		errlvl = ldap_debug;
	} else {
		errlvl = ld->ld_errno;
	}

	return errlvl & loglvl ? 1 : 0;
}

int ldap_log_printf
#ifdef HAVE_STDARG
	( LDAP *ld, int loglvl, char *fmt, ... )
#else
	( va_alist )
va_dcl
#endif
{
	char buf[ 1024 ];
	va_list ap;

#ifdef HAVE_STDARG
	va_start( ap, fmt );
#else
	LDAP *ld;
	int loglvl;
	char *fmt;

	va_start( ap );

	ld = va_arg( ap, LDAP * );
	loglvl = va_arg( ap, int );
	fmt = va_arg( ap, char * );
#endif

	if ( !ldap_log_check( ld, loglvl )) {
		return 0;
	}

#ifdef HAVE_VSNPRINTF
	buf[sizeof(buf) - 1] = '\0';
	vsnprintf( buf, sizeof(buf)-1, fmt, ap );
#elif HAVE_VSPRINTF
	vsprintf( buf, fmt, ap ); /* hope it's not too long */
#else
	/* use doprnt() */
	chokeme = "choke me! I don't have a doprnt manual handy!";
#endif

	va_end(ap);

	(*lber_pvt_log_print)( buf );
	return 1;
}
