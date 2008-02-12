/* fetch.c - routines for fetching data at URLs */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1999-2008 The OpenLDAP Foundation.
 * Portions Copyright 1999-2003 Kurt D. Zeilenga.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted only as authorized by the OpenLDAP
 * Public License.
 *
 * A copy of this license is available in the file LICENSE in the
 * top-level directory of the distribution or, alternatively, at
 * <http://www.OpenLDAP.org/license.html>.
 */
/* This work was initially developed by Kurt D. Zeilenga for
 * inclusion in OpenLDAP Software.
 */

#include "portable.h"

#include <stdio.h>

#include <ac/stdlib.h>

#include <ac/string.h>
#include <ac/socket.h>
#include <ac/time.h>

#ifdef HAVE_FETCH
#include <fetch.h>
#endif

#include "ldap_log.h"
#include "lber_pvt.h"
#include "ldap_pvt.h"
#include "ldap_config.h"
#include "ldif.h"

FILE *
ldif_open_url(
	LDAP_CONST char *urlstr )
{
	FILE *url;
	char *p = NULL;
#ifdef HAVE_FETCH
	url = fetchGetURL( (char*) urlstr, "" );

#else
	if( strncasecmp( "file:", urlstr, sizeof("file:")-1 ) == 0 ) {
		p = urlstr + sizeof("file:")-1;

		/* we don't check for LDAP_DIRSEP since URLs should contain '/' */
		if ( p[0] == '/' && p[1] == '/' ) {
			p += 2;
			/* path must be absolute if authority is present */
			if ( p[0] != '/' )
				return NULL;
		}

		p = ber_strdup( p );
		ldap_pvt_hex_unescape( p );

		url = fopen( p, "rb" );

		ber_memfree( p );
	} else {
		return NULL;
	}
#endif
	return url;
}

int
ldif_fetch_url(
    LDAP_CONST char	*urlstr,
    char	**valuep,
    ber_len_t *vlenp )
{
	FILE *url;
	char buffer[1024];
	char *p = NULL;
	size_t total;
	size_t bytes;

	*valuep = NULL;
	*vlenp = 0;

	url = ldif_open_url( urlstr );

	if( url == NULL ) {
		return -1;
	}

	total = 0;

	while( (bytes = fread( buffer, 1, sizeof(buffer), url )) != 0 ) {
		char *newp = ber_memrealloc( p, total + bytes + 1 );
		if( newp == NULL ) {
			ber_memfree( p );
			fclose( url );
			return -1;
		}
		p = newp;
		AC_MEMCPY( &p[total], buffer, bytes );
		total += bytes;
	}

	fclose( url );

	if( total == 0 ) {
		char *newp = ber_memrealloc( p, 1 );
		if( newp == NULL ) {
			ber_memfree( p );
			return -1;
		}
		p = newp;
	}

	p[total] = '\0';
	*valuep = p;
	*vlenp = total;

	return 0;
}
