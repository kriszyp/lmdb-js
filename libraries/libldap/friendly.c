/* $OpenLDAP$ */
/*
 * Copyright 1998-2000 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */
/*  Portions
 *  Copyright (c) 1990 Regents of the University of Michigan.
 *  All rights reserved.
 *
 *  friendly.c
 */

#include "portable.h"

#include <stdio.h>
#include <ac/stdlib.h>

#include <ac/errno.h>
#include <ac/socket.h>
#include <ac/string.h>
#include <ac/time.h>

#include "ldap-int.h"

char *
ldap_friendly_name(
	LDAP_CONST char *filename,
	/* LDAP_CONST */ char *uname,
	LDAPFriendlyMap **map )
{
	int	i, entries;
	FILE	*fp;
	char	*s;
	char	buf[BUFSIZ];

	if ( map == NULL ) {
		errno = EINVAL;
		return( uname );
	}

	if ( *map == NULL ) {
		if ( (fp = fopen( filename, "r" )) == NULL )
			return( uname );

		entries = 0;
		while ( fgets( buf, sizeof(buf), fp ) != NULL ) {
			if ( buf[0] != '#' )
				entries++;
		}
		rewind( fp );

		if ( (*map = (LDAPFriendlyMap *) LDAP_MALLOC( (entries + 1) *
		    sizeof(LDAPFriendlyMap) )) == NULL ) {
			fclose( fp );
			return( uname );
		}

		i = 0;
		while ( fgets( buf, sizeof(buf), fp ) != NULL && i < entries ) {
			if ( buf[0] == '#' )
				continue;

			if ( (s = strchr( buf, '\n' )) != NULL )
				*s = '\0';

			if ( (s = strchr( buf, '\t' )) == NULL )
				continue;
			*s++ = '\0';

			if ( *s == '"' ) {
				int	esc = 0, found = 0;

				for ( ++s; *s && !found; s++ ) {
					switch ( *s ) {
					case '\\':
						esc = 1;
						break;
					case '"':
						if ( !esc )
							found = 1;
						/* FALL */
					default:
						esc = 0;
						break;
					}
				}
			}

			(*map)[i].lf_unfriendly = LDAP_STRDUP( buf );
			(*map)[i].lf_friendly   = LDAP_STRDUP( s );
			i++;
		}

		fclose( fp );
		(*map)[i].lf_unfriendly = NULL;
	}

	for ( i = 0; (*map)[i].lf_unfriendly != NULL; i++ ) {
		if ( strcasecmp( uname, (*map)[i].lf_unfriendly ) == 0 )
			return( (*map)[i].lf_friendly );
	}
	return( uname );
}


void
ldap_free_friendlymap( LDAPFriendlyMap **map )
{
	LDAPFriendlyMap* pF = *map;

	if ( pF == NULL )
		return;

	while ( pF->lf_unfriendly )
	{
		LDAP_FREE( pF->lf_unfriendly );
		LDAP_FREE( pF->lf_friendly );
		pF++;
	}
	LDAP_FREE( *map );
	*map = NULL;
}
