/*
 * Copyright 1998-1999 The OpenLDAP Foundation, All Rights Reserved.
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
#include <stdlib.h>

#include <ac/ctype.h>
#include <ac/errno.h>
#include <ac/socket.h>
#include <ac/string.h>
#include <ac/time.h>

#include "lber.h"
#include "ldap.h"
#include "ldap-int.h"

char *
ldap_friendly_name( char *filename, char *uname, FriendlyMap **map )
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

		if ( (*map = (FriendlyMap *) malloc( (entries + 1) *
		    sizeof(FriendlyMap) )) == NULL ) {
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

			(*map)[i].f_unfriendly = ldap_strdup( buf );
			(*map)[i].f_friendly   = ldap_strdup( s );
			i++;
		}

		fclose( fp );
		(*map)[i].f_unfriendly = NULL;
	}

	for ( i = 0; (*map)[i].f_unfriendly != NULL; i++ ) {
		if ( strcasecmp( uname, (*map)[i].f_unfriendly ) == 0 )
			return( (*map)[i].f_friendly );
	}
	return( uname );
}


void
ldap_free_friendlymap( FriendlyMap **map )
{
	struct friendly* pF = *map;

	if ( pF == NULL )
		return;

	while ( pF->f_unfriendly )
	{
		free( pF->f_unfriendly );
		free( pF->f_friendly );
		pF++;
	}
	free( *map );
	*map = NULL;
}
