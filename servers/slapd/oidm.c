/* oidm.c - object identifier macro routines */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1998-2003 The OpenLDAP Foundation.
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

#include "portable.h"

#include <stdio.h>

#include <ac/ctype.h>
#include <ac/string.h>
#include <ac/socket.h>

#include "slap.h"

static LDAP_SLIST_HEAD(OidMacroList, slap_oid_macro) om_list
	= LDAP_SLIST_HEAD_INITIALIZER(om_list);

/* Replace an OID Macro invocation with its full numeric OID.
 * If the macro is used with "macroname:suffix" append ".suffix"
 * to the expansion.
 */
char *
oidm_find(char *oid)
{
	OidMacro *om;

	/* OID macros must start alpha */
	if ( OID_LEADCHAR( *oid ) )	{
		return oid;
	}

	LDAP_SLIST_FOREACH( om, &om_list, som_next ) {
		char **names = om->som_names;

		if( names == NULL ) {
			continue;
		}

		for( ; *names != NULL ; names++ ) {
			int pos = dscompare(*names, oid, ':');

			if( pos ) {
				int suflen = strlen(oid + pos);
				char *tmp = SLAP_MALLOC( om->som_oid.bv_len
					+ suflen + 1);
				if( tmp == NULL ) {
#ifdef NEW_LOGGING
					LDAP_LOG( OPERATION, ERR,
						"oidm_find: SLAP_MALLOC failed", 0, 0, 0 );
#else
					Debug( LDAP_DEBUG_ANY,
						"oidm_find: SLAP_MALLOC failed", 0, 0, 0 );
#endif
					return NULL;
				}
				strcpy(tmp, om->som_oid.bv_val);
				if( suflen ) {
					suflen = om->som_oid.bv_len;
					tmp[suflen++] = '.';
					strcpy(tmp+suflen, oid+pos+1);
				}
				return tmp;
			}
		}
	}
	return NULL;
}

void
oidm_destroy()
{
	OidMacro *om;
	while( !LDAP_SLIST_EMPTY( &om_list )) {
		om = LDAP_SLIST_FIRST( &om_list );
		LDAP_SLIST_REMOVE_HEAD( &om_list, som_next );

		ldap_charray_free(om->som_names);
		free(om->som_oid.bv_val);
		free(om);
		
	}
}

int
parse_oidm(
    const char	*fname,
    int		lineno,
    int		argc,
    char 	**argv )
{
	char *oid;
	OidMacro *om;

	if (argc != 3) {
		fprintf( stderr, "%s: line %d: too many arguments\n",
			fname, lineno );
usage:	fprintf( stderr, "\tObjectIdentifier <name> <oid>\n");
		return 1;
	}

	oid = oidm_find( argv[1] );
	if( oid != NULL ) {
		fprintf( stderr,
			"%s: line %d: "
			"ObjectIdentifier \"%s\" previously defined \"%s\"",
			fname, lineno, argv[1], oid );
		return 1;
	}

	om = (OidMacro *) SLAP_MALLOC( sizeof(OidMacro) );
	if( om == NULL ) {
#ifdef NEW_LOGGING
		LDAP_LOG( OPERATION, ERR, "parse_oidm: SLAP_MALLOC failed", 0, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY, "parse_oidm: SLAP_MALLOC failed", 0, 0, 0 );
#endif
		return 1;
	}

	LDAP_SLIST_NEXT( om, som_next ) = NULL;
	om->som_names = NULL;
	ldap_charray_add( &om->som_names, argv[1] );
	om->som_oid.bv_val = oidm_find( argv[2] );

	if (!om->som_oid.bv_val) {
		fprintf( stderr, "%s: line %d: OID %s not recognized\n",
			fname, lineno, argv[2] );
		goto usage;
	}

	if (om->som_oid.bv_val == argv[2]) {
		om->som_oid.bv_val = ch_strdup( argv[2] );
	}

	om->som_oid.bv_len = strlen( om->som_oid.bv_val );

	LDAP_SLIST_INSERT_HEAD( &om_list, om, som_next );
	return 0;
}
