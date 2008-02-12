/* oidm.c - object identifier macro routines */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1998-2008 The OpenLDAP Foundation.
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
#include "lutil.h"

static LDAP_STAILQ_HEAD(OidMacroList, slap_oid_macro) om_list
	= LDAP_STAILQ_HEAD_INITIALIZER(om_list);

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

	LDAP_STAILQ_FOREACH( om, &om_list, som_next ) {
		BerVarray names = om->som_names;

		if( names == NULL ) {
			continue;
		}

		for( ; !BER_BVISNULL( names ) ; names++ ) {
			int pos = dscompare(names->bv_val, oid, ':');

			if( pos ) {
				int suflen = strlen(oid + pos);
				char *tmp = SLAP_MALLOC( om->som_oid.bv_len
					+ suflen + 1);
				if( tmp == NULL ) {
					Debug( LDAP_DEBUG_ANY,
						"oidm_find: SLAP_MALLOC failed", 0, 0, 0 );
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
	while( !LDAP_STAILQ_EMPTY( &om_list )) {
		om = LDAP_STAILQ_FIRST( &om_list );
		LDAP_STAILQ_REMOVE_HEAD( &om_list, som_next );

		ber_bvarray_free(om->som_names);
		ber_bvarray_free(om->som_subs);
		free(om->som_oid.bv_val);
		free(om);
		
	}
}

int
parse_oidm(
    const char	*fname,
    int		lineno,
    int		argc,
    char 	**argv,
	int		user,
	OidMacro **rom)
{
	char *oid;
	OidMacro *om;
	struct berval bv;

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

	om = (OidMacro *) SLAP_CALLOC( sizeof(OidMacro), 1 );
	if( om == NULL ) {
		Debug( LDAP_DEBUG_ANY, "parse_oidm: SLAP_CALLOC failed", 0, 0, 0 );
		return 1;
	}

	om->som_names = NULL;
	om->som_subs = NULL;
	ber_str2bv( argv[1], 0, 1, &bv );
	ber_bvarray_add( &om->som_names, &bv );
	ber_str2bv( argv[2], 0, 1, &bv );
	ber_bvarray_add( &om->som_subs, &bv );
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
	if ( !user )
		om->som_flags |= SLAP_OM_HARDCODE;

	LDAP_STAILQ_INSERT_TAIL( &om_list, om, som_next );
	if ( rom ) *rom = om;
	return 0;
}

void oidm_unparse( BerVarray *res, OidMacro *start, OidMacro *end, int sys )
{
	OidMacro *om;
	int i, j, num;
	struct berval *bva = NULL, idx;
	char ibuf[32], *ptr;

	if ( !start )
		start = LDAP_STAILQ_FIRST( &om_list );

	/* count the result size */
	i = 0;
	for ( om=start; om; om=LDAP_STAILQ_NEXT(om, som_next)) {
		if ( sys && !(om->som_flags & SLAP_OM_HARDCODE)) continue;
		for ( j=0; !BER_BVISNULL(&om->som_names[j]); j++ );
		i += j;
		if ( om == end ) break;
	}
	num = i;
	if (!i) return;

	bva = ch_malloc( (num+1) * sizeof(struct berval) );
	BER_BVZERO( bva+num );
	idx.bv_val = ibuf;
	if ( sys ) {
		idx.bv_len = 0;
		ibuf[0] = '\0';
	}
	for ( i=0,om=start; om; om=LDAP_STAILQ_NEXT(om, som_next)) {
		if ( sys && !(om->som_flags & SLAP_OM_HARDCODE)) continue;
		for ( j=0; !BER_BVISNULL(&om->som_names[j]); i++,j++ ) {
			if ( !sys ) {
				idx.bv_len = sprintf(idx.bv_val, "{%d}", i );
			}
			bva[i].bv_len = idx.bv_len + om->som_names[j].bv_len +
				om->som_subs[j].bv_len + 1;
			bva[i].bv_val = ch_malloc( bva[i].bv_len + 1 );
			ptr = lutil_strcopy( bva[i].bv_val, ibuf );
			ptr = lutil_strcopy( ptr, om->som_names[j].bv_val );
			*ptr++ = ' ';
			strcpy( ptr, om->som_subs[j].bv_val );
		}
		if ( i>=num ) break;
		if ( om == end ) break;
	}
	*res = bva;
}
