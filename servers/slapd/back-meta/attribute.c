/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1999-2003 The OpenLDAP Foundation.
 * Portions Copyright 2001-2003 Pierangelo Masarati.
 * Portions Copyright 1999-2003 Howard Chu.
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
/* ACKNOWLEDGEMENTS:
 * This work was initially developed by the Howard Chu for inclusion
 * in OpenLDAP Software and subsequently enhanced by Pierangelo
 * Masarati.
 */

#include "portable.h"

#include <stdio.h>

#include <ac/socket.h>
#include <ac/string.h>

#include "slap.h"
#include "../back-ldap/back-ldap.h"
#include "back-meta.h"


/* return 0 IFF we can retrieve the attributes
 * of entry with e_ndn
 */

/*
 * FIXME: I never testd this function; I know it compiles ... :)
 */
int
meta_back_attribute(
		Backend			*be,
		Connection		*conn,
		Operation		*op,
		Entry			*target,
		struct berval		*ndn,
		AttributeDescription 	*entry_at,
		BerVarray			*vals
)
{
	struct metainfo *li = ( struct metainfo * )be->be_private;    
	int rc = 1, i, j, count, is_oc, candidate;
	Attribute *attr;
	BerVarray abv, v;
	char **vs; 
	struct berval	mapped;
	LDAPMessage	*result, *e;
	char *gattr[ 2 ];
	LDAP *ld;

	*vals = NULL;
	if ( target != NULL && dn_match( &target->e_nname, ndn ) ) {
		/* we already have a copy of the entry */
		/* attribute and objectclass mapping has already been done */
		attr = attr_find( target->e_attrs, entry_at );
		if ( attr == NULL ) {
			return 1;
		}

		for ( count = 0; attr->a_vals[ count ].bv_val != NULL; count++ )
			;
		v = ( BerVarray )ch_calloc( ( count + 1 ), sizeof( struct berval ) );
		if ( v == NULL ) {
			return 1;
		}

		for ( j = 0, abv = attr->a_vals; --count >= 0; abv++ ) {
			if ( abv->bv_len > 0 ) {
				ber_dupbv( &v[ j ], abv );
				if ( v[ j ].bv_val == NULL ) {
					break;
				}
			}
		}
		v[ j ].bv_val = NULL;
		*vals = v;

		return 0;
	} /* else */

	candidate = meta_back_select_unique_candidate( li, ndn );
	if ( candidate == -1 ) {
		return 1;
	}

	ldap_back_map( &li->targets[ candidate ]->at_map,
			&entry_at->ad_cname, &mapped, BACKLDAP_MAP );
	if ( mapped.bv_val == NULL || mapped.bv_val[0] == '\0' )
		return 1;

	rc =  ldap_initialize( &ld, li->targets[ candidate ]->uri );
	if ( rc != LDAP_SUCCESS ) {
		return 1;
	}

	rc = ldap_bind_s( ld, li->targets[ candidate ]->binddn.bv_val,
			li->targets[ candidate ]->bindpw.bv_val, LDAP_AUTH_SIMPLE );
	if ( rc != LDAP_SUCCESS) {
		return 1;
	}

	gattr[ 0 ] = mapped.bv_val;
	gattr[ 1 ] = NULL;
	if ( ldap_search_ext_s( ld, ndn->bv_val, LDAP_SCOPE_BASE, 
				"(objectClass=*)",
				gattr, 0, NULL, NULL, LDAP_NO_LIMIT,
				LDAP_NO_LIMIT, &result) == LDAP_SUCCESS) {
		if ( ( e = ldap_first_entry( ld, result ) ) != NULL ) {
			vs = ldap_get_values( ld, e, mapped.bv_val );
			if ( vs != NULL ) {
				for ( count = 0; vs[ count ] != NULL;
						count++ ) { }
				v = ( BerVarray )ch_calloc( ( count + 1 ),
						sizeof( struct berval ) );
				if ( v == NULL ) {
					ldap_value_free( vs );
				} else {
					is_oc = ( strcasecmp( "objectclass", mapped.bv_val ) == 0 );
					for ( i = 0, j = 0; i < count; i++ ) {
						ber_str2bv( vs[ i ], 0, 0, &v[ j ] );
						if ( !is_oc ) {
							if ( v[ j ].bv_val == NULL ) {
								ch_free( vs[ i ] );
							} else {
								j++;
							}
						} else {
							ldap_back_map( &li->targets[ candidate ]->oc_map, &v[ j ], &mapped, BACKLDAP_REMAP );
							if ( mapped.bv_val && mapped.bv_val[0] != '\0' ) {
								ber_dupbv( &v[ j ], &mapped );
								if ( v[ j ].bv_val ) {
									j++;
								}
							}
							ch_free( vs[ i ] );
						}
					}
					v[ j ].bv_val = NULL;
					*vals = v;
					rc = 0;
					ch_free( vs );
				}
			}
		}
		ldap_msgfree( result );
	}
	ldap_unbind( ld );

	return(rc);
}

