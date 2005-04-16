/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1999-2005 The OpenLDAP Foundation.
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

#include <ac/string.h>
#include <ac/socket.h>

#include "slap.h"
#include "../back-ldap/back-ldap.h"
#include "back-meta.h"

int
meta_back_add( Operation *op, SlapReply *rs )
{
	struct metainfo	*li = ( struct metainfo * )op->o_bd->be_private;
	struct metaconn	*lc;
	int		i, candidate = -1;
	int		isupdate;
	Attribute	*a;
	LDAPMod		**attrs;
	struct berval	mdn = BER_BVNULL, mapped;
	dncookie	dc;

	Debug(LDAP_DEBUG_ARGS, "==> meta_back_add: %s\n",
			op->o_req_dn.bv_val, 0, 0 );

	/*
	 * get the current connection
	 */
	lc = meta_back_getconn( op, rs, &candidate, LDAP_BACK_SENDERR );
	if ( !lc || !meta_back_dobind( lc, op, LDAP_BACK_SENDERR ) ) {
		return rs->sr_err;
	}

	if ( !meta_back_is_valid( lc, candidate ) ) {
		rs->sr_err = LDAP_UNAVAILABLE;
 		send_ldap_result( op, rs );
		return rs->sr_err;
	}

	/*
	 * Rewrite the add dn, if needed
	 */
	dc.rwmap = &li->mi_targets[ candidate ]->mt_rwmap;
	dc.conn = op->o_conn;
	dc.rs = rs;
	dc.ctx = "addDN";

	if ( ldap_back_dn_massage( &dc, &op->o_req_dn, &mdn ) ) {
		send_ldap_result( op, rs );
		return rs->sr_err;
	}

	/* Count number of attributes in entry ( +1 ) */
	for ( i = 1, a = op->ora_e->e_attrs; a; i++, a = a->a_next );
	
	/* Create array of LDAPMods for ldap_add() */
	attrs = ch_malloc( sizeof( LDAPMod * )*i );

	dc.ctx = "addAttrDN";
	isupdate = be_shadow_update( op );
	for ( i = 0, a = op->ora_e->e_attrs; a; a = a->a_next ) {
		int			j, is_oc = 0;

		if ( !isupdate && a->a_desc->ad_type->sat_no_user_mod  ) {
			continue;
		}

		if ( a->a_desc == slap_schema.si_ad_objectClass 
				|| a->a_desc == slap_schema.si_ad_structuralObjectClass )
		{
			is_oc = 1;
			mapped = a->a_desc->ad_cname;

		} else {
			ldap_back_map( &li->mi_targets[ candidate ]->mt_rwmap.rwm_at,
					&a->a_desc->ad_cname, &mapped, BACKLDAP_MAP );
			if ( BER_BVISNULL( &mapped ) || BER_BVISEMPTY( &mapped ) ) {
				continue;
			}
		}

		attrs[ i ] = ch_malloc( sizeof( LDAPMod ) );
		if ( attrs[ i ] == NULL ) {
			continue;
		}
		attrs[ i ]->mod_op = LDAP_MOD_BVALUES;
		attrs[ i ]->mod_type = mapped.bv_val;

		if ( is_oc ) {
			for ( j = 0; !BER_BVISNULL( &a->a_vals[ j ] ); j++ )
				;

			attrs[ i ]->mod_bvalues =
				(struct berval **)ch_malloc( ( j + 1 ) *
				sizeof( struct berval * ) );

			for ( j = 0; !BER_BVISNULL( &a->a_vals[ j ] ); ) {
				struct ldapmapping	*mapping;

				ldap_back_mapping( &li->mi_targets[ candidate ]->mt_rwmap.rwm_oc,
						&a->a_vals[ j ], &mapping, BACKLDAP_MAP );

				if ( mapping == NULL ) {
					if ( li->mi_targets[ candidate ]->mt_rwmap.rwm_oc.drop_missing ) {
						continue;
					}
					attrs[ i ]->mod_bvalues[ j ] = &a->a_vals[ j ];

				} else {
					attrs[ i ]->mod_bvalues[ j ] = &mapping->dst;
				}
				j++;
			}
			attrs[ i ]->mod_bvalues[ j ] = NULL;

		} else {
			/*
			 * FIXME: dn-valued attrs should be rewritten
			 * to allow their use in ACLs at the back-ldap
			 * level.
			 */
			if ( a->a_desc->ad_type->sat_syntax ==
				slap_schema.si_syn_distinguishedName )
			{
				(void)ldap_dnattr_rewrite( &dc, a->a_vals );
				if ( a->a_vals == NULL ) {
					continue;
				}
			}

			for ( j = 0; !BER_BVISNULL( &a->a_vals[ j ] ); j++ )
				;
			
			attrs[ i ]->mod_bvalues = ch_malloc( ( j + 1 ) * sizeof( struct berval * ) );
			for ( j = 0; !BER_BVISNULL( &a->a_vals[ j ] ); j++ ) {
				attrs[ i ]->mod_bvalues[ j ] = &a->a_vals[ j ];
			}
			attrs[ i ]->mod_bvalues[ j ] = NULL;
		}
		i++;
	}
	attrs[ i ] = NULL;

	rs->sr_err = ldap_add_ext_s( lc->mc_conns[ candidate ].msc_ld, mdn.bv_val,
			      attrs, op->o_ctrls, NULL );
	for ( --i; i >= 0; --i ) {
		free( attrs[ i ]->mod_bvalues );
		free( attrs[ i ] );
	}
	free( attrs );
	if ( mdn.bv_val != op->ora_e->e_dn ) {
		free( mdn.bv_val );
		BER_BVZERO( &mdn );
	}

	return meta_back_op_result( lc, op, rs, candidate );
}

