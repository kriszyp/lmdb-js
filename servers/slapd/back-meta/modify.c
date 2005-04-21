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
meta_back_modify( Operation *op, SlapReply *rs )
{
	struct metainfo	*li = ( struct metainfo * )op->o_bd->be_private;
	struct metaconn	*lc;
	int		rc = 0;
	LDAPMod		**modv = NULL;
	LDAPMod		*mods = NULL;
	Modifications	*ml;
	int		candidate = -1, i;
	int		isupdate;
	struct berval	mdn = BER_BVNULL;
	struct berval	mapped;
	dncookie	dc;
	int		msgid, do_retry = 1;

	lc = meta_back_getconn( op, rs, &candidate, LDAP_BACK_SENDERR );
	if ( !lc || !meta_back_dobind( lc, op, LDAP_BACK_SENDERR ) ) {
		return rs->sr_err;
	}
	
	if ( !meta_back_is_valid( lc, candidate ) ) {
		rs->sr_err = LDAP_OTHER;
		send_ldap_result( op, rs );
		return rs->sr_err;
	}

	/*
	 * Rewrite the modify dn, if needed
	 */
	dc.rwmap = &li->mi_targets[ candidate ]->mt_rwmap;
	dc.conn = op->o_conn;
	dc.rs = rs;
	dc.ctx = "modifyDN";

	if ( ldap_back_dn_massage( &dc, &op->o_req_dn, &mdn ) ) {
		rc = -1;
		goto cleanup;
	}

	for ( i = 0, ml = op->orm_modlist; ml; i++ ,ml = ml->sml_next )
		;

	mods = ch_malloc( sizeof( LDAPMod )*i );
	if ( mods == NULL ) {
		rs->sr_err = LDAP_NO_MEMORY;
		rc = -1;
		goto cleanup;
	}
	modv = ( LDAPMod ** )ch_malloc( ( i + 1 )*sizeof( LDAPMod * ) );
	if ( modv == NULL ) {
		rs->sr_err = LDAP_NO_MEMORY;
		rc = -1;
		goto cleanup;
	}

	dc.ctx = "modifyAttrDN";
	isupdate = be_shadow_update( op );
	for ( i = 0, ml = op->orm_modlist; ml; ml = ml->sml_next ) {
		int	j, is_oc = 0;

		if ( !isupdate && ml->sml_desc->ad_type->sat_no_user_mod  ) {
			continue;
		}

		if ( ml->sml_desc == slap_schema.si_ad_objectClass 
				|| ml->sml_desc == slap_schema.si_ad_structuralObjectClass )
		{
			is_oc = 1;
			mapped = ml->sml_desc->ad_cname;

		} else {
			ldap_back_map( &li->mi_targets[ candidate ]->mt_rwmap.rwm_at,
					&ml->sml_desc->ad_cname, &mapped,
					BACKLDAP_MAP );
			if ( BER_BVISNULL( &mapped ) || BER_BVISEMPTY( &mapped ) ) {
				continue;
			}
		}

		modv[ i ] = &mods[ i ];
		mods[ i ].mod_op = ml->sml_op | LDAP_MOD_BVALUES;
		mods[ i ].mod_type = mapped.bv_val;

		/*
		 * FIXME: dn-valued attrs should be rewritten
		 * to allow their use in ACLs at the back-ldap
		 * level.
		 */
		if ( ml->sml_values != NULL ) {
			if ( is_oc ) {
				for ( j = 0; !BER_BVISNULL( &ml->sml_values[ j ] ); j++ )
					;
				mods[ i ].mod_bvalues =
					(struct berval **)ch_malloc( ( j + 1 ) *
					sizeof( struct berval * ) );
				for ( j = 0; !BER_BVISNULL( &ml->sml_values[ j ] ); ) {
					struct ldapmapping	*mapping;

					ldap_back_mapping( &li->mi_targets[ candidate ]->mt_rwmap.rwm_oc,
							&ml->sml_values[ j ], &mapping, BACKLDAP_MAP );

					if ( mapping == NULL ) {
						if ( li->mi_targets[ candidate ]->mt_rwmap.rwm_oc.drop_missing ) {
							continue;
						}
						mods[ i ].mod_bvalues[ j ] = &ml->sml_values[ j ];

					} else {
						mods[ i ].mod_bvalues[ j ] = &mapping->dst;
					}
					j++;
				}
				mods[ i ].mod_bvalues[ j ] = NULL;

			} else {
				if ( ml->sml_desc->ad_type->sat_syntax ==
						slap_schema.si_syn_distinguishedName )
				{
					( void )ldap_dnattr_rewrite( &dc, ml->sml_values );
					if ( ml->sml_values == NULL ) {
						continue;
					}
				}

				for ( j = 0; !BER_BVISNULL( &ml->sml_values[ j ] ); j++ )
					;
				mods[ i ].mod_bvalues =
					(struct berval **)ch_malloc( ( j + 1 ) *
					sizeof( struct berval * ) );
				for ( j = 0; !BER_BVISNULL( &ml->sml_values[ j ] ); j++ ) {
					mods[ i ].mod_bvalues[ j ] = &ml->sml_values[ j ];
				}
				mods[ i ].mod_bvalues[ j ] = NULL;
			}

		} else {
			mods[ i ].mod_bvalues = NULL;
		}

		i++;
	}
	modv[ i ] = 0;

retry:;
	rs->sr_err = ldap_modify_ext_s( lc->mc_conns[ candidate ].msc_ld, mdn.bv_val,
			modv, op->o_ctrls, NULL );
	if ( rs->sr_err == LDAP_UNAVAILABLE && do_retry ) {
		do_retry = 0;
		if ( meta_back_retry( op, rs, lc, candidate, LDAP_BACK_SENDERR ) ) {
			goto retry;
		}
	}

cleanup:;
	if ( mdn.bv_val != op->o_req_dn.bv_val ) {
		free( mdn.bv_val );
		BER_BVZERO( &mdn );
	}
	if ( modv != NULL ) {
		for ( i = 0; modv[ i ]; i++ ) {
			free( modv[ i ]->mod_bvalues );
		}
	}
	free( mods );
	free( modv );

	if ( rc != -1 ) {
		return meta_back_op_result( lc, op, rs, candidate );
	}
	
	send_ldap_result( op, rs );

	return rs->sr_err;
}

