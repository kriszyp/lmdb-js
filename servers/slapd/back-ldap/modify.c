/* modify.c - ldap backend modify function */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1999-2004 The OpenLDAP Foundation.
 * Portions Copyright 1999-2003 Howard Chu.
 * Portions Copyright 2000-2003 Pierangelo Masarati.
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
#include "back-ldap.h"

int
ldap_back_modify(
    Operation	*op,
    SlapReply	*rs )
{
	struct ldapinfo	*li = (struct ldapinfo *) op->o_bd->be_private;
	struct ldapconn *lc;
	LDAPMod **modv = NULL;
	LDAPMod *mods;
	Modifications *ml;
	int i, j, rc;
	struct berval mapped;
	struct berval mdn = { 0, NULL };
	ber_int_t msgid;
	dncookie dc;
	int isupdate;
#ifdef LDAP_BACK_PROXY_AUTHZ 
	LDAPControl **ctrls = NULL;
#endif /* LDAP_BACK_PROXY_AUTHZ */

	lc = ldap_back_getconn(op, rs);
	if ( !lc || !ldap_back_dobind( lc, op, rs ) ) {
		return( -1 );
	}

	/*
	 * Rewrite the modify dn, if needed
	 */
	dc.rwmap = &li->rwmap;
#ifdef ENABLE_REWRITE
	dc.conn = op->o_conn;
	dc.rs = rs;
	dc.ctx = "modifyDN";
#else
	dc.tofrom = 1;
	dc.normalized = 0;
#endif
	if ( ldap_back_dn_massage( &dc, &op->o_req_ndn, &mdn ) ) {
		send_ldap_result( op, rs );
		return -1;
	}

	for (i=0, ml=op->oq_modify.rs_modlist; ml; i++,ml=ml->sml_next)
		;

	mods = (LDAPMod *)ch_malloc(i*sizeof(LDAPMod));
	if (mods == NULL) {
		rc = LDAP_NO_MEMORY;
		goto cleanup;
	}
	modv = (LDAPMod **)ch_malloc((i+1)*sizeof(LDAPMod *));
	if (modv == NULL) {
		rc = LDAP_NO_MEMORY;
		goto cleanup;
	}

#ifdef ENABLE_REWRITE
	dc.ctx = "modifyAttrDN";
#endif

	isupdate = be_isupdate( op );
	for (i=0, ml=op->oq_modify.rs_modlist; ml; ml=ml->sml_next) {
		int	is_oc = 0;

		if ( !isupdate && ml->sml_desc->ad_type->sat_no_user_mod  ) {
			continue;
		}

		if ( ml->sml_desc == slap_schema.si_ad_objectClass 
				|| ml->sml_desc == slap_schema.si_ad_structuralObjectClass ) {
			is_oc = 1;
			mapped = ml->sml_desc->ad_cname;

		} else {
			ldap_back_map(&li->rwmap.rwm_at,
					&ml->sml_desc->ad_cname,
					&mapped, BACKLDAP_MAP);
			if (mapped.bv_val == NULL || mapped.bv_val[0] == '\0') {
				continue;
			}
		}

		modv[i] = &mods[i];
		mods[i].mod_op = ml->sml_op | LDAP_MOD_BVALUES;
		mods[i].mod_type = mapped.bv_val;

		if ( ml->sml_bvalues != NULL ) {
			if ( is_oc ) {
				for (j = 0; ml->sml_bvalues[j].bv_val; j++);
				mods[i].mod_bvalues = (struct berval **)ch_malloc((j+1) *
					sizeof(struct berval *));
				for (j = 0; ml->sml_bvalues[j].bv_val; j++) {
					ldap_back_map(&li->rwmap.rwm_oc,
							&ml->sml_bvalues[j],
							&mapped, BACKLDAP_MAP);
					if (mapped.bv_val == NULL || mapped.bv_val[0] == '\0') {
						continue;
					}
					mods[i].mod_bvalues[j] = &mapped;
				}
				mods[i].mod_bvalues[j] = NULL;

			} else {
				if ( ml->sml_desc->ad_type->sat_syntax ==
					slap_schema.si_syn_distinguishedName ) {
					ldap_dnattr_rewrite( &dc, ml->sml_bvalues );
				}

				if ( ml->sml_bvalues == NULL ) {	
					continue;
				}

				for (j = 0; ml->sml_bvalues[j].bv_val; j++);
				mods[i].mod_bvalues = (struct berval **)ch_malloc((j+1) *
					sizeof(struct berval *));
				for (j = 0; ml->sml_bvalues[j].bv_val; j++)
					mods[i].mod_bvalues[j] = &ml->sml_bvalues[j];
				mods[i].mod_bvalues[j] = NULL;
			}

		} else {
			mods[i].mod_bvalues = NULL;
		}

		i++;
	}
	modv[i] = 0;

#ifdef LDAP_BACK_PROXY_AUTHZ
	rc = ldap_back_proxy_authz_ctrl( lc, op, rs, &ctrls );
	if ( rc != LDAP_SUCCESS ) {
		goto cleanup;
	}
#endif /* LDAP_BACK_PROXY_AUTHZ */

	rs->sr_err = ldap_modify_ext( lc->ld, mdn.bv_val, modv,
#ifdef LDAP_BACK_PROXY_AUTHZ
			ctrls,
#else /* ! LDAP_BACK_PROXY_AUTHZ */
			op->o_ctrls,
#endif /* ! LDAP_BACK_PROXY_AUTHZ */
			NULL, &msgid );

cleanup:;
#ifdef LDAP_BACK_PROXY_AUTHZ
	if ( ctrls && ctrls != op->o_ctrls ) {
		free( ctrls[ 0 ] );
		free( ctrls );
	}
#endif /* LDAP_BACK_PROXY_AUTHZ */

	if ( mdn.bv_val != op->o_req_ndn.bv_val ) {
		free( mdn.bv_val );
	}
	for (i=0; modv[i]; i++) {
		ch_free(modv[i]->mod_bvalues);
	}
	ch_free( mods );
	ch_free( modv );

#ifdef LDAP_BACK_PROXY_AUTHZ
	if ( rc != LDAP_SUCCESS ) {
		send_ldap_result( op, rs );
		return -1;
	}
#endif /* LDAP_BACK_PROXY_AUTHZ */

	return ldap_back_op_result( lc, op, rs, msgid, 1 );
}

