/* add.c - ldap backend add function */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1999-2003 The OpenLDAP Foundation.
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
/* This is an altered version */
/*
 * Copyright 1999, Howard Chu, All rights reserved. <hyc@highlandsun.com>
 * 
 * Permission is granted to anyone to use this software for any purpose
 * on any computer system, and to alter it and redistribute it, subject
 * to the following restrictions:
 * 
 * 1. The author is not responsible for the consequences of use of this
 *    software, no matter how awful, even if they arise from flaws in it.
 * 
 * 2. The origin of this software must not be misrepresented, either by
 *    explicit claim or by omission.  Since few users ever read sources,
 *    credits should appear in the documentation.
 * 
 * 3. Altered versions must be plainly marked as such, and must not be
 *    misrepresented as being the original software.  Since few users
 *    ever read sources, credits should appear in the documentation.
 * 
 * 4. This notice may not be removed or altered.
 *
 *
 *
 * Copyright 2000, Pierangelo Masarati, All rights reserved. <ando@sys-net.it>
 *
 * This software is being modified by Pierangelo Masarati.
 * The previously reported conditions apply to the modified code as well.
 * Changes in the original code are highlighted where required.
 * Credits for the original code go to the author, Howard Chu.
 */

#include "portable.h"

#include <stdio.h>

#include <ac/string.h>
#include <ac/socket.h>

#include "slap.h"
#include "back-ldap.h"

int
ldap_back_add(
    Operation	*op,
    SlapReply	*rs )
{
	struct ldapinfo	*li = (struct ldapinfo *) op->o_bd->be_private;
	struct ldapconn *lc;
	int i, j;
	Attribute *a;
	LDAPMod **attrs;
	struct berval mapped;
	struct berval mdn = { 0, NULL };
	ber_int_t msgid;
	dncookie dc;

#ifdef NEW_LOGGING
	LDAP_LOG( BACK_LDAP, ENTRY, "ldap_back_add: %s\n", op->o_req_dn.bv_val, 0, 0 );
#else /* !NEW_LOGGING */
	Debug(LDAP_DEBUG_ARGS, "==> ldap_back_add: %s\n", op->o_req_dn.bv_val, 0, 0);
#endif /* !NEW_LOGGING */
	
	lc = ldap_back_getconn(op, rs);
	if ( !lc || !ldap_back_dobind( lc, op, rs ) ) {
		return( -1 );
	}

	/*
	 * Rewrite the add dn, if needed
	 */
	dc.rwmap = &li->rwmap;
#ifdef ENABLE_REWRITE
	dc.conn = op->o_conn;
	dc.rs = rs;
	dc.ctx = "addDn";
#else
	dc.tofrom = 1;
	dc.normalized = 0;
#endif
	if ( ldap_back_dn_massage( &dc, &op->o_req_dn, &mdn ) ) {
		send_ldap_result( op, rs );
		return -1;
	}

	/* Count number of attributes in entry */
	for (i = 1, a = op->oq_add.rs_e->e_attrs; a; i++, a = a->a_next)
		;
	
	/* Create array of LDAPMods for ldap_add() */
	attrs = (LDAPMod **)ch_malloc(sizeof(LDAPMod *)*i);

#ifdef ENABLE_REWRITE
	dc.ctx = "addDnAttr";
#endif
	for (i=0, a=op->oq_add.rs_e->e_attrs; a; a=a->a_next) {
		if ( a->a_desc->ad_type->sat_no_user_mod  ) {
			continue;
		}

		ldap_back_map(&li->rwmap.rwm_at, &a->a_desc->ad_cname, &mapped,
				BACKLDAP_MAP);
		if (mapped.bv_val == NULL || mapped.bv_val[0] == '\0') {
			continue;
		}

		attrs[i] = (LDAPMod *)ch_malloc(sizeof(LDAPMod));
		if (attrs[i] == NULL) {
			continue;
		}

		attrs[i]->mod_op = LDAP_MOD_BVALUES;
		attrs[i]->mod_type = mapped.bv_val;

		if ( a->a_desc->ad_type->sat_syntax ==
			slap_schema.si_syn_distinguishedName ) {
			/*
			 * FIXME: rewrite could fail; in this case
			 * the operation should give up, right?
			 */
			(void)ldap_dnattr_rewrite( &dc, a->a_vals );
		}

		for (j=0; a->a_vals[j].bv_val; j++);
		attrs[i]->mod_vals.modv_bvals = ch_malloc((j+1)*sizeof(struct berval *));
		for (j=0; a->a_vals[j].bv_val; j++)
			attrs[i]->mod_vals.modv_bvals[j] = &a->a_vals[j];
		attrs[i]->mod_vals.modv_bvals[j] = NULL;
		i++;
	}
	attrs[i] = NULL;

	rs->sr_err = ldap_add_ext(lc->ld, mdn.bv_val, attrs,
			op->o_ctrls, NULL, &msgid);
	for (--i; i>= 0; --i) {
		ch_free(attrs[i]->mod_vals.modv_bvals);
		ch_free(attrs[i]);
	}
	ch_free(attrs);
	if ( mdn.bv_val != op->o_req_dn.bv_val ) {
		free( mdn.bv_val );
	}
	
	return ldap_back_op_result( lc, op, rs, msgid, 1 ) != LDAP_SUCCESS;
}

