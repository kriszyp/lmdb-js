/* add.c - ldap backend add function */
/* $OpenLDAP$ */

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
 */

#include "portable.h"

#include <stdio.h>

#include <ac/string.h>
#include <ac/socket.h>

#include "slap.h"
#include "back-ldap.h"

int
ldap_back_add(
    Backend	*be,
    Connection	*conn,
    Operation	*op,
    Entry	*e
)
{
	struct ldapinfo	*li = (struct ldapinfo *) be->be_private;
	struct ldapconn *lc;
	int i;
	Attribute *a;
	LDAPMod **attrs;

	lc = ldap_back_getconn(li, conn, op);
	if (!lc)
		return( -1 );

	if (!lc->bound) {
		ldap_back_dobind(lc, op);
		if (!lc->bound)
			return( -1 );
	}

	/* Count number of attributes in entry */
	for (i=1, a=e->e_attrs; a; i++, a=a->a_next)
		;
	
	/* Create array of LDAPMods for ldap_add() */
	attrs = (LDAPMod **)ch_malloc(sizeof(LDAPMod *)*i);
	attrs[i-1] = 0;

	for (i=0, a=e->e_attrs; a; i++, a=a->a_next) {
		attrs[i] = (LDAPMod *)ch_malloc(sizeof(LDAPMod));
		attrs[i]->mod_op = LDAP_MOD_BVALUES;
		attrs[i]->mod_type = a->a_desc->ad_cname->bv_val;
		attrs[i]->mod_vals.modv_bvals = a->a_vals;
	}

	ldap_add_s(lc->ld, e->e_dn, attrs);
	for (--i; i>= 0; --i)
		free(attrs[i]);
	free(attrs);
	return( ldap_back_op_result( lc, op ));
}
