/* modify.c - ldap backend modify function */
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
ldap_back_modify(
    Backend	*be,
    Connection	*conn,
    Operation	*op,
    const char	*dn,
    const char	*ndn,
    LDAPModList	*ml
)
{
	struct ldapinfo	*li = (struct ldapinfo *) be->be_private;
	struct ldapconn *lc;
	LDAPMod **mods;
	LDAPModList *m;
	int i;

	lc = ldap_back_getconn(li, conn, op);
	if (!lc)
		return( -1 );

	if (!lc->bound) {
		ldap_back_dobind(lc, op);
		if (!lc->bound)
			return( -1 );
	}

	for (i=1, m=ml->ml_next; m; i++,m=m->ml_next)
		;
	mods = (LDAPMod **)ch_malloc((i+1)*sizeof(LDAPMod *));
	mods[i] = 0;

	for (i=0, m=ml; m; i++, m=m->ml_next)
		mods[i] = &m->ml_mod;

	ldap_modify_s( lc->ld, dn, mods );
	free(mods);	
	return( ldap_back_op_result( lc, op ));
}
