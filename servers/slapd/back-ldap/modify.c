/* modify.c - ldap backend modify function */
/* $OpenLDAP$ */
/*
 * Copyright 1998-1999 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
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
ldap_back_modify(
    Backend	*be,
    Connection	*conn,
    Operation	*op,
    const char	*dn,
    const char	*ndn,
    Modifications	*modlist
)
{
	struct ldapinfo	*li = (struct ldapinfo *) be->be_private;
	struct ldapconn *lc;
	LDAPMod **modv;
	LDAPMod *mods;
	Modifications *ml;
	int i;
	char *mdn = NULL, *mapped;

	lc = ldap_back_getconn(li, conn, op);
	if ( !lc || !ldap_back_dobind( lc, op ) ) {
		return( -1 );
	}

	/*
	 * Rewrite the modify dn, if needed
	 */
#ifdef ENABLE_REWRITE
	switch ( rewrite_session( li->rwinfo, "modifyDn", dn, conn, &mdn ) ) {
	case REWRITE_REGEXEC_OK:
		if ( mdn == NULL ) {
			mdn = ( char * )dn;
		}
#ifdef NEW_LOGGING
		LDAP_LOG(( "backend", LDAP_LEVEL_DETAIL1,
				"[rw] modifyDn: \"%s\" -> \"%s\"\n", dn, mdn ));
#else /* !NEW_LOGGING */
		Debug( LDAP_DEBUG_ARGS, "rw> modifyDn: \"%s\" -> \"%s\"\n%s",
				dn, mdn, "" );
#endif /* !NEW_LOGGING */
		break;
		
	case REWRITE_REGEXEC_UNWILLING:
		send_ldap_result( conn, op, LDAP_UNWILLING_TO_PERFORM,
				NULL, "Unwilling to perform", NULL, NULL );
		return( -1 );

	case REWRITE_REGEXEC_ERR:
		send_ldap_result( conn, op, LDAP_OPERATIONS_ERROR,
				NULL, "Operations error", NULL, NULL );
		return( -1 );
	}
#else /* !ENABLE_REWRITE */
	mdn = ldap_back_dn_massage( li, ch_strdup( dn ), 0 );
#endif /* !ENABLE_REWRITE */

	for (i=0, ml=modlist; ml; i++,ml=ml->sml_next)
		;

	mods = (LDAPMod *)ch_malloc(i*sizeof(LDAPMod));
	if (mods == NULL) {
		goto cleanup;
	}
	modv = (LDAPMod **)ch_malloc((i+1)*sizeof(LDAPMod *));
	if (modv == NULL) {
		goto cleanup;
	}

	for (i=0, ml=modlist; ml; ml=ml->sml_next) {
		mapped = ldap_back_map(&li->at_map, ml->sml_desc->ad_cname.bv_val, 0);
		if (mapped == NULL) {
			continue;
		}

		modv[i] = &mods[i];
		mods[i].mod_op = ml->sml_op | LDAP_MOD_BVALUES;
		mods[i].mod_type = mapped;

#ifdef ENABLE_REWRITE
		/*
		 * FIXME: dn-valued attrs should be rewritten
		 * to allow their use in ACLs at the back-ldap
		 * level.
		 */
		if ( strcmp( ml->sml_desc->ad_type->sat_syntax->ssyn_oid,
					SLAPD_DN_SYNTAX ) == 0 ) {
			ldap_dnattr_rewrite( li->rwinfo,
					ml->sml_bvalues, conn );
		}
#endif /* ENABLE_REWRITE */
	
		mods[i].mod_bvalues = ml->sml_bvalues;
		i++;
	}
	modv[i] = 0;

	ldap_modify_s( lc->ld, mdn, modv );

cleanup:;
#ifdef ENABLE_REWRITE
	if ( mdn != dn ) {
#endif /* ENABLE_REWRITE */
		free( mdn );
#ifdef ENABLE_REWRITE
	}
#endif /* ENABLE_REWRITE */
	free(mods);
	free(modv);
	return( ldap_back_op_result( lc, op ));
}

