/* add.c - ldap backend add function */
/* $OpenLDAP$ */
/*
 * Copyright 1998-2003 The OpenLDAP Foundation, All Rights Reserved.
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
ldap_back_add(
    Backend	*be,
    Connection	*conn,
    Operation	*op,
    Entry	*e
)
{
	struct ldapinfo	*li = (struct ldapinfo *) be->be_private;
	struct ldapconn *lc;
	int i, j;
	Attribute *a;
	LDAPMod **attrs;
	struct berval mapped;
	struct berval mdn = { 0, NULL };
	ber_int_t msgid;

#ifdef NEW_LOGGING
	LDAP_LOG( BACK_LDAP, ENTRY, "ldap_back_add: %s\n", e->e_dn, 0, 0 );
#else /* !NEW_LOGGING */
	Debug(LDAP_DEBUG_ARGS, "==> ldap_back_add: %s\n", e->e_dn, 0, 0);
#endif /* !NEW_LOGGING */
	
	lc = ldap_back_getconn(li, conn, op);
	if ( !lc || !ldap_back_dobind( lc, conn, op ) ) {
		return( -1 );
	}

	/*
	 * Rewrite the add dn, if needed
	 */
#ifdef ENABLE_REWRITE
	switch (rewrite_session( li->rwinfo, "addDn", e->e_dn, conn, 
				&mdn.bv_val )) {
	case REWRITE_REGEXEC_OK:
		if ( mdn.bv_val != NULL && mdn.bv_val[ 0 ] != '\0' ) {
			mdn.bv_len = strlen( mdn.bv_val );
		} else {
			mdn = e->e_name;
		}
#ifdef NEW_LOGGING
		LDAP_LOG( BACK_LDAP, DETAIL1, 
			"[rw] addDn: \"%s\" -> \"%s\"\n", e->e_dn, mdn.bv_val, 0 );		
#else /* !NEW_LOGGING */
		Debug( LDAP_DEBUG_ARGS, "rw> addDn: \"%s\" -> \"%s\"\n%s", 
				e->e_dn, mdn.bv_val, "" );
#endif /* !NEW_LOGGING */
		break;
 		
 	case REWRITE_REGEXEC_UNWILLING:
 		send_ldap_result( conn, op, LDAP_UNWILLING_TO_PERFORM,
 				NULL, "Operation not allowed", NULL, NULL );
		return( -1 );
	       	
	case REWRITE_REGEXEC_ERR:
 		send_ldap_result( conn, op, LDAP_OTHER,
 				NULL, "Rewrite error", NULL, NULL );
		return( -1 );
	}
#else /* !ENABLE_REWRITE */
	ldap_back_dn_massage( li, &e->e_name, &mdn, 0, 1 );
#endif /* !ENABLE_REWRITE */

	/* Count number of attributes in entry */
	for (i = 1, a = e->e_attrs; a; i++, a = a->a_next)
		;
	
	/* Create array of LDAPMods for ldap_add() */
	attrs = (LDAPMod **)ch_malloc(sizeof(LDAPMod *)*i);

	for (i=0, a=e->e_attrs; a; a=a->a_next) {
		/*
		 * lastmod should always be <off>, so that
		 * creation/modification operational attrs
		 * of the target directory are used, if available
		 */
#if 0
		if ( !strcasecmp( a->a_desc->ad_cname.bv_val,
			slap_schema.si_ad_creatorsName->ad_cname.bv_val )
			|| !strcasecmp( a->a_desc->ad_cname.bv_val,
			slap_schema.si_ad_createTimestamp->ad_cname.bv_val )
			|| !strcasecmp( a->a_desc->ad_cname.bv_val,
			slap_schema.si_ad_modifiersName->ad_cname.bv_val )
			|| !strcasecmp( a->a_desc->ad_cname.bv_val,
			slap_schema.si_ad_modifyTimestamp->ad_cname.bv_val )
		) {
			continue;
		}
#endif
		
		if ( a->a_desc->ad_type->sat_no_user_mod  ) {
			continue;
		}

		ldap_back_map(&li->at_map, &a->a_desc->ad_cname, &mapped,
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

#ifdef ENABLE_REWRITE
		/*
		 * FIXME: dn-valued attrs should be rewritten
		 * to allow their use in ACLs at back-ldap level.
		 */
		if ( strcmp( a->a_desc->ad_type->sat_syntax->ssyn_oid,
					SLAPD_DN_SYNTAX ) == 0 ) {
			/*
			 * FIXME: rewrite could fail; in this case
			 * the operation should give up, right?
			 */
			(void)ldap_dnattr_rewrite( li->rwinfo, a->a_vals, conn );
		}
#endif /* ENABLE_REWRITE */

		for (j=0; a->a_vals[j].bv_val; j++);
		attrs[i]->mod_vals.modv_bvals = ch_malloc((j+1)*sizeof(struct berval *));
		for (j=0; a->a_vals[j].bv_val; j++)
			attrs[i]->mod_vals.modv_bvals[j] = &a->a_vals[j];
		attrs[i]->mod_vals.modv_bvals[j] = NULL;
		i++;
	}
	attrs[i] = NULL;

	j = ldap_add_ext(lc->ld, mdn.bv_val, attrs, op->o_ctrls, NULL, &msgid);
	for (--i; i>= 0; --i) {
		ch_free(attrs[i]->mod_vals.modv_bvals);
		ch_free(attrs[i]);
	}
	ch_free(attrs);
	if ( mdn.bv_val != e->e_dn ) {
		free( mdn.bv_val );
	}
	
	return( ldap_back_op_result( lc, conn, op, msgid, j ) );
}

#ifdef ENABLE_REWRITE
int
ldap_dnattr_rewrite(
		struct rewrite_info     *rwinfo,
		BerVarray			a_vals,
		void                    *cookie
)
{
	char *mattr;
	
	for ( ; a_vals->bv_val != NULL; a_vals++ ) {
		switch ( rewrite_session( rwinfo, "bindDn", a_vals->bv_val,
					cookie, &mattr )) {
		case REWRITE_REGEXEC_OK:
			if ( mattr == NULL ) {
				/* no substitution */
				continue;
			}
#ifdef NEW_LOGGING
			LDAP_LOG( BACK_LDAP, DETAIL1, 
				"[rw] bindDn (in add of dn-valued"
				" attr): \"%s\" -> \"%s\"\n", a_vals->bv_val, mattr, 0 );
#else /* !NEW_LOGGING */
			Debug( LDAP_DEBUG_ARGS,
					"rw> bindDn (in add of dn-valued attr):"
					" \"%s\" -> \"%s\"\n%s",
					a_vals->bv_val, mattr, "" );
#endif /* !NEW_LOGGING */

			/*
			 * FIXME: replacing server-allocated memory 
			 * (ch_malloc) with librewrite allocated memory
			 * (malloc)
			 */
			ch_free( a_vals->bv_val );
			a_vals->bv_val = mattr;
			a_vals->bv_len = strlen( mattr );
			
			break;
			
		case REWRITE_REGEXEC_UNWILLING:
			
		case REWRITE_REGEXEC_ERR:
			/*
			 * FIXME: better give up,
			 * skip the attribute
			 * or leave it untouched?
			 */
			break;
		}
	}
	
	return 0;
}
#endif /* ENABLE_REWRITE */

