/* search.c - ldap backend search function */
/* $OpenLDAP$ */
/*
 * Copyright 1998-2002 The OpenLDAP Foundation, All Rights Reserved.
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

#include <ac/socket.h>
#include <ac/string.h>
#include <ac/time.h>

#include "slap.h"
#include "back-ldap.h"
#undef ldap_debug	/* silence a warning in ldap-int.h */
#include "../../../libraries/libldap/ldap-int.h"

static int ldap_send_entry( Backend *be, Operation *op, struct ldapconn *lc,
                             LDAPMessage *e, AttributeName *attrs, int attrsonly );

int
ldap_back_search(
    Backend	*be,
    Connection	*conn,
    Operation	*op,
    struct berval	*base,
    struct berval	*nbase,
    int		scope,
    int		deref,
    int		slimit,
    int		tlimit,
    Filter	*filter,
    struct berval	*filterstr,
    AttributeName	*attrs,
    int		attrsonly
)
{
	struct ldapinfo	*li = (struct ldapinfo *) be->be_private;
	struct ldapconn *lc;
	struct timeval	tv;
	LDAPMessage		*res, *e;
	int	count, rc = 0, msgid, sres = LDAP_SUCCESS; 
	char *match = NULL, *err = NULL;
	char *mapped_filter = NULL, **mapped_attrs = NULL;
	struct berval mbase;
#ifdef ENABLE_REWRITE
	char *mmatch = NULL;
	struct berval mfilter = { 0, NULL };
#endif /* ENABLE_REWRITE */
	struct slap_limits_set *limit = NULL;
	int isroot = 0;

	lc = ldap_back_getconn(li, conn, op);
	if ( !lc ) {
		return( -1 );
	}

	/* if not root, get appropriate limits */
	if ( be_isroot( be, &op->o_ndn ) ) {
		isroot = 1;
	} else {
		( void ) get_limits( be, &op->o_ndn, &limit );
	}
	
	/* if no time limit requested, rely on remote server limits */
	/* if requested limit higher than hard limit, abort */
	if ( !isroot && tlimit > limit->lms_t_hard ) {
		/* no hard limit means use soft instead */
		if ( limit->lms_t_hard == 0 && tlimit > limit->lms_t_soft ) {
			tlimit = limit->lms_t_soft;
			
		/* positive hard limit means abort */
		} else if ( limit->lms_t_hard > 0 ) {
			send_search_result( conn, op, LDAP_UNWILLING_TO_PERFORM,
					NULL, NULL, NULL, NULL, 0 );
			rc = 0;
			goto finish;
		}
		
		/* negative hard limit means no limit */
	}
	
	/* if no size limit requested, rely on remote server limits */
	/* if requested limit higher than hard limit, abort */
	if ( !isroot && slimit > limit->lms_s_hard ) {
		/* no hard limit means use soft instead */
		if ( limit->lms_s_hard == 0 && slimit > limit->lms_s_soft ) {
			slimit = limit->lms_s_soft;
			
		/* positive hard limit means abort */
		} else if ( limit->lms_s_hard > 0 ) {
			send_search_result( conn, op, LDAP_UNWILLING_TO_PERFORM,
					NULL, NULL, NULL, NULL, 0 );
			rc = 0;
			goto finish;
		}
		
		/* negative hard limit means no limit */
	}

	if (deref != -1)
		ldap_set_option( lc->ld, LDAP_OPT_DEREF, (void *)&deref);
	if (tlimit != -1)
		ldap_set_option( lc->ld, LDAP_OPT_TIMELIMIT, (void *)&tlimit);
	if (slimit != -1)
		ldap_set_option( lc->ld, LDAP_OPT_SIZELIMIT, (void *)&slimit);
	
	if ( !ldap_back_dobind( lc, op ) ) {
		return( -1 );
	}

	/*
	 * Rewrite the search base, if required
	 */
#ifdef ENABLE_REWRITE
 	switch ( rewrite_session( li->rwinfo, "searchBase",
 				base->bv_val, conn, &mbase.bv_val ) ) {
	case REWRITE_REGEXEC_OK:
		if ( mbase.bv_val == NULL ) {
			mbase = *base;
		}
#ifdef NEW_LOGGING
		LDAP_LOG( BACK_LDAP, DETAIL1, 
			"[rw] searchBase: \"%s\" -> \"%s\"\n", 
			base->bv_val, mbase.bv_val, 0 );
#else /* !NEW_LOGGING */
		Debug( LDAP_DEBUG_ARGS, "rw> searchBase: \"%s\" -> \"%s\"\n%s",
				base->bv_val, mbase.bv_val, "" );
#endif /* !NEW_LOGGING */
		break;
		
	case REWRITE_REGEXEC_UNWILLING:
		send_ldap_result( conn, op, LDAP_UNWILLING_TO_PERFORM,
				NULL, "Unwilling to perform", NULL, NULL );
		rc = -1;
		goto finish;

	case REWRITE_REGEXEC_ERR:
		send_ldap_result( conn, op, LDAP_OTHER,
				NULL, "Operations error", NULL, NULL );
		rc = -1;
		goto finish;
	}
	
	/*
	 * Rewrite the search filter, if required
	 */
	switch ( rewrite_session( li->rwinfo, "searchFilter",
				filterstr->bv_val, conn, &mfilter.bv_val ) ) {
	case REWRITE_REGEXEC_OK:
		if ( mfilter.bv_val == NULL || mfilter.bv_val[0] == '\0') {
			if ( mfilter.bv_val != NULL ) {
				free( mfilter.bv_val );
			}
			mfilter = *filterstr;
		} else {
			mfilter.bv_len = strlen( mfilter.bv_val );
		}

#ifdef NEW_LOGGING
		LDAP_LOG( BACK_LDAP, DETAIL1, 
			"[rw] searchFilter: \"%s\" -> \"%s\"\n",
			filterstr->bv_val, mfilter.bv_val, 0 );
#else /* !NEW_LOGGING */
		Debug( LDAP_DEBUG_ARGS,
				"rw> searchFilter: \"%s\" -> \"%s\"\n%s",
				filterstr->bv_val, mfilter.bv_val, "" );
#endif /* !NEW_LOGGING */
		break;
		
	case REWRITE_REGEXEC_UNWILLING:
		send_ldap_result( conn, op, LDAP_UNWILLING_TO_PERFORM,
				NULL, "Unwilling to perform", NULL, NULL );
	case REWRITE_REGEXEC_ERR:
		rc = -1;
		goto finish;
	}
#else /* !ENABLE_REWRITE */
	ldap_back_dn_massage( li, base, &mbase, 0, 1 );
#endif /* !ENABLE_REWRITE */

	mapped_filter = ldap_back_map_filter(&li->at_map, &li->oc_map,
#ifdef ENABLE_REWRITE
			&mfilter,
#else /* !ENABLE_REWRITE */
			filterstr,
#endif /* !ENABLE_REWRITE */
		       	0);
	if ( mapped_filter == NULL ) {
#ifdef ENABLE_REWRITE
		mapped_filter = mfilter.bv_val;
#else /* !ENABLE_REWRITE */
		mapped_filter = filterstr->bv_val;
#endif /* !ENABLE_REWRITE */
	}

#ifdef ENABLE_REWRITE
	if ( mfilter.bv_val != filterstr->bv_val ) {
		free( mfilter.bv_val );
	}
#endif /* ENABLE_REWRITE */

	mapped_attrs = ldap_back_map_attrs(&li->at_map, attrs, 0);
	if ( mapped_attrs == NULL && attrs) {
		for (count=0; attrs[count].an_name.bv_val; count++);
		mapped_attrs = ch_malloc( (count+1) * sizeof(char *));
		for (count=0; attrs[count].an_name.bv_val; count++) {
			mapped_attrs[count] = attrs[count].an_name.bv_val;
		}
		mapped_attrs[count] = NULL;
	}

	if ((msgid = ldap_search(lc->ld, mbase.bv_val, scope, mapped_filter, mapped_attrs,
		attrsonly)) == -1)
	{
fail:;
		rc = ldap_back_op_result(lc, op);
		goto finish;
	}

	/* We pull apart the ber result, stuff it into a slapd entry, and
	 * let send_search_entry stuff it back into ber format. Slow & ugly,
	 * but this is necessary for version matching, and for ACL processing.
	 */
	
	for (	count=0, rc=0;
			rc != -1;
			rc = ldap_result(lc->ld, msgid, 0, &tv, &res))
	{
		/* check for abandon */
		if (op->o_abandon) {
			ldap_abandon(lc->ld, msgid);
			rc = 0;
			goto finish;
		}
		if (rc == 0) {
			tv.tv_sec = 0;
			tv.tv_usec = 100000;
			ldap_pvt_thread_yield();
		} else if (rc == LDAP_RES_SEARCH_ENTRY) {
			e = ldap_first_entry(lc->ld,res);
			if ( ldap_send_entry(be, op, lc, e, attrs, attrsonly) == LDAP_SUCCESS ) {
				count++;
			}
			ldap_msgfree(res);
		} else {
			sres = ldap_result2error(lc->ld, res, 1);
			sres = ldap_back_map_result(sres);
			ldap_get_option(lc->ld, LDAP_OPT_ERROR_STRING, &err);
			ldap_get_option(lc->ld, LDAP_OPT_MATCHED_DN, &match);
			rc = 0;
			break;
		}
	}

	if (rc == -1)
		goto fail;

#ifdef ENABLE_REWRITE
	/*
	 * Rewrite the matched portion of the search base, if required
	 */
	if ( match != NULL ) {
		switch ( rewrite_session( li->rwinfo, "matchedDn",
				match, conn, &mmatch ) ) {
		case REWRITE_REGEXEC_OK:
			if ( mmatch == NULL ) {
				mmatch = ( char * )match;
			}
#ifdef NEW_LOGGING
			LDAP_LOG( BACK_LDAP, DETAIL1, 
				"[rw]  matchedDn:" " \"%s\" -> \"%s\"\n", match, mmatch, 0 );
#else /* !NEW_LOGGING */
			Debug( LDAP_DEBUG_ARGS, "rw> matchedDn:"
					" \"%s\" -> \"%s\"\n%s",
					match, mmatch, "" );
#endif /* !NEW_LOGGING */
			break;
			
		case REWRITE_REGEXEC_UNWILLING:
			send_ldap_result( conn, op, LDAP_UNWILLING_TO_PERFORM,
					NULL, "Unwilling to perform",
				       	NULL, NULL );
			
		case REWRITE_REGEXEC_ERR:
			rc = -1;
			goto finish;
		}
	}

	send_search_result( conn, op, sres,
		mmatch, err, NULL, NULL, count );

#else /* !ENABLE_REWRITE */
	send_search_result( conn, op, sres,
		match, err, NULL, NULL, count );
#endif /* !ENABLE_REWRITE */

finish:;
	if ( match ) {
#ifdef ENABLE_REWRITE
		if ( mmatch != match ) {
			free( mmatch );
		}
#endif /* ENABLE_REWRITE */
		LDAP_FREE(match);
	}
	if ( err ) {
		LDAP_FREE( err );
	}
	if ( mapped_attrs ) {
		ch_free( mapped_attrs );
	}
	if ( mapped_filter != filterstr->bv_val ) {
		ch_free( mapped_filter );
	}
	if ( mbase.bv_val != base->bv_val ) {
		free( mbase.bv_val );
	}
	
	return rc;
}

static int
ldap_send_entry(
	Backend *be,
	Operation *op,
	struct ldapconn *lc,
	LDAPMessage *e,
	AttributeName *attrs,
	int attrsonly
)
{
	struct ldapinfo *li = (struct ldapinfo *) be->be_private;
	struct berval a, mapped;
	Entry ent;
	BerElement ber = *e->lm_ber;
	Attribute *attr, **attrp;
	struct berval dummy = { 0, NULL };
	struct berval *bv, bdn;
	const char *text;

	if ( ber_scanf( &ber, "{m{", &bdn ) == LBER_ERROR ) {
		return LDAP_DECODING_ERROR;
	}
#ifdef ENABLE_REWRITE

	/*
	 * Rewrite the dn of the result, if needed
	 */
	switch ( rewrite_session( li->rwinfo, "searchResult",
				bdn.bv_val, lc->conn, &ent.e_name.bv_val ) ) {
	case REWRITE_REGEXEC_OK:
		if ( ent.e_name.bv_val == NULL ) {
			ent.e_name = bdn;
		} else {
#ifdef NEW_LOGGING
			LDAP_LOG( BACK_LDAP, DETAIL1, 
				"[rw] searchResult: \"%s\"" " -> \"%s\"\n", 
				bdn.bv_val, ent.e_dn, 0 );
#else /* !NEW_LOGGING */
			Debug( LDAP_DEBUG_ARGS, "rw> searchResult: \"%s\""
 					" -> \"%s\"\n%s", bdn.bv_val, ent.e_dn, "" );
#endif /* !NEW_LOGGING */
			ent.e_name.bv_len = strlen( ent.e_name.bv_val );
		}
		break;
		
	case REWRITE_REGEXEC_ERR:
	case REWRITE_REGEXEC_UNWILLING:
		return LDAP_OTHER;
	}
#else /* !ENABLE_REWRITE */
	ldap_back_dn_massage( li, &bdn, &ent.e_name, 0, 0 );
#endif /* !ENABLE_REWRITE */

	/*
	 * Note: this may fail if the target host(s) schema differs
	 * from the one known to the meta, and a DN with unknown
	 * attributes is returned.
	 * 
	 * FIXME: should we log anything, or delegate to dnNormalize2?
	 */
	if ( dnNormalize2( NULL, &ent.e_name, &ent.e_nname ) != LDAP_SUCCESS ) {
		return LDAP_INVALID_DN_SYNTAX;
	}
	
	ent.e_id = 0;
	ent.e_attrs = 0;
	ent.e_private = 0;
	attrp = &ent.e_attrs;

	while ( ber_scanf( &ber, "{m", &a ) != LBER_ERROR ) {
		ldap_back_map(&li->at_map, &a, &mapped, 1);
		if (mapped.bv_val == NULL)
			continue;
		attr = (Attribute *)ch_malloc( sizeof(Attribute) );
		if (attr == NULL)
			continue;
		attr->a_flags = 0;
		attr->a_next = 0;
		attr->a_desc = NULL;
		if (slap_bv2ad(&mapped, &attr->a_desc, &text) != LDAP_SUCCESS) {
			if (slap_bv2undef_ad(&mapped, &attr->a_desc, &text) 
					!= LDAP_SUCCESS) {
#ifdef NEW_LOGGING
				LDAP_LOG( BACK_LDAP, DETAIL1, 
					"slap_bv2undef_ad(%s):	%s\n", mapped.bv_val, text, 0 );
#else /* !NEW_LOGGING */
				Debug( LDAP_DEBUG_ANY, 
						"slap_bv2undef_ad(%s):	"
 						"%s\n%s", mapped.bv_val, text, "" );
#endif /* !NEW_LOGGING */
				ch_free(attr);
				continue;
			}
		}

		/* no subschemaSubentry */
		if ( attr->a_desc == slap_schema.si_ad_subschemaSubentry ) {
			ch_free(attr);
			continue;
		}
		
		if (ber_scanf( &ber, "[W]", &attr->a_vals ) == LBER_ERROR ) {
			attr->a_vals = &dummy;
		} else if ( attr->a_desc == slap_schema.si_ad_objectClass
				|| attr->a_desc == slap_schema.si_ad_structuralObjectClass ) {
			int i, last;
			assert( attr->a_vals );
			for ( last = 0; attr->a_vals[last].bv_val; last++ ) ;
			for ( i = 0, bv = attr->a_vals; bv->bv_val; bv++, i++ ) {
				ldap_back_map(&li->oc_map, bv, &mapped, 1);
				if (mapped.bv_val == NULL) {
					LBER_FREE(bv->bv_val);
					bv->bv_val = NULL;
					if (--last < 0)
						break;
					*bv = attr->a_vals[last];
					attr->a_vals[last].bv_val = NULL;
					i--;
				} else if ( mapped.bv_val != bv->bv_val ) {
					/*
					 * FIXME: after LBER_FREEing
					 * the value is replaced by
					 * ch_alloc'ed memory
					 */
					LBER_FREE(bv->bv_val);
					ber_dupbv( bv, &mapped );
				}
			}

		/*
		 * It is necessary to try to rewrite attributes with
		 * dn syntax because they might be used in ACLs as
		 * members of groups; since ACLs are applied to the
		 * rewritten stuff, no dn-based subject clause could
		 * be used at the ldap backend side (see
		 * http://www.OpenLDAP.org/faq/data/cache/452.html)
		 * The problem can be overcome by moving the dn-based
		 * ACLs to the target directory server, and letting
		 * everything pass thru the ldap backend.
		 */
		} else if ( strcmp( attr->a_desc->ad_type->sat_syntax->ssyn_oid,
					SLAPD_DN_SYNTAX ) == 0 ) {
			int i;
			assert( attr->a_vals );
			for ( i = 0, bv = attr->a_vals; bv->bv_val; bv++, i++ ) {
				struct berval newval;
				
#ifdef ENABLE_REWRITE
				switch ( rewrite_session( li->rwinfo,
							"searchResult",
							bv->bv_val,
							lc->conn, 
							&newval.bv_val )) {
				case REWRITE_REGEXEC_OK:
					/* left as is */
					if ( newval.bv_val == NULL ) {
						break;
					}
					newval.bv_len = strlen( newval.bv_val );
#ifdef NEW_LOGGING
					LDAP_LOG( BACK_LDAP, DETAIL1, 
						"[rw] searchResult on attr=%s: \"%s\" -> \"%s\"\n",
						attr->a_desc->ad_type->sat_cname.bv_val,
						bv->bv_val, newval.bv_val );
#else /* !NEW_LOGGING */
					Debug( LDAP_DEBUG_ARGS,
		"rw> searchResult on attr=%s: \"%s\" -> \"%s\"\n",
						attr->a_desc->ad_type->sat_cname.bv_val,
						bv->bv_val, newval.bv_val );
#endif /* !NEW_LOGGING */
					free( bv->bv_val );
					*bv = newval;
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
#else /* !ENABLE_REWRITE */
				ldap_back_dn_massage( li, bv, &newval, 0, 0 );
				*bv = newval;
#endif /* !ENABLE_REWRITE */
			}
		}

		*attrp = attr;
		attrp = &attr->a_next;
	}
	send_search_entry( be, lc->conn, op, &ent, attrs, attrsonly, NULL );
	while (ent.e_attrs) {
		attr = ent.e_attrs;
		ent.e_attrs = attr->a_next;
		if (attr->a_vals != &dummy)
			ber_bvarray_free(attr->a_vals);
		ch_free(attr);
	}
	
	if ( ent.e_dn && ( ent.e_dn != bdn.bv_val ) )
		free( ent.e_dn );
	if ( ent.e_ndn )
		free( ent.e_ndn );

	return LDAP_SUCCESS;
}
