/* search.c - ldap backend search function */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 2003 The OpenLDAP Foundation.
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

#include <ac/socket.h>
#include <ac/string.h>
#include <ac/time.h>

#include "slap.h"
#include "back-ldap.h"
#undef ldap_debug	/* silence a warning in ldap-int.h */
#include "../../../libraries/libldap/ldap-int.h"

#include "lutil.h"

static int
ldap_build_entry( Operation *op, LDAPMessage *e, Entry *ent,
	 struct berval *bdn, int flags );
#define LDAP_BUILD_ENTRY_PRIVATE	0x01
#define LDAP_BUILD_ENTRY_NORMALIZE	0x02

static struct berval dummy = { 0, NULL };

int
ldap_back_search(
    Operation	*op,
    SlapReply *rs )
{
	struct ldapinfo	*li = (struct ldapinfo *) op->o_bd->be_private;
	struct ldapconn *lc;
	struct timeval	tv;
	LDAPMessage		*res, *e;
	int	rc = 0, msgid; 
	struct berval match = { 0, NULL };
	char **mapped_attrs = NULL;
	struct berval mbase;
	struct berval mfilter = { 0, NULL };
	struct slap_limits_set *limit = NULL;
	int isroot = 0;
	int dontfreetext = 0;
	dncookie dc;
#ifdef LDAP_BACK_PROXY_AUTHZ
	LDAPControl **ctrls = NULL;
#endif /* LDAP_BACK_PROXY_AUTHZ */

	lc = ldap_back_getconn(op, rs);
	if ( !lc ) {
		return( -1 );
	}

	/*
	 * FIXME: in case of values return filter, we might want
	 * to map attrs and maybe rewrite value
	 */
	if ( !ldap_back_dobind( lc, op, rs ) ) {
		return( -1 );
	}

	/* if not root, get appropriate limits */
	if ( be_isroot( op->o_bd, &op->o_ndn ) ) {
		isroot = 1;
	} else {
		( void ) get_limits( op->o_bd, &op->o_ndn, &limit );
	}
	
	/* if no time limit requested, rely on remote server limits */
	/* if requested limit higher than hard limit, abort */
	if ( !isroot && op->oq_search.rs_tlimit > limit->lms_t_hard ) {
		/* no hard limit means use soft instead */
		if ( limit->lms_t_hard == 0
				&& limit->lms_t_soft > -1
				&& op->oq_search.rs_tlimit > limit->lms_t_soft ) {
			op->oq_search.rs_tlimit = limit->lms_t_soft;
			
		/* positive hard limit means abort */
		} else if ( limit->lms_t_hard > 0 ) {
			rs->sr_err = LDAP_ADMINLIMIT_EXCEEDED;
			rc = 0;
			goto finish;
		}
		
		/* negative hard limit means no limit */
	}
	
	/* if no size limit requested, rely on remote server limits */
	/* if requested limit higher than hard limit, abort */
	if ( !isroot && op->oq_search.rs_slimit > limit->lms_s_hard ) {
		/* no hard limit means use soft instead */
		if ( limit->lms_s_hard == 0
				&& limit->lms_s_soft > -1
				&& op->oq_search.rs_slimit > limit->lms_s_soft ) {
			op->oq_search.rs_slimit = limit->lms_s_soft;
			
		/* positive hard limit means abort */
		} else if ( limit->lms_s_hard > 0 ) {
			rs->sr_err = LDAP_ADMINLIMIT_EXCEEDED;
			rc = 0;
			goto finish;
		}
		
		/* negative hard limit means no limit */
	}

	/* should we check return values? */
	if (op->oq_search.rs_deref != -1)
		ldap_set_option( lc->ld, LDAP_OPT_DEREF, (void *)&op->oq_search.rs_deref);
	if (op->oq_search.rs_tlimit != -1) {
		tv.tv_sec = op->oq_search.rs_tlimit;
		tv.tv_usec = 0;
	} else {
		tv.tv_sec = 0;
	}

	/*
	 * Rewrite the search base, if required
	 */
	dc.rwmap = &li->rwmap;
#ifdef ENABLE_REWRITE
	dc.conn = op->o_conn;
	dc.rs = rs;
	dc.ctx = "searchBase";
#else
	dc.tofrom = 1;
	dc.normalized = 0;
#endif
	if ( ldap_back_dn_massage( &dc, &op->o_req_dn, &mbase ) ) {
		send_ldap_result( op, rs );
		return -1;
	}

	rc = ldap_back_filter_map_rewrite( &dc, op->oq_search.rs_filter,
			&mfilter, BACKLDAP_MAP );

	if ( rc ) {
		rs->sr_err = LDAP_OTHER;
		rs->sr_text = "Rewrite error";
		dontfreetext = 1;
		rc = -1;
		goto finish;
	}

	rs->sr_err = ldap_back_map_attrs( &li->rwmap.rwm_at,
			op->oq_search.rs_attrs,
			BACKLDAP_MAP, &mapped_attrs );
	if ( rs->sr_err ) {
		rc = -1;
		goto finish;
	}

#ifdef LDAP_BACK_PROXY_AUTHZ
	rc = ldap_back_proxy_authz_ctrl( lc, op, rs, &ctrls );
	if ( rc != LDAP_SUCCESS ) {
		dontfreetext = 1;
		goto finish;
	}
#endif /* LDAP_BACK_PROXY_AUTHZ */
	
	rs->sr_err = ldap_search_ext(lc->ld, mbase.bv_val,
			op->oq_search.rs_scope, mfilter.bv_val,
			mapped_attrs, op->oq_search.rs_attrsonly,
#ifdef LDAP_BACK_PROXY_AUTHZ
			ctrls,
#else /* ! LDAP_BACK_PROXY_AUTHZ */
			op->o_ctrls,
#endif /* ! LDAP_BACK_PROXY_AUTHZ */
			NULL,
			tv.tv_sec ? &tv : NULL, op->oq_search.rs_slimit,
			&msgid );

	if ( rs->sr_err != LDAP_SUCCESS ) {
fail:;
		rc = ldap_back_op_result(lc, op, rs, msgid, 0);
		goto finish;
	}

	/* We pull apart the ber result, stuff it into a slapd entry, and
	 * let send_search_entry stuff it back into ber format. Slow & ugly,
	 * but this is necessary for version matching, and for ACL processing.
	 */

	for ( rc=0; rc != -1; rc = ldap_result(lc->ld, msgid, 0, &tv, &res))
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
			Entry ent;
			struct berval bdn;
			e = ldap_first_entry(lc->ld,res);
			if ( ldap_build_entry(op, e, &ent, &bdn,
						LDAP_BUILD_ENTRY_PRIVATE) == LDAP_SUCCESS ) {
				rs->sr_entry = &ent;
				rs->sr_attrs = op->oq_search.rs_attrs;
				send_search_entry( op, rs );
				while (ent.e_attrs) {
					Attribute *a;
					BerVarray v;

					a = ent.e_attrs;
					ent.e_attrs = a->a_next;

					v = a->a_vals;
					if (a->a_vals != &dummy)
						ber_bvarray_free(a->a_vals);
					if (a->a_nvals != v)
						ber_bvarray_free(a->a_nvals);
					ch_free(a);
				}
				
				if ( ent.e_dn && ( ent.e_dn != bdn.bv_val ) )
					free( ent.e_dn );
				if ( ent.e_ndn )
					free( ent.e_ndn );
			}
			ldap_msgfree(res);

		} else if ( rc == LDAP_RES_SEARCH_REFERENCE ) {
			char		**references = NULL;
			int		cnt;

			rc = ldap_parse_reference( lc->ld, res,
					&references, &rs->sr_ctrls, 1 );

			if ( rc != LDAP_SUCCESS ) {
				continue;
			}

			if ( references == NULL ) {
				continue;
			}

			for ( cnt = 0; references[ cnt ]; cnt++ )
				/* NO OP */ ;
				
			rs->sr_ref = ch_calloc( cnt + 1, sizeof( struct berval ) );

			for ( cnt = 0; references[ cnt ]; cnt++ ) {
				rs->sr_ref[ cnt ].bv_val = references[ cnt ];
				rs->sr_ref[ cnt ].bv_len = strlen( references[ cnt ] );
			}

			/* ignore return value by now */
			( void )send_search_reference( op, rs );

			/* cleanup */
			if ( references ) {
				ldap_value_free( references );
				ch_free( rs->sr_ref );
				rs->sr_ref = NULL;
			}

			if ( rs->sr_ctrls ) {
				ldap_controls_free( rs->sr_ctrls );
				rs->sr_ctrls = NULL;
			}

		} else {
			rc = ldap_parse_result(lc->ld, res, &rs->sr_err,
					&match.bv_val, (char **)&rs->sr_text,
					NULL, NULL, 1);
			if (rc != LDAP_SUCCESS ) rs->sr_err = rc;
			rs->sr_err = ldap_back_map_result(rs);
			rc = 0;
			break;
		}
	}

	if (rc == -1)
		goto fail;

	/*
	 * Rewrite the matched portion of the search base, if required
	 */
	if ( match.bv_val && *match.bv_val ) {
		struct berval mdn;

#ifdef ENABLE_REWRITE
		dc.ctx = "matchedDn";
#else
		dc.tofrom = 0;
		dc.normalized = 0;
#endif
		match.bv_len = strlen( match.bv_val );
		ldap_back_dn_massage(&dc, &match, &mdn);
		rs->sr_matched = mdn.bv_val;
	}
	if ( rs->sr_v2ref ) {
		rs->sr_err = LDAP_REFERRAL;
	}

finish:;
	send_ldap_result( op, rs );

#ifdef LDAP_BACK_PROXY_AUTHZ
	if ( ctrls && ctrls != op->o_ctrls ) {
		free( ctrls[ 0 ] );
		free( ctrls );
	}
#endif /* LDAP_BACK_PROXY_AUTHZ */

	if ( match.bv_val ) {
		if ( rs->sr_matched != match.bv_val ) {
			free( (char *)rs->sr_matched );
		}
		rs->sr_matched = NULL;
		LDAP_FREE( match.bv_val );
	}
	if ( rs->sr_text ) {
		if ( !dontfreetext ) {
			LDAP_FREE( (char *)rs->sr_text );
		}
		rs->sr_text = NULL;
	}
	if ( mapped_attrs ) {
		ch_free( mapped_attrs );
	}
	if ( mfilter.bv_val != op->oq_search.rs_filterstr.bv_val ) {
		ch_free( mfilter.bv_val );
	}
	if ( mbase.bv_val != op->o_req_dn.bv_val ) {
		free( mbase.bv_val );
	}
	
	return rc;
}

static int
ldap_build_entry(
	Operation *op,
	LDAPMessage *e,
	Entry *ent,
	struct berval *bdn,
	int flags
)
{
	struct ldapinfo *li = (struct ldapinfo *) op->o_bd->be_private;
	struct berval a, mapped;
	BerElement ber = *e->lm_ber;
	Attribute *attr, **attrp;
	struct berval *bv;
	const char *text;
	int last;
	int private = flags & LDAP_BUILD_ENTRY_PRIVATE;
	int normalize = flags & LDAP_BUILD_ENTRY_NORMALIZE;
	dncookie dc;

	/* safe assumptions ... */
	assert( ent );
	ent->e_bv.bv_val = NULL;

	if ( ber_scanf( &ber, "{m{", bdn ) == LBER_ERROR ) {
		return LDAP_DECODING_ERROR;
	}

	/*
	 * Rewrite the dn of the result, if needed
	 */
	dc.rwmap = &li->rwmap;
#ifdef ENABLE_REWRITE
	dc.conn = op->o_conn;
	dc.rs = NULL;
	dc.ctx = "searchResult";
#else
	dc.tofrom = 0;
	dc.normalized = 0;
#endif
	if ( ldap_back_dn_massage( &dc, bdn, &ent->e_name ) ) {
		return LDAP_OTHER;
	}

	/*
	 * Note: this may fail if the target host(s) schema differs
	 * from the one known to the meta, and a DN with unknown
	 * attributes is returned.
	 * 
	 * FIXME: should we log anything, or delegate to dnNormalize?
	 */
	if ( dnNormalize( 0, NULL, NULL, &ent->e_name, &ent->e_nname,
		op->o_tmpmemctx ) != LDAP_SUCCESS )
	{
		return LDAP_INVALID_DN_SYNTAX;
	}
	
	ent->e_id = 0;
	ent->e_attrs = 0;
	ent->e_private = 0;
	attrp = &ent->e_attrs;

#ifdef ENABLE_REWRITE
	dc.ctx = "searchAttrDN";
#endif
	while ( ber_scanf( &ber, "{m", &a ) != LBER_ERROR ) {
		ldap_back_map(&li->rwmap.rwm_at, &a, &mapped, BACKLDAP_REMAP);
		if (mapped.bv_val == NULL || mapped.bv_val[0] == '\0')
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

			/* 
			 * We eat target's subschemaSubentry because
			 * a search for this value is likely not
			 * to resolve to the appropriate backend;
			 * later, the local subschemaSubentry is
			 * added.
			 */
			( void )ber_scanf( &ber, "x" /* [W] */ );

			ch_free(attr);
			continue;
		}
		
		if ( ber_scanf( &ber, "[W]", &attr->a_vals ) == LBER_ERROR
				|| attr->a_vals == NULL ) {
			/*
			 * Note: attr->a_vals can be null when using
			 * values result filter
			 */
			if (private) {
				attr->a_vals = &dummy;
			} else {
				attr->a_vals = ch_malloc(sizeof(struct berval));
				attr->a_vals->bv_val = NULL;
				attr->a_vals->bv_len = 0;
			}
			last = 0;
		} else {
			for ( last = 0; attr->a_vals[last].bv_val; last++ );
		}
		if ( last == 0 ) {
			/* empty */
		} else if ( attr->a_desc == slap_schema.si_ad_objectClass
				|| attr->a_desc == slap_schema.si_ad_structuralObjectClass ) {
			for ( bv = attr->a_vals; bv->bv_val; bv++ ) {
				ldap_back_map(&li->rwmap.rwm_oc, bv, &mapped,
						BACKLDAP_REMAP);
				if (mapped.bv_val == NULL || mapped.bv_val[0] == '\0') {
					LBER_FREE(bv->bv_val);
					bv->bv_val = NULL;
					if (--last < 0)
						break;
					*bv = attr->a_vals[last];
					attr->a_vals[last].bv_val = NULL;
					bv--;

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
		} else if ( attr->a_desc->ad_type->sat_syntax ==
				slap_schema.si_syn_distinguishedName ) {
			ldap_dnattr_result_rewrite( &dc, attr->a_vals );
		}

		if ( normalize && last && attr->a_desc->ad_type->sat_equality &&
			attr->a_desc->ad_type->sat_equality->smr_normalize ) {
			int i;

			attr->a_nvals = ch_malloc((last+1)*sizeof(struct berval));
			for (i=0; i<last; i++) {
				attr->a_desc->ad_type->sat_equality->smr_normalize(
					SLAP_MR_VALUE_OF_ATTRIBUTE_SYNTAX,
					attr->a_desc->ad_type->sat_syntax,
					attr->a_desc->ad_type->sat_equality,
					&attr->a_vals[i], &attr->a_nvals[i],
					NULL /* op->o_tmpmemctx */ );
			}
			attr->a_nvals[i].bv_val = NULL;
			attr->a_nvals[i].bv_len = 0;
		} else {
			attr->a_nvals = attr->a_vals;
		}
		*attrp = attr;
		attrp = &attr->a_next;
	}

	/* make sure it's free'able */
	if (!private && ent->e_name.bv_val == bdn->bv_val)
		ber_dupbv( &ent->e_name, bdn );
	return LDAP_SUCCESS;
}

/* return 0 IFF we can retrieve the entry with ndn
 */
int
ldap_back_entry_get(
	Operation *op,
	struct berval	*ndn,
	ObjectClass *oc,
	AttributeDescription *at,
	int rw,
	Entry **ent
)
{
	struct ldapinfo *li = (struct ldapinfo *) op->o_bd->be_private;    
	struct ldapconn *lc;
	int rc = 1, is_oc;
	struct berval mapped = { 0, NULL }, bdn, mdn;
	LDAPMessage	*result = NULL, *e = NULL;
	char *gattr[3];
	char *filter = NULL;
	Connection *oconn;
	SlapReply rs;
	dncookie dc;

	/* Tell getconn this is a privileged op */
	is_oc = op->o_do_not_cache;
	op->o_do_not_cache = 1;
	lc = ldap_back_getconn(op, &rs);
	oconn = op->o_conn;
	op->o_conn = NULL;
	if ( !lc || !ldap_back_dobind(lc, op, &rs) ) {
		op->o_do_not_cache = is_oc;
		op->o_conn = oconn;
		return 1;
	}
	op->o_do_not_cache = is_oc;
	op->o_conn = oconn;

	/*
	 * Rewrite the search base, if required
	 */
	dc.rwmap = &li->rwmap;
#ifdef ENABLE_REWRITE
	dc.conn = op->o_conn;
	dc.rs = &rs;
	dc.ctx = "searchBase";
#else
	dc.tofrom = 1;
	dc.normalized = 1;
#endif
	if ( ldap_back_dn_massage( &dc, ndn, &mdn ) ) {
		return 1;
	}

	if ( at ) {
		ldap_back_map(&li->rwmap.rwm_at, &at->ad_cname, &mapped, BACKLDAP_MAP);
		if (mapped.bv_val == NULL || mapped.bv_val[0] == '\0') {
			rc = 1;
			goto cleanup;
		}
	}

	is_oc = (strcasecmp("objectclass", mapped.bv_val) == 0);
	if (oc && !is_oc) {
		gattr[0] = "objectclass";
		gattr[1] = mapped.bv_val;
		gattr[2] = NULL;
	} else {
		gattr[0] = mapped.bv_val;
		gattr[1] = NULL;
	}
	if (oc) {
		char *ptr;
		ldap_back_map(&li->rwmap.rwm_oc, &oc->soc_cname, &mapped,
						BACKLDAP_MAP);
		filter = ch_malloc(sizeof("(objectclass=)") + mapped.bv_len);
		ptr = lutil_strcopy(filter, "(objectclass=");
		ptr = lutil_strcopy(ptr, mapped.bv_val);
		*ptr++ = ')';
		*ptr++ = '\0';
	}

	if (ldap_search_ext_s(lc->ld, mdn.bv_val, LDAP_SCOPE_BASE, filter,
				gattr, 0, NULL, NULL, LDAP_NO_LIMIT,
				LDAP_NO_LIMIT, &result) != LDAP_SUCCESS)
	{
		goto cleanup;
	}

	if ((e = ldap_first_entry(lc->ld, result)) == NULL) {
		goto cleanup;
	}

	*ent = ch_calloc(1,sizeof(Entry));

	rc = ldap_build_entry(op, e, *ent, &bdn, LDAP_BUILD_ENTRY_NORMALIZE);

	if (rc != LDAP_SUCCESS) {
		ch_free(*ent);
		*ent = NULL;
	}

cleanup:
	if (result) {
		ldap_msgfree(result);
	}

	if ( filter ) {
		ch_free( filter );
	}

	if ( mdn.bv_val != ndn->bv_val ) {
		ch_free( mdn.bv_val );
	}

	return(rc);
}

