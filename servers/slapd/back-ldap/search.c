/* search.c - ldap backend search function */
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

static struct berval dummy = BER_BVNULL;

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
	struct berval match = BER_BVNULL;
	char **mapped_attrs = NULL;
	struct berval mbase;
	struct berval mfilter = BER_BVNULL;
	int dontfreetext = 0;
	dncookie dc;
	LDAPControl **ctrls = NULL;

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

	/* should we check return values? */
	if (op->ors_deref != -1)
		ldap_set_option( lc->ld, LDAP_OPT_DEREF, (void *)&op->ors_deref);
	if (op->ors_tlimit != -1) {
		tv.tv_sec = op->ors_tlimit;
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
	if ( ldap_back_dn_massage( &dc, &op->o_req_ndn, &mbase ) ) {
		send_ldap_result( op, rs );
		return -1;
	}

	rc = ldap_back_filter_map_rewrite( &dc, op->ors_filter,
			&mfilter, BACKLDAP_MAP );

	switch ( rc ) {
	case LDAP_SUCCESS:
		break;

	case LDAP_COMPARE_FALSE:
		rs->sr_err = LDAP_SUCCESS;
		rs->sr_text = NULL;
		rc = 0;
		goto finish;

	default:
		rs->sr_err = LDAP_OTHER;
		rs->sr_text = "Rewrite error";
		dontfreetext = 1;
		rc = -1;
		goto finish;
	}

	rs->sr_err = ldap_back_map_attrs( &li->rwmap.rwm_at,
			op->ors_attrs,
			BACKLDAP_MAP, &mapped_attrs );
	if ( rs->sr_err ) {
		rc = -1;
		goto finish;
	}

	ctrls = op->o_ctrls;
#ifdef LDAP_BACK_PROXY_AUTHZ
	rc = ldap_back_proxy_authz_ctrl( lc, op, rs, &ctrls );
	if ( rc != LDAP_SUCCESS ) {
		dontfreetext = 1;
		goto finish;
	}
#endif /* LDAP_BACK_PROXY_AUTHZ */
	
	rs->sr_err = ldap_search_ext(lc->ld, mbase.bv_val,
			op->ors_scope, mfilter.bv_val,
			mapped_attrs, op->ors_attrsonly,
			ctrls, NULL,
			tv.tv_sec ? &tv : NULL, op->ors_slimit,
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
			Entry ent = {0};
			struct berval bdn;
			int abort = 0;
			e = ldap_first_entry(lc->ld,res);
			if ( ( rc = ldap_build_entry(op, e, &ent, &bdn,
						LDAP_BUILD_ENTRY_PRIVATE)) == LDAP_SUCCESS ) {
				rs->sr_entry = &ent;
				rs->sr_attrs = op->ors_attrs;
				rs->sr_flags = 0;
				abort = send_search_entry( op, rs );
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
			if ( abort ) {
				ldap_abandon(lc->ld, msgid);
				goto finish;
			}

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
			rs->sr_err = slap_map_api2result( rs );
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
		dc.ctx = "matchedDN";
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
	if ( mfilter.bv_val != op->ors_filterstr.bv_val ) {
		ch_free( mfilter.bv_val );
	}
	if ( mbase.bv_val != op->o_req_ndn.bv_val ) {
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
	/* Note: if the distinguished values or the naming attributes
	 * change, should we massage them as well?
	 */
	if ( dnNormalize( 0, NULL, NULL, &ent->e_name, &ent->e_nname,
		op->o_tmpmemctx ) != LDAP_SUCCESS )
	{
		return LDAP_INVALID_DN_SYNTAX;
	}

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

		if ( last && attr->a_desc->ad_type->sat_equality &&
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
	struct berval mapped = BER_BVNULL, bdn, mdn;
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

	rc = ldap_build_entry(op, e, *ent, &bdn, 0);

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

