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

int
ldap_back_search(
		Operation	*op,
		SlapReply	*rs )
{
	struct ldapconn *lc;
	struct timeval	tv;
	LDAPMessage	*res,
			*e;
	int		rc = 0,
			msgid; 
	struct berval	match = BER_BVNULL;
	int		i;
	char		**attrs = NULL;
	int		dontfreetext = 0;
	int		freeconn = 0;
	int		do_retry = 1;
	LDAPControl	**ctrls = NULL;

	lc = ldap_back_getconn( op, rs );
	if ( !lc ) {
		return -1;
	}

	/*
	 * FIXME: in case of values return filter, we might want
	 * to map attrs and maybe rewrite value
	 */
	if ( !ldap_back_dobind( lc, op, rs ) ) {
		return -1;
	}

	/* should we check return values? */
	if ( op->ors_deref != -1 ) {
		ldap_set_option( lc->lc_ld, LDAP_OPT_DEREF,
				(void *)&op->ors_deref );
	}

	if ( op->ors_tlimit != SLAP_NO_LIMIT ) {
		tv.tv_sec = op->ors_tlimit;
		tv.tv_usec = 0;

	} else {
		tv.tv_sec = 0;
	}

	if ( op->ors_attrs ) {
		for ( i = 0; !BER_BVISNULL( &op->ors_attrs[i].an_name ); i++ )
			/* just count attrs */ ;

		attrs = ch_malloc( ( i + 1 )*sizeof( char * ) );
		if ( attrs == NULL ) {
			rs->sr_err = LDAP_NO_MEMORY;
			rc = -1;
			goto finish;
		}
	
		for ( i = 0; !BER_BVISNULL( &op->ors_attrs[i].an_name ); i++ ) {
			attrs[ i ] = op->ors_attrs[i].an_name.bv_val;
		}
		attrs[ i ] = NULL;
	}

	ctrls = op->o_ctrls;
#ifdef LDAP_BACK_PROXY_AUTHZ
	rc = ldap_back_proxy_authz_ctrl( lc, op, rs, &ctrls );
	if ( rc != LDAP_SUCCESS ) {
		dontfreetext = 1;
		goto finish;
	}
#endif /* LDAP_BACK_PROXY_AUTHZ */
	
retry:
	rs->sr_err = ldap_search_ext( lc->lc_ld, op->o_req_ndn.bv_val,
			op->ors_scope, op->ors_filterstr.bv_val,
			attrs, op->ors_attrsonly, ctrls, NULL,
			tv.tv_sec ? &tv : NULL,
			op->ors_slimit, &msgid );

	if ( rs->sr_err != LDAP_SUCCESS ) {
fail:;
		rc = ldap_back_op_result( lc, op, rs, msgid, 0 );
		if ( freeconn ) {
			ldap_back_freeconn( op, lc );
			lc = NULL;
		}
		goto finish;
	}

	/* We pull apart the ber result, stuff it into a slapd entry, and
	 * let send_search_entry stuff it back into ber format. Slow & ugly,
	 * but this is necessary for version matching, and for ACL processing.
	 */

	for ( rc = 0; rc != -1; rc = ldap_result( lc->lc_ld, msgid, 0, &tv, &res ) )
	{
		/* check for abandon */
		if ( op->o_abandon ) {
			ldap_abandon_ext( lc->lc_ld, msgid, NULL, NULL );
			rc = 0;
			goto finish;
		}

		if ( rc == 0 ) {
			tv.tv_sec = 0;
			tv.tv_usec = 100000;
			ldap_pvt_thread_yield();

		} else if ( rc == LDAP_RES_SEARCH_ENTRY ) {
			Entry		ent = {0};
			struct berval	bdn;
			int		abort = 0;

			do_retry = 0;

			e = ldap_first_entry( lc->lc_ld, res );
			rc = ldap_build_entry( op, e, &ent, &bdn,
					LDAP_BUILD_ENTRY_PRIVATE );
		       if ( rc == LDAP_SUCCESS ) {
				rs->sr_entry = &ent;
				rs->sr_attrs = op->ors_attrs;
				rs->sr_operational_attrs = NULL;
				rs->sr_flags = 0;
				abort = send_search_entry( op, rs );
				while ( ent.e_attrs ) {
					Attribute	*a;
					BerVarray	v;

					a = ent.e_attrs;
					ent.e_attrs = a->a_next;

					v = a->a_vals;
					if ( a->a_vals != &slap_dummy_bv ) {
						ber_bvarray_free( a->a_vals );
					}
					if ( a->a_nvals != v ) {
						ber_bvarray_free( a->a_nvals );
					}
					ch_free( a );
				}
				
				if ( ent.e_dn && ( ent.e_dn != bdn.bv_val ) ) {
					free( ent.e_dn );
				}
				if ( ent.e_ndn ) {
					free( ent.e_ndn );
				}
			}
			ldap_msgfree( res );
			if ( abort ) {
				ldap_abandon_ext( lc->lc_ld, msgid, NULL, NULL );
				goto finish;
			}

		} else if ( rc == LDAP_RES_SEARCH_REFERENCE ) {
			char		**references = NULL;
			int		cnt;

			do_retry = 0;
			rc = ldap_parse_reference( lc->lc_ld, res,
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
				ber_str2bv( references[ cnt ], 0, 0, &rs->sr_ref[ cnt ] );
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
			rc = ldap_parse_result( lc->lc_ld, res, &rs->sr_err,
					&match.bv_val, (char **)&rs->sr_text,
					NULL, &rs->sr_ctrls, 1 );
			if (rc != LDAP_SUCCESS ) {
				rs->sr_err = rc;
			}
			rs->sr_err = slap_map_api2result( rs );
			rc = 0;
			break;
		}
	}

	if ( rc == -1 ) {
		if ( do_retry ) {
			do_retry = 0;
			if ( ldap_back_retry( lc, op, rs ) ) {
				goto retry;
			}
		}
		/* FIXME: invalidate the connection? */
		rs->sr_err = LDAP_SERVER_DOWN;
		freeconn = 1;
		goto fail;
	}

	/*
	 * Rewrite the matched portion of the search base, if required
	 */
	if ( !BER_BVISNULL( &match ) && !BER_BVISEMPTY( &match ) ) {
		rs->sr_matched = match.bv_val;
	}
	if ( rs->sr_v2ref ) {
		rs->sr_err = LDAP_REFERRAL;
	}

finish:;
	send_ldap_result( op, rs );

#ifdef LDAP_BACK_PROXY_AUTHZ
	(void)ldap_back_proxy_authz_ctrl_free( op, &ctrls );
#endif /* LDAP_BACK_PROXY_AUTHZ */

	if ( rs->sr_ctrls ) {
		ldap_controls_free( rs->sr_ctrls );
		rs->sr_ctrls = NULL;
	}

	if ( match.bv_val ) {
		rs->sr_matched = NULL;
		LDAP_FREE( match.bv_val );
	}
	if ( rs->sr_text ) {
		if ( !dontfreetext ) {
			LDAP_FREE( (char *)rs->sr_text );
		}
		rs->sr_text = NULL;
	}
	if ( attrs ) {
		ch_free( attrs );
	}

	return rc;
}

static int
ldap_build_entry(
		Operation	*op,
		LDAPMessage	*e,
		Entry		*ent,
		struct berval	*bdn,
		int		flags )
{
	struct berval	a;
	BerElement	ber = *e->lm_ber;
	Attribute	*attr, **attrp;
	const char	*text;
	int		last;
	int		private = flags & LDAP_BUILD_ENTRY_PRIVATE;

	/* safe assumptions ... */
	assert( ent );
	BER_BVZERO( &ent->e_bv );

	if ( ber_scanf( &ber, "{m{", bdn ) == LBER_ERROR ) {
		return LDAP_DECODING_ERROR;
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
	if ( dnPrettyNormal( NULL, bdn, &ent->e_name, &ent->e_nname,
		op->o_tmpmemctx ) != LDAP_SUCCESS )
	{
		return LDAP_INVALID_DN_SYNTAX;
	}

	attrp = &ent->e_attrs;

	while ( ber_scanf( &ber, "{m", &a ) != LBER_ERROR ) {
		int				i;
		slap_syntax_validate_func	*validate;
		slap_syntax_transform_func	*pretty;

		attr = (Attribute *)ch_malloc( sizeof( Attribute ) );
		if ( attr == NULL ) {
			continue;
		}
		attr->a_flags = 0;
		attr->a_next = 0;
		attr->a_desc = NULL;
		if ( slap_bv2ad( &a, &attr->a_desc, &text ) 
				!= LDAP_SUCCESS )
		{
			if ( slap_bv2undef_ad( &a, &attr->a_desc, &text ) 
					!= LDAP_SUCCESS )
			{
				Debug( LDAP_DEBUG_ANY, 
					"slap_bv2undef_ad(%s):	%s\n",
					a.bv_val, text, 0 );
				ch_free( attr );
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

			ch_free( attr );
			continue;
		}
		
		if ( ber_scanf( &ber, "[W]", &attr->a_vals ) == LBER_ERROR
				|| attr->a_vals == NULL )
		{
			/*
			 * Note: attr->a_vals can be null when using
			 * values result filter
			 */
			if ( private ) {
				attr->a_vals = (struct berval *)&slap_dummy_bv;
				
			} else {
				attr->a_vals = ch_malloc( sizeof( struct berval ) );
				BER_BVZERO( &attr->a_vals[ 0 ] );
			}
			last = 0;

		} else {
			for ( last = 0; !BER_BVISNULL( &attr->a_vals[ last ] ); last++ )
				/* just count vals */ ;
		}

		validate = attr->a_desc->ad_type->sat_syntax->ssyn_validate;
		pretty = attr->a_desc->ad_type->sat_syntax->ssyn_pretty;

		if ( !validate && !pretty ) {
			attr->a_nvals = NULL;
			attr_free( attr );
			goto next_attr;
		}

		for ( i = 0; i < last; i++ ) {
			struct berval	pval;
			int		rc;

			if ( pretty ) {
				rc = pretty( attr->a_desc->ad_type->sat_syntax,
					&attr->a_vals[i], &pval, NULL );

			} else {
				rc = validate( attr->a_desc->ad_type->sat_syntax,
					&attr->a_vals[i] );
			}

			if ( rc != LDAP_SUCCESS ) {
				/* check if, by chance, it's an undefined objectClass */
				if ( attr->a_desc == slap_schema.si_ad_objectClass &&
						oc_bvfind_undef( &attr->a_vals[i] ) != NULL )
				{
					ber_dupbv( &pval, &attr->a_vals[i] );

				} else {
					attr->a_nvals = NULL;
					attr_free( attr );
					goto next_attr;
				}
			}

			if ( pretty ) {
				LBER_FREE( attr->a_vals[i].bv_val );
				attr->a_vals[i] = pval;
			}
		}

		if ( last && attr->a_desc->ad_type->sat_equality &&
				attr->a_desc->ad_type->sat_equality->smr_normalize )
		{
			attr->a_nvals = ch_malloc( ( last + 1 )*sizeof( struct berval ) );
			for ( i = 0; i < last; i++ ) {
				int		rc;

				/*
				 * check that each value is valid per syntax
				 * and pretty if appropriate
				 */
				rc = attr->a_desc->ad_type->sat_equality->smr_normalize(
					SLAP_MR_VALUE_OF_ATTRIBUTE_SYNTAX,
					attr->a_desc->ad_type->sat_syntax,
					attr->a_desc->ad_type->sat_equality,
					&attr->a_vals[i], &attr->a_nvals[i],
					NULL /* op->o_tmpmemctx */ );

				if ( rc != LDAP_SUCCESS ) {
					BER_BVZERO( &attr->a_nvals[i] );
					ch_free( attr );
					goto next_attr;
				}
			}
			BER_BVZERO( &attr->a_nvals[i] );

		} else {
			attr->a_nvals = attr->a_vals;
		}
		*attrp = attr;
		attrp = &attr->a_next;

next_attr:;
	}

	return LDAP_SUCCESS;
}

/* return 0 IFF we can retrieve the entry with ndn
 */
int
ldap_back_entry_get(
		Operation		*op,
		struct berval		*ndn,
		ObjectClass		*oc,
		AttributeDescription	*at,
		int			rw,
		Entry			**ent
)
{
	struct ldapconn *lc;
	int		rc = 1,
			is_oc,
			do_not_cache;
	struct berval	bdn;
	LDAPMessage	*result = NULL,
			*e = NULL;
	char		*gattr[3];
	char		*filter = NULL;
	Connection	*oconn;
	SlapReply	rs;
	int		do_retry = 1;

	/* Tell getconn this is a privileged op */
	do_not_cache = op->o_do_not_cache;
	op->o_do_not_cache = 1;
	lc = ldap_back_getconn( op, &rs );
	oconn = op->o_conn;
	op->o_conn = NULL;
	if ( !lc || !ldap_back_dobind( lc, op, &rs ) ) {
		op->o_do_not_cache = do_not_cache;
		op->o_conn = oconn;
		return 1;
	}
	op->o_do_not_cache = do_not_cache;
	op->o_conn = oconn;

	if ( at ) {
		is_oc = ( strcasecmp( "objectclass", at->ad_cname.bv_val ) == 0 );
		if ( oc && !is_oc ) {
			gattr[0] = "objectclass";
			gattr[1] = at->ad_cname.bv_val;
			gattr[2] = NULL;

		} else {
			gattr[0] = at->ad_cname.bv_val;
			gattr[1] = NULL;
		}
	}

	if ( oc ) {
		char	*ptr;

		filter = ch_malloc( STRLENOF( "(objectclass=)" ) 
				+ oc->soc_cname.bv_len + 1 );
		ptr = lutil_strcopy( filter, "(objectclass=" );
		ptr = lutil_strcopy( ptr, oc->soc_cname.bv_val );
		*ptr++ = ')';
		*ptr++ = '\0';
	}

retry:
	rc = ldap_search_ext_s( lc->lc_ld, ndn->bv_val, LDAP_SCOPE_BASE, filter,
				at ? gattr : NULL, 0, NULL, NULL, LDAP_NO_LIMIT,
				LDAP_NO_LIMIT, &result );
	if ( rc != LDAP_SUCCESS ) {
		if ( rc == LDAP_SERVER_DOWN && do_retry ) {
			do_retry = 0;
			if ( ldap_back_retry( lc, op, &rs ) ) {
				goto retry;
			}
		}
		goto cleanup;
	}

	e = ldap_first_entry( lc->lc_ld, result );
	if ( e == NULL ) {
		goto cleanup;
	}

	*ent = ch_calloc( 1, sizeof( Entry ) );

	rc = ldap_build_entry( op, e, *ent, &bdn, 0 );

	if ( rc != LDAP_SUCCESS ) {
		ch_free( *ent );
		*ent = NULL;
	}

cleanup:
	if ( result ) {
		ldap_msgfree( result );
	}

	if ( filter ) {
		ch_free( filter );
	}

	return rc;
}

