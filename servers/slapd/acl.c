/* acl.c - routines to parse and check acl's */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1998-2004 The OpenLDAP Foundation.
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
/* Portions Copyright (c) 1995 Regents of the University of Michigan.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that this notice is preserved and that due credit is given
 * to the University of Michigan at Ann Arbor. The name of the University
 * may not be used to endorse or promote products derived from this
 * software without specific prior written permission. This software
 * is provided ``as is'' without express or implied warranty.
 */

#include "portable.h"

#include <stdio.h>

#include <ac/regex.h>
#include <ac/socket.h>
#include <ac/string.h>

#include "slap.h"
#include "sets.h"
#include "lber_pvt.h"

#ifdef LDAP_SLAPI
#include "slapi/slapi.h"
#endif /* LDAPI_SLAPI */

#define ACL_BUF_SIZE 	1024	/* use most appropriate size */

/*
 * speed up compares
 */
static struct berval 
	aci_bv_entry 		= BER_BVC("entry"),
	aci_bv_children 	= BER_BVC("children"),
	aci_bv_br_entry		= BER_BVC("[entry]"),
	aci_bv_br_all		= BER_BVC("[all]"),
	aci_bv_access_id 	= BER_BVC("access-id"),
	aci_bv_anonymous	= BER_BVC("anonymous"),
	aci_bv_public		= BER_BVC("public"),
	aci_bv_users		= BER_BVC("users"),
	aci_bv_self 		= BER_BVC("self"),
	aci_bv_dnattr 		= BER_BVC("dnattr"),
	aci_bv_group		= BER_BVC("group"),
	aci_bv_role		= BER_BVC("role"),
	aci_bv_set		= BER_BVC("set"),
	aci_bv_set_ref		= BER_BVC("set-ref"),
	aci_bv_grant		= BER_BVC("grant"),
	aci_bv_deny		= BER_BVC("deny"),

	aci_bv_ip_eq		= BER_BVC("IP="),
#ifdef LDAP_PF_LOCAL
	aci_bv_path_eq		= BER_BVC("PATH="),
	aci_bv_dirsep		= BER_BVC(LDAP_DIRSEP),
#endif /* LDAP_PF_LOCAL */
	
	aci_bv_group_class 	= BER_BVC(SLAPD_GROUP_CLASS),
	aci_bv_group_attr 	= BER_BVC(SLAPD_GROUP_ATTR),
	aci_bv_role_class	= BER_BVC(SLAPD_ROLE_CLASS),
	aci_bv_role_attr	= BER_BVC(SLAPD_ROLE_ATTR),
	aci_bv_set_attr		= BER_BVC(SLAPD_ACI_SET_ATTR);


static AccessControl * acl_get(
	AccessControl *ac, int *count,
	Operation *op, Entry *e,
	AttributeDescription *desc,
	struct berval *val,
	int nmatches, regmatch_t *matches,
	AccessControlState *state );

static slap_control_t acl_mask(
	AccessControl *ac, slap_mask_t *mask,
	Operation *op, Entry *e,
	AttributeDescription *desc,
	struct berval *val,
	regmatch_t *matches,
	int count,
	AccessControlState *state );

#ifdef SLAPD_ACI_ENABLED
static int aci_mask(
	Operation *op, Entry *e,
	AttributeDescription *desc,
	struct berval *val,
	struct berval *aci,
	regmatch_t *matches,
	slap_access_t *grant,
	slap_access_t *deny,
	struct berval *scope);
#endif

static int	regex_matches(
	struct berval *pat, char *str, char *buf, regmatch_t *matches);
static void	string_expand(
	struct berval *newbuf, struct berval *pattern,
	char *match, regmatch_t *matches);

typedef	struct AciSetCookie {
	Operation *op;
	Entry *e;
} AciSetCookie;

SLAP_SET_GATHER aci_set_gather;
static int aci_match_set ( struct berval *subj, Operation *op,
    Entry *e, int setref );

/*
 * access_allowed - check whether op->o_ndn is allowed the requested access
 * to entry e, attribute attr, value val.  if val is null, access to
 * the whole attribute is assumed (all values).
 *
 * This routine loops through all access controls and calls
 * acl_mask() on each applicable access control.
 * The loop exits when a definitive answer is reached or
 * or no more controls remain.
 *
 * returns:
 *		0	access denied
 *		1	access granted
 *
 * Notes:
 * - can be legally called with op == NULL
 * - can be legally called with op->o_bd == NULL
 */

int
access_allowed_mask(
	Operation		*op,
	Entry		*e,
	AttributeDescription	*desc,
	struct berval	*val,
	slap_access_t	access,
	AccessControlState *state,
	slap_mask_t *maskp )
{
	int				ret = 1;
	int				count;
	AccessControl			*a = NULL;
	Backend *be;
	int	be_null = 0;

#ifdef LDAP_DEBUG
	char accessmaskbuf[ACCESSMASK_MAXLEN];
#endif
	slap_mask_t mask;
	slap_control_t control;
	const char *attr;
	regmatch_t matches[MAXREMATCHES];
	int        st_same_attr = 0;
	static AccessControlState state_init = ACL_STATE_INIT;

	assert( e != NULL );
	assert( desc != NULL );
	assert( access > ACL_NONE );
	if ( maskp ) ACL_INVALIDATE( *maskp );

	attr = desc->ad_cname.bv_val;

	assert( attr != NULL );

	if( op && op->o_is_auth_check &&
		( access == ACL_SEARCH || access == ACL_READ ))
	{
		access = ACL_AUTH;
	}

	if( state ) {
		if ( state->as_vd_ad==desc) {
			if ( state->as_recorded ) {
				if( state->as_recorded & ACL_STATE_RECORDED_NV &&
					val == NULL )
				{
					return state->as_result;
				} else if ( state->as_recorded & ACL_STATE_RECORDED_VD &&
					val != NULL && state->as_vd_acl == NULL )
				{
					return state->as_result;
				}
			}
			st_same_attr = 1;
		} else {
			*state = state_init;
		}

		state->as_vd_ad=desc;
	}

	Debug( LDAP_DEBUG_ACL,
		"=> access_allowed: %s access to \"%s\" \"%s\" requested\n",
	    access2str( access ), e->e_dn, attr );

	if ( op == NULL ) {
		/* no-op call */
		goto done;
	}

	be = op->o_bd;
	if ( be == NULL ) {
		be = &backends[0];
		be_null = 1;
#ifdef LDAP_DEVEL
		/*
		 * FIXME: experimental; use first backend rules
		 * iff there is no global_acl (ITS#3100) */
		if ( frontendDB->be_acl == NULL ) 
#endif
		{
			op->o_bd = be;
		}
	}
	assert( be != NULL );

#ifdef LDAP_SLAPI
	if ( op->o_pb != NULL ) {
		ret = slapi_int_access_allowed( op, e, desc, val, access, state );
		if ( ret == 0 ) {
			/* ACL plugin denied access */
			goto done;
		}
	}
#endif /* LDAP_SLAPI */

	/* grant database root access */
	if ( be != NULL && be_isroot( op ) ) {
		Debug( LDAP_DEBUG_ACL,
		    "<= root access granted\n",
			0, 0, 0 );
		if ( maskp ) {
			mask = ACL_LVL_WRITE;
		}

		goto done;
	}

	/*
	 * no-user-modification operational attributes are ignored
	 * by ACL_WRITE checking as any found here are not provided
	 * by the user
	 */
	if ( access >= ACL_WRITE && is_at_no_user_mod( desc->ad_type )
		&& desc != slap_schema.si_ad_entry
		&& desc != slap_schema.si_ad_children )
	{
		Debug( LDAP_DEBUG_ACL, "NoUserMod Operational attribute:"
			" %s access granted\n",
			attr, 0, 0 );
		goto done;
	}

	/* use backend default access if no backend acls */
	if( be != NULL && be->be_acl == NULL ) {
		Debug( LDAP_DEBUG_ACL,
			"=> access_allowed: backend default %s access %s to \"%s\"\n",
			access2str( access ),
			be->be_dfltaccess >= access ? "granted" : "denied",
			op->o_dn.bv_val ? op->o_dn.bv_val : "(anonymous)" );
		ret = be->be_dfltaccess >= access;

		if ( maskp ) {
			int	i;

			mask = ACL_PRIV_LEVEL;
			for ( i = ACL_NONE; i <= be->be_dfltaccess; i++ ) {
				mask |= ACL_ACCESS2PRIV( i );
			}
		}

		goto done;

#ifdef notdef
	/* be is always non-NULL */
	/* use global default access if no global acls */
	} else if ( be == NULL && frontendDB->be_acl == NULL ) {
		Debug( LDAP_DEBUG_ACL,
			"=> access_allowed: global default %s access %s to \"%s\"\n",
			access2str( access ),
			frontendDB->be_dfltaccess >= access ? "granted" : "denied", op->o_dn.bv_val );
		ret = frontendDB->be_dfltaccess >= access;

		if ( maskp ) {
			int	i;

			mask = ACL_PRIV_LEVEL;
			for ( i = ACL_NONE; i <= global_default_access; i++ ) {
				mask |= ACL_ACCESS2PRIV( i );
			}
		}

		goto done;
#endif
	}

	ret = 0;
	control = ACL_BREAK;

	if( st_same_attr ) {
		assert( state->as_vd_acl != NULL );

		a = state->as_vd_acl;
		count = state->as_vd_acl_count;
		if ( !ACL_IS_INVALID( state->as_vd_acl_mask )) {
			mask = state->as_vd_acl_mask;
			AC_MEMCPY( matches, state->as_vd_acl_matches, sizeof(matches) );
			goto vd_access;
		}

	} else {
		if ( state ) state->as_vi_acl = NULL;
		a = NULL;
		ACL_INIT(mask);
		count = 0;
		memset(matches, '\0', sizeof(matches));
	}

	while((a = acl_get( a, &count, op, e, desc, val,
		MAXREMATCHES, matches, state )) != NULL)
	{
		int i;

		for (i = 0; i < MAXREMATCHES && matches[i].rm_so > 0; i++) {
			Debug( LDAP_DEBUG_ACL, "=> match[%d]: %d %d ", i,
			    (int)matches[i].rm_so, (int)matches[i].rm_eo );
			if( matches[i].rm_so <= matches[0].rm_eo ) {
				int n;
				for ( n = matches[i].rm_so; n < matches[i].rm_eo; n++) {
					Debug( LDAP_DEBUG_ACL, "%c", e->e_ndn[n], 0, 0 );
				}
			}
			Debug( LDAP_DEBUG_ARGS, "\n", 0, 0, 0 );
		}

		if (state) {
			if (state->as_vi_acl == a && (state->as_recorded & ACL_STATE_RECORDED_NV)) {
				Debug( LDAP_DEBUG_ACL, "access_allowed: result from state (%s)\n", attr, 0, 0 );
				ret = state->as_result;
				goto done;
			} else {
				Debug( LDAP_DEBUG_ACL, "access_allowed: no res from state (%s)\n", attr, 0, 0);
			}
		}

vd_access:
		control = acl_mask( a, &mask, op,
			e, desc, val, matches, count, state );

		if ( control != ACL_BREAK ) {
			break;
		}

		memset(matches, '\0', sizeof(matches));
	}

	if ( ACL_IS_INVALID( mask ) ) {
		Debug( LDAP_DEBUG_ACL,
			"=> access_allowed: \"%s\" (%s) invalid!\n",
			e->e_dn, attr, 0 );
		ACL_INIT(mask);

	} else if ( control == ACL_BREAK ) {
		Debug( LDAP_DEBUG_ACL,
			"=> access_allowed: no more rules\n", 0, 0, 0);

		goto done;
	}

	Debug( LDAP_DEBUG_ACL,
		"=> access_allowed: %s access %s by %s\n",
		access2str( access ),
		ACL_GRANT(mask, access) ? "granted" : "denied",
		accessmask2str( mask, accessmaskbuf ) );

	ret = ACL_GRANT(mask, access);

done:
	if( state != NULL ) {
		/* If not value-dependent, save ACL in case of more attrs */
		if ( !(state->as_recorded & ACL_STATE_RECORDED_VD) ) {
			state->as_vi_acl = a;
			state->as_result = ret;
		}
		state->as_recorded |= ACL_STATE_RECORDED;
	}
	if (be_null) op->o_bd = NULL;
	if ( maskp ) *maskp = mask;
	return ret;
}


/*
 * acl_get - return the acl applicable to entry e, attribute
 * attr.  the acl returned is suitable for use in subsequent calls to
 * acl_access_allowed().
 */

static AccessControl *
acl_get(
	AccessControl *a,
	int			*count,
	Operation	*op,
	Entry		*e,
	AttributeDescription *desc,
	struct berval	*val,
	int			nmatch,
	regmatch_t	*matches,
	AccessControlState *state )
{
	const char *attr;
	int dnlen, patlen;
	AccessControl *prev;

	assert( e != NULL );
	assert( count != NULL );
	assert( desc != NULL );

	attr = desc->ad_cname.bv_val;

	assert( attr != NULL );

	if( a == NULL ) {
		if( op->o_bd == NULL ) {
			a = frontendDB->be_acl;
		} else {
			a = op->o_bd->be_acl;
		}
		prev = NULL;

		assert( a != NULL );

	} else {
		prev = a;
		a = a->acl_next;
	}

	dnlen = e->e_nname.bv_len;

	for ( ; a != NULL; a = a->acl_next ) {
		(*count) ++;

		if ( a->acl_dn_pat.bv_len || ( a->acl_dn_style != ACL_STYLE_REGEX )) {
			if ( a->acl_dn_style == ACL_STYLE_REGEX ) {
				Debug( LDAP_DEBUG_ACL, "=> dnpat: [%d] %s nsub: %d\n", 
					*count, a->acl_dn_pat.bv_val, (int) a->acl_dn_re.re_nsub );
				if (regexec(&a->acl_dn_re, e->e_ndn, nmatch, matches, 0))
					continue;

			} else {
				Debug( LDAP_DEBUG_ACL, "=> dn: [%d] %s\n", 
					*count, a->acl_dn_pat.bv_val, 0 );
				patlen = a->acl_dn_pat.bv_len;
				if ( dnlen < patlen )
					continue;

				if ( a->acl_dn_style == ACL_STYLE_BASE ) {
					/* base dn -- entire object DN must match */
					if ( dnlen != patlen )
						continue;

				} else if ( a->acl_dn_style == ACL_STYLE_ONE ) {
					int	rdnlen = -1, sep = 0;

					if ( dnlen <= patlen )
						continue;

					if ( patlen > 0 ) {
						if ( !DN_SEPARATOR( e->e_ndn[dnlen - patlen - 1] ) )
							continue;
						sep = 1;
					}

					rdnlen = dn_rdnlen( NULL, &e->e_nname );
					if ( rdnlen != dnlen - patlen - sep )
						continue;

				} else if ( a->acl_dn_style == ACL_STYLE_SUBTREE ) {
					if ( dnlen > patlen && !DN_SEPARATOR( e->e_ndn[dnlen - patlen - 1] ) )
						continue;

				} else if ( a->acl_dn_style == ACL_STYLE_CHILDREN ) {
					if ( dnlen <= patlen )
						continue;
					if ( !DN_SEPARATOR( e->e_ndn[dnlen - patlen - 1] ) )
						continue;
				}

				if ( strcmp( a->acl_dn_pat.bv_val, e->e_ndn + dnlen - patlen ) != 0 )
					continue;
			}

			Debug( LDAP_DEBUG_ACL, "=> acl_get: [%d] matched\n",
				*count, 0, 0 );
		}

		if ( a->acl_attrs && !ad_inlist( desc, a->acl_attrs ) ) {
			matches[0].rm_so = matches[0].rm_eo = -1;
			continue;
		}

		/* Is this ACL only for a specific value? */
		if ( a->acl_attrval.bv_len ) {
			if ( val == NULL ) {
				continue;
			}

			if( state && !( state->as_recorded & ACL_STATE_RECORDED_VD )) {
				state->as_recorded |= ACL_STATE_RECORDED_VD;
				state->as_vd_acl = prev;
				state->as_vd_acl_count = *count;
				state->as_vd_access = a->acl_access;
				state->as_vd_access_count = 1;
				ACL_INVALIDATE( state->as_vd_acl_mask );
			}

			if ( a->acl_attrval_style == ACL_STYLE_REGEX ) {
				Debug( LDAP_DEBUG_ACL,
					"acl_get: valpat %s\n",
					a->acl_attrval.bv_val, 0, 0 );
				if (regexec(&a->acl_attrval_re, val->bv_val, 0, NULL, 0))
					continue;
			} else {
				int match = 0;
				const char *text;
				Debug( LDAP_DEBUG_ACL,
					"acl_get: val %s\n",
					a->acl_attrval.bv_val, 0, 0 );
	
				if ( a->acl_attrs[0].an_desc->ad_type->sat_syntax != slap_schema.si_syn_distinguishedName ) {
					if (value_match( &match, desc,
						desc->ad_type->sat_equality, 0,
						val, &a->acl_attrval, &text ) != LDAP_SUCCESS ||
							match )
						continue;
					
				} else {
					int		patlen, vdnlen;
	
					patlen = a->acl_attrval.bv_len;
					vdnlen = val->bv_len;
	
					if ( vdnlen < patlen )
						continue;
	
					if ( a->acl_dn_style == ACL_STYLE_BASE ) {
						if ( vdnlen > patlen )
							continue;
	
					} else if ( a->acl_dn_style == ACL_STYLE_ONE ) {
						int rdnlen = -1;
	
						if ( !DN_SEPARATOR( val->bv_val[vdnlen - patlen - 1] ) )
							continue;
	
						rdnlen = dn_rdnlen( NULL, val );
						if ( rdnlen != vdnlen - patlen - 1 )
							continue;
	
					} else if ( a->acl_dn_style == ACL_STYLE_SUBTREE ) {
						if ( vdnlen > patlen && !DN_SEPARATOR( val->bv_val[vdnlen - patlen - 1] ) )
							continue;
	
					} else if ( a->acl_dn_style == ACL_STYLE_CHILDREN ) {
						if ( vdnlen <= patlen )
							continue;
	
						if ( !DN_SEPARATOR( val->bv_val[vdnlen - patlen - 1] ) )
							continue;
					}
	
					if ( strcmp( a->acl_attrval.bv_val, val->bv_val + vdnlen - patlen ))
						continue;
				}
			}
		}

		if ( a->acl_filter != NULL ) {
			ber_int_t rc = test_filter( NULL, e, a->acl_filter );
			if ( rc != LDAP_COMPARE_TRUE ) {
				continue;
			}
		}

		Debug( LDAP_DEBUG_ACL, "=> acl_get: [%d] attr %s\n",
		       *count, attr, 0);
		return a;
	}

	Debug( LDAP_DEBUG_ACL, "<= acl_get: done.\n", 0, 0, 0 );
	return( NULL );
}

/*
 * Record value-dependent access control state
 */
#define ACL_RECORD_VALUE_STATE do { \
		if( state && !( state->as_recorded & ACL_STATE_RECORDED_VD )) { \
			state->as_recorded |= ACL_STATE_RECORDED_VD; \
			state->as_vd_acl = a; \
			AC_MEMCPY( state->as_vd_acl_matches, matches, \
				sizeof( state->as_vd_acl_matches )) ; \
			state->as_vd_acl_count = count; \
			state->as_vd_access = b; \
			state->as_vd_access_count = i; \
		} \
	} while( 0 )

/*
 * acl_mask - modifies mask based upon the given acl and the
 * requested access to entry e, attribute attr, value val.  if val
 * is null, access to the whole attribute is assumed (all values).
 *
 * returns	0	access NOT allowed
 *		1	access allowed
 */

static slap_control_t
acl_mask(
	AccessControl	*a,
	slap_mask_t *mask,
	Operation	*op,
	Entry		*e,
	AttributeDescription *desc,
	struct berval	*val,
	regmatch_t	*matches,
	int	count,
	AccessControlState *state )
{
	int		i, odnlen, patlen;
	Access	*b;
#ifdef LDAP_DEBUG
	char accessmaskbuf[ACCESSMASK_MAXLEN];
	char accessmaskbuf1[ACCESSMASK_MAXLEN];
#endif
	const char *attr;

	assert( a != NULL );
	assert( mask != NULL );
	assert( desc != NULL );

	attr = desc->ad_cname.bv_val;

	assert( attr != NULL );

	Debug( LDAP_DEBUG_ACL,
		"=> acl_mask: access to entry \"%s\", attr \"%s\" requested\n",
		e->e_dn, attr, 0 );

	Debug( LDAP_DEBUG_ACL,
		"=> acl_mask: to %s by \"%s\", (%s) \n",
		val ? "value" : "all values",
		op->o_ndn.bv_val ?  op->o_ndn.bv_val : "",
		accessmask2str( *mask, accessmaskbuf ) );


	if( state && ( state->as_recorded & ACL_STATE_RECORDED_VD )
		&& state->as_vd_acl == a )
	{
		b = state->as_vd_access;
		i = state->as_vd_access_count;

	} else {
		b = a->acl_access;
		i = 1;
	}

	for ( ; b != NULL; b = b->a_next, i++ ) {
		slap_mask_t oldmask, modmask;

		ACL_INVALIDATE( modmask );

		/* AND <who> clauses */
		if ( b->a_dn_pat.bv_len != 0 ) {
			Debug( LDAP_DEBUG_ACL, "<= check a_dn_pat: %s\n",
				b->a_dn_pat.bv_val, 0, 0);
			/*
			 * if access applies to the entry itself, and the
			 * user is bound as somebody in the same namespace as
			 * the entry, OR the given dn matches the dn pattern
			 */
			if ( bvmatch( &b->a_dn_pat, &aci_bv_anonymous ) ) {
				if ( op->o_ndn.bv_len != 0 ) {
					continue;
				}

			} else if ( bvmatch( &b->a_dn_pat, &aci_bv_users ) ) {
				if ( op->o_ndn.bv_len == 0 ) {
					continue;
				}

			} else if ( bvmatch( &b->a_dn_pat, &aci_bv_self ) ) {
				if ( op->o_ndn.bv_len == 0 ) {
					continue;
				}
				
				if ( e->e_dn == NULL || !dn_match( &e->e_nname, &op->o_ndn ) ) {
					continue;
				}

			} else if ( b->a_dn_style == ACL_STYLE_REGEX ) {
				if ( !ber_bvccmp( &b->a_dn_pat, '*' ) ) {
					int ret = regex_matches( &b->a_dn_pat,
						op->o_ndn.bv_val, e->e_ndn, matches );

					if( ret == 0 ) {
						continue;
					}
				}

			} else {
				struct berval pat;
				int got_match = 0;

				if ( e->e_dn == NULL )
					continue;

				if ( b->a_dn_expand ) {
					struct berval bv;
					char buf[ACL_BUF_SIZE];

					bv.bv_len = sizeof( buf ) - 1;
					bv.bv_val = buf;

					string_expand(&bv, &b->a_dn_pat, 
							e->e_ndn, matches);
					if ( dnNormalize(0, NULL, NULL, &bv, &pat, op->o_tmpmemctx ) != LDAP_SUCCESS ) {
						/* did not expand to a valid dn */
						continue;
					}
				} else {
					pat = b->a_dn_pat;
				}

				patlen = pat.bv_len;
				odnlen = op->o_ndn.bv_len;
				if ( odnlen < patlen ) {
					goto dn_match_cleanup;

				}

				if ( b->a_dn_style == ACL_STYLE_BASE ) {
					/* base dn -- entire object DN must match */
					if ( odnlen != patlen ) {
						goto dn_match_cleanup;
					}

				} else if ( b->a_dn_style == ACL_STYLE_ONE ) {
					int rdnlen = -1;

					if ( odnlen <= patlen ) {
						goto dn_match_cleanup;
					}

					if ( !DN_SEPARATOR( op->o_ndn.bv_val[odnlen - patlen - 1] ) ) {
						goto dn_match_cleanup;
					}

					rdnlen = dn_rdnlen( NULL, &op->o_ndn );
					if ( rdnlen != odnlen - patlen - 1 ) {
						goto dn_match_cleanup;
					}

				} else if ( b->a_dn_style == ACL_STYLE_SUBTREE ) {
					if ( odnlen > patlen && !DN_SEPARATOR( op->o_ndn.bv_val[odnlen - patlen - 1] ) ) {
						goto dn_match_cleanup;
					}

				} else if ( b->a_dn_style == ACL_STYLE_CHILDREN ) {
					if ( odnlen <= patlen ) {
						goto dn_match_cleanup;
					}

					if ( !DN_SEPARATOR( op->o_ndn.bv_val[odnlen - patlen - 1] ) ) {
						goto dn_match_cleanup;
					}
				}

				got_match = !strcmp( pat.bv_val, op->o_ndn.bv_val + odnlen - patlen );

dn_match_cleanup:;
				if ( pat.bv_val != b->a_dn_pat.bv_val ) {
					free( pat.bv_val );
				}

				if ( !got_match ) {
					continue;
				}
			}
		}

		if ( b->a_sockurl_pat.bv_len ) {
			if ( ! op->o_conn->c_listener ) {
				continue;
			}
			Debug( LDAP_DEBUG_ACL, "<= check a_sockurl_pat: %s\n",
				b->a_sockurl_pat.bv_val, 0, 0 );

			if ( !ber_bvccmp( &b->a_sockurl_pat, '*' ) ) {
				if ( b->a_sockurl_style == ACL_STYLE_REGEX) {
					if (!regex_matches( &b->a_sockurl_pat, op->o_conn->c_listener_url.bv_val,
							e->e_ndn, matches ) ) 
					{
						continue;
					}

				} else if ( b->a_sockurl_style == ACL_STYLE_EXPAND ) {
					struct berval	bv;
					char buf[ACL_BUF_SIZE];

					bv.bv_len = sizeof( buf ) - 1;
					bv.bv_val = buf;
					string_expand( &bv, &b->a_sockurl_pat, e->e_ndn, matches );

					if ( ber_bvstrcasecmp( &bv, &op->o_conn->c_listener_url ) != 0 ) {
						continue;
					}

				} else {
					if ( ber_bvstrcasecmp( &b->a_sockurl_pat, &op->o_conn->c_listener_url ) != 0 )
						continue;
				}
			}
		}

		if ( b->a_domain_pat.bv_len ) {
			if ( !op->o_conn->c_peer_domain.bv_val ) {
				continue;
			}
			Debug( LDAP_DEBUG_ACL, "<= check a_domain_pat: %s\n",
				b->a_domain_pat.bv_val, 0, 0 );
			if ( !ber_bvccmp( &b->a_domain_pat, '*' ) ) {
				if ( b->a_domain_style == ACL_STYLE_REGEX) {
					if (!regex_matches( &b->a_domain_pat, op->o_conn->c_peer_domain.bv_val,
							e->e_ndn, matches ) ) 
					{
						continue;
					}
				} else {
					char buf[ACL_BUF_SIZE];

					struct berval 	cmp = op->o_conn->c_peer_domain;
					struct berval 	pat = b->a_domain_pat;

					if ( b->a_domain_expand ) {
						struct berval bv;

						bv.bv_len = sizeof(buf) - 1;
						bv.bv_val = buf;

						string_expand(&bv, &b->a_domain_pat, e->e_ndn, matches);
						pat = bv;
					}

					if ( b->a_domain_style == ACL_STYLE_SUBTREE ) {
						int offset = cmp.bv_len - pat.bv_len;
						if ( offset < 0 ) {
							continue;
						}

						if ( offset == 1 || ( offset > 1 && cmp.bv_val[ offset - 1 ] != '.' ) ) {
							continue;
						}

						/* trim the domain */
						cmp.bv_val = &cmp.bv_val[ offset ];
						cmp.bv_len -= offset;
					}
					
					if ( ber_bvstrcasecmp( &pat, &cmp ) != 0 ) {
						continue;
					}
				}
			}
		}

		if ( b->a_peername_pat.bv_len ) {
			if ( !op->o_conn->c_peer_name.bv_val ) {
				continue;
			}
			Debug( LDAP_DEBUG_ACL, "<= check a_peername_path: %s\n",
				b->a_peername_pat.bv_val, 0, 0 );
			if ( !ber_bvccmp( &b->a_peername_pat, '*' ) ) {
				if ( b->a_peername_style == ACL_STYLE_REGEX ) {
					if (!regex_matches( &b->a_peername_pat, op->o_conn->c_peer_name.bv_val,
							e->e_ndn, matches ) ) 
					{
						continue;
					}

				} else {
					/* try exact match */
					if ( b->a_peername_style == ACL_STYLE_BASE ) {
						if ( ber_bvstrcasecmp( &b->a_peername_pat, &op->o_conn->c_peer_name ) != 0 ) {
							continue;
						}

					} else if ( b->a_peername_style == ACL_STYLE_EXPAND ) {
						struct berval	bv;
						char buf[ACL_BUF_SIZE];

						bv.bv_len = sizeof( buf ) - 1;
						bv.bv_val = buf;
						string_expand( &bv, &b->a_peername_pat, e->e_ndn, matches );

						if ( ber_bvstrcasecmp( &bv, &op->o_conn->c_peer_name ) != 0 ) {
							continue;
						}

					/* extract IP and try exact match */
					} else if ( b->a_peername_style == ACL_STYLE_IP ) {
						char		*port;
						char		buf[] = "255.255.255.255";
						struct berval	ip;
						unsigned long	addr;
						int		port_number = -1;
						
						if ( strncasecmp( op->o_conn->c_peer_name.bv_val, 
									aci_bv_ip_eq.bv_val, aci_bv_ip_eq.bv_len ) != 0 ) 
							continue;

						ip.bv_val = op->o_conn->c_peer_name.bv_val + aci_bv_ip_eq.bv_len;
						ip.bv_len = op->o_conn->c_peer_name.bv_len - aci_bv_ip_eq.bv_len;

						port = strrchr( ip.bv_val, ':' );
						if ( port ) {
							char	*next;
							
							ip.bv_len = port - ip.bv_val;
							++port;
							port_number = strtol( port, &next, 10 );
							if ( next[0] != '\0' )
								continue;
						}
						
						/* the port check can be anticipated here */
						if ( b->a_peername_port != -1 && port_number != b->a_peername_port )
							continue;
						
						/* address longer than expected? */
						if ( ip.bv_len >= sizeof(buf) )
							continue;

						AC_MEMCPY( buf, ip.bv_val, ip.bv_len );
						buf[ ip.bv_len ] = '\0';

						addr = inet_addr( buf );

						/* unable to convert? */
						if ( addr == (unsigned long)(-1) )
							continue;

						if ( (addr & b->a_peername_mask) != b->a_peername_addr )
							continue;

#ifdef LDAP_PF_LOCAL
					/* extract path and try exact match */
					} else if ( b->a_peername_style == ACL_STYLE_PATH ) {
						struct berval path;
						
						if ( strncmp( op->o_conn->c_peer_name.bv_val,
									aci_bv_path_eq.bv_val, aci_bv_path_eq.bv_len ) != 0 )
							continue;

						path.bv_val = op->o_conn->c_peer_name.bv_val + aci_bv_path_eq.bv_len;
						path.bv_len = op->o_conn->c_peer_name.bv_len - aci_bv_path_eq.bv_len;

						if ( ber_bvcmp( &b->a_peername_pat, &path ) != 0 )
							continue;

#endif /* LDAP_PF_LOCAL */

					/* exact match (very unlikely...) */
					} else if ( ber_bvcmp( &op->o_conn->c_peer_name, &b->a_peername_pat ) != 0 ) {
							continue;
					}
				}
			}
		}

		if ( b->a_sockname_pat.bv_len ) {
			if ( !op->o_conn->c_sock_name.bv_val ) {
				continue;
			}
			Debug( LDAP_DEBUG_ACL, "<= check a_sockname_path: %s\n",
				b->a_sockname_pat.bv_val, 0, 0 );
			if ( !ber_bvccmp( &b->a_sockname_pat, '*' ) ) {
				if ( b->a_sockname_style == ACL_STYLE_REGEX) {
					if (!regex_matches( &b->a_sockname_pat, op->o_conn->c_sock_name.bv_val,
							e->e_ndn, matches ) ) 
					{
						continue;
					}

				} else if ( b->a_sockname_style == ACL_STYLE_EXPAND ) {
					struct berval	bv;
					char buf[ACL_BUF_SIZE];

					bv.bv_len = sizeof( buf ) - 1;
					bv.bv_val = buf;
					string_expand( &bv, &b->a_sockname_pat, e->e_ndn, matches );

					if ( ber_bvstrcasecmp( &bv, &op->o_conn->c_sock_name ) != 0 ) {
						continue;
					}

				} else {
					if ( ber_bvstrcasecmp( &b->a_sockname_pat, &op->o_conn->c_sock_name ) != 0 )
						continue;
				}
			}
		}

		if ( b->a_dn_at != NULL ) {
			Attribute	*at;
			struct berval	bv;
			int rc, match = 0;
			const char *text;
			const char *attr = b->a_dn_at->ad_cname.bv_val;

			assert( attr != NULL );

			if ( op->o_ndn.bv_len == 0 ) {
				continue;
			}

			Debug( LDAP_DEBUG_ACL, "<= check a_dn_at: %s\n",
				attr, 0, 0);
			bv = op->o_ndn;

			/* see if asker is listed in dnattr */
			for( at = attrs_find( e->e_attrs, b->a_dn_at );
				at != NULL;
				at = attrs_find( at->a_next, b->a_dn_at ) )
			{
				if( value_find_ex( b->a_dn_at,
					SLAP_MR_ATTRIBUTE_VALUE_NORMALIZED_MATCH |
						SLAP_MR_ASSERTED_VALUE_NORMALIZED_MATCH,
					at->a_nvals,
					&bv, op->o_tmpmemctx ) == 0 )
				{
					/* found it */
					match = 1;
					break;
				}
			}

			if( match ) {
				/* have a dnattr match. if this is a self clause then
				 * the target must also match the op dn.
				 */
				if ( b->a_dn_self ) {
					/* check if the target is an attribute. */
					if ( val == NULL ) continue;

					/* target is attribute, check if the attribute value
					 * is the op dn.
					 */
					rc = value_match( &match, b->a_dn_at,
						b->a_dn_at->ad_type->sat_equality, 0,
						val, &bv, &text );
					/* on match error or no match, fail the ACL clause */
					if (rc != LDAP_SUCCESS || match != 0 )
						continue;
				}
			} else {
				/* no dnattr match, check if this is a self clause */
				if ( ! b->a_dn_self )
					continue;

				ACL_RECORD_VALUE_STATE;
				
				/* this is a self clause, check if the target is an
				 * attribute.
				 */
				if ( val == NULL )
					continue;

				/* target is attribute, check if the attribute value
				 * is the op dn.
				 */
				rc = value_match( &match, b->a_dn_at,
					b->a_dn_at->ad_type->sat_equality, 0,
					val, &bv, &text );

				/* on match error or no match, fail the ACL clause */
				if (rc != LDAP_SUCCESS || match != 0 )
					continue;
			}
		}

		if ( b->a_group_pat.bv_len ) {
			struct berval bv;
			struct berval ndn = BER_BVNULL;
			int rc;

			if ( op->o_ndn.bv_len == 0 ) {
				continue;
			}

			/* b->a_group is an unexpanded entry name, expanded it should be an 
			 * entry with objectclass group* and we test to see if odn is one of
			 * the values in the attribute group
			 */
			/* see if asker is listed in dnattr */
			if ( b->a_group_style == ACL_STYLE_EXPAND ) {
				char buf[ACL_BUF_SIZE];
				bv.bv_len = sizeof(buf) - 1;
				bv.bv_val = buf; 

				string_expand( &bv, &b->a_group_pat, e->e_ndn, matches );
				if ( dnNormalize( 0, NULL, NULL, &bv, &ndn, op->o_tmpmemctx ) != LDAP_SUCCESS ) {
					/* did not expand to a valid dn */
					continue;
				}

				bv = ndn;

			} else {
				bv = b->a_group_pat;
			}

			rc = backend_group( op, e, &bv, &op->o_ndn,
				b->a_group_oc, b->a_group_at );

			if ( ndn.bv_val ) free( ndn.bv_val );

			if ( rc != 0 ) {
				continue;
			}
		}

		if ( b->a_set_pat.bv_len != 0 ) {
			struct berval bv;
			char buf[ACL_BUF_SIZE];
			if( b->a_set_style == ACL_STYLE_REGEX ){
				bv.bv_len = sizeof(buf) - 1;
				bv.bv_val = buf;
				string_expand( &bv, &b->a_set_pat, e->e_ndn, matches );
			}else{
				bv = b->a_set_pat;
			}
			if (aci_match_set( &bv, op, e, 0 ) == 0) {
				continue;
			}
		}

		if ( b->a_authz.sai_ssf ) {
			Debug( LDAP_DEBUG_ACL, "<= check a_authz.sai_ssf: ACL %u > OP %u\n",
				b->a_authz.sai_ssf, op->o_ssf, 0 );
			if ( b->a_authz.sai_ssf >  op->o_ssf ) {
				continue;
			}
		}

		if ( b->a_authz.sai_transport_ssf ) {
			Debug( LDAP_DEBUG_ACL,
				"<= check a_authz.sai_transport_ssf: ACL %u > OP %u\n",
				b->a_authz.sai_transport_ssf, op->o_transport_ssf, 0 );
			if ( b->a_authz.sai_transport_ssf >  op->o_transport_ssf ) {
				continue;
			}
		}

		if ( b->a_authz.sai_tls_ssf ) {
			Debug( LDAP_DEBUG_ACL,
				"<= check a_authz.sai_tls_ssf: ACL %u > OP %u\n",
				b->a_authz.sai_tls_ssf, op->o_tls_ssf, 0 );
			if ( b->a_authz.sai_tls_ssf >  op->o_tls_ssf ) {
				continue;
			}
		}

		if ( b->a_authz.sai_sasl_ssf ) {
			Debug( LDAP_DEBUG_ACL,
				"<= check a_authz.sai_sasl_ssf: ACL %u > OP %u\n",
				b->a_authz.sai_sasl_ssf, op->o_sasl_ssf, 0 );
			if ( b->a_authz.sai_sasl_ssf >	op->o_sasl_ssf ) {
				continue;
			}
		}

#ifdef SLAPD_ACI_ENABLED
		if ( b->a_aci_at != NULL ) {
			Attribute	*at;
			slap_access_t grant, deny, tgrant, tdeny;
			struct berval parent_ndn, old_parent_ndn;
			BerVarray bvals = NULL;
			int ret,stop;

			/* this case works different from the others above.
			 * since aci's themselves give permissions, we need
			 * to first check b->a_access_mask, the ACL's access level.
			 */

			if ( e->e_nname.bv_len == 0 ) {
				/* no ACIs in the root DSE */
				continue;
			}

			/* first check if the right being requested
			 * is allowed by the ACL clause.
			 */
			if ( ! ACL_GRANT( b->a_access_mask, *mask ) ) {
				continue;
			}
			/* start out with nothing granted, nothing denied */
			ACL_INIT(tgrant);
			ACL_INIT(tdeny);

			/* get the aci attribute */
			at = attr_find( e->e_attrs, b->a_aci_at );
			if ( at != NULL ) {
#if 0
				/* FIXME: this breaks acl caching;
				 * see also ACL_RECORD_VALUE_STATE below */
				ACL_RECORD_VALUE_STATE;
#endif
				/* the aci is an multi-valued attribute.  The
				* rights are determined by OR'ing the individual
				* rights given by the acis.
				*/
				for ( i = 0; !BER_BVISNULL( &at->a_nvals[i] ); i++ ) {
					if (aci_mask( op,
						e, desc, val,
						&at->a_nvals[i],
						matches, &grant, &deny,  &aci_bv_entry ) != 0)
					{
						tgrant |= grant;
						tdeny |= deny;
					}
				}
				Debug(LDAP_DEBUG_ACL, "<= aci_mask grant %s deny %s\n",
					  accessmask2str(tgrant,accessmaskbuf), 
					  accessmask2str(tdeny, accessmaskbuf1), 0);

			}
			/* If the entry level aci didn't contain anything valid for the 
			 * current operation, climb up the tree and evaluate the
			 * acis with scope set to subtree
			 */
			if( (tgrant == ACL_PRIV_NONE) && (tdeny == ACL_PRIV_NONE) ){
				dnParent(&(e->e_nname), &parent_ndn);
				while ( parent_ndn.bv_val != old_parent_ndn.bv_val ){
					old_parent_ndn = parent_ndn;
					Debug(LDAP_DEBUG_ACL, "checking ACI of %s\n", parent_ndn.bv_val, 0, 0);
					ret = backend_attribute(op, NULL, &parent_ndn, b->a_aci_at, &bvals, ACL_AUTH);
					switch(ret){
					case LDAP_SUCCESS :
						stop = 0;
						if (!bvals){
							break;
						}

						for( i = 0; bvals[i].bv_val != NULL; i++){
#if 0
							/* FIXME: this breaks acl caching;
							 * see also ACL_RECORD_VALUE_STATE above */
							ACL_RECORD_VALUE_STATE;
#endif
							if (aci_mask(op, e, desc, val, &bvals[i], matches,
									&grant, &deny, &aci_bv_children) != 0) {
								tgrant |= grant;
								tdeny |= deny;
								/* evaluation stops as soon as either a "deny" or a 
								 * "grant" directive matches.
								 */
								if( (tgrant != ACL_PRIV_NONE) || (tdeny != ACL_PRIV_NONE) ){
									stop = 1;
								}
							}
							Debug(LDAP_DEBUG_ACL, "<= aci_mask grant %s deny %s\n", 
								accessmask2str(tgrant,accessmaskbuf),
								accessmask2str(tdeny, accessmaskbuf1), 0);
						}
						break;

					case LDAP_NO_SUCH_ATTRIBUTE:
						/* just go on if the aci-Attribute is not present in
						 * the current entry 
						 */
						Debug(LDAP_DEBUG_ACL, "no such attribute\n", 0, 0, 0);
						stop = 0;
						break;

					case LDAP_NO_SUCH_OBJECT:
						/* We have reached the base object */
						Debug(LDAP_DEBUG_ACL, "no such object\n", 0, 0, 0);
						stop = 1;
						break;

					default:
						stop = 1;
						break;
					}
					if (stop){
						break;
					}
					dnParent(&old_parent_ndn, &parent_ndn);
				}
			}


			/* remove anything that the ACL clause does not allow */
			tgrant &= b->a_access_mask & ACL_PRIV_MASK;
			tdeny &= ACL_PRIV_MASK;

			/* see if we have anything to contribute */
			if( ACL_IS_INVALID(tgrant) && ACL_IS_INVALID(tdeny) ) { 
				continue;
			}

			/* this could be improved by changing acl_mask so that it can deal with
			 * by clauses that return grant/deny pairs.  Right now, it does either
			 * additive or subtractive rights, but not both at the same time.  So,
			 * we need to combine the grant/deny pair into a single rights mask in
			 * a smart way:	 if either grant or deny is "empty", then we use the
			 * opposite as is, otherwise we remove any denied rights from the grant
			 * rights mask and construct an additive mask.
			 */
			if (ACL_IS_INVALID(tdeny)) {
				modmask = tgrant | ACL_PRIV_ADDITIVE;

			} else if (ACL_IS_INVALID(tgrant)) {
				modmask = tdeny | ACL_PRIV_SUBSTRACTIVE;

			} else {
				modmask = (tgrant & ~tdeny) | ACL_PRIV_ADDITIVE;
			}

		} else
#endif
		{
			modmask = b->a_access_mask;
		}

		Debug( LDAP_DEBUG_ACL,
			"<= acl_mask: [%d] applying %s (%s)\n",
			i, accessmask2str( modmask, accessmaskbuf ), 
			b->a_type == ACL_CONTINUE
				? "continue"
				: b->a_type == ACL_BREAK
					? "break"
					: "stop" );
		/* save old mask */
		oldmask = *mask;

		if( ACL_IS_ADDITIVE(modmask) ) {
			/* add privs */
			ACL_PRIV_SET( *mask, modmask );

			/* cleanup */
			ACL_PRIV_CLR( *mask, ~ACL_PRIV_MASK );

		} else if( ACL_IS_SUBTRACTIVE(modmask) ) {
			/* substract privs */
			ACL_PRIV_CLR( *mask, modmask );

			/* cleanup */
			ACL_PRIV_CLR( *mask, ~ACL_PRIV_MASK );

		} else {
			/* assign privs */
			*mask = modmask;
		}

		Debug( LDAP_DEBUG_ACL,
			"<= acl_mask: [%d] mask: %s\n",
			i, accessmask2str(*mask, accessmaskbuf), 0 );

		if( b->a_type == ACL_CONTINUE ) {
			continue;

		} else if ( b->a_type == ACL_BREAK ) {
			return ACL_BREAK;

		} else {
			return ACL_STOP;
		}
	}

	/* implicit "by * none" clause */
	ACL_INIT(*mask);

	Debug( LDAP_DEBUG_ACL,
		"<= acl_mask: no more <who> clauses, returning %s (stop)\n",
		accessmask2str(*mask, accessmaskbuf), 0, 0 );
	return ACL_STOP;
}

/*
 * acl_check_modlist - check access control on the given entry to see if
 * it allows the given modifications by the user associated with op.
 * returns	1	if mods allowed ok
 *		0	mods not allowed
 */

int
acl_check_modlist(
	Operation	*op,
	Entry	*e,
	Modifications	*mlist
)
{
	struct berval *bv;
	AccessControlState state = ACL_STATE_INIT;
	Backend *be;
	int be_null = 0;
	int ret = 1; /* default is access allowed */

	be = op->o_bd;
	if ( be == NULL ) {
		be = &backends[0];
		be_null = 1;
		op->o_bd = be;
	}
	assert( be != NULL );

	/* short circuit root database access */
	if ( be_isroot( op ) ) {
		Debug( LDAP_DEBUG_ACL,
			"<= acl_access_allowed: granted to database root\n",
		    0, 0, 0 );
		goto done;
	}

	/* use backend default access if no backend acls */
	if( op->o_bd != NULL && op->o_bd->be_acl == NULL ) {
		Debug( LDAP_DEBUG_ACL,
			"=> access_allowed: backend default %s access %s to \"%s\"\n",
			access2str( ACL_WRITE ),
			op->o_bd->be_dfltaccess >= ACL_WRITE ? "granted" : "denied", op->o_dn.bv_val );
		ret = (op->o_bd->be_dfltaccess >= ACL_WRITE);
		goto done;
	}

	for ( ; mlist != NULL; mlist = mlist->sml_next ) {
		/*
		 * no-user-modification operational attributes are ignored
		 * by ACL_WRITE checking as any found here are not provided
		 * by the user
		 */
		if ( is_at_no_user_mod( mlist->sml_desc->ad_type ) ) {
			Debug( LDAP_DEBUG_ACL, "acl: no-user-mod %s:"
				" modify access granted\n",
				mlist->sml_desc->ad_cname.bv_val, 0, 0 );
			continue;
		}

		switch ( mlist->sml_op ) {
		case LDAP_MOD_REPLACE:
			/*
			 * We must check both permission to delete the whole
			 * attribute and permission to add the specific attributes.
			 * This prevents abuse from selfwriters.
			 */
			if ( ! access_allowed( op, e,
				mlist->sml_desc, NULL, ACL_WRITE, &state ) )
			{
				ret = 0;
				goto done;
			}

			if ( mlist->sml_values == NULL ) break;

			/* fall thru to check value to add */

		case LDAP_MOD_ADD:
			assert( mlist->sml_values != NULL );

			for ( bv = mlist->sml_nvalues
					? mlist->sml_nvalues : mlist->sml_values;
				bv->bv_val != NULL; bv++ )
			{
				if ( ! access_allowed( op, e,
					mlist->sml_desc, bv, ACL_WRITE, &state ) )
				{
					ret = 0;
					goto done;
				}
			}
			break;

		case LDAP_MOD_DELETE:
			if ( mlist->sml_values == NULL ) {
				if ( ! access_allowed( op, e,
					mlist->sml_desc, NULL, ACL_WRITE, NULL ) )
				{
					ret = 0;
					goto done;
				}
				break;
			}
			for ( bv = mlist->sml_nvalues
					? mlist->sml_nvalues : mlist->sml_values;
				bv->bv_val != NULL; bv++ )
			{
				if ( ! access_allowed( op, e,
					mlist->sml_desc, bv, ACL_WRITE, &state ) )
				{
					ret = 0;
					goto done;
				}
			}
			break;

		case SLAP_MOD_SOFTADD:
			/* allow adding attribute via modrdn thru */
			break;

		default:
			assert( 0 );
			/* not reached */
			ret = 0;
			break;
		}
	}

done:
	if (be_null) op->o_bd = NULL;
	return( ret );
}

static int
aci_get_part(
	struct berval *list,
	int ix,
	char sep,
	struct berval *bv )
{
	int len;
	char *p;

	if (bv) {
		BER_BVZERO( bv );
	}
	len = list->bv_len;
	p = list->bv_val;
	while (len >= 0 && --ix >= 0) {
		while (--len >= 0 && *p++ != sep) ;
	}
	while (len >= 0 && *p == ' ') {
		len--;
		p++;
	}
	if (len < 0)
		return(-1);

	if (!bv)
		return(0);

	bv->bv_val = p;
	while (--len >= 0 && *p != sep) {
		bv->bv_len++;
		p++;
	}
	while (bv->bv_len > 0 && *--p == ' ')
		bv->bv_len--;
	return(bv->bv_len);
}

BerVarray
aci_set_gather (SetCookie *cookie, struct berval *name, struct berval *attr)
{
	AciSetCookie *cp = (AciSetCookie *)cookie;
	BerVarray bvals = NULL;
	struct berval ndn;

	/* this routine needs to return the bervals instead of
	 * plain strings, since syntax is not known.  It should
	 * also return the syntax or some "comparison cookie".
	 */

	if (dnNormalize(0, NULL, NULL, name, &ndn, cp->op->o_tmpmemctx) == LDAP_SUCCESS) {
		const char *text;
		AttributeDescription *desc = NULL;
		if (slap_bv2ad(attr, &desc, &text) == LDAP_SUCCESS) {
			backend_attribute(cp->op,
				cp->e, &ndn, desc, &bvals, ACL_NONE);
		}
		slap_sl_free(ndn.bv_val, cp->op->o_tmpmemctx);
	}
	return(bvals);
}

static int
aci_match_set (
	struct berval *subj,
	Operation *op,
	Entry *e,
	int setref
)
{
	struct berval	set = BER_BVNULL;
	int		rc = 0;
	AciSetCookie	cookie;

	if (setref == 0) {
		ber_dupbv_x( &set, subj, op->o_tmpmemctx );
	} else {
		struct berval		subjdn, ndn = BER_BVNULL;
		struct berval		setat;
		BerVarray		bvals;
		const char		*text;
		AttributeDescription	*desc = NULL;

		/* format of string is "entry/setAttrName" */
		if ( aci_get_part( subj, 0, '/', &subjdn ) < 0 ) {
			return(0);
		}

		if ( aci_get_part( subj, 1, '/', &setat ) < 0 ) {
			setat = aci_bv_set_attr;
		}

		/*
		 * NOTE: dnNormalize honors the ber_len field
		 * as the length of the dn to be normalized
		 */
		if ( slap_bv2ad( &setat, &desc, &text ) == LDAP_SUCCESS ) {
			if ( dnNormalize( 0, NULL, NULL, &subjdn, &ndn, op->o_tmpmemctx ) == LDAP_SUCCESS )
			{
				backend_attribute( op, e, &ndn, desc, &bvals, ACL_NONE );
				if ( bvals != NULL && !BER_BVISNULL( &bvals[0] ) ) {
					int	i;

					set = bvals[0];
					BER_BVZERO( &bvals[0] );
					for ( i = 1; !BER_BVISNULL( &bvals[i] ); i++ )
						/* count */ ;
					bvals[0].bv_val = bvals[i-1].bv_val;
					BER_BVZERO( &bvals[i-1] );
				}
				ber_bvarray_free_x( bvals, op->o_tmpmemctx );
				slap_sl_free( ndn.bv_val, op->o_tmpmemctx );
			}
		}
	}

	if ( !BER_BVISNULL( &set ) ) {
		cookie.op = op;
		cookie.e = e;
		rc = ( slap_set_filter( aci_set_gather, (SetCookie *)&cookie, &set,
			&op->o_ndn, &e->e_nname, NULL ) > 0 );
		slap_sl_free( set.bv_val, op->o_tmpmemctx );
	}

	return(rc);
}

#ifdef SLAPD_ACI_ENABLED
static int
aci_list_map_rights(
	struct berval *list )
{
	struct berval bv;
	slap_access_t mask;
	int i;

	ACL_INIT(mask);
	for (i = 0; aci_get_part(list, i, ',', &bv) >= 0; i++) {
		if (bv.bv_len <= 0)
			continue;
		switch (*bv.bv_val) {
		case 'c':
			ACL_PRIV_SET(mask, ACL_PRIV_COMPARE);
			break;
		case 's':
			/* **** NOTE: draft-ietf-ldapext-aci-model-0.3.txt defines
			 * the right 's' to mean "set", but in the examples states
			 * that the right 's' means "search".  The latter definition
			 * is used here.
			 */
			ACL_PRIV_SET(mask, ACL_PRIV_SEARCH);
			break;
		case 'r':
			ACL_PRIV_SET(mask, ACL_PRIV_READ);
			break;
		case 'w':
			ACL_PRIV_SET(mask, ACL_PRIV_WRITE);
			break;
		case 'x':
			/* **** NOTE: draft-ietf-ldapext-aci-model-0.3.txt does not 
			 * define any equivalent to the AUTH right, so I've just used
			 * 'x' for now.
			 */
			ACL_PRIV_SET(mask, ACL_PRIV_AUTH);
			break;
		default:
			break;
		}

	}
	return(mask);
}

static int
aci_list_has_attr(
	struct berval *list,
	const struct berval *attr,
	struct berval *val )
{
	struct berval bv, left, right;
	int i;

	for (i = 0; aci_get_part(list, i, ',', &bv) >= 0; i++) {
		if (aci_get_part(&bv, 0, '=', &left) < 0
			|| aci_get_part(&bv, 1, '=', &right) < 0)
		{
			if (ber_bvstrcasecmp(attr, &bv) == 0)
				return(1);
		} else if (val == NULL) {
			if (ber_bvstrcasecmp(attr, &left) == 0)
				return(1);
		} else {
			if (ber_bvstrcasecmp(attr, &left) == 0) {
				/* this is experimental code that implements a
				 * simple (prefix) match of the attribute value.
				 * the ACI draft does not provide for aci's that
				 * apply to specific values, but it would be
				 * nice to have.  If the <attr> part of an aci's
				 * rights list is of the form <attr>=<value>,
				 * that means the aci applies only to attrs with
				 * the given value.  Furthermore, if the attr is
				 * of the form <attr>=<value>*, then <value> is
				 * treated as a prefix, and the aci applies to 
				 * any value with that prefix.
				 *
				 * Ideally, this would allow r.e. matches.
				 */
				if (aci_get_part(&right, 0, '*', &left) < 0
					|| right.bv_len <= left.bv_len)
				{
					if (ber_bvstrcasecmp(val, &right) == 0)
						return(1);
				} else if (val->bv_len >= left.bv_len) {
					if (strncasecmp( val->bv_val, left.bv_val, left.bv_len ) == 0)
						return(1);
				}
			}
		}
	}
	return(0);
}

static slap_access_t
aci_list_get_attr_rights(
	struct berval *list,
	const struct berval *attr,
	struct berval *val )
{
    struct berval bv;
    slap_access_t mask;
    int i;

	/* loop through each rights/attr pair, skip first part (action) */
	ACL_INIT(mask);
	for (i = 1; aci_get_part(list, i + 1, ';', &bv) >= 0; i += 2) {
		if (aci_list_has_attr(&bv, attr, val) == 0)
			continue;
		if (aci_get_part(list, i, ';', &bv) < 0)
			continue;
		mask |= aci_list_map_rights(&bv);
	}
	return(mask);
}

static int
aci_list_get_rights(
	struct berval *list,
	const struct berval *attr,
	struct berval *val,
	slap_access_t *grant,
	slap_access_t *deny )
{
    struct berval perm, actn;
    slap_access_t *mask;
    int i, found;

	if (attr == NULL || attr->bv_len == 0 
			|| ber_bvstrcasecmp( attr, &aci_bv_entry ) == 0) {
		attr = &aci_bv_br_entry;
	}

	found = 0;
	ACL_INIT(*grant);
	ACL_INIT(*deny);
	/* loop through each permissions clause */
	for (i = 0; aci_get_part(list, i, '$', &perm) >= 0; i++) {
		if (aci_get_part(&perm, 0, ';', &actn) < 0)
			continue;
		if (ber_bvstrcasecmp( &aci_bv_grant, &actn ) == 0) {
			mask = grant;
		} else if (ber_bvstrcasecmp( &aci_bv_deny, &actn ) == 0) {
			mask = deny;
		} else {
			continue;
		}

		found = 1;
		*mask |= aci_list_get_attr_rights(&perm, attr, val);
		*mask |= aci_list_get_attr_rights(&perm, &aci_bv_br_all, NULL);
	}
	return(found);
}

static int
aci_group_member (
	struct berval *subj,
	struct berval *defgrpoc,
	struct berval *defgrpat,
	Operation		*op,
	Entry		*e,
	regmatch_t	*matches
)
{
	struct berval subjdn;
	struct berval grpoc;
	struct berval grpat;
	ObjectClass *grp_oc = NULL;
	AttributeDescription *grp_ad = NULL;
	const char *text;
	int rc;

	/* format of string is "group/objectClassValue/groupAttrName" */
	if (aci_get_part(subj, 0, '/', &subjdn) < 0) {
		return(0);
	}

	if (aci_get_part(subj, 1, '/', &grpoc) < 0) {
		grpoc = *defgrpoc;
	}

	if (aci_get_part(subj, 2, '/', &grpat) < 0) {
		grpat = *defgrpat;
	}

	rc = slap_bv2ad( &grpat, &grp_ad, &text );
	if( rc != LDAP_SUCCESS ) {
		rc = 0;
		goto done;
	}
	rc = 0;

	grp_oc = oc_bvfind( &grpoc );

	if (grp_oc != NULL && grp_ad != NULL ) {
		char buf[ACL_BUF_SIZE];
		struct berval bv, ndn;
		bv.bv_len = sizeof( buf ) - 1;
		bv.bv_val = (char *)&buf;
		string_expand(&bv, &subjdn, e->e_ndn, matches);
		if ( dnNormalize(0, NULL, NULL, &bv, &ndn, op->o_tmpmemctx) == LDAP_SUCCESS ) {
			rc = (backend_group(op, e, &ndn, &op->o_ndn,
				grp_oc, grp_ad) == 0);
			free( ndn.bv_val );
		}
	}

done:
	return(rc);
}

static int
aci_mask(
    Operation		*op,
    Entry			*e,
	AttributeDescription *desc,
    struct berval	*val,
    struct berval	*aci,
	regmatch_t		*matches,
	slap_access_t	*grant,
	slap_access_t	*deny,
	struct berval	*scope
)
{
    struct berval bv, perms, sdn;
	int rc;
		

	assert( desc->ad_cname.bv_val != NULL );

	/* parse an aci of the form:
		oid#scope#action;rights;attr;rights;attr$action;rights;attr;rights;attr#dnType#subjectDN

	   See draft-ietf-ldapext-aci-model-04.txt section 9.1 for
	   a full description of the format for this attribute.
	   Differences: "this" in the draft is "self" here, and
	   "self" and "public" is in the position of dnType.

	   For now, this routine only supports scope=entry.
	 */
	/* check that the aci has all 5 components */
	if (aci_get_part(aci, 4, '#', NULL) < 0)
		return(0);

	/* check that the aci family is supported */
	if (aci_get_part(aci, 0, '#', &bv) < 0)
		return(0);

	/* check that the scope matches */
	if (aci_get_part(aci, 1, '#', &bv) < 0
		|| ber_bvstrcasecmp( scope, &bv ) != 0)
	{
		return(0);
	}

	/* get the list of permissions clauses, bail if empty */
	if (aci_get_part(aci, 2, '#', &perms) <= 0)
		return(0);

	/* check if any permissions allow desired access */
	if (aci_list_get_rights(&perms, &desc->ad_cname, val, grant, deny) == 0)
		return(0);

	/* see if we have a DN match */
	if (aci_get_part(aci, 3, '#', &bv) < 0)
		return(0);

	if (aci_get_part(aci, 4, '#', &sdn) < 0)
		return(0);

	if (ber_bvstrcasecmp( &aci_bv_access_id, &bv ) == 0) {
		struct berval ndn;
		rc = 0;
		if ( dnNormalize(0, NULL, NULL, &sdn, &ndn, op->o_tmpmemctx) == LDAP_SUCCESS ) {
			if (dn_match( &op->o_ndn, &ndn))
				rc = 1;
			free(ndn.bv_val);
		}
		return (rc);

	} else if (ber_bvstrcasecmp( &aci_bv_public, &bv ) == 0) {
		return(1);

	} else if (ber_bvstrcasecmp( &aci_bv_self, &bv ) == 0) {
		if (dn_match(&op->o_ndn, &e->e_nname))
			return(1);

	} else if (ber_bvstrcasecmp( &aci_bv_dnattr, &bv ) == 0) {
		Attribute *at;
		AttributeDescription *ad = NULL;
		const char *text;

		rc = slap_bv2ad( &sdn, &ad, &text );

		if( rc != LDAP_SUCCESS ) {
			return 0;
		}

		rc = 0;

		bv = op->o_ndn;

		for(at = attrs_find( e->e_attrs, ad );
			at != NULL;
			at = attrs_find( at->a_next, ad ) )
		{
			if (value_find_ex( ad,
				SLAP_MR_ATTRIBUTE_VALUE_NORMALIZED_MATCH |
					SLAP_MR_ASSERTED_VALUE_NORMALIZED_MATCH,
				at->a_nvals,
				&bv, op->o_tmpmemctx) == 0 )
			{
				rc = 1;
				break;
			}
		}

		return rc;


	} else if (ber_bvstrcasecmp( &aci_bv_group, &bv ) == 0) {
		if (aci_group_member(&sdn, &aci_bv_group_class, &aci_bv_group_attr, op, e, matches))
			return(1);

	} else if (ber_bvstrcasecmp( &aci_bv_role, &bv ) == 0) {
		if (aci_group_member(&sdn, &aci_bv_role_class, &aci_bv_role_attr, op, e, matches))
			return(1);

	} else if (ber_bvstrcasecmp( &aci_bv_set, &bv ) == 0) {
		if (aci_match_set(&sdn, op, e, 0))
			return(1);

	} else if (ber_bvstrcasecmp( &aci_bv_set_ref, &bv ) == 0) {
		if (aci_match_set(&sdn, op, e, 1))
			return(1);

	}

	return(0);
}

#endif	/* SLAPD_ACI_ENABLED */

static void
string_expand(
	struct berval *bv,
	struct berval *pat,
	char *match,
	regmatch_t *matches)
{
	ber_len_t	size;
	char   *sp;
	char   *dp;
	int	flag;

	size = 0;
	bv->bv_val[0] = '\0';
	bv->bv_len--; /* leave space for lone $ */

	flag = 0;
	for ( dp = bv->bv_val, sp = pat->bv_val; size < bv->bv_len &&
		sp < pat->bv_val + pat->bv_len ; sp++ )
	{
		/* did we previously see a $ */
		if ( flag ) {
			if ( flag == 1 && *sp == '$' ) {
				*dp++ = '$';
				size++;
				flag = 0;

			} else if ( flag == 1 && *sp == '{' /*'}'*/) {
				flag = 2;

			} else if ( *sp >= '0' && *sp <= '9' ) {
				int	n;
				int	i;
				int	l;

				n = *sp - '0';

				if ( flag == 2 ) {
					for ( sp++; *sp != '\0' && *sp != /*'{'*/ '}'; sp++ ) {
						if ( *sp >= '0' && *sp <= '9' ) {
							n = 10*n + ( *sp - '0' );
						}
					}

					if ( *sp != /*'{'*/ '}' ) {
						/* error */
					}
				}

				if ( n >= MAXREMATCHES ) {
				
				}
				
				*dp = '\0';
				i = matches[n].rm_so;
				l = matches[n].rm_eo; 
				for ( ; size < bv->bv_len && i < l; size++, i++ ) {
					*dp++ = match[i];
				}
				*dp = '\0';

				flag = 0;
			}
		} else {
			if (*sp == '$') {
				flag = 1;
			} else {
				*dp++ = *sp;
				size++;
			}
		}
	}

	if ( flag ) {
		/* must have ended with a single $ */
		*dp++ = '$';
		size++;
	}

	*dp = '\0';
	bv->bv_len = size;

	Debug( LDAP_DEBUG_TRACE, "=> string_expand: pattern:  %.*s\n", (int)pat->bv_len, pat->bv_val, 0 );
	Debug( LDAP_DEBUG_TRACE, "=> string_expand: expanded: %s\n", bv->bv_val, 0, 0 );
}

static int
regex_matches(
	struct berval *pat,			/* pattern to expand and match against */
	char *str,				/* string to match against pattern */
	char *buf,				/* buffer with $N expansion variables */
	regmatch_t *matches		/* offsets in buffer for $N expansion variables */
)
{
	regex_t re;
	char newbuf[ACL_BUF_SIZE];
	struct berval bv;
	int	rc;

	bv.bv_len = sizeof(newbuf) - 1;
	bv.bv_val = newbuf;

	if(str == NULL) str = "";

	string_expand(&bv, pat, buf, matches);
	if (( rc = regcomp(&re, newbuf, REG_EXTENDED|REG_ICASE))) {
		char error[ACL_BUF_SIZE];
		regerror(rc, &re, error, sizeof(error));

		Debug( LDAP_DEBUG_TRACE,
		    "compile( \"%s\", \"%s\") failed %s\n",
			pat->bv_val, str, error );
		return( 0 );
	}

	rc = regexec(&re, str, 0, NULL, 0);
	regfree( &re );

	Debug( LDAP_DEBUG_TRACE,
	    "=> regex_matches: string:	 %s\n", str, 0, 0 );
	Debug( LDAP_DEBUG_TRACE,
	    "=> regex_matches: rc: %d %s\n",
		rc, !rc ? "matches" : "no matches", 0 );
	return( !rc );
}

