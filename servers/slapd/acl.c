/* acl.c - routines to parse and check acl's */
/* $OpenLDAP$ */
/*
 * Copyright 1998-2000 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "portable.h"

#include <stdio.h>

#include <ac/regex.h>
#include <ac/socket.h>
#include <ac/string.h>

#include "slap.h"
#include "sets.h"

static AccessControl * acl_get(
	AccessControl *ac, int *count,
	Backend *be, Operation *op,
	Entry *e,
	AttributeDescription *desc,
	int nmatches, regmatch_t *matches );

static slap_control_t acl_mask(
	AccessControl *ac, slap_access_mask_t *mask,
	Backend *be, Connection *conn, Operation *op,
	Entry *e,
	AttributeDescription *desc,
	struct berval *val,
	regmatch_t *matches );

#ifdef SLAPD_ACI_ENABLED
static int aci_mask(
	Backend *be,
    Connection *conn,
	Operation *op,
	Entry *e,
	AttributeDescription *desc,
	struct berval *val,
	struct berval *aci,
	regmatch_t *matches,
	slap_access_t *grant,
	slap_access_t *deny );
#endif

static int	regex_matches(
	char *pat, char *str, char *buf, regmatch_t *matches);
static void	string_expand(
	char *newbuf, int bufsiz, char *pattern,
	char *match, regmatch_t *matches);

char **aci_set_gather (void *cookie, char *name, char *attr);
static int aci_match_set ( struct berval *subj, Backend *be,
    Entry *e, Connection *conn, Operation *op, int setref );

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
 */

int
access_allowed(
    Backend		*be,
    Connection		*conn,
    Operation		*op,
    Entry		*e,
	AttributeDescription	*desc,
    struct berval	*val,
    slap_access_t	access )
{
	int				count;
	AccessControl	*a;
#ifdef LDAP_DEBUG
	char accessmaskbuf[ACCESSMASK_MAXLEN];
#endif
	slap_access_mask_t mask;
	slap_control_t control;

	const char *attr = desc ? desc->ad_cname->bv_val : NULL;

	regmatch_t       matches[MAXREMATCHES];

	Debug( LDAP_DEBUG_ACL,
		"=> access_allowed: %s access to \"%s\" \"%s\" requested\n",
	    access2str( access ),
		e->e_dn, attr );

	assert( be != NULL );
	assert( e != NULL );
	assert( attr != NULL );
	assert( access > ACL_NONE );

	/* grant database root access */
	if ( be != NULL && be_isroot( be, op->o_ndn ) ) {
		Debug( LDAP_DEBUG_ACL,
		    "<= root access granted\n",
			0, 0, 0 );
		return 1;
	}

	/*
	 * no-user-modification operational attributes are ignored
	 * by ACL_WRITE checking as any found here are not provided
	 * by the user
	 */
	if ( access >= ACL_WRITE && is_at_no_user_mod( desc->ad_type ) )
	{
 		Debug( LDAP_DEBUG_ACL, "NoUserMod Operational attribute:"
			" %s access granted\n",
			attr, 0, 0 );
		return 1;
	}

	/* use backend default access if no backend acls */
	if( be != NULL && be->be_acl == NULL ) {
		Debug( LDAP_DEBUG_ACL,
			"=> access_allowed: backend default %s access %s to \"%s\"\n",
			access2str( access ),
			be->be_dfltaccess >= access ? "granted" : "denied", op->o_dn );

		return be->be_dfltaccess >= access;

#ifdef notdef
	/* be is always non-NULL */
	/* use global default access if no global acls */
	} else if ( be == NULL && global_acl == NULL ) {
		Debug( LDAP_DEBUG_ACL,
			"=> access_allowed: global default %s access %s to \"%s\"\n",
			access2str( access ),
			global_default_access >= access ? "granted" : "denied", op->o_dn );

		return global_default_access >= access;
#endif
	}

	ACL_INIT(mask);
	memset(matches, '\0', sizeof(matches));
	
	control = ACL_BREAK;
	a = NULL;
	count = 0;

	while( a = acl_get( a, &count, be, op, e, desc, MAXREMATCHES, matches ) )
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

		control = acl_mask( a, &mask, be, conn, op,
			e, desc, val, matches );

		if ( control != ACL_BREAK ) {
			break;
		}

		memset(matches, '\0', sizeof(matches));
	}

	if ( ACL_IS_INVALID( mask ) ) {
		Debug( LDAP_DEBUG_ACL,
			"=> access_allowed: \"%s\" (%s) invalid!\n",
			e->e_dn, attr, 0 );
		ACL_INIT( mask );

	} else if ( control == ACL_BREAK ) {
		Debug( LDAP_DEBUG_ACL,
			"=> access_allowed: no more rules\n", 0, 0, 0);
		ACL_INIT( mask );
	}

	Debug( LDAP_DEBUG_ACL,
		"=> access_allowed: %s access %s by %s\n",
		access2str( access ),
		ACL_GRANT(mask, access) ? "granted" : "denied",
		accessmask2str( mask, accessmaskbuf ) );

	return ACL_GRANT(mask, access);
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
    Backend		*be,
    Operation	*op,
    Entry		*e,
	AttributeDescription *desc,
    int			nmatch,
    regmatch_t	*matches )
{
	const char *attr;
	int dnlen, patlen;

	assert( e != NULL );
	assert( count != NULL );

	attr = desc ? desc->ad_cname->bv_val : NULL;

	if( a == NULL ) {
		if( be == NULL ) {
			a = global_acl;
		} else {
			a = be->be_acl;
		}

		assert( a != NULL );

	} else {
		a = a->acl_next;
	}

	dnlen = strlen(e->e_ndn);

	for ( ; a != NULL; a = a->acl_next ) {
		(*count) ++;

		if (a->acl_dn_pat != NULL) {
			if ( a->acl_dn_style == ACL_STYLE_REGEX ) {
				Debug( LDAP_DEBUG_ACL, "=> dnpat: [%d] %s nsub: %d\n", 
					*count, a->acl_dn_pat, (int) a->acl_dn_re.re_nsub );

				if (regexec(&a->acl_dn_re, e->e_ndn, nmatch, matches, 0))
					continue;

			} else {
				Debug( LDAP_DEBUG_ACL, "=> dn: [%d] %s\n", 
					*count, a->acl_dn_pat, 0 );

				patlen = strlen( a->acl_dn_pat );
				if ( dnlen < patlen )
					continue;

				if ( a->acl_dn_style == ACL_STYLE_BASE ) {
					/* base dn -- entire object DN must match */
					if ( dnlen != patlen )
						continue;

				} else if ( a->acl_dn_style == ACL_STYLE_ONE ) {
					char *rdn;
					int rdnlen = -1;

					if ( dnlen <= patlen )
						continue;

					if ( e->e_ndn[dnlen - patlen - 1] != ',' )
						continue;

					rdn = dn_rdn( NULL, e->e_ndn );
					if ( rdn != NULL ) {
						rdnlen = strlen( rdn );
						ch_free( rdn );
					}
					if ( rdnlen != dnlen - patlen - 1 )
						continue;

				} else if ( a->acl_dn_style == ACL_STYLE_SUBTREE ) {
					if ( dnlen > patlen && e->e_ndn[dnlen - patlen - 1] != ',' )
						continue;

				} else if ( a->acl_dn_style == ACL_STYLE_CHILDREN ) {
					if ( dnlen <= patlen )
						continue;
					if ( e->e_ndn[dnlen - patlen - 1] != ',' )
						continue;
				}

				if ( strcmp( a->acl_dn_pat, e->e_ndn + dnlen - patlen ) != 0 )
					continue;
			}

			Debug( LDAP_DEBUG_ACL, "=> acl_get: [%d] matched\n",
				*count, 0, 0 );
		}

		if ( a->acl_filter != NULL ) {
			ber_int_t rc = test_filter( NULL, NULL, NULL, e, a->acl_filter );
			if ( rc != LDAP_COMPARE_TRUE ) {
				continue;
			}
		}

        Debug( LDAP_DEBUG_ACL, "=> acl_get: [%d] check attr %s\n",
			*count, attr, 0);

		if ( attr == NULL || a->acl_attrs == NULL ||
			ad_inlist( desc, a->acl_attrs ) )
		{
			Debug( LDAP_DEBUG_ACL,
				"<= acl_get: [%d] acl %s attr: %s\n",
				*count, e->e_dn, attr );
			return a;
		}
		matches[0].rm_so = matches[0].rm_eo = -1;
	}

	Debug( LDAP_DEBUG_ACL, "<= acl_get: done.\n", 0, 0, 0 );
	return( NULL );
}


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
	slap_access_mask_t *mask,
    Backend		*be,
    Connection	*conn,
    Operation	*op,
    Entry		*e,
	AttributeDescription *desc,
    struct berval	*val,
	regmatch_t	*matches
)
{
	int		i, odnlen, patlen;
	Access	*b;
#ifdef LDAP_DEBUG
	char accessmaskbuf[ACCESSMASK_MAXLEN];
#endif
	const char *attr = desc ? desc->ad_cname->bv_val : NULL;

	assert( a != NULL );
	assert( mask != NULL );

	Debug( LDAP_DEBUG_ACL,
		"=> acl_mask: access to entry \"%s\", attr \"%s\" requested\n",
		e->e_dn, attr, 0 );

	Debug( LDAP_DEBUG_ACL,
		"=> acl_mask: to value \"%s\" by \"%s\", (%s) \n",
		val ? val->bv_val : "*",
		op->o_ndn ?  op->o_ndn : "",
		accessmask2str( *mask, accessmaskbuf ) );

	for ( i = 1, b = a->acl_access; b != NULL; b = b->a_next, i++ ) {
		slap_access_mask_t oldmask, modmask;

		ACL_INVALIDATE( modmask );

		/* AND <who> clauses */
		if ( b->a_dn_pat != NULL ) {
			Debug( LDAP_DEBUG_ACL, "<= check a_dn_pat: %s\n",
				b->a_dn_pat, 0, 0);
			/*
			 * if access applies to the entry itself, and the
			 * user is bound as somebody in the same namespace as
			 * the entry, OR the given dn matches the dn pattern
			 */
			if ( strcmp( b->a_dn_pat, "anonymous" ) == 0 ) {
				if (op->o_ndn != NULL && op->o_ndn[0] != '\0' ) {
					continue;
				}

			} else if ( strcmp( b->a_dn_pat, "users" ) == 0 ) {
				if (op->o_ndn == NULL || op->o_ndn[0] == '\0' ) {
					continue;
				}

			} else if ( strcmp( b->a_dn_pat, "self" ) == 0 ) {
				if( op->o_ndn == NULL || op->o_ndn[0] == '\0' ) {
					continue;
				}
				
				if ( e->e_dn == NULL || strcmp( e->e_ndn, op->o_ndn ) != 0 ) {
					continue;
				}

			} else if ( b->a_dn_style == ACL_STYLE_REGEX ) {
				if ( strcmp( b->a_dn_pat, "*" ) != 0 ) {
					int ret = regex_matches( b->a_dn_pat,
						op->o_ndn, e->e_ndn, matches );

					if( ret == 0 ) {
						continue;
					}
				}

			} else {
				if ( e->e_dn == NULL )
					continue;

				patlen = strlen( b->a_dn_pat );
				odnlen = strlen( op->o_ndn );
				if ( odnlen < patlen )
					continue;

				if ( b->a_dn_style == ACL_STYLE_BASE ) {
					/* base dn -- entire object DN must match */
					if ( odnlen != patlen )
						continue;

				} else if ( b->a_dn_style == ACL_STYLE_ONE ) {
					char *rdn;
					int rdnlen = -1;

					if ( odnlen <= patlen )
						continue;

					if ( op->o_ndn[odnlen - patlen - 1] != ',' )
						continue;

					rdn = dn_rdn( NULL, op->o_ndn );
					if ( rdn != NULL ) {
						rdnlen = strlen( rdn );
						ch_free( rdn );
					}
					if ( rdnlen != odnlen - patlen - 1 )
						continue;

				} else if ( b->a_dn_style == ACL_STYLE_SUBTREE ) {
					if ( odnlen > patlen && op->o_ndn[odnlen - patlen - 1] != ',' )
						continue;

				} else if ( b->a_dn_style == ACL_STYLE_CHILDREN ) {
					if ( odnlen <= patlen )
						continue;
					if ( op->o_ndn[odnlen - patlen - 1] != ',' )
						continue;
				}

				if ( strcmp( b->a_dn_pat, op->o_ndn + odnlen - patlen ) != 0 )
					continue;

			}
		}

		if ( b->a_sockurl_pat != NULL ) {
			Debug( LDAP_DEBUG_ACL, "<= check a_sockurl_pat: %s\n",
				b->a_sockurl_pat, 0, 0 );

			if ( strcmp( b->a_sockurl_pat, "*" ) != 0) {
				if ( b->a_sockurl_style == ACL_STYLE_REGEX) {
					if (!regex_matches( b->a_sockurl_pat, conn->c_listener_url,
							e->e_ndn, matches ) ) 
					{
						continue;
					}
				} else {
					if ( strcasecmp( b->a_sockurl_pat, conn->c_listener_url ) == 0 )
						continue;
				}
			}
		}

		if ( b->a_domain_pat != NULL ) {
			Debug( LDAP_DEBUG_ACL, "<= check a_domain_pat: %s\n",
				b->a_domain_pat, 0, 0 );

			if ( strcmp( b->a_domain_pat, "*" ) != 0) {
				if ( b->a_domain_style == ACL_STYLE_REGEX) {
					if (!regex_matches( b->a_domain_pat, conn->c_peer_domain,
							e->e_ndn, matches ) ) 
					{
						continue;
					}
				} else {
					if ( strcasecmp( b->a_domain_pat, conn->c_peer_domain ) == 0 )
						continue;
				}
			}
		}

		if ( b->a_peername_pat != NULL ) {
			Debug( LDAP_DEBUG_ACL, "<= check a_peername_path: %s\n",
				b->a_peername_pat, 0, 0 );

			if ( strcmp( b->a_peername_pat, "*" ) != 0) {
				if ( b->a_peername_style == ACL_STYLE_REGEX) {
					if (!regex_matches( b->a_peername_pat, conn->c_peer_name,
							e->e_ndn, matches ) ) 
					{
						continue;
					}
				} else {
					if ( strcasecmp( b->a_peername_pat, conn->c_peer_name ) == 0 )
						continue;
				}
			}
		}

		if ( b->a_sockname_pat != NULL ) {
			Debug( LDAP_DEBUG_ACL, "<= check a_sockname_path: %s\n",
				b->a_sockname_pat, 0, 0 );

			if ( strcmp( b->a_sockname_pat, "*" ) != 0) {
				if ( b->a_sockname_style == ACL_STYLE_REGEX) {
					if (!regex_matches( b->a_sockname_pat, conn->c_sock_name,
							e->e_ndn, matches ) ) 
					{
						continue;
					}
				} else {
					if ( strcasecmp( b->a_sockname_pat, conn->c_sock_name ) == 0 )
						continue;
				}
			}
		}

		if ( b->a_dn_at != NULL && op->o_ndn != NULL ) {
			Attribute	*at;
			struct berval	bv;
			int rc, match = 0;
			const char *text;
			const char *desc = b->a_dn_at->ad_cname->bv_val;

			Debug( LDAP_DEBUG_ACL, "<= check a_dn_at: %s\n",
				desc, 0, 0);

			bv.bv_val = op->o_ndn;
			bv.bv_len = strlen( bv.bv_val );

			/* see if asker is listed in dnattr */
			for( at = attrs_find( e->e_attrs, b->a_dn_at );
				at != NULL;
				at = attrs_find( at->a_next, b->a_dn_at ) )
			{
				if( value_find( b->a_dn_at, at->a_vals, &bv ) == 0 ) {
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
			} else {
				/* no dnattr match, check if this is a self clause */
				if ( ! b->a_dn_self )
					continue;
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

		if ( b->a_group_pat != NULL && op->o_ndn != NULL ) {
			char buf[1024];

			/* b->a_group is an unexpanded entry name, expanded it should be an 
			 * entry with objectclass group* and we test to see if odn is one of
			 * the values in the attribute group
			 */
			/* see if asker is listed in dnattr */
			if ( b->a_group_style == ACL_STYLE_REGEX ) {
				string_expand(buf, sizeof(buf), b->a_group_pat, e->e_ndn, matches);
				if ( dn_normalize(buf) == NULL ) {
					/* did not expand to a valid dn */
					continue;
				}
			} else {
				strncpy( buf, b->a_group_pat, sizeof(buf) - 1 );
				buf[sizeof(buf) - 1] = 0;
			}

			if (backend_group(be, e, buf, op->o_ndn,
				b->a_group_oc, b->a_group_at) != 0)
			{
				continue;
			}
		}

		if ( b->a_set_pat != NULL ) {
			struct berval bv;

			bv.bv_val = b->a_set_pat;
			bv.bv_len = strlen(b->a_set_pat);
			if (aci_match_set( &bv, be, e, conn, op, 0 ) == 0) {
				continue;
			}
		}

#ifdef SLAPD_ACI_ENABLED
		if ( b->a_aci_at != NULL ) {
			Attribute	*at;
			slap_access_t grant, deny, tgrant, tdeny;

			/* this case works different from the others above.
			 * since aci's themselves give permissions, we need
			 * to first check b->a_mask, the ACL's access level.
			 */

			if( op->o_ndn == NULL || op->o_ndn[0] == '\0' ) {
				continue;
			}

			if ( e->e_dn == NULL ) {
				continue;
			}

			/* first check if the right being requested
			 * is allowed by the ACL clause.
			 */
			if ( ! ACL_GRANT( b->a_mask, *mask ) ) {
				continue;
			}

			/* get the aci attribute */
			at = attr_find( e->e_attrs, b->a_aci_at );
			if ( at == NULL ) {
				continue;
			}

			/* start out with nothing granted, nothing denied */
			ACL_INIT(tgrant);
			ACL_INIT(tdeny);

			/* the aci is an multi-valued attribute.  The
			 * rights are determined by OR'ing the individual
			 * rights given by the acis.
			 */
			for ( i = 0; at->a_vals[i] != NULL; i++ ) {
				if (aci_mask( be, conn, op,
					e, desc, val, at->a_vals[i],
					matches, &grant, &deny ) != 0)
				{
					tgrant |= grant;
					tdeny |= deny;
				}
			}

			/* remove anything that the ACL clause does not allow */
			tgrant &= b->a_mask & ACL_PRIV_MASK;
			tdeny &= ACL_PRIV_MASK;

			/* see if we have anything to contribute */
			if( ACL_IS_INVALID(tgrant) && ACL_IS_INVALID(tdeny) ) { 
				continue;
			}

			/* this could be improved by changing acl_mask so that it can deal with
			 * by clauses that return grant/deny pairs.  Right now, it does either
			 * additive or subtractive rights, but not both at the same time.  So,
			 * we need to combine the grant/deny pair into a single rights mask in
			 * a smart way:  if either grant or deny is "empty", then we use the
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
			modmask = b->a_mask;
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

	Debug( LDAP_DEBUG_ACL,
		"<= acl_mask: no more <who> clauses, returning %s (stop)\n",
		accessmask2str(*mask, accessmaskbuf), 0, 0 );
	return ACL_STOP;
}

/*
 * acl_check_modlist - check access control on the given entry to see if
 * it allows the given modifications by the user associated with op.
 * returns	1	if mods allowed ok
 *			0	mods not allowed
 */

int
acl_check_modlist(
    Backend	*be,
    Connection	*conn,
    Operation	*op,
    Entry	*e,
    Modifications	*mlist
)
{
	int		i;

	assert( be != NULL );

	/* short circuit root database access */
	if ( be_isroot( be, op->o_ndn ) ) {
		Debug( LDAP_DEBUG_ACL,
			"<= acl_access_allowed: granted to database root\n",
		    0, 0, 0 );
		return 1;
	}

	/* use backend default access if no backend acls */
	if( be != NULL && be->be_acl == NULL ) {
		Debug( LDAP_DEBUG_ACL,
			"=> access_allowed: backend default %s access %s to \"%s\"\n",
			access2str( ACL_WRITE ),
			be->be_dfltaccess >= ACL_WRITE ? "granted" : "denied", op->o_dn );

		return be->be_dfltaccess >= ACL_WRITE;

#ifdef notdef
	/* be is always non-NULL */
	/* use global default access if no global acls */
	} else if ( be == NULL && global_acl == NULL ) {
		Debug( LDAP_DEBUG_ACL,
			"=> access_allowed: global default %s access %s to \"%s\"\n",
			access2str( ACL_WRITE ),
			global_default_access >= ACL_WRITE ? "granted" : "denied", op->o_dn );

		return global_default_access >= ACL_WRITE;
#endif
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
				mlist->sml_desc->ad_cname->bv_val, 0, 0 );
			continue;
		}

		switch ( mlist->sml_op ) {
		case LDAP_MOD_REPLACE:
		case LDAP_MOD_ADD:
			if ( mlist->sml_bvalues == NULL ) {
				break;
			}
			for ( i = 0; mlist->sml_bvalues[i] != NULL; i++ ) {
				if ( ! access_allowed( be, conn, op, e,
					mlist->sml_desc, mlist->sml_bvalues[i], ACL_WRITE ) )
				{
					return( 0 );
				}
			}
			break;

		case LDAP_MOD_DELETE:
			if ( mlist->sml_bvalues == NULL ) {
				if ( ! access_allowed( be, conn, op, e,
					mlist->sml_desc, NULL, ACL_WRITE ) )
				{
					return( 0 );
				}
				break;
			}
			for ( i = 0; mlist->sml_bvalues[i] != NULL; i++ ) {
				if ( ! access_allowed( be, conn, op, e,
					mlist->sml_desc, mlist->sml_bvalues[i], ACL_WRITE ) )
				{
					return( 0 );
				}
			}
			break;
		}
	}

	return( 1 );
}

static char *
aci_bvstrdup( struct berval *bv )
{
	char *s;

	s = (char *)ch_malloc(bv->bv_len + 1);
	if (s != NULL) {
		memcpy(s, bv->bv_val, bv->bv_len);
		s[bv->bv_len] = 0;
	}
	return(s);
}

static int
aci_strbvcmp(
	const char *s,
	struct berval *bv )
{
	int res, len;

	res = strncasecmp( s, bv->bv_val, bv->bv_len );
	if (res)
		return(res);
	len = strlen(s);
	if (len > (int)bv->bv_len)
		return(1);
	if (len < (int)bv->bv_len)
		return(-1);
	return(0);
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
		bv->bv_len = 0;
		bv->bv_val = NULL;
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

char **
aci_set_gather (void *cookie, char *name, char *attr)
{
	struct {
    	Backend *be;
    	Entry *e;
    	Connection *conn;
    	Operation *op;
	} *cp = (void *)cookie;
	struct berval **bvals = NULL;
	char **vals = NULL;
	char *ndn;
	int i;

	/* this routine needs to return the bervals instead of
	 * plain strings, since syntax is not known.  It should
	 * also return the syntax or some "comparison cookie".
	 */

	if ((ndn = ch_strdup(name)) != NULL) {
		if (dn_normalize(ndn) != NULL) {
			const char *text;
			AttributeDescription *desc = NULL;
			if (slap_str2ad(attr, &desc, &text) == LDAP_SUCCESS) {
				backend_attribute(cp->be, NULL /*cp->conn*/,
									NULL /*cp->op*/, cp->e,
									ndn, desc, &bvals);
				if (bvals != NULL) {
					for (i = 0; bvals[i] != NULL; i++) { }
					vals = ch_calloc(i + 1, sizeof(char *));
					if (vals != NULL) {
						while (--i >= 0) {
							vals[i] = bvals[i]->bv_val;
							bvals[i]->bv_val = NULL;
						}
					}
					ber_bvecfree(bvals);
				}
				ad_free(desc, 1);
			}
		}
		ch_free(ndn);
	}
	return(vals);
}

static int
aci_match_set (
	struct berval *subj,
    Backend *be,
    Entry *e,
    Connection *conn,
    Operation *op,
    int setref
)
{
	char *set = NULL;
	int rc = 0;
	struct {
    	Backend *be;
    	Entry *e;
    	Connection *conn;
    	Operation *op;
	} cookie;

	if (setref == 0) {
		set = aci_bvstrdup(subj);
	} else {
		struct berval bv;
		char *subjdn;
		char *setat;
		struct berval **bvals;
		const char *text;
		AttributeDescription *desc = NULL;

		/* format of string is "entry/setAttrName" */
		if (aci_get_part(subj, 0, '/', &bv) < 0) {
			return(0);
		}

		subjdn = aci_bvstrdup(&bv);
		if ( subjdn == NULL ) {
			return(0);
		}

		if ( aci_get_part(subj, 1, '/', &bv) < 0 ) {
			setat = ch_strdup( SLAPD_ACI_SET_ATTR );
		} else {
			setat = aci_bvstrdup(&bv);
		}
		if ( setat != NULL ) {
			if ( dn_normalize(subjdn) != NULL
				&& slap_str2ad(setat, &desc, &text) == LDAP_SUCCESS )
			{
				backend_attribute(be, NULL, NULL, e,
								subjdn, desc, &bvals);
				ad_free(desc, 1);
				if ( bvals != NULL ) {
					if ( bvals[0] != NULL )
						set = ch_strdup(bvals[0]->bv_val);
					ber_bvecfree(bvals);
				}
			}
			ch_free(setat);
		}
		ch_free(subjdn);
	}

	if (set != NULL) {
		cookie.be = be;
		cookie.e = e;
		cookie.conn = conn;
		cookie.op = op;
		rc = (set_filter(aci_set_gather, &cookie, set, op->o_ndn, e->e_ndn, NULL) > 0);
		ch_free(set);
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
	const char *attr,
	struct berval *val )
{
	struct berval bv, left, right;
	int i;

	for (i = 0; aci_get_part(list, i, ',', &bv) >= 0; i++) {
		if (aci_get_part(&bv, 0, '=', &left) < 0
			|| aci_get_part(&bv, 1, '=', &right) < 0)
		{
			if (aci_strbvcmp(attr, &bv) == 0)
				return(1);
		} else if (val == NULL) {
			if (aci_strbvcmp(attr, &left) == 0)
				return(1);
		} else {
			if (aci_strbvcmp(attr, &left) == 0) {
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
					if (aci_strbvcmp(val->bv_val, &right) == 0)
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
	const char *attr,
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
	const char *attr,
	struct berval *val,
	slap_access_t *grant,
	slap_access_t *deny )
{
    struct berval perm, actn;
    slap_access_t *mask;
    int i, found;

	if (attr == NULL || *attr == 0 || strcasecmp(attr, "entry") == 0) {
		attr = "[entry]";
	}

	found = 0;
	ACL_INIT(*grant);
	ACL_INIT(*deny);
	/* loop through each permissions clause */
	for (i = 0; aci_get_part(list, i, '$', &perm) >= 0; i++) {
		if (aci_get_part(&perm, 0, ';', &actn) < 0)
			continue;
		if (aci_strbvcmp( "grant", &actn ) == 0) {
			mask = grant;
		} else if (aci_strbvcmp( "deny", &actn ) == 0) {
			mask = deny;
		} else {
			continue;
		}

		found = 1;
		*mask |= aci_list_get_attr_rights(&perm, attr, val);
		*mask |= aci_list_get_attr_rights(&perm, "[all]", NULL);
	}
	return(found);
}

static int
aci_group_member (
	struct berval *subj,
	const char *defgrpoc,
	const char *defgrpat,
    Backend		*be,
    Entry		*e,
    Operation		*op,
	regmatch_t	*matches
)
{
	struct berval bv;
	char *subjdn, *grpdn = NULL;
	char *grpoc;
	char *grpat;
	ObjectClass *grp_oc = NULL;
	AttributeDescription *grp_ad = NULL;
	char *text;
	int rc;

	/* format of string is "group/objectClassValue/groupAttrName" */
	if (aci_get_part(subj, 0, '/', &bv) < 0) {
		return(0);
	}

	subjdn = aci_bvstrdup(&bv);
	if (subjdn == NULL) {
		return(0);
	}

	if (aci_get_part(subj, 1, '/', &bv) < 0) {
		grpoc = ch_strdup( defgrpoc );
	} else {
		grpoc = aci_bvstrdup(&bv);
	}

	if (aci_get_part(subj, 2, '/', &bv) < 0) {
		grpat = ch_strdup( defgrpat );
	} else {
		grpat = aci_bvstrdup(&bv);
	}

	rc = slap_str2ad( grpat, &grp_ad, &text );
	if( rc != LDAP_SUCCESS ) {
		rc = 0;
		goto done;
	}
	rc = 0;

	grp_oc = oc_find( grpoc );
	grpdn = (char *)ch_malloc(1024);

	if (grp_oc != NULL && grp_ad != NULL && grpdn != NULL) {
		string_expand(grpdn, 1024, subjdn, e->e_ndn, matches);
		if ( dn_normalize(grpdn) != NULL ) {
			rc = (backend_group(be, e, grpdn, op->o_ndn, grp_oc, grp_ad) == 0);
		}
	}

done:
	if( grp_ad != NULL ) ad_free( grp_ad, 1 );
	ch_free(grpdn);
	ch_free(grpat);
	ch_free(grpoc);
	ch_free(subjdn);
	return(rc);
}

static int
aci_mask(
    Backend			*be,
    Connection		*conn,
    Operation		*op,
    Entry			*e,
	AttributeDescription *desc,
    struct berval	*val,
    struct berval	*aci,
	regmatch_t		*matches,
	slap_access_t	*grant,
	slap_access_t	*deny
)
{
    struct berval bv, perms, sdn;
    char *subjdn;
	int rc;
	char *attr = desc->ad_cname->bv_val;

	/* parse an aci of the form:
		oid#scope#action;rights;attr;rights;attr$action;rights;attr;rights;attr#dnType#subjectDN

	   See draft-ietf-ldapext-aci-model-04.txt section 9.1 for
	   a full description of the format for this attribute.

	   For now, this routine only supports scope=entry.
	 */

	/* check that the aci has all 5 components */
	if (aci_get_part(aci, 4, '#', NULL) < 0)
		return(0);

	/* check that the aci family is supported */
	if (aci_get_part(aci, 0, '#', &bv) < 0)
		return(0);

	/* check that the scope is "entry" */
	if (aci_get_part(aci, 1, '#', &bv) < 0
		|| aci_strbvcmp( "entry", &bv ) != 0)
	{
		return(0);
	}

	/* get the list of permissions clauses, bail if empty */
	if (aci_get_part(aci, 2, '#', &perms) <= 0)
		return(0);

	/* check if any permissions allow desired access */
	if (aci_list_get_rights(&perms, attr, val, grant, deny) == 0)
		return(0);

	/* see if we have a DN match */
	if (aci_get_part(aci, 3, '#', &bv) < 0)
		return(0);

	if (aci_get_part(aci, 4, '#', &sdn) < 0)
		return(0);

	if (aci_strbvcmp( "access-id", &bv ) == 0) {
		subjdn = aci_bvstrdup(&sdn);
		if (subjdn == NULL)
			return(0);
		rc = 1;
		if ( dn_normalize(subjdn) != NULL )
			if (strcasecmp(op->o_ndn, subjdn) != 0)
				rc = 0;
		ch_free(subjdn);
		return(rc);
	}

	if (aci_strbvcmp( "self", &bv ) == 0) {
		if (strcasecmp(op->o_ndn, e->e_ndn) == 0)
			return(1);

	} else if (aci_strbvcmp( "dnattr", &bv ) == 0) {
		char *dnattr = aci_bvstrdup(&sdn);
		Attribute *at;
		AttributeDescription *ad = NULL;
		const char *text;

		rc = slap_str2ad( dnattr, &ad, &text );
		ch_free( dnattr );

		if( rc != LDAP_SUCCESS ) {
			return 0;
		}

		rc = 0;

		bv.bv_val = op->o_ndn;
		bv.bv_len = strlen( bv.bv_val );

		for(at = attrs_find( e->e_attrs, ad );
			at != NULL;
			at = attrs_find( at->a_next, ad ) )
		{
			if (value_find( ad, at->a_vals, &bv) == 0 ) {
				rc = 1;
				break;
			}
		}

		ad_free( ad, 1 );
		return rc;


	} else if (aci_strbvcmp( "group", &bv ) == 0) {
		if (aci_group_member(&sdn, SLAPD_GROUP_CLASS, SLAPD_GROUP_ATTR, be, e, op, matches))
			return(1);

	} else if (aci_strbvcmp( "role", &bv ) == 0) {
		if (aci_group_member(&sdn, SLAPD_ROLE_CLASS, SLAPD_ROLE_ATTR, be, e, op, matches))
			return(1);

	} else if (aci_strbvcmp( "set", &bv ) == 0) {
		if (aci_match_set(&sdn, be, e, conn, op, 0))
			return(1);

	} else if (aci_strbvcmp( "set-ref", &bv ) == 0) {
		if (aci_match_set(&sdn, be, e, conn, op, 1))
			return(1);

	}

	return(0);
}

#endif	/* SLAPD_ACI_ENABLED */

static void
string_expand(
	char *newbuf,
	int bufsiz,
	char *pat,
	char *match,
	regmatch_t *matches)
{
	int     size;
	char   *sp;
	char   *dp;
	int     flag;

	size = 0;
	newbuf[0] = '\0';
	bufsiz--; /* leave space for lone $ */

	flag = 0;
	for ( dp = newbuf, sp = pat; size < bufsiz && *sp ; sp++) {
		/* did we previously see a $ */
		if (flag) {
			if (*sp == '$') {
				*dp++ = '$';
				size++;
			} else if (*sp >= '0' && *sp <= '9' ) {
				int     n;
				int     i;
				int     l;

				n = *sp - '0';
				*dp = '\0';
				i = matches[n].rm_so;
				l = matches[n].rm_eo; 
				for ( ; size < 512 && i < l; size++, i++ ) {
					*dp++ = match[i];
					size++;
				}
				*dp = '\0';
			}
			flag = 0;
		} else {
			if (*sp == '$') {
				flag = 1;
			} else {
				*dp++ = *sp;
				size++;
			}
		}
	}

	if (flag) {
		/* must have ended with a single $ */
		*dp++ = '$';
		size++;
	}

	*dp = '\0';

	Debug( LDAP_DEBUG_TRACE, "=> string_expand: pattern:  %s\n", pat, 0, 0 );
	Debug( LDAP_DEBUG_TRACE, "=> string_expand: expanded: %s\n", newbuf, 0, 0 );
}

static int
regex_matches(
	char *pat,				/* pattern to expand and match against */
	char *str,				/* string to match against pattern */
	char *buf,				/* buffer with $N expansion variables */
	regmatch_t *matches		/* offsets in buffer for $N expansion variables */
)
{
	regex_t re;
	char newbuf[512];
	int	rc;

	if(str == NULL) str = "";

	string_expand(newbuf, sizeof(newbuf), pat, buf, matches);
	if (( rc = regcomp(&re, newbuf, REG_EXTENDED|REG_ICASE))) {
		char error[512];
		regerror(rc, &re, error, sizeof(error));

		Debug( LDAP_DEBUG_TRACE,
		    "compile( \"%s\", \"%s\") failed %s\n",
			pat, str, error );
		return( 0 );
	}

	rc = regexec(&re, str, 0, NULL, 0);
	regfree( &re );

	Debug( LDAP_DEBUG_TRACE,
	    "=> regex_matches: string:   %s\n", str, 0, 0 );
	Debug( LDAP_DEBUG_TRACE,
	    "=> regex_matches: rc: %d %s\n",
		rc, !rc ? "matches" : "no matches", 0 );
	return( !rc );
}

