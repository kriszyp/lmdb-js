/* acl.c - routines to parse and check acl's */
/* $OpenLDAP$ */
/*
 * Copyright 1998-1999 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "portable.h"

#include <stdio.h>

#include <ac/regex.h>
#include <ac/socket.h>
#include <ac/string.h>

#include "slap.h"

static AccessControl * acl_get(
	AccessControl *ac, int *count,
	Backend *be, Operation *op,
	Entry *e, char *attr,
	int nmatches, regmatch_t *matches );

static slap_control_t acl_mask(
	AccessControl *ac, slap_access_mask_t *mask,
	Backend *be, Connection *conn, Operation *op,
	Entry *e, char *attr, struct berval *val,
	regmatch_t *matches );

#ifdef SLAPD_ACI_ENABLED
static int aci_access_allowed(
	Backend *be,
	Operation *op,
	Entry *e, char *attr, struct berval *aci,
	regmatch_t *matches );
#endif

static int	regex_matches(char *pat, char *str, char *buf, regmatch_t *matches);
static void	string_expand(char *newbuf, int bufsiz, char *pattern,
			      char *match, regmatch_t *matches);


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
    char		*attr,
    struct berval	*val,
    slap_access_t	access
)
{
	int				count;
	AccessControl	*a;
	char accessmaskbuf[ACCESSMASK_MAXLEN];
	slap_access_mask_t mask;
	slap_control_t control;

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

	/* no user modify operational attributes are ignored by ACL checking */
	if ( oc_check_no_usermod_attr( attr ) ) {
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
	memset(matches, 0, sizeof(matches));
	
	control = ACL_BREAK;
	a = NULL;
	count = 0;

	while( a = acl_get( a, &count, be, op, e, attr, MAXREMATCHES, matches ) )
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
			e, attr, val, matches );

		if ( control != ACL_BREAK ) {
			break;
		}

		memset(matches, 0, sizeof(matches));
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
    char		*attr,
    int			nmatch,
    regmatch_t	*matches
)
{
	AccessControl	*next;
	assert( e != NULL );
	assert( count != NULL );

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

	for ( ; a != NULL; a = a->acl_next ) {
		(*count) ++;

		if (a->acl_dn_pat != NULL) {
			Debug( LDAP_DEBUG_ACL, "=> dnpat: [%d] %s nsub: %d\n", 
				*count, a->acl_dn_pat, (int) a->acl_dn_re.re_nsub );

			if (regexec(&a->acl_dn_re, e->e_ndn, nmatch, matches, 0)) {
				continue;

			} else {
				Debug( LDAP_DEBUG_ACL, "=> acl_get: [%d] matched\n",
					*count, 0, 0);
			}
		}

		if ( a->acl_filter != NULL ) {
			if ( test_filter( NULL, NULL, NULL, e, a->acl_filter ) != 0 ) {
				continue;
			}
		}

        Debug( LDAP_DEBUG_ACL, "=> acl_get: [%d] check attr %s\n",
			*count, attr, 0);

		if ( attr == NULL || a->acl_attrs == NULL ||
			charray_inlist( a->acl_attrs, attr ) )
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
    char		*attr,
    struct berval	*val,
	regmatch_t	*matches
)
{
	int		i;
	Access	*b;
	char accessmaskbuf[ACCESSMASK_MAXLEN];

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
			if ( strcasecmp( b->a_dn_pat, "anonymous" ) == 0 ) {
				if (op->o_ndn != NULL && op->o_ndn[0] != '\0' ) {
					continue;
				}

			} else if ( strcasecmp( b->a_dn_pat, "self" ) == 0 ) {
				if( op->o_ndn == NULL || op->o_ndn[0] == '\0' ) {
					continue;
				}
				
				if ( e->e_dn == NULL || strcmp( e->e_ndn, op->o_ndn ) != 0 ) {
					continue;
				}

			} else if ( strcmp( b->a_dn_pat, ".*" ) != 0 &&
				!regex_matches( b->a_dn_pat, op->o_ndn, e->e_ndn, matches ) )
			{
				continue;
			}
		}

		if ( b->a_sockurl_pat != NULL ) {
			Debug( LDAP_DEBUG_ACL, "<= check a_sockurl_pat: %s\n",
				b->a_sockurl_pat, 0, 0 );

			if ( strcmp( b->a_sockurl_pat, ".*" ) != 0 &&
				!regex_matches( b->a_sockurl_pat, conn->c_listener_url,
				e->e_ndn, matches ) ) 
			{
				continue;
			}
		}

		if ( b->a_domain_pat != NULL ) {
			Debug( LDAP_DEBUG_ACL, "<= check a_domain_pat: %s\n",
				b->a_domain_pat, 0, 0 );

			if ( strcmp( b->a_domain_pat, ".*" ) != 0 &&
				!regex_matches( b->a_domain_pat, conn->c_peer_domain,
				e->e_ndn, matches ) ) 
			{
				continue;
			}
		}

		if ( b->a_peername_pat != NULL ) {
			Debug( LDAP_DEBUG_ACL, "<= check a_peername_path: %s\n",
				b->a_peername_pat, 0, 0 );

			if ( strcmp( b->a_peername_pat, ".*" ) != 0 &&
				!regex_matches( b->a_peername_pat, conn->c_peer_name,
				e->e_ndn, matches ) )
			{
				continue;
			}
		}

		if ( b->a_sockname_pat != NULL ) {
			Debug( LDAP_DEBUG_ACL, "<= check a_sockname_path: %s\n",
				b->a_sockname_pat, 0, 0 );

			if ( strcmp( b->a_sockname_pat, ".*" ) != 0 &&
				!regex_matches( b->a_sockname_pat, conn->c_sock_name,
				e->e_ndn, matches ) )
			{
				continue;
			}
		}

		if ( b->a_dn_at != NULL && op->o_ndn != NULL ) {
			Attribute	*at;
			struct berval	bv;

			Debug( LDAP_DEBUG_ACL, "<= check a_dn_at: %s\n",
				b->a_dn_at, 0, 0);

			bv.bv_val = op->o_ndn;
			bv.bv_len = strlen( bv.bv_val );

			/* see if asker is listed in dnattr */ 
			if ( (at = attr_find( e->e_attrs, b->a_dn_at )) != NULL &&
				value_find( at->a_vals, &bv, at->a_syntax, 3 ) == 0 )
			{
				if ( b->a_dn_self && 
					(val == NULL || value_cmp( &bv, val, at->a_syntax, 2 )) )
				{
					continue;
				}

			/* asker not listed in dnattr - check for self access */
			} else if ( ! b->a_dn_self || val == NULL ||
				value_cmp( &bv, val, at->a_syntax, 2 ) != 0 )
			{
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
			string_expand(buf, sizeof(buf), b->a_group_pat, e->e_ndn, matches);
			if ( dn_normalize(buf) == NULL ) {
				/* did not expand to a valid dn */
				continue;
			}

			if (backend_group(be, e, buf, op->o_ndn,
				b->a_group_oc, b->a_group_at) != 0)
			{
				continue;
			}
		}

#ifdef SLAPD_ACI_ENABLED
		if ( b->a_aci_at != NULL ) {
			Attribute	*at;

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

			/* first check if the right being requested is
			 * higher than allowed by the ACL clause.
			 */
			if ( ! ACL_GRANT( b->a_mask, access ) ) {
				continue;
			}

			/* get the aci attribute */
			at = attr_find( e->e_attrs, b->a_aci_at );
			if ( at == NULL ) {
				continue;
			}

			/* the aci is an multi-valued attribute.  The
			 * rights are determined by OR'ing the individual
			 * rights given by the acis.
			 */
			for ( i = 0; at->a_vals[i] != NULL; i++ ) {
				if ( aci_access_allowed( be, op,
					e, attr, at->a_vals[i],
					matches ) )
				{
					Debug( LDAP_DEBUG_ACL,
						"<= acl_mask: matched by clause #%d access granted\n",
						i, 0, 0 );
					break;
				}
			}

			if( ACL_IS_INVALID( modmask ) ) { 
				continue;
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
    LDAPModList	*mlist
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

	for ( ; mlist != NULL; mlist = mlist->ml_next ) {
		regmatch_t       matches[MAXREMATCHES];

		/* the lastmod attributes are ignored by ACL checking */
		if ( oc_check_no_usermod_attr( mlist->ml_type ) ) {
			Debug( LDAP_DEBUG_ACL, "Operational attribute: %s access allowed\n",
				mlist->ml_type, 0, 0 );
			continue;
		}

		switch ( mlist->ml_op & ~LDAP_MOD_BVALUES ) {
		case LDAP_MOD_REPLACE:
		case LDAP_MOD_ADD:
			if ( mlist->ml_bvalues == NULL ) {
				break;
			}
			for ( i = 0; mlist->ml_bvalues[i] != NULL; i++ ) {
				if ( ! access_allowed( be, conn, op, e,
					mlist->ml_type, mlist->ml_bvalues[i],
					ACL_WRITE ) )
				{
					return( 0 );
				}
			}
			break;

		case LDAP_MOD_DELETE:
			if ( mlist->ml_bvalues == NULL ) {
				if ( ! access_allowed( be, conn, op, e,
					mlist->ml_type, NULL, 
					ACL_WRITE ) )
				{
					return( 0 );
				}
				break;
			}
			for ( i = 0; mlist->ml_bvalues[i] != NULL; i++ ) {
				if ( ! access_allowed( be, conn, op, e,
					mlist->ml_type, mlist->ml_bvalues[i],
					ACL_WRITE ) )
				{
					return( 0 );
				}
			}
			break;
		}
	}

	return( 1 );
}

#ifdef SLAPD_ACI_ENABLED
static char *
aci_bvstrdup (struct berval *bv)
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
aci_strbvcmp (char *s, struct berval *bv)
{
	int res, len;

	res = strncasecmp( s, bv->bv_val, bv->bv_len );
	if (res)
		return(res);
	len = strlen(s);
	if (len > bv->bv_len)
		return(1);
	if (len < bv->bv_len)
		return(-1);
	return(0);
}

static int
aci_get_part (struct berval *list, int ix, char sep, struct berval *bv)
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

static int
aci_list_has_right(
	struct berval *list,
	slap_access_t access,
	int action)
{
	struct berval bv;
	int i;
	slap_access_t right;

	for (i = 0; aci_get_part(list, i, ',', &bv) >= 0; i++) {
		if (bv.bv_len <= 0)
			continue;
		switch (*bv.bv_val) {
		case 'c':
			right = ACL_COMPARE;
			break;
		case 's':
			/* **** NOTE: draft-ietf-ldapext-aci-model-0.3.txt defines
			 * the right 's' to mean "set", but in the examples states
			 * that the right 's' means "search".  The latter definition
			 * is used here.
			 */
			right = ACL_SEARCH;
			break;
		case 'r':
			right = ACL_READ;
			break;
		case 'w':
			right = ACL_WRITE;
			break;
		case 'x':
			/* **** NOTE: draft-ietf-ldapext-aci-model-0.3.txt does not 
			 * define any equivalent to the AUTH right, so I've just used
			 * 'x' for now.
			 */
			right = ACL_AUTH;
			break;
		default:
			right = 0;
			break;
		}

#ifdef SLAPD_ACI_DISCRETE_RIGHTS
		if (right & access) {
			return(action);
		}
#else
		if (action != 0) {
			/* check granted */
			if (ACL_GRANT(right, access))
				return(1);
		} else {
			/* check denied */
			if (right <= access)
				return(1);
		}
#endif
	}

#ifdef SLAPD_ACI_DISCRETE_RIGHTS
	return(!action);
#else
	return(0);
#endif
}

static int
aci_list_has_attr (struct berval *list, char *attr)
{
	struct berval bv;
	int i;

	for (i = 0; aci_get_part(list, i, ',', &bv) >= 0; i++) {
		if (aci_strbvcmp(attr, &bv) == 0) {
			return(1);
		}
	}
	return(0);
}

static int
aci_list_has_attr_right (struct berval *list, char *attr, int access, int action)
{
    struct berval bv;
    int i, found;

	/* loop through each rights/attr pair, skip first part (action) */
	found = -1;
	for (i = 1; aci_get_part(list, i + 1, ';', &bv) >= 0; i += 2) {
		if (aci_list_has_attr(&bv, attr) == 0)
			continue;
		found = 0;
		if (aci_get_part(list, i, ';', &bv) < 0)
			continue;
		if (aci_list_has_right(&bv, access, action) != 0)
			return(1);
	}
	return(found);
}

static int
aci_list_has_permission(
	struct berval *list,
	char *attr,
	slap_access_t access)
{
    struct berval perm, actn;
    int i, action, specific, general;

	if (attr == NULL || *attr == 0 || strcasecmp(attr, "entry") == 0) {
		attr = "[entry]";
	}

	/* loop through each permissions clause */
	for (i = 0; aci_get_part(list, i, '$', &perm) >= 0; i++) {
		if (aci_get_part(&perm, 0, ';', &actn) < 0)
			continue;
		if (aci_strbvcmp( "grant", &actn ) == 0) {
			action = 1;
		} else if (aci_strbvcmp( "deny", &actn ) == 0) {
			action = 0;
		} else {
			continue;
		}

		specific = aci_list_has_attr_right(&perm, attr, access, action);
		if (specific >= 0)
			return(specific);

		general = aci_list_has_attr_right(&perm, "[all]", access, action);
		if (general >= 0)
			return(general);
	}
	return(0);
}

static int
aci_group_member (
	struct berval *subj,
	char *grpoc,
	char *grpat,
    Backend		*be,
    Entry		*e,
    Operation		*op,
	regmatch_t	*matches
)
{
	struct berval bv;
	char *subjdn, *grpdn;
	int rc = 0;

	/* format of string is "group/objectClassValue/groupAttrName" */
	if (aci_get_part(subj, 0, '/', &bv) < 0)
		return(0);
	subjdn = aci_bvstrdup(&bv);
	if (subjdn == NULL)
		return(0);

	if (aci_get_part(subj, 1, '/', &bv) < 0)
		grpoc = ch_strdup(grpoc);
	else
		grpoc = aci_bvstrdup(&bv);

	if (aci_get_part(subj, 2, '/', &bv) < 0)
		grpat = ch_strdup(grpat);
	else
		grpat = aci_bvstrdup(&bv);

	grpdn = (char *)ch_malloc(1024);
	if (grpoc != NULL && grpat != NULL && grpdn != NULL) {
		string_expand(grpdn, 1024, subjdn, e->e_ndn, matches);
		if ( dn_normalize(grpdn) != NULL ) {
			rc = (backend_group(be, e, grpdn, op->o_ndn, grpoc, grpat) == 0);
		}
		ch_free(grpdn);
	}
	if (grpat != NULL)
		ch_free(grpat);
	if (grpoc != NULL)
		ch_free(grpoc);
	ch_free(subjdn);
	return(rc);
}

static int
aci_access_allowed (
    struct berval	*aci,
    char			*attr,
    Backend			*be,
    Entry			*e,
    Operation		*op,
    slap_access_t	access,
	regmatch_t		*matches
)
{
    struct berval bv, perms, sdn;
    char *subjdn;
	int rc;

	Debug( LDAP_DEBUG_ACL,
		"=> aci_access_allowed: %s access to entry \"%s\"\n",
		access2str( access ), e->e_dn, 0 );

	Debug( LDAP_DEBUG_ACL,
		"=> aci_access_allowed: %s access to attribute \"%s\" by \"%s\"\n",
	    access2str( access ),
		attr,
		op->o_ndn ? op->o_ndn : "" );

	/* parse an aci of the form:
		oid#scope#action;rights;attr;rights;attr$action;rights;attr;rights;attr#dnType#subjectDN

	   See draft-ietf-ldapext-aci-model-0.3.txt section 9.1 for
	   a full description of the format for this attribute.

	   For now, this routine only supports scope=entry.
	 */

	/* check that the aci has all 5 components */
	if (aci_get_part(aci, 4, '#', NULL) < 0)
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
	if (aci_list_has_permission(&perms, attr, access) == 0)
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
		rc = 0;
		if ( dn_normalize(subjdn) != NULL )
			rc = (strcasecmp(op->o_ndn, subjdn) == 0);
		ch_free(subjdn);
		return(rc);
	}

	if (aci_strbvcmp( "self", &bv ) == 0) {
		return(strcasecmp(op->o_ndn, e->e_ndn) == 0);
	}

	if (aci_strbvcmp( "group", &bv ) == 0) {
		return(aci_group_member(&sdn, "groupOfNames", "member", be, e, op, matches));
	}

	if (aci_strbvcmp( "role", &bv ) == 0) {
		return(aci_group_member(&sdn, "organizationalRole", "roleOccupant", be, e, op, matches));
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

