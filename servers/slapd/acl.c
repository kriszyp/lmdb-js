/* acl.c - routines to parse and check acl's */

#include "portable.h"

#include <stdio.h>

#include <ac/regex.h>
#include <ac/socket.h>
#include <ac/string.h>

#include "slap.h"

static int	regex_matches(char *pat, char *str, char *buf, regmatch_t *matches);
static void	string_expand(char *newbuf, int bufsiz, char *pattern,
			      char *match, regmatch_t *matches);


/*
 * access_allowed - check whether op->o_ndn is allowed the requested access
 * to entry e, attribute attr, value val.  if val is null, access to
 * the whole attribute is assumed (all values).  this routine finds
 * the applicable acl and calls acl_access_allowed() to make the
 * decision.
 *
 * returns	0	access NOT allowed
 *		1	access allowed
 */

int
access_allowed(
    Backend		*be,
    Connection		*conn,
    Operation		*op,
    Entry		*e,
    char		*attr,
    struct berval	*val,
    int			access
)
{
	int				rc;
	struct acl		*a;
	char            *edn;

	regmatch_t       matches[MAXREMATCHES];
	int              i;
	int              n;

	if ( be == NULL ) {
		return( 0 );
	}

	edn = e->e_ndn;

	Debug( LDAP_DEBUG_ACL, "\n=> access_allowed: entry (%s) attr (%s)\n",
		e->e_dn, attr, 0 );

	/* the lastmod attributes are ignored by ACL checking */
	if ( oc_check_no_usermod_attr( attr ) ) {
 		Debug( LDAP_DEBUG_ACL, "Operational attribute: %s access allowed\n",
			attr, 0, 0 );
		return(1);
	}

	memset(matches, 0, sizeof(matches));

	a = acl_get_applicable( be, op, e, attr, MAXREMATCHES, matches );

	if (a) {
		for (i = 0; i < MAXREMATCHES && matches[i].rm_so > 0; i++) {
			Debug( LDAP_DEBUG_ARGS, "=> match[%d]: %d %d ", i,
			       (int)matches[i].rm_so, (int)matches[i].rm_eo );

			if( matches[i].rm_so <= matches[0].rm_eo ) {
				for ( n = matches[i].rm_so; n < matches[i].rm_eo; n++) {
					Debug( LDAP_DEBUG_ARGS, "%c", edn[n], 0, 0 );
				}
			}
			Debug( LDAP_DEBUG_ARGS, "\n", 0, 0, 0 );
		}
	}

	rc = acl_access_allowed( a, be, conn, e, val, op, access, edn, matches );

	Debug( LDAP_DEBUG_ACL, "\n=> access_allowed: exit (%s) attr (%s)\n",
		e->e_dn, attr, 0);

	return( rc );
}

/*
 * acl_get_applicable - return the acl applicable to entry e, attribute
 * attr.  the acl returned is suitable for use in subsequent calls to
 * acl_access_allowed().
 */

struct acl *
acl_get_applicable(
    Backend		*be,
    Operation		*op,
    Entry		*e,
    char		*attr,
    int			nmatch,
    regmatch_t	*matches
)
{
	int		i;
	struct acl	*a;
    char		*edn;

	Debug( LDAP_DEBUG_ACL, "\n=> acl_get: entry (%s) attr (%s)\n",
		e->e_dn, attr, 0 );

	if ( be_isroot( be, op->o_ndn ) ) {
		Debug( LDAP_DEBUG_ACL,
		    "<= acl_get: no acl applicable to database root\n", 0, 0,
		    0 );
		return( NULL );
	}

    edn = e->e_ndn;

	Debug( LDAP_DEBUG_ARGS, "=> acl_get: edn %s\n", edn, 0, 0 );

	/* check for a backend-specific acl that matches the entry */
	for ( i = 1, a = be->be_acl; a != NULL; a = a->acl_next, i++ ) {
		if (a->acl_dnpat != NULL) {
			Debug( LDAP_DEBUG_TRACE, "=> dnpat: [%d] %s nsub: %d\n", 
				i, a->acl_dnpat, (int) a->acl_dnre.re_nsub);

			if (regexec(&a->acl_dnre, edn, nmatch, matches, 0))
				continue;
			else
				Debug( LDAP_DEBUG_TRACE, "=> acl_get:[%d]  backend ACL match\n",
					i, 0, 0);
		}

		if ( a->acl_filter != NULL ) {
			if ( test_filter( NULL, NULL, NULL, e, a->acl_filter ) != 0 ) {
				continue;
			}
		}

        Debug( LDAP_DEBUG_ARGS, "=> acl_get: [%d] check attr %s\n", i, attr, 0);

		if ( attr == NULL || a->acl_attrs == NULL ||
			charray_inlist( a->acl_attrs, attr ) )
		{
			Debug( LDAP_DEBUG_ACL, "<= acl_get: [%d] backend acl %s attr: %s\n",
				i, e->e_dn, attr );
			return( a );
		}
		matches[0].rm_so = matches[0].rm_eo = -1;
	}

	/* check for a global acl that matches the entry */
	for ( i = 1, a = global_acl; a != NULL; a = a->acl_next, i++ ) {
		if (a->acl_dnpat != NULL) {
			Debug( LDAP_DEBUG_TRACE, "=> dnpat: [%d] %s nsub: %d\n", 
				i, a->acl_dnpat, (int) a->acl_dnre.re_nsub);

			if (regexec(&a->acl_dnre, edn, nmatch, matches, 0)) {
				continue;
			} else {
				Debug( LDAP_DEBUG_TRACE, "=> acl_get: [%d] global ACL match\n",
					i, 0, 0);
			}
		}

		if ( a->acl_filter != NULL ) {
			if ( test_filter( NULL, NULL, NULL, e, a->acl_filter ) != 0 ) {
				continue;
			}
		}

		Debug( LDAP_DEBUG_ARGS, "=> acl_get: [%d] check attr\n", i, 0, 0);

		if ( attr == NULL || a->acl_attrs == NULL ||
			charray_inlist( a->acl_attrs, attr ) )
		{
			Debug( LDAP_DEBUG_ACL, "<= acl_get: [%d] global acl %s attr: %s\n",
				i, e->e_dn, attr );
			return( a );
		}

		matches[0].rm_so = matches[0].rm_eo = -1;
	}

	Debug( LDAP_DEBUG_ACL, "<= acl_get: no match\n", 0, 0, 0 );
	return( NULL );
}

/*
 * acl_access_allowed - check whether the given acl allows dn the
 * requested access to entry e, attribute attr, value val.  if val
 * is null, access to the whole attribute is assumed (all values).
 *
 * returns	0	access NOT allowed
 *		1	access allowed
 */

int
acl_access_allowed(
    struct acl		*a,
    Backend		*be,
    Connection		*conn,
    Entry		*e,
    struct berval	*val,
    Operation		*op,
    int			access,
	char		*edn,
	regmatch_t	*matches
)
{
	int		i;
	struct access	*b;
	Attribute	*at;
	struct berval	bv;
	int		default_access;

	Debug( LDAP_DEBUG_ACL,
		"\n=> acl_access_allowed: %s access to entry \"%s\"\n",
		access2str( access ), e->e_dn, 0 );

	Debug( LDAP_DEBUG_ACL,
		"\n=> acl_access_allowed: %s access to value \"%s\" by \"%s\"\n",
	    access2str( access ),
		val ? val->bv_val : "any",
		op->o_ndn ?  op->o_ndn : "" );

	if ( be_isroot( be, op->o_ndn ) ) {
		Debug( LDAP_DEBUG_ACL,
			"<= acl_access_allowed: granted to database root\n",
		    0, 0, 0 );
		return( 1 );
	}

	default_access = be->be_dfltaccess ? be->be_dfltaccess : global_default_access;

	if ( a == NULL ) {
		Debug( LDAP_DEBUG_ACL,
		    "<= acl_access_allowed: %s by default (no matching to)\n",
		    default_access >= access ? "granted" : "denied", 0, 0 );
		return( default_access >= access );
	}

	if ( op->o_ndn != NULL ) {
		bv.bv_val = op->o_ndn;
		bv.bv_len = strlen( bv.bv_val );
	}

	for ( i = 1, b = a->acl_access; b != NULL; b = b->a_next, i++ ) {
		if ( b->a_dnpat != NULL ) {
			Debug( LDAP_DEBUG_TRACE, "<= check a_dnpat: %s\n",
				b->a_dnpat, 0, 0);
			/*
			 * if access applies to the entry itself, and the
			 * user is bound as somebody in the same namespace as
			 * the entry, OR the given dn matches the dn pattern
			 */
			if ( strcasecmp( b->a_dnpat, "anonymous" ) == 0 && 
				(op->o_ndn == NULL || *(op->o_ndn) == '\0' ) ) 
			{
				Debug( LDAP_DEBUG_ACL,
				"<= acl_access_allowed: matched by clause #%d access %s\n",
				    i, ACL_GRANT(b->a_access, access)
						? "granted" : "denied", 0 );

				return ACL_GRANT(b->a_access, access );

			} else if ( strcasecmp( b->a_dnpat, "self" ) == 0 && 
				op->o_ndn != NULL && *(op->o_ndn) && e->e_dn != NULL ) 
			{
				if ( strcmp( edn, op->o_ndn ) == 0 ) {
					Debug( LDAP_DEBUG_ACL,
					"<= acl_access_allowed: matched by clause #%d access %s\n",
					    i, ACL_GRANT(b->a_access, access)
							? "granted" : "denied", 0 );

					return ACL_GRANT(b->a_access, access );
				}
			} else {
				if ( regex_matches( b->a_dnpat, op->o_ndn, edn, matches ) ) {
					Debug( LDAP_DEBUG_ACL,
				    "<= acl_access_allowed: matched by clause #%d access %s\n",
				    i, ACL_GRANT(b->a_access, access)
						? "granted" : "denied", 0 );

					return ACL_GRANT(b->a_access, access );
				}
			}
		}
		if ( b->a_addrpat != NULL ) {
			if ( regex_matches( b->a_addrpat, conn->c_client_addr,
				edn, matches ) )
			{
				Debug( LDAP_DEBUG_ACL,
				    "<= acl_access_allowed: matched by clause #%d access %s\n",
				    i, ACL_GRANT(b->a_access, access)
						? "granted" : "denied", 0 );

				return ACL_GRANT(b->a_access, access );
			}
		}
		if ( b->a_domainpat != NULL ) {
			Debug( LDAP_DEBUG_ARGS, "<= check a_domainpath: %s\n",
				b->a_domainpat, 0, 0 );
			if ( regex_matches( b->a_domainpat, conn->c_client_name,
				edn, matches ) ) 
			{
				Debug( LDAP_DEBUG_ACL,
				    "<= acl_access_allowed: matched by clause #%d access %s\n",
				    i, ACL_GRANT(b->a_access, access)
						? "granted" : "denied", 0 );

				return ACL_GRANT(b->a_access, access );
			}
		}
		if ( b->a_dnattr != NULL && op->o_ndn != NULL ) {
			Debug( LDAP_DEBUG_ARGS, "<= check a_dnattr: %s\n",
				b->a_dnattr, 0, 0);
			/* see if asker is listed in dnattr */
			if ( (at = attr_find( e->e_attrs, b->a_dnattr )) != NULL && 
				value_find( at->a_vals, &bv, at->a_syntax, 3 ) == 0 )
			{
				if ( ACL_IS_SELF(b->a_access) && 
					(val == NULL || value_cmp( &bv, val, at->a_syntax, 2 )) )
				{
					continue;
				}

				Debug( LDAP_DEBUG_ACL,
				    "<= acl_acces_allowed: matched by clause #%d access %s\n",
				    i, ACL_GRANT(b->a_access, access)
						? "granted" : "denied", 0 );

				return ACL_GRANT(b->a_access, access );
			}

			/* asker not listed in dnattr - check for self access */
			if ( ! ACL_IS_SELF(b->a_access) || val == NULL ||
				value_cmp( &bv, val, at->a_syntax, 2 ) != 0 )
			{
				continue;
			}

			Debug( LDAP_DEBUG_ACL,
				"<= acl_access_allowed: matched by clause #%d (self) access %s\n",
			    i, ACL_GRANT(b->a_access, access)
					? "granted" : "denied", 0 );

			return ACL_GRANT(b->a_access, access );
		}

		if ( b->a_group != NULL && op->o_ndn != NULL ) {
			char buf[1024];

			/* b->a_group is an unexpanded entry name, expanded it should be an 
			 * entry with objectclass group* and we test to see if odn is one of
			 * the values in the attribute group
			 */
			/* see if asker is listed in dnattr */
			string_expand(buf, sizeof(buf), b->a_group, edn, matches);
			(void) dn_normalize_case(buf);

			if (backend_group(be, e, buf, op->o_ndn,
				b->a_group_oc, b->a_group_at) == 0)
			{
				Debug( LDAP_DEBUG_ACL,
					"<= acl_access_allowed: matched by clause #%d (group) access granted\n",
					i, 0, 0 );
				return ACL_GRANT(b->a_access, access );
			}
		}
	}

	Debug( LDAP_DEBUG_ACL,
		"<= acl_access_allowed: %s by default (no matching by)\n",
	    default_access >= access ? "granted" : "denied", 0, 0 );

	return( default_access >= access );
}

/*
 * acl_check_modlist - check access control on the given entry to see if
 * it allows the given modifications by the user associated with op.
 * returns	LDAP_SUCCESS	mods allowed ok
 *		anything else	mods not allowed - return is an error
 *				code indicating the problem
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
	struct acl	*a;
	char	*edn = e->e_ndn;

	for ( ; mlist != NULL; mlist = mlist->ml_next ) {
		regmatch_t       matches[MAXREMATCHES];

		/* the lastmod attributes are ignored by ACL checking */
		if ( oc_check_no_usermod_attr( mlist->ml_type ) ) {
			Debug( LDAP_DEBUG_ACL, "Operational attribute: %s access allowed\n",
				mlist->ml_type, 0, 0 );
			continue;
		}

		a = acl_get_applicable( be, op, e, mlist->ml_type,
			MAXREMATCHES, matches );

		switch ( mlist->ml_op & ~LDAP_MOD_BVALUES ) {
		case LDAP_MOD_REPLACE:
		case LDAP_MOD_ADD:
			if ( mlist->ml_bvalues == NULL ) {
				break;
			}
			for ( i = 0; mlist->ml_bvalues[i] != NULL; i++ ) {
				if ( ! acl_access_allowed( a, be, conn, e, mlist->ml_bvalues[i], 
					op, ACL_WRITE, edn, matches) ) 
				{
					return( LDAP_INSUFFICIENT_ACCESS );
				}
			}
			break;

		case LDAP_MOD_DELETE:
			if ( mlist->ml_bvalues == NULL ) {
				if ( ! acl_access_allowed( a, be, conn, e,
					NULL, op, ACL_WRITE, edn, matches) ) 
				{
					return( LDAP_INSUFFICIENT_ACCESS );
				}
				break;
			}
			for ( i = 0; mlist->ml_bvalues[i] != NULL; i++ ) {
				if ( ! acl_access_allowed( a, be, conn, e, mlist->ml_bvalues[i], 
					op, ACL_WRITE, edn, matches) ) 
				{
					return( LDAP_INSUFFICIENT_ACCESS );
				}
			}
			break;
		}
	}

	return( LDAP_SUCCESS );
}

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

