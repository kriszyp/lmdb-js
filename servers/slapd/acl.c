/* acl.c - routines to parse and check acl's */

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#ifdef sunos5
#include "regexpr.h"
#else
#include "regex.h"
#endif
#include "slap.h"

extern Attribute	*attr_find();
extern char		*re_comp();
extern struct acl	*global_acl;
extern int		global_default_access;
extern char		*access2str();
extern char		*dn_normalize_case();

int		acl_access_allowed();
int		access_allowed();
struct acl	*acl_get_applicable();

static int	regex_matches();

extern pthread_mutex_t	regex_mutex;

/*
 * access_allowed - check whether dn is allowed the requested access
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
    char		*dn,
    int			access
)
{
	int		rc;
	struct acl	*a;

	if ( be == NULL ) {
		return( 0 );
	}

	a = acl_get_applicable( be, op, e, attr );
	rc = acl_access_allowed( a, be, conn, e, val, op, access );

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
    char		*attr
)
{
	int		i;
	struct acl	*a;
	char		*edn;

	Debug( LDAP_DEBUG_ACL, "=> acl_get: entry (%s) attr (%s)\n", e->e_dn,
	    attr, 0 );

	if ( be_isroot( be, op->o_dn ) ) {
		Debug( LDAP_DEBUG_ACL,
		    "<= acl_get: no acl applicable to database root\n", 0, 0,
		    0 );
		return( NULL );
	}

	/* check for a backend-specific acl that matches the entry */
	for ( i = 1, a = be->be_acl; a != NULL; a = a->acl_next, i++ ) {
		if ( a->acl_dnpat != NULL ) {
			edn = dn_normalize_case( strdup( e->e_dn ) );
			if ( ! regex_matches( a->acl_dnpat, edn ) ) {
				free( edn );
				continue;
			}
			free( edn );
		}
		if ( a->acl_filter != NULL ) {
			if ( test_filter( NULL, NULL, NULL, e, a->acl_filter )
			    != 0 ) {
				continue;
			}
		}
		if ( attr == NULL || a->acl_attrs == NULL ||
		    charray_inlist( a->acl_attrs, attr ) ) {
			Debug( LDAP_DEBUG_ACL, "<= acl_get: backend acl #%d\n",
			    i, e->e_dn, attr );
			return( a );
		}
	}

	/* check for a global acl that matches the entry */
	for ( i = 1, a = global_acl; a != NULL; a = a->acl_next, i++ ) {
		if ( a->acl_dnpat != NULL ) {
			edn = dn_normalize_case( strdup( e->e_dn ) );
			if ( ! regex_matches( a->acl_dnpat, edn ) ) {
				free( edn );
				continue;
			}
			free( edn );
		}
		if ( a->acl_filter != NULL ) {
			if ( test_filter( NULL, NULL, NULL, e, a->acl_filter )
			    != 0 ) {
				continue;
			}
		}
		if ( attr == NULL || a->acl_attrs == NULL || charray_inlist(
		    a->acl_attrs, attr ) ) {
			Debug( LDAP_DEBUG_ACL, "<= acl_get: global acl #%d\n",
			    i, e->e_dn, attr );
			return( a );
		}
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
    int			access
)
{
	int		i;
	char		*edn, *odn;
	struct access	*b;
	Attribute	*at;
	struct berval	bv;
	int		default_access;

	Debug( LDAP_DEBUG_ACL, "=> acl: %s access to value \"%s\" by \"%s\"\n",
	    access2str( access ), val ? val->bv_val : "any", op->o_dn ?
	    op->o_dn : "" );

	if ( be_isroot( be, op->o_dn ) ) {
		Debug( LDAP_DEBUG_ACL, "<= acl: granted to database root\n",
		    0, 0, 0 );
		return( 1 );
	}

	default_access = be->be_dfltaccess ? be->be_dfltaccess :
	    global_default_access;
	if ( a == NULL ) {
		Debug( LDAP_DEBUG_ACL,
		    "<= acl: %s by default (no matching to)\n",
		    default_access >= access ? "granted" : "denied", 0, 0 );
		return( default_access >= access );
	}

	odn = NULL;
	if ( op->o_dn != NULL ) {
		odn = dn_normalize_case( strdup( op->o_dn ) );
		bv.bv_val = odn;
		bv.bv_len = strlen( odn );
	}
	for ( i = 1, b = a->acl_access; b != NULL; b = b->a_next, i++ ) {
		if ( b->a_dnpat != NULL ) {
			/*
			 * if access applies to the entry itself, and the
			 * user is bound as somebody in the same namespace as
			 * the entry, OR the given dn matches the dn pattern
			 */
			if ( strcasecmp( b->a_dnpat, "self" ) == 0 && op->o_dn
			    != NULL && *(op->o_dn) && e->e_dn != NULL ) {
				edn = dn_normalize_case( strdup( e->e_dn ) );
				if ( strcasecmp( edn, op->o_dn ) == 0 ) {
					free( edn );
					if ( odn ) free( odn );
					Debug( LDAP_DEBUG_ACL,
				    "<= acl: matched by clause #%d access %s\n",
					    i, (b->a_access & ~ACL_SELF) >=
					    access ? "granted" : "denied", 0 );

					return( (b->a_access & ~ACL_SELF)
					    >= access );
				}
				free( edn );
			} else {
				if ( regex_matches( b->a_dnpat, odn ) ) {
					if ( odn ) free( odn );
					Debug( LDAP_DEBUG_ACL,
				    "<= acl: matched by clause #%d access %s\n",
				    i, (b->a_access & ~ACL_SELF) >= access ?
					    "granted" : "denied", 0 );

					return( (b->a_access & ~ACL_SELF)
					    >= access );
				}
			}
		}
		if ( b->a_addrpat != NULL ) {
			if ( regex_matches( b->a_addrpat, conn->c_addr ) ) {
				if ( odn ) free( odn );
				Debug( LDAP_DEBUG_ACL,
				    "<= acl: matched by clause #%d access %s\n",
				    i, (b->a_access & ~ACL_SELF) >= access ?
				    "granted" : "denied", 0 );

				return( (b->a_access & ~ACL_SELF) >= access );
			}
		}
		if ( b->a_domainpat != NULL ) {
			if ( regex_matches( b->a_domainpat, conn->c_domain ) ) {
				if ( odn ) free( odn );
				Debug( LDAP_DEBUG_ACL,
				    "<= acl: matched by clause #%d access %s\n",
				    i, (b->a_access & ~ACL_SELF) >= access ?
				    "granted" : "denied", 0 );

				return( (b->a_access & ~ACL_SELF) >= access );
			}
		}
		if ( b->a_dnattr != NULL && op->o_dn != NULL ) {
			/* see if asker is listed in dnattr */
			if ( (at = attr_find( e->e_attrs, b->a_dnattr ))
			    != NULL && value_find( at->a_vals, &bv,
			    at->a_syntax, 3 ) == 0 )
			{
				if ( (b->a_access & ACL_SELF) && (val == NULL
				    || value_cmp( &bv, val, at->a_syntax,
				    2 )) ) {
					continue;
				}

				if ( odn ) free( odn );
				Debug( LDAP_DEBUG_ACL,
				    "<= acl: matched by clause #%d access %s\n",
				    i, (b->a_access & ~ACL_SELF) >= access ?
				    "granted" : "denied", 0 );

				return( (b->a_access & ~ACL_SELF) >= access );
			}

			/* asker not listed in dnattr - check for self access */
			if ( ! (b->a_access & ACL_SELF) || val == NULL ||
			    value_cmp( &bv, val, at->a_syntax, 2 ) != 0 ) {
				continue;
			}

			if ( odn ) free( odn );
			Debug( LDAP_DEBUG_ACL,
			    "<= acl: matched by clause #%d (self) access %s\n",
			    i, (b->a_access & ~ACL_SELF) >= access ? "granted"
			    : "denied", 0 );

			return( (b->a_access & ~ACL_SELF) >= access );
		}
	}

	if ( odn ) free( odn );
	Debug( LDAP_DEBUG_ACL, "<= acl: %s by default (no matching by)\n",
	    default_access >= access ? "granted" : "denied", 0, 0 );

	return( default_access >= access );
}

/*
 * acl_check_mods - check access control on the given entry to see if
 * it allows the given modifications by the user associated with op.
 * returns	LDAP_SUCCESS	mods allowed ok
 *		anything else	mods not allowed - return is an error
 *				code indicating the problem
 */

int
acl_check_mods(
    Backend	*be,
    Connection	*conn,
    Operation	*op,
    Entry	*e,
    LDAPMod	*mods
)
{
	int		i;
	struct acl	*a;

	for ( ; mods != NULL; mods = mods->mod_next ) {
		if ( strcasecmp( mods->mod_type, "modifiersname" ) == 0 ||
		    strcasecmp( mods->mod_type, "modifytimestamp" ) == 0 ) {
			continue;
		}

		a = acl_get_applicable( be, op, e, mods->mod_type );

		switch ( mods->mod_op & ~LDAP_MOD_BVALUES ) {
		case LDAP_MOD_REPLACE:
		case LDAP_MOD_ADD:
			if ( mods->mod_bvalues == NULL ) {
				break;
			}
			for ( i = 0; mods->mod_bvalues[i] != NULL; i++ ) {
				if ( ! acl_access_allowed( a, be, conn, e,
				    mods->mod_bvalues[i], op, ACL_WRITE ) ) {
					return( LDAP_INSUFFICIENT_ACCESS );
				}
			}
			break;

		case LDAP_MOD_DELETE:
			if ( mods->mod_bvalues == NULL ) {
				if ( ! acl_access_allowed( a, be, conn, e,
				    NULL, op, ACL_WRITE ) ) {
					return( LDAP_INSUFFICIENT_ACCESS );
				}
				break;
			}
			for ( i = 0; mods->mod_bvalues[i] != NULL; i++ ) {
				if ( ! acl_access_allowed( a, be, conn, e,
				    mods->mod_bvalues[i], op, ACL_WRITE ) ) {
					return( LDAP_INSUFFICIENT_ACCESS );
				}
			}
			break;
		}
	}

	return( LDAP_SUCCESS );
}

#ifdef sunos5

static int
regex_matches( char *pat, char *str )
{
	char	*e;
	int	rc;

	if ( (e = compile( pat, NULL, NULL )) == NULL ) {
		Debug( LDAP_DEBUG_ANY,
		    "compile( \"%s\", \"%s\") failed\n", pat, str, 0 );
		return( 0 );
	}
	rc = step( str ? str : "", e );
	free( e );

	return( rc );
}

#else /* sunos5 */

static int
regex_matches( char *pat, char *str )
{
	char	*e;
	int	rc;

	pthread_mutex_lock( &regex_mutex );
	if ( (e = re_comp( pat )) != NULL ) {
		Debug( LDAP_DEBUG_ANY,
		    "re_comp( \"%s\", \"%s\") failed because (%s)\n", pat, str,
		    e );
		pthread_mutex_unlock( &regex_mutex );
		return( 0 );
	}
	rc = re_exec( str ? str : "" );
	pthread_mutex_unlock( &regex_mutex );

	return( rc == 1 );
}

#endif /* sunos5 */
