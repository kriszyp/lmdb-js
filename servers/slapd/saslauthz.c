/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1998-2004 The OpenLDAP Foundation.
 * Portions Copyright 2000 Mark Adamson, Carnegie Mellon.
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

#include "portable.h"

#include <stdio.h>

#include <ac/stdlib.h>
#include <ac/string.h>
#include <ac/ctype.h>

#include "slap.h"

#include <limits.h>

#include <ldap_pvt.h>
#include "lutil.h"

#define SASLREGEX_REPLACE 10

#define LDAP_X_SCOPE_EXACT	((ber_int_t) 0x0010)
#define LDAP_X_SCOPE_REGEX	((ber_int_t) 0x0020)
#define LDAP_X_SCOPE_CHILDREN	((ber_int_t) 0x0030)
#define LDAP_X_SCOPE_SUBTREE	((ber_int_t) 0x0040)
#define LDAP_X_SCOPE_ONELEVEL	((ber_int_t) 0x0050)
#define LDAP_X_SCOPE_GROUP	((ber_int_t) 0x0060)

/*
 * IDs in DNauthzid form can now have a type specifier, that
 * influences how they are used in related operations.
 *
 * syntax: dn[.{exact|regex}]:<val>
 *
 * dn.exact:	the value must pass normalization and is used 
 *		in exact DN match.
 * dn.regex:	the value is treated as a regular expression 
 *		in matching DN values in authz{To|From}
 *		attributes.
 * dn:		for backwards compatibility reasons, the value 
 *		is treated as a regular expression, and thus 
 *		it is not normalized nor validated; it is used
 *		in exact or regex comparisons based on the 
 *		context.
 *
 * IDs in DNauthzid form can now have a type specifier, that
 * influences how they are used in related operations.
 *
 * syntax: u[.mech[/realm]]:<val>
 * 
 * where mech is a SIMPLE, AUTHZ, or a SASL mechanism name
 * and realm is mechanism specific realm (separate to those
 * which are representable as part of the principal).
 */

typedef struct sasl_regexp {
  char *sr_match;						/* regexp match pattern */
  char *sr_replace; 					/* regexp replace pattern */
  regex_t sr_workspace;					/* workspace for regexp engine */
  int sr_offset[SASLREGEX_REPLACE+2];	/* offsets of $1,$2... in *replace */
} SaslRegexp_t;

static int nSaslRegexp = 0;
static SaslRegexp_t *SaslRegexp = NULL;

#ifdef SLAP_AUTH_REWRITE
#include "rewrite.h"
struct rewrite_info	*sasl_rwinfo = NULL;
#define AUTHID_CONTEXT	"authid"
#endif /* SLAP_AUTH_REWRITE */

/* What SASL proxy authorization policies are allowed? */
#define	SASL_AUTHZ_NONE	0x00
#define	SASL_AUTHZ_FROM	0x01
#define	SASL_AUTHZ_TO	0x02
#define SASL_AUTHZ_AND	0x10

static int authz_policy = SASL_AUTHZ_NONE;

static
int slap_sasl_match( Operation *opx, struct berval *rule,
	struct berval *assertDN, struct berval *authc );

int slap_sasl_setpolicy( const char *arg )
{
	int rc = LDAP_SUCCESS;

	if ( strcasecmp( arg, "none" ) == 0 ) {
		authz_policy = SASL_AUTHZ_NONE;
	} else if ( strcasecmp( arg, "from" ) == 0 ) {
		authz_policy = SASL_AUTHZ_FROM;
	} else if ( strcasecmp( arg, "to" ) == 0 ) {
		authz_policy = SASL_AUTHZ_TO;
	} else if ( strcasecmp( arg, "both" ) == 0 || strcasecmp( arg, "any" ) == 0 ) {
		authz_policy = SASL_AUTHZ_FROM | SASL_AUTHZ_TO;
	} else if ( strcasecmp( arg, "all" ) == 0 ) {
		authz_policy = SASL_AUTHZ_FROM | SASL_AUTHZ_TO | SASL_AUTHZ_AND;
	} else {
		rc = LDAP_OTHER;
	}
	return rc;
}

int slap_parse_user( struct berval *id, struct berval *user,
		struct berval *realm, struct berval *mech )
{
	char	u;
	
	assert( id );
	assert( !BER_BVISNULL( id ) );
	assert( user );
	assert( realm );
	assert( mech );

	u = id->bv_val[ 0 ];
	
	if ( u != 'u' && u != 'U' ) {
		/* called with something other than u: */
		return LDAP_PROTOCOL_ERROR;
	}

	/* uauthzid form:
	 *		u[.mech[/realm]]:user
	 */
	
	user->bv_val = strchr( id->bv_val, ':' );
	if ( BER_BVISNULL( user ) ) {
		return LDAP_PROTOCOL_ERROR;
	}
	user->bv_val[ 0 ] = '\0';
	user->bv_val++;
	user->bv_len = id->bv_len - ( user->bv_val - id->bv_val );

	mech->bv_val = strchr( id->bv_val, '.' );
	if ( !BER_BVISNULL( mech ) ) {
		mech->bv_val[ 0 ] = '\0';
		mech->bv_val++;

		realm->bv_val = strchr( mech->bv_val, '/' );

		if ( !BER_BVISNULL( realm ) ) {
			realm->bv_val[ 0 ] = '\0';
			realm->bv_val++;
			mech->bv_len = realm->bv_val - mech->bv_val - 1;
			realm->bv_len = user->bv_val - realm->bv_val - 1;
		} else {
			mech->bv_len = user->bv_val - mech->bv_val - 1;
		}

	} else {
		BER_BVZERO( realm );
	}

	if ( id->bv_val[ 1 ] != '\0' ) {
		return LDAP_PROTOCOL_ERROR;
	}

	if ( !BER_BVISNULL( mech ) ) {
		assert( mech->bv_val == id->bv_val + 2 );

		AC_MEMCPY( mech->bv_val - 2, mech->bv_val, mech->bv_len + 1 );
		mech->bv_val -= 2;
	}

	if ( !BER_BVISNULL( realm ) ) {
		assert( realm->bv_val >= id->bv_val + 2 );

		AC_MEMCPY( realm->bv_val - 2, realm->bv_val, realm->bv_len + 1 );
		realm->bv_val -= 2;
	}

	/* leave "u:" before user */
	user->bv_val -= 2;
	user->bv_len += 2;
	user->bv_val[ 0 ] = u;
	user->bv_val[ 1 ] = ':';

	return LDAP_SUCCESS;
}

static int slap_parseURI( Operation *op, struct berval *uri,
	struct berval *base, struct berval *nbase,
	int *scope, Filter **filter, struct berval *fstr )
{
	struct berval bv;
	int rc;
	LDAPURLDesc *ludp;

	assert( uri != NULL && !BER_BVISNULL( uri ) );
	BER_BVZERO( base );
	BER_BVZERO( nbase );
	BER_BVZERO( fstr );
	*scope = -1;
	*filter = NULL;

#ifdef NEW_LOGGING
	LDAP_LOG( TRANSPORT, ENTRY, 
		"slap_parseURI: parsing %s\n", uri->bv_val, 0, 0 );
#else
	Debug( LDAP_DEBUG_TRACE,
		"slap_parseURI: parsing %s\n", uri->bv_val, 0, 0 );
#endif

	rc = LDAP_PROTOCOL_ERROR;
	/*
	 * dn[.<dnstyle>]:<dnpattern>
	 * <dnstyle> ::= {exact|regex|children|subtree|onelevel}
	 *
	 * <dnstyle> defaults to "exact"
	 * if <dnstyle> is not "regex", <dnpattern> must pass DN normalization
	 */
	if ( !strncasecmp( uri->bv_val, "dn", STRLENOF( "dn" ) ) ) {
		bv.bv_val = uri->bv_val + STRLENOF( "dn" );

		if ( bv.bv_val[ 0 ] == '.' ) {
			bv.bv_val++;

			if ( !strncasecmp( bv.bv_val, "exact:", STRLENOF( "exact:" ) ) ) {
				bv.bv_val += STRLENOF( "exact:" );
				*scope = LDAP_X_SCOPE_EXACT;

			} else if ( !strncasecmp( bv.bv_val, "regex:", STRLENOF( "regex:" ) ) ) {
				bv.bv_val += STRLENOF( "regex:" );
				*scope = LDAP_X_SCOPE_REGEX;

			} else if ( !strncasecmp( bv.bv_val, "children:", STRLENOF( "children:" ) ) ) {
				bv.bv_val += STRLENOF( "children:" );
				*scope = LDAP_X_SCOPE_CHILDREN;

			} else if ( !strncasecmp( bv.bv_val, "subtree:", STRLENOF( "subtree:" ) ) ) {
				bv.bv_val += STRLENOF( "subtree:" );
				*scope = LDAP_X_SCOPE_SUBTREE;

			} else if ( !strncasecmp( bv.bv_val, "onelevel:", STRLENOF( "onelevel:" ) ) ) {
				bv.bv_val += STRLENOF( "onelevel:" );
				*scope = LDAP_X_SCOPE_ONELEVEL;

			} else {
				return LDAP_PROTOCOL_ERROR;
			}

		} else {
			if ( bv.bv_val[ 0 ] != ':' ) {
				return LDAP_PROTOCOL_ERROR;
			}
			*scope = LDAP_X_SCOPE_EXACT;
			bv.bv_val++;
		}

		bv.bv_val += strspn( bv.bv_val, " " );
		/* jump here in case no type specification was present
		 * and uri was not an URI... HEADS-UP: assuming EXACT */
is_dn:		bv.bv_len = uri->bv_len - (bv.bv_val - uri->bv_val);

		switch ( *scope ) {
		case LDAP_X_SCOPE_EXACT:
		case LDAP_X_SCOPE_CHILDREN:
		case LDAP_X_SCOPE_SUBTREE:
		case LDAP_X_SCOPE_ONELEVEL:
			rc = dnNormalize( 0, NULL, NULL, &bv, nbase, op->o_tmpmemctx );
			if( rc != LDAP_SUCCESS ) {
				*scope = -1;
			}
			break;

		case LDAP_X_SCOPE_REGEX:
			ber_dupbv_x( nbase, &bv, op->o_tmpmemctx );
			rc = LDAP_SUCCESS;
			break;

		default:
			*scope = -1;
			break;
		}

		return rc;

	/*
	 * u:<uid>
	 */
	} else if ( ( uri->bv_val[ 0 ] == 'u' || uri->bv_val[ 0 ] == 'U' )
			&& ( uri->bv_val[ 1 ] == ':' 
				|| uri->bv_val[ 1 ] == '/' 
				|| uri->bv_val[ 1 ] == '.' ) )
	{
		Connection	c = *op->o_conn;
		char		buf[ SLAP_LDAPDN_MAXLEN ];
		struct berval	id,
				user = BER_BVNULL,
				realm = BER_BVNULL,
				mech = BER_BVNULL;

		if ( sizeof( buf ) <= uri->bv_len ) {
			return LDAP_INVALID_SYNTAX;
		}

		id.bv_len = uri->bv_len;
		id.bv_val = buf;
		strncpy( buf, uri->bv_val, sizeof( buf ) );

		rc = slap_parse_user( &id, &user, &realm, &mech );
		if ( rc != LDAP_SUCCESS ) {
			return rc;
		}

		if ( !BER_BVISNULL( &mech ) ) {
			c.c_sasl_bind_mech = mech;
		} else {
			BER_BVSTR( &c.c_sasl_bind_mech, "AUTHZ" );
		}
		
		rc = slap_sasl_getdn( &c, op, &user,
				realm.bv_val, nbase, SLAP_GETDN_AUTHZID );

		if ( rc == LDAP_SUCCESS ) {
			*scope = LDAP_X_SCOPE_EXACT;
		}

		return rc;

	/*
	 * group[/<groupoc>[/<groupat>]]:<groupdn>
	 *
	 * groupoc defaults to "groupOfNames"
	 * groupat defaults to "member"
	 * 
	 * <groupdn> must pass DN normalization
	 */
	} else if ( strncasecmp( uri->bv_val, "group", STRLENOF( "group" ) ) == 0 )
	{
		struct berval	group_dn = BER_BVNULL,
				group_oc = BER_BVNULL,
				member_at = BER_BVNULL;
		char		*tmp;

		bv.bv_val = uri->bv_val + STRLENOF( "group" );
		group_dn.bv_val = strchr( bv.bv_val, ':' );
		if ( group_dn.bv_val == NULL ) {
			/* last chance: assume it's a(n exact) DN ... */
			bv.bv_val = uri->bv_val;
			*scope = LDAP_X_SCOPE_EXACT;
			goto is_dn;
		}
		
		if ( bv.bv_val[ 0 ] == '/' ) {
			group_oc.bv_val = &bv.bv_val[ 1 ];

			member_at.bv_val = strchr( group_oc.bv_val, '/' );
			if ( member_at.bv_val ) {
				group_oc.bv_len = member_at.bv_val - group_oc.bv_val;
				member_at.bv_val++;
				member_at.bv_len = group_dn.bv_val - member_at.bv_val;

			} else {
				group_oc.bv_len = group_dn.bv_val - group_oc.bv_val;
				BER_BVSTR( &member_at, "member" );
			}

		} else {
			BER_BVSTR( &group_oc, "groupOfNames" );
		}
		group_dn.bv_val++;
		group_dn.bv_len = uri->bv_len - ( group_dn.bv_val - uri->bv_val );

		rc = dnNormalize( 0, NULL, NULL, &group_dn, nbase, op->o_tmpmemctx );
		if ( rc != LDAP_SUCCESS ) {
			*scope = -1;
			return rc;
		}
		*scope = LDAP_X_SCOPE_GROUP;

		/* FIXME: caller needs to add value of member attribute
		 * and close brackets twice */
		fstr->bv_len = STRLENOF( "(&(objectClass=)(=" /* )) */ )
			+ group_oc.bv_len + member_at.bv_len;
		fstr->bv_val = ch_malloc( fstr->bv_len + 1 );

		tmp = lutil_strncopy( fstr->bv_val, "(&(objectClass=" /* )) */ ,
				STRLENOF( "(&(objectClass=" /* )) */ ) );
		tmp = lutil_strncopy( tmp, group_oc.bv_val, group_oc.bv_len );
		tmp = lutil_strncopy( tmp, /* ( */ ")(" /* ) */ ,
				STRLENOF( /* ( */ ")(" /* ) */ ) );
		tmp = lutil_strncopy( tmp, member_at.bv_val, member_at.bv_len );
		tmp = lutil_strncopy( tmp, "=", STRLENOF( "=" ) );

		return rc;
	}

	/*
	 * ldap:///<base>??<scope>?<filter>
	 * <scope> ::= {base|one|subtree}
	 *
	 * <scope> defaults to "base"
	 * <base> must pass DN normalization
	 * <filter> must pass str2filter()
	 */
	rc = ldap_url_parse( uri->bv_val, &ludp );
	if ( rc == LDAP_URL_ERR_BADSCHEME ) {
		/*
		 * last chance: assume it's a(n exact) DN ...
		 *
		 * NOTE: must pass DN normalization
		 */
		bv.bv_val = uri->bv_val;
		*scope = LDAP_X_SCOPE_EXACT;
		goto is_dn;
	}

	if ( rc != LDAP_URL_SUCCESS ) {
		return LDAP_PROTOCOL_ERROR;
	}

	if (( ludp->lud_host && *ludp->lud_host )
		|| ludp->lud_attrs || ludp->lud_exts )
	{
		/* host part must be empty */
		/* attrs and extensions parts must be empty */
		rc = LDAP_PROTOCOL_ERROR;
		goto done;
	}

	/* Grab the scope */
	*scope = ludp->lud_scope;

	/* Grab the filter */
	if ( ludp->lud_filter ) {
		*filter = str2filter_x( op, ludp->lud_filter );
		if ( *filter == NULL ) {
			rc = LDAP_PROTOCOL_ERROR;
			goto done;
		}
		ber_str2bv( ludp->lud_filter, 0, 0, fstr );
	}

	/* Grab the searchbase */
	ber_str2bv( ludp->lud_dn, 0, 0, base );
	rc = dnNormalize( 0, NULL, NULL, base, nbase, op->o_tmpmemctx );

done:
	if( rc != LDAP_SUCCESS ) {
		if( *filter ) filter_free_x( op, *filter );
		BER_BVZERO( base );
		BER_BVZERO( fstr );
	} else {
		/* Don't free these, return them to caller */
		ludp->lud_filter = NULL;
		ludp->lud_dn = NULL;
	}

	ldap_free_urldesc( ludp );
	return( rc );
}

static int slap_sasl_rx_off(char *rep, int *off)
{
	const char *c;
	int n;

	/* Precompile replace pattern. Find the $<n> placeholders */
	off[0] = -2;
	n = 1;
	for ( c = rep;	 *c;  c++ ) {
		if ( *c == '\\' && c[1] ) {
			c++;
			continue;
		}
		if ( *c == '$' ) {
			if ( n == SASLREGEX_REPLACE ) {
#ifdef NEW_LOGGING
				LDAP_LOG( TRANSPORT, ERR, 
					"slap_sasl_rx_off: \"%s\" has too many $n "
					"placeholders (max %d)\n", rep, SASLREGEX_REPLACE, 0  );
#else
				Debug( LDAP_DEBUG_ANY,
					"SASL replace pattern %s has too many $n "
						"placeholders (max %d)\n",
					rep, SASLREGEX_REPLACE, 0 );
#endif

				return( LDAP_OTHER );
			}
			off[n] = c - rep;
			n++;
		}
	}

	/* Final placeholder, after the last $n */
	off[n] = c - rep;
	n++;
	off[n] = -1;
	return( LDAP_SUCCESS );
}

#ifdef SLAP_AUTH_REWRITE
int slap_sasl_rewrite_config( 
		const char	*fname,
		int		lineno,
		int		argc,
		char		**argv
)
{
	int	rc;
	char	*savearg0;

	/* init at first call */
	if ( sasl_rwinfo == NULL ) {
 		sasl_rwinfo = rewrite_info_init( REWRITE_MODE_USE_DEFAULT );
	}

	/* strip "authid-" prefix for parsing */
	savearg0 = argv[0];
	argv[0] += STRLENOF( "authid-" );
 	rc = rewrite_parse( sasl_rwinfo, fname, lineno, argc, argv );
	argv[0] = savearg0;

	return rc;
}

int slap_sasl_rewrite_destroy( void )
{
	if ( sasl_rwinfo ) {
		rewrite_info_delete( &sasl_rwinfo );
		sasl_rwinfo = NULL;
	}

	return 0;
}

int slap_sasl_regexp_rewrite_config(
		const char	*fname,
		int		lineno,
		const char	*match,
		const char	*replace,
		const char	*context )
{
	int	rc;
	char	*newreplace, *p;
	char	*argvRule[] = { "rewriteRule", NULL, NULL, "@", NULL };

	/* init at first call */
	if ( sasl_rwinfo == NULL ) {
		char *argvEngine[] = { "rewriteEngine", "on", NULL };
		char *argvContext[] = { "rewriteContext", NULL, NULL };

		/* initialize rewrite engine */
 		sasl_rwinfo = rewrite_info_init( REWRITE_MODE_USE_DEFAULT );

		/* switch on rewrite engine */
 		rc = rewrite_parse( sasl_rwinfo, fname, lineno, 2, argvEngine );
 		if (rc != LDAP_SUCCESS) {
			return rc;
		}

		/* create generic authid context */
		argvContext[1] = AUTHID_CONTEXT;
 		rc = rewrite_parse( sasl_rwinfo, fname, lineno, 2, argvContext );
 		if (rc != LDAP_SUCCESS) {
			return rc;
		}
	}

	newreplace = ch_strdup( replace );
	
	for (p = strchr( newreplace, '$' ); p; p = strchr( p + 1, '$' ) ) {
		if ( isdigit( p[1] ) ) {
			p[0] = '%';
		} else {
			p++;
		}
	}

	argvRule[1] = (char *)match;
	argvRule[2] = newreplace;
 	rc = rewrite_parse( sasl_rwinfo, fname, lineno, 4, argvRule );
	ch_free( newreplace );

	return rc;
}
#endif /* SLAP_AUTH_REWRITE */

int slap_sasl_regexp_config( const char *match, const char *replace )
{
#ifdef SLAP_AUTH_REWRITE
	return slap_sasl_regexp_rewrite_config( "sasl-regexp", 0,
			match, replace, AUTHID_CONTEXT );
#else /* ! SLAP_AUTH_REWRITE */
	int rc;
	SaslRegexp_t *reg;

	SaslRegexp = (SaslRegexp_t *) ch_realloc( (char *) SaslRegexp,
	  (nSaslRegexp + 1) * sizeof(SaslRegexp_t) );

	reg = &SaslRegexp[nSaslRegexp];

	reg->sr_match = ch_strdup( match );
	reg->sr_replace = ch_strdup( replace );

	/* Precompile matching pattern */
	rc = regcomp( &reg->sr_workspace, reg->sr_match, REG_EXTENDED|REG_ICASE );
	if ( rc ) {
#ifdef NEW_LOGGING
		LDAP_LOG( TRANSPORT, ERR, 
			"slap_sasl_regexp_config: \"%s\" could not be compiled.\n",
			reg->sr_match, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY,
		"SASL match pattern %s could not be compiled by regexp engine\n",
		reg->sr_match, 0, 0 );
#endif

		return( LDAP_OTHER );
	}

	rc = slap_sasl_rx_off( reg->sr_replace, reg->sr_offset );
	if ( rc != LDAP_SUCCESS ) return rc;

	nSaslRegexp++;
	return( LDAP_SUCCESS );
#endif /* ! SLAP_AUTH_REWRITE */
}

/* Perform replacement on regexp matches */
static void slap_sasl_rx_exp(
	const char *rep,
	const int *off,
	regmatch_t *str,
	const char *saslname,
	struct berval *out,
	void *ctx )
{
	int i, n, len, insert;

	/* Get the total length of the final URI */

	n=1;
	len = 0;
	while( off[n] >= 0 ) {
		/* Len of next section from replacement string (x,y,z above) */
		len += off[n] - off[n-1] - 2;
		if( off[n+1] < 0)
			break;

		/* Len of string from saslname that matched next $i  (b,d above) */
		i = rep[ off[n] + 1 ]	- '0';
		len += str[i].rm_eo - str[i].rm_so;
		n++;
	}
	out->bv_val = slap_sl_malloc( len + 1, ctx );
	out->bv_len = len;

	/* Fill in URI with replace string, replacing $i as we go */
	n=1;
	insert = 0;
	while( off[n] >= 0) {
		/* Paste in next section from replacement string (x,y,z above) */
		len = off[n] - off[n-1] - 2;
		strncpy( out->bv_val+insert, rep + off[n-1] + 2, len);
		insert += len;
		if( off[n+1] < 0)
			break;

		/* Paste in string from saslname that matched next $i  (b,d above) */
		i = rep[ off[n] + 1 ]	- '0';
		len = str[i].rm_eo - str[i].rm_so;
		strncpy( out->bv_val+insert, saslname + str[i].rm_so, len );
		insert += len;

		n++;
	}

	out->bv_val[insert] = '\0';
}

/* Take the passed in SASL name and attempt to convert it into an
   LDAP URI to find the matching LDAP entry, using the pattern matching
   strings given in the saslregexp config file directive(s) */

static int slap_authz_regexp( struct berval *in, struct berval *out,
		int flags, void *ctx )
{
#ifdef SLAP_AUTH_REWRITE
	const char	*context = AUTHID_CONTEXT;

	if ( sasl_rwinfo == NULL || BER_BVISNULL( in ) ) {
		return 0;
	}

	/* FIXME: if aware of authc/authz mapping, 
	 * we could use different contexts ... */
	switch ( rewrite_session( sasl_rwinfo, context, in->bv_val, NULL, 
				&out->bv_val ) )
	{
	case REWRITE_REGEXEC_OK:
		if ( !BER_BVISNULL( out ) ) {
			char *val = out->bv_val;
			ber_str2bv_x( val, 0, 1, out, ctx );
			free( val );
		} else {
			ber_dupbv_x( out, in, ctx );
		}
#ifdef NEW_LOGGING
		LDAP_LOG( BACK_LDAP, DETAIL1, 
			"[rw] %s: \"%s\" -> \"%s\"\n",
			context, in->bv_val, out->bv_val );		
#else /* !NEW_LOGGING */
		Debug( LDAP_DEBUG_ARGS,
			"[rw] %s: \"%s\" -> \"%s\"\n",
			context, in->bv_val, out->bv_val );		
#endif /* !NEW_LOGGING */
		return 1;
 		
 	case REWRITE_REGEXEC_UNWILLING:
	case REWRITE_REGEXEC_ERR:
	default:
		return 0;
	}

#else /* ! SLAP_AUTH_REWRITE */
	char *saslname = in->bv_val;
	SaslRegexp_t *reg;
  	regmatch_t sr_strings[SASLREGEX_REPLACE];	/* strings matching $1,$2 ... */
	int i;

	memset( out, 0, sizeof( *out ) );

#ifdef NEW_LOGGING
	LDAP_LOG( TRANSPORT, ENTRY, 
		"slap_authz_regexp: converting SASL name %s\n", saslname, 0, 0 );
#else
	Debug( LDAP_DEBUG_TRACE, "slap_authz_regexp: converting SASL name %s\n",
	   saslname, 0, 0 );
#endif

	if (( saslname == NULL ) || ( nSaslRegexp == 0 )) {
		return( 0 );
	}

	/* Match the normalized SASL name to the saslregexp patterns */
	for( reg = SaslRegexp,i=0;  i<nSaslRegexp;  i++,reg++ ) {
		if ( regexec( &reg->sr_workspace, saslname, SASLREGEX_REPLACE,
		  sr_strings, 0)  == 0 )
			break;
	}

	if( i >= nSaslRegexp ) return( 0 );

	/*
	 * The match pattern may have been of the form "a(b.*)c(d.*)e" and the
	 * replace pattern of the form "x$1y$2z". The returned string needs
	 * to replace the $1,$2 with the strings that matched (b.*) and (d.*)
	 */
	slap_sasl_rx_exp( reg->sr_replace, reg->sr_offset,
		sr_strings, saslname, out, ctx );

#ifdef NEW_LOGGING
	LDAP_LOG( TRANSPORT, ENTRY, 
		"slap_authz_regexp: converted SASL name to %s\n",
		BER_BVISEMPTY( out ) ? "" : out->bv_val, 0, 0 );
#else
	Debug( LDAP_DEBUG_TRACE,
		"slap_authz_regexp: converted SASL name to %s\n",
		BER_BVISEMPTY( out ) ? "" : out->bv_val, 0, 0 );
#endif

	return( 1 );
#endif /* ! SLAP_AUTH_REWRITE */
}

/* This callback actually does some work...*/
static int sasl_sc_sasl2dn( Operation *o, SlapReply *rs )
{
	struct berval *ndn = o->o_callback->sc_private;

	if (rs->sr_type != REP_SEARCH) return 0;

	/* We only want to be called once */
	if ( !BER_BVISNULL( ndn ) ) {
		o->o_tmpfree(ndn->bv_val, o->o_tmpmemctx);
		BER_BVZERO( ndn );

#ifdef NEW_LOGGING
		LDAP_LOG( TRANSPORT, DETAIL1,
			"slap_sc_sasl2dn: search DN returned more than 1 entry\n", 0, 0, 0 );
#else
		Debug( LDAP_DEBUG_TRACE,
			"slap_sc_sasl2dn: search DN returned more than 1 entry\n", 0, 0, 0 );
#endif
		return -1;
	}

	ber_dupbv_x(ndn, &rs->sr_entry->e_nname, o->o_tmpmemctx);
	return 0;
}


typedef struct smatch_info {
	struct berval *dn;
	int match;
} smatch_info;

static int sasl_sc_smatch( Operation *o, SlapReply *rs )
{
	smatch_info *sm = o->o_callback->sc_private;

	if ( rs->sr_type != REP_SEARCH ) {
		if ( rs->sr_err != LDAP_SUCCESS ) {
			sm->match = -1;
		}
		return 0;
	}

	if ( sm->match == 1 ) {
		sm->match = -1;
		return 0;
	}

	if (dn_match(sm->dn, &rs->sr_entry->e_nname)) {
		sm->match = 1;

	} else {
		sm->match = -1;
	}

	return 0;
}

int
slap_sasl_matches( Operation *op, BerVarray rules,
		struct berval *assertDN, struct berval *authc )
{
	int	rc = LDAP_INAPPROPRIATE_AUTH;

	if ( rules != NULL ) {
		int	i;

		for( i = 0; !BER_BVISNULL( &rules[i] ); i++ ) {
			rc = slap_sasl_match( op, &rules[i], assertDN, authc );
			if ( rc == LDAP_SUCCESS ) break;
		}
	}
	
	return rc;
}

/*
 * Map a SASL regexp rule to a DN. If the rule is just a DN or a scope=base
 * URI, just strcmp the rule (or its searchbase) to the *assertDN. Otherwise,
 * the rule must be used as an internal search for entries. If that search
 * returns the *assertDN entry, the match is successful.
 *
 * The assertDN should not have the dn: prefix
 */

static
int slap_sasl_match( Operation *opx, struct berval *rule,
	struct berval *assertDN, struct berval *authc )
{
	int rc; 
	regex_t reg;
	smatch_info sm;
	slap_callback cb = { NULL, sasl_sc_smatch, NULL, NULL };
	Operation op = {0};
	SlapReply rs = {REP_RESULT};

	sm.dn = assertDN;
	sm.match = 0;
	cb.sc_private = &sm;

#ifdef NEW_LOGGING
	LDAP_LOG( TRANSPORT, ENTRY, 
		"slap_sasl_match: comparing DN %s to rule %s\n", 
		assertDN->bv_val, rule->bv_val,0 );
#else
	Debug( LDAP_DEBUG_TRACE,
	   "===>slap_sasl_match: comparing DN %s to rule %s\n",
		assertDN->bv_val, rule->bv_val, 0 );
#endif

	rc = slap_parseURI( opx, rule, &op.o_req_dn,
		&op.o_req_ndn, &op.oq_search.rs_scope, &op.oq_search.rs_filter,
		&op.ors_filterstr );
	if( rc != LDAP_SUCCESS ) goto CONCLUDED;

	/* Massive shortcut: search scope == base */
	switch ( op.oq_search.rs_scope ) {
	case LDAP_SCOPE_BASE:
	case LDAP_X_SCOPE_EXACT:
exact_match:
		if ( dn_match( &op.o_req_ndn, assertDN ) ) {
			rc = LDAP_SUCCESS;
		} else {
			rc = LDAP_INAPPROPRIATE_AUTH;
		}
		goto CONCLUDED;

	case LDAP_X_SCOPE_CHILDREN:
	case LDAP_X_SCOPE_SUBTREE:
	case LDAP_X_SCOPE_ONELEVEL:
	{
		int	d = assertDN->bv_len - op.o_req_ndn.bv_len;

		rc = LDAP_INAPPROPRIATE_AUTH;

		if ( d == 0 && op.oq_search.rs_scope == LDAP_X_SCOPE_SUBTREE ) {
			goto exact_match;

		} else if ( d > 0 ) {
			struct berval bv;

			/* leave room for at least one char of attributeType,
			 * one for '=' and one for ',' */
			if ( d < STRLENOF( "x=,") ) {
				goto CONCLUDED;
			}

			bv.bv_len = op.o_req_ndn.bv_len;
			bv.bv_val = assertDN->bv_val + d;

			if ( bv.bv_val[ -1 ] == ',' && dn_match( &op.o_req_ndn, &bv ) ) {
				switch ( op.oq_search.rs_scope ) {
				case LDAP_X_SCOPE_SUBTREE:
				case LDAP_X_SCOPE_CHILDREN:
					rc = LDAP_SUCCESS;
					break;

				case LDAP_X_SCOPE_ONELEVEL:
				{
					struct berval	pdn;

					dnParent( assertDN, &pdn );
					/* the common portion of the DN
					 * already matches, so only check
					 * if parent DN of assertedDN 
					 * is all the pattern */
					if ( pdn.bv_len == op.o_req_ndn.bv_len ) {
						rc = LDAP_SUCCESS;
					}
					break;
				}
				default:
					/* at present, impossible */
					assert( 0 );
				}
			}
		}
		goto CONCLUDED;
	}

	case LDAP_X_SCOPE_REGEX:
		rc = regcomp(&reg, op.o_req_ndn.bv_val,
			REG_EXTENDED|REG_ICASE|REG_NOSUB);
		if ( rc == 0 ) {
			rc = regexec(&reg, assertDN->bv_val, 0, NULL, 0);
			regfree( &reg );
		}
		if ( rc == 0 ) {
			rc = LDAP_SUCCESS;
		} else {
			rc = LDAP_INAPPROPRIATE_AUTH;
		}
		goto CONCLUDED;

	case LDAP_X_SCOPE_GROUP: {
		char	*tmp;

		/* Now filterstr looks like "(&(objectClass=<group_oc>)(<member_at>="
		 * we need to append the <assertDN> so that the <group_dn> is searched
		 * with scope "base", and the filter ensures that <assertDN> is
		 * member of the group */
		tmp = ch_realloc( op.ors_filterstr.bv_val,
				op.ors_filterstr.bv_len + assertDN->bv_len + STRLENOF( /* (( */ "))" ) + 1 );
		if ( tmp == NULL ) {
			rc = LDAP_NO_MEMORY;
			goto CONCLUDED;
		}
		op.ors_filterstr.bv_val = tmp;
		
		tmp = lutil_strcopy( &tmp[ op.ors_filterstr.bv_len ], assertDN->bv_val );
		tmp = lutil_strcopy( tmp, /* (( */ "))" );

		/* pass opx because str2filter_x may (and does) use o_tmpmfuncs */
		op.ors_filter = str2filter_x( opx, op.ors_filterstr.bv_val );
		if ( op.ors_filter == NULL ) {
			rc = LDAP_PROTOCOL_ERROR;
			goto CONCLUDED;
		}
		op.ors_scope = LDAP_SCOPE_BASE;

		/* hijack match DN: use that of the group instead of the assertDN;
		 * assertDN is now in the filter */
		sm.dn = &op.o_req_ndn;

		/* do the search */
		break;
		}

	default:
		break;
	}

	/* Must run an internal search. */
	if ( op.oq_search.rs_filter == NULL ) {
		rc = LDAP_FILTER_ERROR;
		goto CONCLUDED;
	}

#ifdef NEW_LOGGING
	LDAP_LOG( TRANSPORT, DETAIL1, 
		"slap_sasl_match: performing internal search (base=%s, scope=%d)\n",
		op.o_req_ndn.bv_val, op.oq_search.rs_scope, 0 );
#else
	Debug( LDAP_DEBUG_TRACE,
	   "slap_sasl_match: performing internal search (base=%s, scope=%d)\n",
	   op.o_req_ndn.bv_val, op.oq_search.rs_scope, 0 );
#endif

	op.o_bd = select_backend( &op.o_req_ndn, 0, 1 );
	if(( op.o_bd == NULL ) || ( op.o_bd->be_search == NULL)) {
		rc = LDAP_INAPPROPRIATE_AUTH;
		goto CONCLUDED;
	}

	op.o_tag = LDAP_REQ_SEARCH;
	op.o_protocol = LDAP_VERSION3;
	op.o_ndn = *authc;
	op.o_callback = &cb;
	op.o_time = slap_get_time();
	op.o_do_not_cache = 1;
	op.o_is_auth_check = 1;
	op.o_threadctx = opx->o_threadctx;
	op.o_tmpmemctx = opx->o_tmpmemctx;
	op.o_tmpmfuncs = opx->o_tmpmfuncs;
#ifdef LDAP_SLAPI
	op.o_pb = opx->o_pb;
#endif
	op.o_conn = opx->o_conn;
	op.o_connid = opx->o_connid;
	/* use req_ndn as req_dn instead of non-pretty base of uri */
	if( !BER_BVISNULL( &op.o_req_dn ) ) ch_free( op.o_req_dn.bv_val );
	ber_dupbv_x( &op.o_req_dn, &op.o_req_ndn, op.o_tmpmemctx );
	op.oq_search.rs_slimit = 1;
	op.oq_search.rs_tlimit = -1;
	op.o_sync_slog_size = -1;

	op.o_bd->be_search( &op, &rs );

	if (sm.match == 1) {
		rc = LDAP_SUCCESS;
	} else {
		rc = LDAP_INAPPROPRIATE_AUTH;
	}

CONCLUDED:
	if( !BER_BVISNULL( &op.o_req_dn ) ) slap_sl_free( op.o_req_dn.bv_val, opx->o_tmpmemctx );
	if( !BER_BVISNULL( &op.o_req_ndn ) ) slap_sl_free( op.o_req_ndn.bv_val, opx->o_tmpmemctx );
	if( op.oq_search.rs_filter ) filter_free_x( opx, op.oq_search.rs_filter );
	if( !BER_BVISNULL( &op.ors_filterstr ) ) ch_free( op.ors_filterstr.bv_val );

#ifdef NEW_LOGGING
	LDAP_LOG( TRANSPORT, ENTRY, 
		"slap_sasl_match: comparison returned %d\n", rc, 0, 0 );
#else
	Debug( LDAP_DEBUG_TRACE,
	   "<===slap_sasl_match: comparison returned %d\n", rc, 0, 0);
#endif

	return( rc );
}


/*
 * This function answers the question, "Can this ID authorize to that ID?",
 * based on authorization rules. The rules are stored in the *searchDN, in the
 * attribute named by *attr. If any of those rules map to the *assertDN, the
 * authorization is approved.
 *
 * The DNs should not have the dn: prefix
 */
static int
slap_sasl_check_authz( Operation *op,
	struct berval *searchDN,
	struct berval *assertDN,
	AttributeDescription *ad,
	struct berval *authc )
{
	int i, rc;
	BerVarray vals = NULL;

#ifdef NEW_LOGGING
	LDAP_LOG( TRANSPORT, ENTRY, 
		"slap_sasl_check_authz: does %s match %s rule in %s?\n",
	    assertDN->bv_val, ad->ad_cname.bv_val, searchDN->bv_val);
#else
	Debug( LDAP_DEBUG_TRACE,
	   "==>slap_sasl_check_authz: does %s match %s rule in %s?\n",
	   assertDN->bv_val, ad->ad_cname.bv_val, searchDN->bv_val);
#endif

	rc = backend_attribute( op, NULL, searchDN, ad, &vals );
	if( rc != LDAP_SUCCESS ) goto COMPLETE;

	/* Check if the *assertDN matches any *vals */
	rc = slap_sasl_matches( op, vals, assertDN, authc );

COMPLETE:
	if( vals ) ber_bvarray_free_x( vals, op->o_tmpmemctx );

#ifdef NEW_LOGGING
	LDAP_LOG( TRANSPORT, RESULTS, 
		"slap_sasl_check_authz: %s check returning %s\n", 
		ad->ad_cname.bv_val, rc, 0 );
#else
	Debug( LDAP_DEBUG_TRACE,
	   "<==slap_sasl_check_authz: %s check returning %d\n",
		ad->ad_cname.bv_val, rc, 0);
#endif

	return( rc );
}

/*
 * Given a SASL name (e.g. "UID=name,cn=REALM,cn=MECH,cn=AUTH")
 * return the LDAP DN to which it matches. The SASL regexp rules in the config
 * file turn the SASL name into an LDAP URI. If the URI is just a DN (or a
 * search with scope=base), just return the URI (or its searchbase). Otherwise
 * an internal search must be done, and if that search returns exactly one
 * entry, return the DN of that one entry.
 */
void slap_sasl2dn( Operation *opx,
	struct berval *saslname, struct berval *sasldn, int flags )
{
	int rc;
	slap_callback cb = { NULL, sasl_sc_sasl2dn, NULL, NULL };
	Operation op = {0};
	SlapReply rs = {REP_RESULT};
	struct berval regout = BER_BVNULL;

#ifdef NEW_LOGGING
	LDAP_LOG( TRANSPORT, ENTRY, 
		"slap_sasl2dn: converting SASL name %s to DN.\n",
		saslname->bv_val, 0, 0 );
#else
	Debug( LDAP_DEBUG_TRACE, "==>slap_sasl2dn: "
		"converting SASL name %s to a DN\n",
		saslname->bv_val, 0,0 );
#endif

	sasldn->bv_val = NULL;
	sasldn->bv_len = 0;
	cb.sc_private = sasldn;

	/* Convert the SASL name into a minimal URI */
	if( !slap_authz_regexp( saslname, &regout, flags, opx->o_tmpmemctx ) ) {
		goto FINISHED;
	}

	rc = slap_parseURI( opx, &regout, &op.o_req_dn,
		&op.o_req_ndn, &op.oq_search.rs_scope, &op.oq_search.rs_filter,
		&op.ors_filterstr );
	if ( !BER_BVISNULL( &regout ) ) slap_sl_free( regout.bv_val, opx->o_tmpmemctx );
	if ( rc != LDAP_SUCCESS ) {
		goto FINISHED;
	}

	/* Must do an internal search */
	op.o_bd = select_backend( &op.o_req_ndn, 0, 1 );

	/* Massive shortcut: search scope == base */
	switch ( op.oq_search.rs_scope ) {
	case LDAP_SCOPE_BASE:
	case LDAP_X_SCOPE_EXACT:
		*sasldn = op.o_req_ndn;
		BER_BVZERO( &op.o_req_ndn );
		/* intentionally continue to next case */

	case LDAP_X_SCOPE_REGEX:
	case LDAP_X_SCOPE_SUBTREE:
	case LDAP_X_SCOPE_CHILDREN:
	case LDAP_X_SCOPE_ONELEVEL:
	case LDAP_X_SCOPE_GROUP:
		/* correctly parsed, but illegal */
		goto FINISHED;

	case LDAP_SCOPE_ONELEVEL:
	case LDAP_SCOPE_SUBTREE:
#ifdef LDAP_SCOPE_SUBORDINATE
	case LDAP_SCOPE_SUBORDINATE:
#endif
		/* do a search */
		break;

	default:
		/* catch unhandled cases (there shouldn't be) */
		assert( 0 );
	}

#ifdef NEW_LOGGING
	LDAP_LOG( TRANSPORT, DETAIL1, 
		"slap_sasl2dn: performing internal search (base=%s, scope=%d)\n",
		op.o_req_ndn.bv_val, op.oq_search.rs_scope, 0 );
#else
	Debug( LDAP_DEBUG_TRACE,
		"slap_sasl2dn: performing internal search (base=%s, scope=%d)\n",
		op.o_req_ndn.bv_val, op.oq_search.rs_scope, 0 );
#endif

	if(( op.o_bd == NULL ) || ( op.o_bd->be_search == NULL)) {
		goto FINISHED;
	}

	op.o_conn = opx->o_conn;
	op.o_connid = opx->o_connid;
	op.o_tag = LDAP_REQ_SEARCH;
	op.o_protocol = LDAP_VERSION3;
	op.o_ndn = opx->o_conn->c_ndn;
	op.o_callback = &cb;
	op.o_time = slap_get_time();
	op.o_do_not_cache = 1;
	op.o_is_auth_check = 1;
	op.o_threadctx = opx->o_threadctx;
	op.o_tmpmemctx = opx->o_tmpmemctx;
	op.o_tmpmfuncs = opx->o_tmpmfuncs;
#ifdef LDAP_SLAPI
	op.o_pb = opx->o_pb;
#endif
	op.oq_search.rs_deref = LDAP_DEREF_NEVER;
	op.oq_search.rs_slimit = 1;
	op.oq_search.rs_tlimit = -1;
	op.oq_search.rs_attrsonly = 1;
	/* use req_ndn as req_dn instead of non-pretty base of uri */
	if( !BER_BVISNULL( &op.o_req_dn ) ) ch_free( op.o_req_dn.bv_val );
	ber_dupbv_x( &op.o_req_dn, &op.o_req_ndn, op.o_tmpmemctx );

	op.o_bd->be_search( &op, &rs );
	
FINISHED:
	if( !BER_BVISEMPTY( sasldn ) ) {
		opx->o_conn->c_authz_backend = op.o_bd;
	}
	if( !BER_BVISNULL( &op.o_req_dn ) ) slap_sl_free( op.o_req_dn.bv_val, opx->o_tmpmemctx );
	if( !BER_BVISNULL( &op.o_req_ndn ) ) slap_sl_free( op.o_req_ndn.bv_val, opx->o_tmpmemctx );
	if( op.oq_search.rs_filter ) filter_free_x( opx, op.oq_search.rs_filter );
	if( !BER_BVISNULL( &op.ors_filterstr ) ) ch_free( op.ors_filterstr.bv_val );

#ifdef NEW_LOGGING
	LDAP_LOG( TRANSPORT, ENTRY, 
		"slap_sasl2dn: Converted SASL name to %s\n",
		!BER_BVISEMPTY( sasldn ) ? sasldn->bv_val : "<nothing>", 0, 0 );
#else
	Debug( LDAP_DEBUG_TRACE, "<==slap_sasl2dn: Converted SASL name to %s\n",
		!BER_BVISEMPTY( sasldn ) ? sasldn->bv_val : "<nothing>", 0, 0 );
#endif

	return;
}


/* Check if a bind can SASL authorize to another identity.
 * The DNs should not have the dn: prefix
 */

int slap_sasl_authorized( Operation *op,
	struct berval *authcDN, struct berval *authzDN )
{
	int rc = LDAP_INAPPROPRIATE_AUTH;

	/* User binding as anonymous */
	if ( authzDN == NULL ) {
		rc = LDAP_SUCCESS;
		goto DONE;
	}

#ifdef NEW_LOGGING
	LDAP_LOG( TRANSPORT, ENTRY, 
		"slap_sasl_authorized: can %s become %s?\n", 
		authcDN->bv_val, authzDN->bv_val, 0 );
#else
	Debug( LDAP_DEBUG_TRACE,
	   "==>slap_sasl_authorized: can %s become %s?\n",
		authcDN->bv_val, authzDN->bv_val, 0 );
#endif

	/* If person is authorizing to self, succeed */
	if ( dn_match( authcDN, authzDN ) ) {
		rc = LDAP_SUCCESS;
		goto DONE;
	}

	/* Allow the manager to authorize as any DN. */
	if( op->o_conn->c_authz_backend &&
		be_isroot_dn( op->o_conn->c_authz_backend, authcDN ))
	{
		rc = LDAP_SUCCESS;
		goto DONE;
	}

	/* Check source rules */
	if( authz_policy & SASL_AUTHZ_TO ) {
		rc = slap_sasl_check_authz( op, authcDN, authzDN,
			slap_schema.si_ad_saslAuthzTo, authcDN );
		if( rc == LDAP_SUCCESS && !(authz_policy & SASL_AUTHZ_AND) ) {
			goto DONE;
		}
	}

	/* Check destination rules */
	if( authz_policy & SASL_AUTHZ_FROM ) {
		rc = slap_sasl_check_authz( op, authzDN, authcDN,
			slap_schema.si_ad_saslAuthzFrom, authcDN );
		if( rc == LDAP_SUCCESS ) {
			goto DONE;
		}
	}

	rc = LDAP_INAPPROPRIATE_AUTH;

DONE:

#ifdef NEW_LOGGING
	LDAP_LOG( TRANSPORT, RESULTS, "slap_sasl_authorized: return %d\n", rc,0,0 );
#else
	Debug( LDAP_DEBUG_TRACE,
		"<== slap_sasl_authorized: return %d\n", rc, 0, 0 );
#endif

	return( rc );
}
