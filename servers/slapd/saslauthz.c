/*
 * Copyright 1998-2003 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */
/*
 * Copyright (c) 2000, Mark Adamson, Carnegie Mellon.  All rights reserved.
 * This software is not subject to any license of Carnegie Mellon University.
 *
 * Redistribution and use in source and binary forms are permitted without 
 * restriction or fee of any kind as long as this notice is preserved.
 *
 * The name "Carnegie Mellon" must not be used to endorse or promote
 * products derived from this software without prior written permission.
 *
 */

#include "portable.h"

#include <stdio.h>

#include <ac/stdlib.h>
#include <ac/string.h>

#include "slap.h"

#include <limits.h>

#include <ldap_pvt.h>

#define SASLREGEX_REPLACE 10

typedef struct sasl_regexp {
  char *sr_match;							/* regexp match pattern */
  char *sr_replace; 						/* regexp replace pattern */
  regex_t sr_workspace;						/* workspace for regexp engine */
  int sr_offset[SASLREGEX_REPLACE+2];		/* offsets of $1,$2... in *replace */
} SaslRegexp_t;

static int nSaslRegexp = 0;
static SaslRegexp_t *SaslRegexp = NULL;

/* What SASL proxy authorization policies are allowed? */
#define	SASL_AUTHZ_NONE	0
#define	SASL_AUTHZ_FROM	1
#define	SASL_AUTHZ_TO	2

static int authz_policy = SASL_AUTHZ_NONE;

int slap_sasl_setpolicy( const char *arg )
{
	int rc = LDAP_SUCCESS;

	if ( strcasecmp( arg, "none" ) == 0 ) {
		authz_policy = SASL_AUTHZ_NONE;
	} else if ( strcasecmp( arg, "from" ) == 0 ) {
		authz_policy = SASL_AUTHZ_FROM;
	} else if ( strcasecmp( arg, "to" ) == 0 ) {
		authz_policy = SASL_AUTHZ_TO;
	} else if ( strcasecmp( arg, "both" ) == 0 ) {
		authz_policy = SASL_AUTHZ_FROM | SASL_AUTHZ_TO;
	} else {
		rc = LDAP_OTHER;
	}
	return rc;
}

/* URI format: ldap://<host>/<base>[?[<attrs>][?[<scope>][?[<filter>]]]] */

static int slap_parseURI( struct berval *uri,
	struct berval *searchbase, int *scope, Filter **filter )
{
	struct berval bv;
	int rc;
	LDAPURLDesc *ludp;

	assert( uri != NULL && uri->bv_val != NULL );
	searchbase->bv_val = NULL;
	searchbase->bv_len = 0;
	*scope = -1;
	*filter = NULL;

#ifdef NEW_LOGGING
	LDAP_LOG( TRANSPORT, ENTRY, 
		"slap_parseURI: parsing %s\n", uri->bv_val, 0, 0 );
#else
	Debug( LDAP_DEBUG_TRACE, "slap_parseURI: parsing %s\n", uri->bv_val, 0, 0 );
#endif

	/* If it does not look like a URI, assume it is a DN */
	if( !strncasecmp( uri->bv_val, "dn:", sizeof("dn:")-1 ) ) {
		bv.bv_val = uri->bv_val + sizeof("dn:")-1;
		bv.bv_val += strspn( bv.bv_val, " " );

is_dn:	bv.bv_len = uri->bv_len - (bv.bv_val - uri->bv_val);

		rc = dnNormalize2( NULL, &bv, searchbase );
		if( rc == LDAP_SUCCESS ) {
			*scope = LDAP_SCOPE_BASE;
		}
		return( rc );
	}

	rc = ldap_url_parse( uri->bv_val, &ludp );
	if ( rc == LDAP_URL_ERR_BADSCHEME ) {
		bv.bv_val = uri->bv_val;
		goto is_dn;
	}

	if ( rc != LDAP_URL_SUCCESS ) {
		return LDAP_PROTOCOL_ERROR;
	}

	if (( ludp->lud_host && *ludp->lud_host )
		|| ludp->lud_attrs || ludp->lud_exts )
	{
		/* host part should be empty */
		/* attrs and extensions parts should be empty */
		return LDAP_PROTOCOL_ERROR;
	}

	/* Grab the scope */
	*scope = ludp->lud_scope;

	/* Grab the filter */
	if ( ludp->lud_filter ) {
		*filter = str2filter( ludp->lud_filter );
		if ( *filter == NULL ) {
			rc = LDAP_PROTOCOL_ERROR;
			goto done;
		}
	}

	/* Grab the searchbase */
	bv.bv_val = ludp->lud_dn;
	bv.bv_len = strlen( bv.bv_val );
	rc = dnNormalize2( NULL, &bv, searchbase );

done:
	if( rc != LDAP_SUCCESS ) {
		if( *filter ) filter_free( *filter );
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

int slap_sasl_regexp_config( const char *match, const char *replace )
{
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
}


/* Perform replacement on regexp matches */
static void slap_sasl_rx_exp(
	const char *rep,
	const int *off,
	regmatch_t *str,
	const char *saslname,
	struct berval *out )
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
	out->bv_val = ch_malloc( len + 1 );
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

static int slap_sasl_regexp( struct berval *in, struct berval *out )
{
	char *saslname = in->bv_val;
	SaslRegexp_t *reg;
  	regmatch_t sr_strings[SASLREGEX_REPLACE];	/* strings matching $1,$2 ... */
	int i;

	memset( out, 0, sizeof( *out ) );

#ifdef NEW_LOGGING
	LDAP_LOG( TRANSPORT, ENTRY, 
		"slap_sasl_regexp: converting SASL name %s\n", saslname, 0, 0 );
#else
	Debug( LDAP_DEBUG_TRACE, "slap_sasl_regexp: converting SASL name %s\n",
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
		sr_strings, saslname, out );

#ifdef NEW_LOGGING
	LDAP_LOG( TRANSPORT, ENTRY, 
		"slap_sasl_regexp: converted SASL name to %s\n",
		out->bv_len ? out->bv_val : "", 0, 0 );
#else
	Debug( LDAP_DEBUG_TRACE,
		"slap_sasl_regexp: converted SASL name to %s\n",
		out->bv_len ? out->bv_val : "", 0, 0 );
#endif

	return( 1 );
}

/* Two empty callback functions to avoid sending results */
void slap_cb_null_response( Connection *conn, Operation *o, ber_tag_t tag,
	ber_int_t msgid, ber_int_t err, const char *matched,
	const char *text, BerVarray ref, const char *resoid,
	struct berval *resdata, struct berval *sasldata, LDAPControl **c)
{
}

void slap_cb_null_sresult( Connection *conn, Operation *o, ber_int_t err,
	const char *matched, const char *text, BerVarray refs, LDAPControl **c,
	int nentries)
{
}

int slap_cb_null_sreference( BackendDB *db, Connection *conn, Operation *o, 
	Entry *e, BerVarray r, LDAPControl **c, BerVarray *v2)
{
	return 0;
}

/* This callback actually does some work...*/
static int sasl_sc_sasl2dn( BackendDB *be, Connection *conn, Operation *o,
	Entry *e, AttributeName *an, int ao, LDAPControl **c)
{
	struct berval *ndn = o->o_callback->sc_private;

	/* We only want to be called once */
	if( ndn->bv_val ) {
		free(ndn->bv_val);
		ndn->bv_val = NULL;

#ifdef NEW_LOGGING
		LDAP_LOG( TRANSPORT, DETAIL1,
			"slap_sasl2dn: search DN returned more than 1 entry\n", 0, 0, 0 );
#else
		Debug( LDAP_DEBUG_TRACE,
			"slap_sasl2dn: search DN returned more than 1 entry\n", 0,0,0 );
#endif
		return -1;
	}

	ber_dupbv(ndn, &e->e_nname);
	return 0;
}


typedef struct smatch_info {
	struct berval *dn;
	int match;
} smatch_info;

static int sasl_sc_smatch( BackendDB *be, Connection *conn, Operation *o,
	Entry *e, AttributeName *an, int ao, LDAPControl **c)
{
	smatch_info *sm = o->o_callback->sc_private;

	if (dn_match(sm->dn, &e->e_nname)) {
		sm->match = 1;
		return -1;	/* short-circuit the search */
	}

	return 1;
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
int slap_sasl_match(Connection *conn, struct berval *rule, struct berval *assertDN, struct berval *authc )
{
	struct berval searchbase = {0, NULL};
	int rc, scope;
	Backend *be;
	Filter *filter=NULL;
	regex_t reg;
	smatch_info sm;
	slap_callback cb = {
		slap_cb_null_response,
		slap_cb_null_sresult,
		sasl_sc_smatch,
		NULL
	};
	Operation op = {0};

#ifdef NEW_LOGGING
	LDAP_LOG( TRANSPORT, ENTRY, 
		"slap_sasl_match: comparing DN %s to rule %s\n", 
		assertDN->bv_val, rule->bv_val,0 );
#else
	Debug( LDAP_DEBUG_TRACE,
	   "===>slap_sasl_match: comparing DN %s to rule %s\n",
		assertDN->bv_val, rule->bv_val, 0 );
#endif

	rc = slap_parseURI( rule, &searchbase, &scope, &filter );
	if( rc != LDAP_SUCCESS ) goto CONCLUDED;

	/* Massive shortcut: search scope == base */
	if( scope == LDAP_SCOPE_BASE ) {
		rc = regcomp(&reg, searchbase.bv_val,
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
	}

	/* Must run an internal search. */

#ifdef NEW_LOGGING
	LDAP_LOG( TRANSPORT, DETAIL1, 
		"slap_sasl_match: performing internal search (base=%s, scope=%d)\n",
		searchbase.bv_val, scope,0 );
#else
	Debug( LDAP_DEBUG_TRACE,
	   "slap_sasl_match: performing internal search (base=%s, scope=%d)\n",
	   searchbase.bv_val, scope, 0 );
#endif

	be = select_backend( &searchbase, 0, 1 );
	if(( be == NULL ) || ( be->be_search == NULL)) {
		rc = LDAP_INAPPROPRIATE_AUTH;
		goto CONCLUDED;
	}

	sm.dn = assertDN;
	sm.match = 0;
	cb.sc_private = &sm;

	op.o_tag = LDAP_REQ_SEARCH;
	op.o_protocol = LDAP_VERSION3;
	op.o_ndn = *authc;
	op.o_callback = &cb;
	op.o_time = slap_get_time();
	op.o_do_not_cache = 1;
	op.o_is_auth_check = 1;
	op.o_threadctx = conn->c_sasl_bindop->o_threadctx;

	(*be->be_search)( be, conn, &op, /*base=*/NULL, &searchbase,
	   scope, /*deref=*/1, /*sizelimit=*/0, /*time=*/0, filter, /*fstr=*/NULL,
	   /*attrs=*/NULL, /*attrsonly=*/0 );

	if (sm.match) {
		rc = LDAP_SUCCESS;
	} else {
		rc = LDAP_INAPPROPRIATE_AUTH;
	}

CONCLUDED:
	if( searchbase.bv_len ) ch_free( searchbase.bv_val );
	if( filter ) filter_free( filter );

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
slap_sasl_check_authz( Connection *conn,
	struct berval *searchDN,
	struct berval *assertDN,
	AttributeDescription *ad,
	struct berval *authc )
{
	int i, rc;
	BerVarray vals=NULL;

#ifdef NEW_LOGGING
	LDAP_LOG( TRANSPORT, ENTRY, 
		"slap_sasl_check_authz: does %s match %s rule in %s?\n",
	    assertDN->bv_val, ad->ad_cname.bv_val, searchDN->bv_val);
#else
	Debug( LDAP_DEBUG_TRACE,
	   "==>slap_sasl_check_authz: does %s match %s rule in %s?\n",
	   assertDN->bv_val, ad->ad_cname.bv_val, searchDN->bv_val);
#endif

	rc = backend_attribute( NULL, NULL, conn->c_sasl_bindop, NULL,
		searchDN, ad, &vals );
	if( rc != LDAP_SUCCESS ) goto COMPLETE;

	/* Check if the *assertDN matches any **vals */
	for( i=0; vals[i].bv_val != NULL; i++ ) {
		rc = slap_sasl_match( conn, &vals[i], assertDN, authc );
		if ( rc == LDAP_SUCCESS ) goto COMPLETE;
	}
	rc = LDAP_INAPPROPRIATE_AUTH;

COMPLETE:
	if( vals ) ber_bvarray_free( vals );

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
void slap_sasl2dn( Connection *conn,
	struct berval *saslname, struct berval *sasldn )
{
	int rc;
	Backend *be = NULL;
	struct berval dn = { 0, NULL };
	int scope = LDAP_SCOPE_BASE;
	Filter *filter = NULL;
	slap_callback cb = { slap_cb_null_response,
		slap_cb_null_sresult, sasl_sc_sasl2dn, slap_cb_null_sreference, NULL};
	Operation op = {0};
	struct berval regout = { 0, NULL };

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
	if( !slap_sasl_regexp( saslname, &regout ) ) {
		goto FINISHED;
	}

	rc = slap_parseURI( &regout, &dn, &scope, &filter );
	if( regout.bv_val ) ch_free( regout.bv_val );
	if( rc != LDAP_SUCCESS ) {
		goto FINISHED;
	}

	/* Must do an internal search */
	be = select_backend( &dn, 0, 1 );

	/* Massive shortcut: search scope == base */
	if( scope == LDAP_SCOPE_BASE ) {
		*sasldn = dn;
		dn.bv_len = 0;
		dn.bv_val = NULL;
		goto FINISHED;
	}

#ifdef NEW_LOGGING
	LDAP_LOG( TRANSPORT, DETAIL1, 
		"slap_sasl2dn: performing internal search (base=%s, scope=%d)\n",
		dn.bv_val, scope, 0 );
#else
	Debug( LDAP_DEBUG_TRACE,
		"slap_sasl2dn: performing internal search (base=%s, scope=%d)\n",
		dn.bv_val, scope, 0 );
#endif

	if(( be == NULL ) || ( be->be_search == NULL)) {
		goto FINISHED;
	}

	op.o_tag = LDAP_REQ_SEARCH;
	op.o_protocol = LDAP_VERSION3;
	op.o_ndn = conn->c_ndn;
	op.o_callback = &cb;
	op.o_time = slap_get_time();
	op.o_do_not_cache = 1;
	op.o_is_auth_check = 1;
	op.o_threadctx = conn->c_sasl_bindop->o_threadctx;

	(*be->be_search)( be, conn, &op, NULL, &dn,
		scope, LDAP_DEREF_NEVER, 1, 0,
		filter, NULL, NULL, 1 );
	
FINISHED:
	if( sasldn->bv_len ) {
		conn->c_authz_backend = be;
	}
	if( dn.bv_len ) ch_free( dn.bv_val );
	if( filter ) filter_free( filter );

#ifdef NEW_LOGGING
	LDAP_LOG( TRANSPORT, ENTRY, 
		"slap_sasl2dn: Converted SASL name to %s\n",
		sasldn->bv_len ? sasldn->bv_val : "<nothing>", 0, 0 );
#else
	Debug( LDAP_DEBUG_TRACE, "<==slap_sasl2dn: Converted SASL name to %s\n",
		sasldn->bv_len ? sasldn->bv_val : "<nothing>", 0, 0 );
#endif

	return;
}


/* Check if a bind can SASL authorize to another identity.
 * The DNs should not have the dn: prefix
 */

int slap_sasl_authorized( Connection *conn,
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
	if( conn->c_authz_backend && be_isroot( conn->c_authz_backend, authcDN )) {
		rc = LDAP_SUCCESS;
		goto DONE;
	}

	/* Check source rules */
	if( authz_policy & SASL_AUTHZ_TO ) {
		rc = slap_sasl_check_authz( conn, authcDN, authzDN,
			slap_schema.si_ad_saslAuthzTo, authcDN );
		if( rc == LDAP_SUCCESS ) {
			goto DONE;
		}
	}

	/* Check destination rules */
	if( authz_policy & SASL_AUTHZ_FROM ) {
		rc = slap_sasl_check_authz( conn, authzDN, authcDN,
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
