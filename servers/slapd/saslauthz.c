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

#ifdef HAVE_CYRUS_SASL
#include <limits.h>

#ifdef HAVE_SASL_SASL_H
#include <sasl/sasl.h>
#else
#include <sasl.h>
#endif

#include <ldap_pvt.h>
#endif

/* URI format: ldap://<host>/<base>[?[<attrs>][?[<scope>][?[<filter>]]]] */

static int slap_parseURI( char *uri,
	struct berval *searchbase, int *scope, Filter **filter )
{
	char *start, *end;
	struct berval bv;
	int rc;


	assert( uri != NULL );
	searchbase->bv_val = NULL;
	searchbase->bv_len = 0;
	*scope = -1;
	*filter = NULL;

#ifdef NEW_LOGGING
	LDAP_LOG(( "sasl", LDAP_LEVEL_ENTRY,
		"slap_parseURI: parsing %s\n", uri ));
#else
	Debug( LDAP_DEBUG_TRACE, "slap_parseURI: parsing %s\n", uri, 0, 0 );
#endif

	/* If it does not look like a URI, assume it is a DN */
	if( !strncasecmp( uri, "dn:", sizeof("dn:")-1 ) ) {
		uri += sizeof("dn:")-1;
		uri += strspn( uri, " " );
		bv.bv_val = uri;
		/* FIXME: if dnNormalize actually uses input bv_len we
		 * will have to make this right.
		 */
is_dn:		bv.bv_len = 1;
		rc = dnNormalize2( NULL, &bv, searchbase );
		if (rc == LDAP_SUCCESS) {
			*scope = LDAP_SCOPE_BASE;
		}
		return( rc );
	}

	/* FIXME: should use ldap_url_parse() */
	if( strncasecmp( uri, "ldap://", sizeof("ldap://")-1 ) ) {
		bv.bv_val = uri;
		goto is_dn;
	}

	end = strchr( uri + (sizeof("ldap://")-1), '/' );
	if ( end == NULL )
		return( LDAP_PROTOCOL_ERROR );

	/* could check the hostname here */

	/* Grab the searchbase */
	start = end+1;
	end = strchr( start, '?' );
	bv.bv_val = start;
	if( end == NULL ) {
		bv.bv_len = 1;
		return dnNormalize2( NULL, &bv, searchbase );
	}
	*end = '\0';
	bv.bv_len = end - start;
	rc = dnNormalize2( NULL, &bv, searchbase );
	*end = '?';
	if (rc != LDAP_SUCCESS)
		return( rc );

	/* Skip the attrs */
	start = end+1;
	end = strchr( start, '?' );
	if( end == NULL ) {
		return( LDAP_SUCCESS );
	}

	/* Grab the scope */
	start = end+1;
	if( !strncasecmp( start, "base?", sizeof("base?")-1 )) {
		*scope = LDAP_SCOPE_BASE;
		start += sizeof("base?")-1;
	}
	else if( !strncasecmp( start, "one?", sizeof("one?")-1 )) {
		*scope = LDAP_SCOPE_ONELEVEL;
		start += sizeof("one?")-1;
	}
	else if( !strncasecmp( start, "sub?", sizeof("sub?")-1 )) {
		*scope = LDAP_SCOPE_SUBTREE;
		start += sizeof("sub?")-1;
	}
	else {
		free( searchbase->bv_val );
		searchbase->bv_val = NULL;
		return( LDAP_PROTOCOL_ERROR );
	}

	/* Grab the filter */
	*filter = str2filter( start );

	return( LDAP_SUCCESS );
}


int slap_sasl_regexp_config( const char *match, const char *replace )
{
#ifdef HAVE_CYRUS_SASL
	const char *c;
	int rc, n;
	SaslRegexp_t *reg;
	struct berval bv, nbv;

	SaslRegexp = (SaslRegexp_t *) ch_realloc( (char *) SaslRegexp,
	  (nSaslRegexp + 1) * sizeof(SaslRegexp_t) );
	reg = &( SaslRegexp[nSaslRegexp] );
	ber_str2bv( match, 0, 0, &bv );
	rc = dnNormalize2( NULL, &bv, &nbv );
	if ( rc ) {
#ifdef NEW_LOGGING
		LDAP_LOG(( "sasl", LDAP_LEVEL_ERR,
			   "slap_sasl_regexp_config: \"%s\" could not be normalized.\n",
			   match ));
#else
		Debug( LDAP_DEBUG_ANY,
		"SASL match pattern %s could not be normalized.\n",
		match, 0, 0 );
#endif
		return( rc );
	}
	reg->sr_match = nbv.bv_val;

	ber_str2bv( replace, 0, 0, &bv );
	rc = dnNormalize2( NULL, &bv, &nbv );
	if ( rc ) {
#ifdef NEW_LOGGING
		LDAP_LOG(( "sasl", LDAP_LEVEL_ERR,
			   "slap_sasl_regexp_config: \"%s\" could not be normalized.\n",
			   replace ));
#else
		Debug( LDAP_DEBUG_ANY,
		"SASL replace pattern %s could not be normalized.\n",
		replace, 0, 0 );
#endif
		return( rc );
	}
	reg->sr_replace = nbv.bv_val;

	/* Precompile matching pattern */
	rc = regcomp( &reg->sr_workspace, reg->sr_match, REG_EXTENDED|REG_ICASE );
	if ( rc ) {
#ifdef NEW_LOGGING
		LDAP_LOG(( "sasl", LDAP_LEVEL_ERR,
			   "slap_sasl_regexp_config: \"%s\" could not be compiled.\n",
			   reg->sr_match ));
#else
		Debug( LDAP_DEBUG_ANY,
		"SASL match pattern %s could not be compiled by regexp engine\n",
		reg->sr_match, 0, 0 );
#endif

		return( LDAP_OPERATIONS_ERROR );
	}

	/* Precompile replace pattern. Find the $<n> placeholders */
	reg->sr_offset[0] = -2;
	n = 1;
	for ( c = reg->sr_replace;	 *c;  c++ ) {
		if ( *c == '\\' ) {
			c++;
			continue;
		}
		if ( *c == '$' ) {
			if ( n == SASLREGEX_REPLACE ) {
#ifdef NEW_LOGGING
				LDAP_LOG(( "sasl", LDAP_LEVEL_ERR,
					"slap_sasl_regexp_config: \"%s\" has too many $n "
						"placeholders (max %d)\n",
					reg->sr_replace, SASLREGEX_REPLACE ));
#else
				Debug( LDAP_DEBUG_ANY,
					"SASL replace pattern %s has too many $n "
						"placeholders (max %d)\n",
					reg->sr_replace, SASLREGEX_REPLACE, 0 );
#endif

				return( LDAP_OPERATIONS_ERROR );
			}
			reg->sr_offset[n] = c - reg->sr_replace;
			n++;
		}
	}

	/* Final placeholder, after the last $n */
	reg->sr_offset[n] = c - reg->sr_replace;
	n++;
	reg->sr_offset[n] = -1;

	nSaslRegexp++;
#endif
	return( LDAP_SUCCESS );
}


#ifdef HAVE_CYRUS_SASL

/* Take the passed in SASL name and attempt to convert it into an
   LDAP URI to find the matching LDAP entry, using the pattern matching
   strings given in the saslregexp config file directive(s) */
static
char *slap_sasl_regexp( char *saslname )
{
	char *uri=NULL;
	int i, n, len, insert;
	SaslRegexp_t *reg;

#ifdef NEW_LOGGING
	LDAP_LOG(( "sasl", LDAP_LEVEL_ENTRY,
		"slap_sasl_regexp: converting SASL name %s\n", saslname ));
#else
	Debug( LDAP_DEBUG_TRACE, "slap_sasl_regexp: converting SASL name %s\n",
	   saslname, 0, 0 );
#endif

	if (( saslname == NULL ) || ( nSaslRegexp == 0 ))
		return( NULL );

	/* Match the normalized SASL name to the saslregexp patterns */
	for( reg = SaslRegexp,i=0;  i<nSaslRegexp;  i++,reg++ ) {
		if ( regexec( &reg->sr_workspace, saslname, SASLREGEX_REPLACE,
		  reg->sr_strings, 0)  == 0 )
			break;
	}

	if( i >= nSaslRegexp )
		return( NULL );

	/*
	 * The match pattern may have been of the form "a(b.*)c(d.*)e" and the
	 * replace pattern of the form "x$1y$2z". The returned string needs
	 * to replace the $1,$2 with the strings that matched (b.*) and (d.*)
	 */


	/* Get the total length of the final URI */

	n=1;
	len = 0;
	while( reg->sr_offset[n] >= 0 ) {
		/* Len of next section from replacement string (x,y,z above) */
		len += reg->sr_offset[n] - reg->sr_offset[n-1] - 2;
		if( reg->sr_offset[n+1] < 0)
			break;

		/* Len of string from saslname that matched next $i  (b,d above) */
		i = reg->sr_replace[ reg->sr_offset[n] + 1 ]	- '0';
		len += reg->sr_strings[i].rm_eo - reg->sr_strings[i].rm_so;
		n++;
	}
	uri = ch_malloc( len + 1 );

	/* Fill in URI with replace string, replacing $i as we go */
	n=1;
	insert = 0;
	while( reg->sr_offset[n] >= 0) {
		/* Paste in next section from replacement string (x,y,z above) */
		len = reg->sr_offset[n] - reg->sr_offset[n-1] - 2;
		strncpy( uri+insert, reg->sr_replace + reg->sr_offset[n-1] + 2, len);
		insert += len;
		if( reg->sr_offset[n+1] < 0)
			break;

		/* Paste in string from saslname that matched next $i  (b,d above) */
		i = reg->sr_replace[ reg->sr_offset[n] + 1 ]	- '0';
		len = reg->sr_strings[i].rm_eo - reg->sr_strings[i].rm_so;
		strncpy( uri+insert, saslname + reg->sr_strings[i].rm_so, len );
		insert += len;

		n++;
	}

	uri[insert] = '\0';
#ifdef NEW_LOGGING
	LDAP_LOG(( "sasl", LDAP_LEVEL_ENTRY,
		"slap_sasl_regexp: converted SASL name to %s\n", uri ));
#else
	Debug( LDAP_DEBUG_TRACE,
	   "slap_sasl_regexp: converted SASL name to %s\n", uri, 0, 0 );
#endif

	return( uri );
}

/* Two empty callback functions to avoid sending results */
static void sasl_sc_r( Connection *conn, Operation *o, ber_tag_t tag,
	ber_int_t msgid, ber_int_t err, const char *matched,
	const char *text, BerVarray ref, const char *resoid,
	struct berval *resdata, struct berval *sasldata, LDAPControl **c)
{
}

static void sasl_sc_s( Connection *conn, Operation *o, ber_int_t err,
	const char *matched, const char *text, BerVarray refs, LDAPControl **c,
	int nentries)
{
}

/* This callback actually does some work...*/
static int sasl_sc_sasl2dn( BackendDB *be, Connection *conn, Operation *o,
	Entry *e, AttributeName *an, int ao, LDAPControl **c)
{
	struct berval *ndn = o->o_callback->sc_private;

	/* We only want to be called once */
	if (ndn->bv_val) {
		free(ndn->bv_val);
		ndn->bv_val = NULL;
#ifdef NEW_LOGGING
	LDAP_LOG(( "sasl", LDAP_LEVEL_DETAIL1,
		   "slap_sasl2dn: search DN returned more than 1 entry\n" ));
#else
	Debug( LDAP_DEBUG_TRACE,
	   "slap_sasl2dn: search DN returned more than 1 entry\n", 0,0,0 );
#endif
		return -1;
	} else {
		ber_dupbv(ndn, &e->e_nname);
		return 0;
	}
}

/*
 * Given a SASL name (e.g. "UID=name,cn=REALM,cn=MECH,cn=AUTH")
 * return the LDAP DN to which it matches. The SASL regexp rules in the config
 * file turn the SASL name into an LDAP URI. If the URI is just a DN (or a
 * search with scope=base), just return the URI (or its searchbase). Otherwise
 * an internal search must be done, and if that search returns exactly one
 * entry, return the DN of that one entry.
 */

void slap_sasl2dn( struct berval *saslname, struct berval *dn )
{
	char *uri=NULL;
	struct berval searchbase = {0, NULL};
	int rc, scope;
	Backend *be;
	Filter *filter=NULL;
	slap_callback cb = {sasl_sc_r, sasl_sc_s, sasl_sc_sasl2dn, NULL};
	Operation op = {0};

#ifdef NEW_LOGGING
	LDAP_LOG(( "sasl", LDAP_LEVEL_ENTRY,
		"slap_sasl2dn: converting SASL name %s to DN.\n", saslname->bv_val ));
#else
	Debug( LDAP_DEBUG_TRACE,
		"==>slap_sasl2dn: Converting SASL name %s to a DN\n", saslname->bv_val, 0,0 );
#endif
	dn->bv_val = NULL;
	dn->bv_len = 0;
	cb.sc_private = dn;

	/* Convert the SASL name into an LDAP URI */
	uri = slap_sasl_regexp( saslname->bv_val );
	if( uri == NULL )
		goto FINISHED;

	rc = slap_parseURI( uri, &searchbase, &scope, &filter );
	if( rc ) {
		goto FINISHED;
	}

	/* Massive shortcut: search scope == base */
	if( scope == LDAP_SCOPE_BASE ) {
		*dn = searchbase;
		searchbase.bv_len = 0;
		searchbase.bv_val = NULL;
		goto FINISHED;
	}

	/* Must do an internal search */

#ifdef NEW_LOGGING
	LDAP_LOG(( "sasl", LDAP_LEVEL_DETAIL1,
		   "slap_sasl2dn: performing internal search (base=%s, scope=%d)\n",
		   searchbase.bv_val, scope ));
#else
	Debug( LDAP_DEBUG_TRACE,
	   "slap_sasl2dn: performing internal search (base=%s, scope=%d)\n",
	   searchbase.bv_val, scope, 0 );
#endif

	be = select_backend( &searchbase, 0, 1 );
	if(( be == NULL ) || ( be->be_search == NULL))
		goto FINISHED;
	suffix_alias( be, &searchbase );

	ldap_pvt_thread_mutex_init( &op.o_abandonmutex );
	op.o_tag = LDAP_REQ_SEARCH;
	op.o_protocol = LDAP_VERSION3;
	op.o_ndn = *saslname;
	op.o_callback = &cb;
	op.o_time = slap_get_time();

	(*be->be_search)( be, /*conn*/NULL, &op, /*base*/NULL, &searchbase,
	   scope, /*deref=*/1, /*sizelimit=*/1, /*time=*/0, filter, /*fstr=*/NULL,
	   /*attrs=*/NULL, /*attrsonly=*/0 );
	
	ldap_pvt_thread_mutex_destroy( &op.o_abandonmutex );

FINISHED:
	if( searchbase.bv_len ) ch_free( searchbase.bv_val );
	if( filter ) filter_free( filter );
	if( uri ) ch_free( uri );

#ifdef NEW_LOGGING
	LDAP_LOG(( "sasl", LDAP_LEVEL_ENTRY,
		"slap_sasl2dn: Converted SASL name to %s\n",
		dn->bv_len ? dn->bv_val : "<nothing>" ));
#else
	Debug( LDAP_DEBUG_TRACE, "<==slap_sasl2dn: Converted SASL name to %s\n",
		dn->bv_len ? dn->bv_val : "<nothing>", 0, 0 );
#endif

	return;
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
	} else {
		return 1;
	}
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
int slap_sasl_match( char *rule, struct berval *assertDN, struct berval *authc )
{
	struct berval searchbase = {0, NULL};
	int rc, scope;
	Backend *be;
	Filter *filter=NULL;
	regex_t reg;
	smatch_info sm;
	slap_callback cb = {sasl_sc_r, sasl_sc_s, sasl_sc_smatch, &sm};
	Operation op = {0};

#ifdef NEW_LOGGING
	LDAP_LOG(( "sasl", LDAP_LEVEL_ENTRY,
		"slap_sasl_match: comparing DN %s to rule %s\n", assertDN->bv_val, rule ));
#else
	Debug( LDAP_DEBUG_TRACE,
	   "===>slap_sasl_match: comparing DN %s to rule %s\n", assertDN->bv_val, rule, 0 );
#endif

	rc = slap_parseURI( rule, &searchbase, &scope, &filter );
	if( rc != LDAP_SUCCESS )
		goto CONCLUDED;

	/* Massive shortcut: search scope == base */
	if( scope == LDAP_SCOPE_BASE ) {
		rc = regcomp(&reg, searchbase.bv_val,
			REG_EXTENDED|REG_ICASE|REG_NOSUB);
		if ( rc == 0 ) {
			rc = regexec(&reg, assertDN->bv_val, 0, NULL, 0);
			regfree( &reg );
		}
		if ( rc == 0 )
			rc = LDAP_SUCCESS;
		else
			rc = LDAP_INAPPROPRIATE_AUTH;
		goto CONCLUDED;
	}

	/* Must run an internal search. */

#ifdef NEW_LOGGING
	LDAP_LOG(( "sasl", LDAP_LEVEL_DETAIL1,
		"slap_sasl_match: performing internal search (base=%s, scope=%d)\n",
		searchbase.bv_val, scope ));
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
	suffix_alias( be, &searchbase );

	sm.dn = assertDN;
	sm.match = 0;

	ldap_pvt_thread_mutex_init( &op.o_abandonmutex );
	op.o_tag = LDAP_REQ_SEARCH;
	op.o_protocol = LDAP_VERSION3;
	op.o_ndn = *authc;
	op.o_callback = &cb;
	op.o_time = slap_get_time();

	(*be->be_search)( be, /*conn=*/NULL, &op, /*base=*/NULL, &searchbase,
	   scope, /*deref=*/1, /*sizelimit=*/0, /*time=*/0, filter, /*fstr=*/NULL,
	   /*attrs=*/NULL, /*attrsonly=*/0 );

	ldap_pvt_thread_mutex_destroy( &op.o_abandonmutex );

	if (sm.match)
		rc = LDAP_SUCCESS;
	else
		rc = LDAP_INAPPROPRIATE_AUTH;

CONCLUDED:
	if( searchbase.bv_len ) ch_free( searchbase.bv_val );
	if( filter ) filter_free( filter );
#ifdef NEW_LOGGING
	LDAP_LOG(( "sasl", LDAP_LEVEL_ENTRY,
		   "slap_sasl_match: comparison returned %d\n", rc ));
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
 * DN's passed in should have a dn: prefix
 */
static int
slap_sasl_check_authz(struct berval *searchDN, struct berval *assertDN, struct berval *attr, struct berval *authc)
{
	const char *errmsg;
	int i, rc;
	BerVarray vals=NULL;
	AttributeDescription *ad=NULL;
	struct berval bv;

#ifdef NEW_LOGGING
	LDAP_LOG(( "sasl", LDAP_LEVEL_ENTRY,
		   "slap_sasl_check_authz: does %s match %s rule in %s?\n",
		   assertDN->bv_val, attr->bv_val, searchDN->bv_val ));
#else
	Debug( LDAP_DEBUG_TRACE,
	   "==>slap_sasl_check_authz: does %s match %s rule in %s?\n",
	   assertDN->bv_val, attr->bv_val, searchDN->bv_val);
#endif

	rc = slap_bv2ad( attr, &ad, &errmsg );
	if( rc != LDAP_SUCCESS )
		goto COMPLETE;

	bv.bv_val = searchDN->bv_val + 3;
	bv.bv_len = searchDN->bv_len - 3;
	rc = backend_attribute( NULL, NULL, NULL, NULL, &bv, ad, &vals );
	if( rc != LDAP_SUCCESS )
		goto COMPLETE;

	bv.bv_val = assertDN->bv_val + 3;
	bv.bv_len = assertDN->bv_len - 3;
	/* Check if the *assertDN matches any **vals */
	for( i=0; vals[i].bv_val != NULL; i++ ) {
		rc = slap_sasl_match( vals[i].bv_val, &bv, authc );
		if ( rc == LDAP_SUCCESS )
			goto COMPLETE;
	}
	rc = LDAP_INAPPROPRIATE_AUTH;

COMPLETE:
	if( vals ) ber_bvarray_free( vals );

#ifdef NEW_LOGGING
	LDAP_LOG(( "sasl", LDAP_LEVEL_ENTRY,
		   "slap_sasl_check_authz: %s check returning %s\n", attr->bv_val, rc ));
#else
	Debug( LDAP_DEBUG_TRACE,
	   "<==slap_sasl_check_authz: %s check returning %d\n", attr->bv_val, rc, 0);
#endif

	return( rc );
}
#endif	/* HAVE_CYRUS_SASL */


/* Check if a bind can SASL authorize to another identity.
   Accepts authorization DN's with "dn:" prefix */

static struct berval sasl_authz_src = {
	sizeof(SASL_AUTHZ_SOURCE_ATTR)-1, SASL_AUTHZ_SOURCE_ATTR };

static struct berval sasl_authz_dst = {
	sizeof(SASL_AUTHZ_DEST_ATTR)-1, SASL_AUTHZ_DEST_ATTR };

int slap_sasl_authorized( struct berval *authcDN, struct berval *authzDN )
{
	int rc = LDAP_INAPPROPRIATE_AUTH;

#ifdef HAVE_CYRUS_SASL
	/* User binding as anonymous */
	if ( authzDN == NULL ) {
		rc = LDAP_SUCCESS;
		goto DONE;
	}

#ifdef NEW_LOGGING
	LDAP_LOG(( "sasl", LDAP_LEVEL_ENTRY,
		"slap_sasl_authorized: can %s become %s?\n", authcDN->bv_val, authzDN->bv_val ));
#else
	Debug( LDAP_DEBUG_TRACE,
	   "==>slap_sasl_authorized: can %s become %s?\n", authcDN->bv_val, authzDN->bv_val, 0 );
#endif

	/* If person is authorizing to self, succeed */
	if ( dn_match( authcDN, authzDN ) ) {
		rc = LDAP_SUCCESS;
		goto DONE;
	}

	/* Check source rules */
	rc = slap_sasl_check_authz( authcDN, authzDN, &sasl_authz_src,
	   authcDN );
	if( rc == LDAP_SUCCESS ) {
		goto DONE;
	}

	/* Check destination rules */
	rc = slap_sasl_check_authz( authzDN, authcDN, &sasl_authz_dst,
	   authcDN );
	if( rc == LDAP_SUCCESS ) {
		goto DONE;
	}

	rc = LDAP_INAPPROPRIATE_AUTH;

DONE:
#endif

#ifdef NEW_LOGGING
	LDAP_LOG(( "sasl", LDAP_LEVEL_ENTRY,
		"slap_sasl_authorized: return %d\n", rc ));
#else
	Debug( LDAP_DEBUG_TRACE,
		"<== slap_sasl_authorized: return %d\n", rc, 0, 0 );
#endif

	return( rc );
}
