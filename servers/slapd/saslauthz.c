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

#include <ac/stdlib.h>
#include <stdio.h>

#include "slap.h"
#include "proto-slap.h"

#include <ac/string.h>

#ifdef HAVE_CYRUS_SASL
#include <limits.h>
#include <sasl.h>
#include <ldap_pvt.h>
#endif





/* URI format:  ldap://<host>/<base>[?[<attrs>][?[<scope>][?[<filter>]]]]   */

int slap_parseURI( char *uri, char **searchbase, int *scope, Filter **filter )
{
	char *start, *end;


	assert( uri != NULL );
	*searchbase = NULL;
	*scope = -1;
	*filter = NULL;

	Debug( LDAP_DEBUG_TRACE, "slap_parseURI: parsing %s\n", uri, 0, 0 );

	/* If it does not look like a URI, assume it is a DN */
	if( strncasecmp( uri, "ldap://", 7 ) ) {
		*searchbase = ch_strdup( uri );
		dn_normalize( *searchbase );
		*scope = LDAP_SCOPE_BASE;
		return( LDAP_SUCCESS );
	}

	end = strchr( uri + 7, '/' );
	if ( end == NULL )
		return( LDAP_PROTOCOL_ERROR );

	/* could check the hostname here */

	/* Grab the searchbase */
	start = end+1;
	end = strchr( start, '?' );
	if( end == NULL ) {
		*searchbase = ch_strdup( start );
		dn_normalize( *searchbase );
		return( LDAP_SUCCESS );
	}
	*end = '\0';
	*searchbase = ch_strdup( start );
	*end = '?';
	dn_normalize( *searchbase );

	/* Skip the attrs */
	start = end+1;
	end = strchr( start, '?' );
	if( end == NULL ) {
		return( LDAP_SUCCESS );
	}

	/* Grab the scope */
	start = end+1;
	if( !strncasecmp( start, "base?", 5 )) {
		*scope = LDAP_SCOPE_BASE;
		start += 5;
	}
	else if( !strncasecmp( start, "one?", 4 )) {
		*scope = LDAP_SCOPE_ONELEVEL;
		start += 4;
	}
	else if( !strncasecmp( start, "sub?", 3 )) {
		*scope = LDAP_SCOPE_SUBTREE;
		start += 4;
	}
	else {
		ch_free( *searchbase );
		*searchbase = NULL;
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

	SaslRegexp = (SaslRegexp_t *) ch_realloc( (char *) SaslRegexp,
	  (nSaslRegexp + 1) * sizeof(SaslRegexp_t) );
	reg = &( SaslRegexp[nSaslRegexp] );
	reg->match = ch_strdup( match );
	reg->replace = ch_strdup( replace );
	dn_normalize( reg->match );
	dn_normalize( reg->replace );

	/* Precompile matching pattern */
	rc = regcomp( &reg->workspace, reg->match, REG_EXTENDED|REG_ICASE );
	if ( rc ) {
		Debug( LDAP_DEBUG_ANY,
		"SASL match pattern %s could not be compiled by regexp engine\n",
		reg->match, 0, 0 );
		return( LDAP_OPERATIONS_ERROR );
	}

	/* Precompile replace pattern. Find the $<n> placeholders */
	reg->offset[0] = -2;
	n = 1;
	for ( c = reg->replace;  *c;  c++ ) {
		if ( *c == '\\' ) {
			c++;
			continue;
		}
		if ( *c == '$' ) {
			if ( n == SASLREGEX_REPLACE ) {
				Debug( LDAP_DEBUG_ANY,
				   "SASL replace pattern %s has too many $n placeholders (max %d)\n",
				   reg->replace, SASLREGEX_REPLACE, 0 );
				return( LDAP_OPERATIONS_ERROR );
			}
			reg->offset[n] = c - reg->replace;
			n++;
		}
	}

	/* Final placeholder, after the last $n */
	reg->offset[n] = c - reg->replace;
	n++;
	reg->offset[n] = -1;

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


	Debug( LDAP_DEBUG_TRACE, "slap_sasl_regexp: converting SASL name %s\n",
	   saslname, 0, 0 );
	if (( saslname == NULL ) || ( nSaslRegexp == 0 ))
		return( NULL );

	/* Match the normalized SASL name to the saslregexp patterns */
	for( reg = SaslRegexp,i=0;  i<nSaslRegexp;  i++,reg++ ) {
		if ( regexec( &reg->workspace, saslname, SASLREGEX_REPLACE,
		  reg->strings, 0)  == 0 )
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
	while( reg->offset[n] >= 0 ) {
		/* Len of next section from replacement string (x,y,z above) */
		len += reg->offset[n] - reg->offset[n-1] - 2;
		if( reg->offset[n+1] < 0)
			break;

		/* Len of string from saslname that matched next $i  (b,d above) */
		i = reg->replace[ reg->offset[n] + 1 ]  - '0';
		len += reg->strings[i].rm_eo - reg->strings[i].rm_so;
		n++;
	}
	uri = ch_malloc( len + 1 );

	/* Fill in URI with replace string, replacing $i as we go */
	n=1;
	insert = 0;
	while( reg->offset[n] >= 0) {
		/* Paste in next section from replacement string (x,y,z above) */
		len = reg->offset[n] - reg->offset[n-1] - 2;
		strncpy( uri+insert, reg->replace + reg->offset[n-1] + 2, len);
		insert += len;
		if( reg->offset[n+1] < 0)
			break;

		/* Paste in string from saslname that matched next $i  (b,d above) */
		i = reg->replace[ reg->offset[n] + 1 ]  - '0';
		len = reg->strings[i].rm_eo - reg->strings[i].rm_so;
		strncpy( uri+insert, saslname + reg->strings[i].rm_so, len );
		insert += len;

		n++;
	}

	uri[insert] = '\0';
	Debug( LDAP_DEBUG_TRACE,
	   "slap_sasl_regexp: converted SASL name to %s\n", uri, 0, 0 );
	return( uri );
}





/*
 * Given a SASL name (e.g. "UID=name+cn=REALM,cn=MECH,cn=AUTHZ")
 * return the LDAP DN to which it matches. The SASL regexp rules in the config
 * file turn the SASL name into an LDAP URI. If the URI is just a DN (or a
 * search with scope=base), just return the URI (or its searchbase). Otherwise
 * an internal search must be done, and if that search returns exactly one
 * entry, return the DN of that one entry.
 */

static
char *slap_sasl2dn( char *saslname )
{
	char *uri=NULL, *searchbase=NULL, *DN=NULL;
	int rc, scope;
	Backend *be;
	Filter *filter=NULL;
	Connection *conn=NULL;
	LDAP *client=NULL;
	LDAPMessage *res=NULL, *msg;


	Debug( LDAP_DEBUG_TRACE,
	  "==>slap_sasl2dn: Converting SASL name %s to a DN\n", saslname, 0,0 );

	/* Convert the SASL name into an LDAP URI */
	uri = slap_sasl_regexp( saslname );
	if( uri == NULL )
		goto FINISHED;

	rc = slap_parseURI( uri, &searchbase, &scope, &filter );
	if( rc )
		goto FINISHED;

	/* Massive shortcut: search scope == base */
	if( scope == LDAP_SCOPE_BASE ) {
		DN = ch_strdup( searchbase );
		goto FINISHED;
	}

	/* Must do an internal search */

	Debug( LDAP_DEBUG_TRACE,
	   "slap_sasl2dn: performing internal search (base=%s, scope=%d)\n",
	   searchbase, scope, 0 );

	be = select_backend( searchbase, 0 );
	if(( be == NULL ) || ( be->be_search == NULL))
		goto FINISHED;
	searchbase = suffix_alias( be, searchbase );

	rc = connection_internal_open( &conn, &client, saslname );
	if( rc != LDAP_SUCCESS )
		goto FINISHED;

	(*be->be_search)( be, conn, conn->c_ops, /*base=*/NULL, searchbase,
	   scope, /*deref=*/1, /*sizelimit=*/1, /*time=*/0, filter, /*fstr=*/NULL,
	   /*attrs=*/NULL, /*attrsonly=*/0 );


	/* Read the client side of the internal search */
	rc = ldap_result( client, LDAP_RES_ANY, LDAP_MSG_ALL, NULL, &res );
	if( rc == -1 )
		goto FINISHED;

	/* Make sure exactly one entry was returned */
	rc = ldap_count_entries( client, res );
	Debug( LDAP_DEBUG_TRACE,
	   "slap_sasl2dn: search DN returned %d entries\n", rc,0,0 );
	if( rc != 1 )
		goto FINISHED;

	msg = ldap_first_entry( client, res );
	DN = ldap_get_dn( client, msg );

FINISHED:
	if( searchbase ) ch_free( searchbase );
	if( filter ) filter_free( filter );
	if( uri ) ch_free( uri );
	if( conn ) connection_internal_close( conn );
	if( res ) ldap_msgfree( res );
	if( client  ) ldap_unbind( client );
	if( DN ) dn_normalize( DN );
	Debug( LDAP_DEBUG_TRACE, "<==slap_sasl2dn: Converted SASL name to %s\n",
	   DN ? DN : "<nothing>", 0, 0 );
	return( DN );
}





/*
 * Map a SASL regexp rule to a DN. If the rule is just a DN or a scope=base
 * URI, just strcmp the rule (or its searchbase) to the *assertDN. Otherwise,
 * the rule must be used as an internal search for entries. If that search
 * returns the *assertDN entry, the match is successful.
 */

static
int slap_sasl_match( char *rule, char *assertDN, char *authc )
{
	char *searchbase=NULL, *dn=NULL;
	int rc, scope;
	Backend *be;
	Filter *filter=NULL;
	Connection *conn=NULL;
	LDAP *client=NULL;
	LDAPMessage *res=NULL, *msg;


	Debug( LDAP_DEBUG_TRACE,
	   "===>slap_sasl_match: comparing DN %s to rule %s\n", assertDN, rule, 0 );

	rc = slap_parseURI( rule, &searchbase, &scope, &filter );
	if( rc != LDAP_SUCCESS )
		goto CONCLUDED;

	/* Massive shortcut: search scope == base */
	if( scope == LDAP_SCOPE_BASE ) {
		dn_normalize( searchbase );
		if( strcmp( searchbase, assertDN ) == 0 )
			rc = LDAP_SUCCESS;
		else
			rc = LDAP_INAPPROPRIATE_AUTH;
		goto CONCLUDED;
	}

	/* Must run an internal search. */

	Debug( LDAP_DEBUG_TRACE,
	   "slap_sasl_match: performing internal search (base=%s, scope=%d)\n",
	   searchbase, scope, 0 );

	be = select_backend( searchbase, 0 );
	if(( be == NULL ) || ( be->be_search == NULL)) {
		rc = LDAP_INAPPROPRIATE_AUTH;
		goto CONCLUDED;
	}
	searchbase = suffix_alias( be, searchbase );

	/* Make an internal connection on which to run the search */
	rc = connection_internal_open( &conn, &client, authc );
	if( rc != LDAP_SUCCESS )
		goto CONCLUDED;

	(*be->be_search)( be, conn, conn->c_ops, /*base=*/NULL, searchbase,
	   scope, /*deref=*/1, /*sizelimit=*/0, /*time=*/0, filter, /*fstr=*/NULL,
	   /*attrs=*/NULL, /*attrsonly=*/0 );


	/* On the client side of the internal search, read the results. Check
	   if the assertDN matches any of the DN's returned by the search */
	rc = ldap_result( client, LDAP_RES_ANY, LDAP_MSG_ALL, NULL, &res );
	if( rc == -1 )
		goto CONCLUDED;

	for( msg=ldap_first_entry( client, res );
	      msg;
	      msg=ldap_next_entry( client, msg ) )   {
		dn = ldap_get_dn( client, msg );
		dn_normalize( dn );
		rc = strcmp( dn, assertDN );
		ch_free( dn );
		if( rc == 0 ) {
			rc = LDAP_SUCCESS;
			goto CONCLUDED;
		}
	}
	rc = LDAP_INAPPROPRIATE_AUTH;

CONCLUDED:
	if( searchbase ) ch_free( searchbase );
	if( filter ) filter_free( filter );
	if( conn ) connection_internal_close( conn );
	if( res ) ldap_msgfree( res );
	if( client  ) ldap_unbind( client );
	Debug( LDAP_DEBUG_TRACE,
	   "<===slap_sasl_match: comparison returned %d\n", rc, 0, 0);
	return( rc );
}





/*
 * This function answers the question, "Can this ID authorize to that ID?",
 * based on authorization rules. The rules are stored in the *searchDN, in the
 * attribute named by *attr. If any of those rules map to the *assertDN, the
 * authorization is approved.
 */

static int
slap_sasl_check_authz(char *searchDN, char *assertDN, char *attr, char *authc)
{
	const char *errmsg;
	int i, rc;
	struct berval **vals=NULL;
	AttributeDescription *ad=NULL;


	Debug( LDAP_DEBUG_TRACE,
	   "==>slap_sasl_check_authz: does %s match %s rule in %s?\n",
	   assertDN, attr, searchDN);
	rc = slap_str2ad( attr, &ad, &errmsg );
	if( rc != LDAP_SUCCESS )
		goto COMPLETE;

	rc = backend_attribute( NULL, NULL, NULL, NULL, searchDN, ad, &vals );
	if( rc != LDAP_SUCCESS )
		goto COMPLETE;

	/* Check if the *assertDN matches any **vals */
	for( i=0; vals[i] != NULL; i++ ) {
		rc = slap_sasl_match( vals[i]->bv_val, assertDN, authc );
		if ( rc == LDAP_SUCCESS )
			goto COMPLETE;
	}
	rc = LDAP_INAPPROPRIATE_AUTH;

COMPLETE:
	if( vals ) ber_bvecfree( vals );
	if( ad ) ad_free( ad, 1 );

	Debug( LDAP_DEBUG_TRACE,
	   "<==slap_sasl_check_authz: %s check returning %d\n", attr, rc, 0);
	return( rc );
}



#endif  /* HAVE_CYRUS_SASL */





/* Check if a bind can SASL authorize to another identity. */

int slap_sasl_authorized( Connection *conn,
	const char *authcid, const char *authzid )
{
	int rc;
	char *saslname=NULL,*authcDN=NULL,*realm=NULL, *authzDN=NULL;

#ifdef HAVE_CYRUS_SASL
	Debug( LDAP_DEBUG_TRACE,
	   "==>slap_sasl_authorized: can %s become %s?\n", authcid, authzid, 0 );

	/* Create a complete SASL name for the SASL regexp patterns */

	sasl_getprop( conn->c_sasl_context, SASL_REALM, (void **)&realm );

	/* Allocate space */
	rc = strlen("uid=,cn=,cn=,cn=AUTHZ ");
	if ( realm ) rc += strlen( realm );
	if ( authcid ) rc += strlen( authcid );
	rc += strlen( conn->c_sasl_bind_mech );
	saslname = ch_malloc( rc );

	/* Build the SASL name with whatever we have, and normalize it */
	saslname[0] = '\0';
	rc = 0;
	if ( authcid )
		rc += sprintf( saslname+rc, "%sUID=%s", rc?",":"", authcid);
	if ( realm )
		rc += sprintf( saslname+rc, "%sCN=%s", rc?",":"", realm);
	if ( conn->c_sasl_bind_mech )
		rc += sprintf( saslname+rc, "%sCN=%s", rc?",":"",
		   conn->c_sasl_bind_mech);
	sprintf( saslname+rc, "%sCN=AUTHZ", rc?",":"");
	dn_normalize( saslname );

	authcDN = slap_sasl2dn( saslname );
	if( authcDN == NULL )
		goto DONE;

	/* Normalize the name given by the clientside of the connection */
	authzDN = ch_strdup( authzid );
	dn_normalize( authzDN );


	/* Check source rules */
	rc = slap_sasl_check_authz( authcDN, authzDN, SASL_AUTHZ_SOURCE_ATTR,
	   authcDN );
	if( rc == LDAP_SUCCESS )
		goto DONE;

	/* Check destination rules */
	rc = slap_sasl_check_authz( authzDN, authcDN, SASL_AUTHZ_DEST_ATTR,
	   authcDN );
	if( rc == LDAP_SUCCESS )
		goto DONE;

#endif
	rc = LDAP_INAPPROPRIATE_AUTH;

DONE:
	if( saslname ) ch_free( saslname );
	if( authcDN ) ch_free( authcDN );
	if( authzDN ) ch_free( authzDN );
	Debug( LDAP_DEBUG_TRACE, "<== slap_sasl_authorized: return %d\n",rc,0,0 );
	return( rc );
}
