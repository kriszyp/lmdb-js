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





/* URI format:	ldap://<host>/<base>[?[<attrs>][?[<scope>][?[<filter>]]]]   */

int slap_parseURI( char *uri, char **searchbase, int *scope, Filter **filter )
{
	char *start, *end;


	assert( uri != NULL );
	*searchbase = NULL;
	*scope = -1;
	*filter = NULL;

#ifdef NEW_LOGGING
	LDAP_LOG(( "sasl", LDAP_LEVEL_ENTRY,
		   "slap_parseURI: parsing %s\n", uri ));
#else
	Debug( LDAP_DEBUG_TRACE, "slap_parseURI: parsing %s\n", uri, 0, 0 );
#endif


	/* If it does not look like a URI, assume it is a DN */
	if( !strncasecmp( uri, "dn:", 3 ) ) {
		uri += 3;
		uri += strspn( uri, " " );
		*searchbase = ch_strdup( uri );
		dn_normalize( *searchbase );
		*scope = LDAP_SCOPE_BASE;
		return( LDAP_SUCCESS );
	}
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
#ifdef NEW_LOGGING
		LDAP_LOG(( "sasl", LDAP_LEVEL_ERR,
			   "slap_sasl_regexp_config: \"%s\" could not be compiled.\n",
			   reg->match ));
#else
		Debug( LDAP_DEBUG_ANY,
		"SASL match pattern %s could not be compiled by regexp engine\n",
		reg->match, 0, 0 );
#endif

		return( LDAP_OPERATIONS_ERROR );
	}

	/* Precompile replace pattern. Find the $<n> placeholders */
	reg->offset[0] = -2;
	n = 1;
	for ( c = reg->replace;	 *c;  c++ ) {
		if ( *c == '\\' ) {
			c++;
			continue;
		}
		if ( *c == '$' ) {
			if ( n == SASLREGEX_REPLACE ) {
#ifdef NEW_LOGGING
				LDAP_LOG(( "sasl", LDAP_LEVEL_ERR,
					   "slap_sasl_regexp_config: \"%s\" has too many $n placeholders (max %d)\n",
					   reg->replace, SASLREGEX_REPLACE ));
#else
				Debug( LDAP_DEBUG_ANY,
				   "SASL replace pattern %s has too many $n placeholders (max %d)\n",
				   reg->replace, SASLREGEX_REPLACE, 0 );
#endif

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
		i = reg->replace[ reg->offset[n] + 1 ]	- '0';
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
		i = reg->replace[ reg->offset[n] + 1 ]	- '0';
		len = reg->strings[i].rm_eo - reg->strings[i].rm_so;
		strncpy( uri+insert, saslname + reg->strings[i].rm_so, len );
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





/*
 * Given a SASL name (e.g. "UID=name,cn=REALM,cn=MECH,cn=AUTH")
 * return the LDAP DN to which it matches. The SASL regexp rules in the config
 * file turn the SASL name into an LDAP URI. If the URI is just a DN (or a
 * search with scope=base), just return the URI (or its searchbase). Otherwise
 * an internal search must be done, and if that search returns exactly one
 * entry, return the DN of that one entry.
 */

char *slap_sasl2dn( char *saslname )
{
	char *uri=NULL, *searchbase=NULL, *DN=NULL;
	int rc, scope;
	Backend *be;
	Filter *filter=NULL;
	Connection *conn=NULL;
	LDAP *client=NULL;
	LDAPMessage *res=NULL, *msg;


#ifdef NEW_LOGGING
	LDAP_LOG(( "sasl", LDAP_LEVEL_ENTRY,
		   "slap_sasl2dn: converting SASL name %s to DN.\n", saslname ));
#else
	Debug( LDAP_DEBUG_TRACE,
	  "==>slap_sasl2dn: Converting SASL name %s to a DN\n", saslname, 0,0 );
#endif


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

#ifdef NEW_LOGGING
	LDAP_LOG(( "sasl", LDAP_LEVEL_DETAIL1,
		   "slap_sasl2dn: performing internal search (base=%s, scope=%s)\n",
		   searchbase, scope ));
#else
	Debug( LDAP_DEBUG_TRACE,
	   "slap_sasl2dn: performing internal search (base=%s, scope=%d)\n",
	   searchbase, scope, 0 );
#endif


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
#ifdef NEW_LOGGING
	LDAP_LOG(( "sasl", LDAP_LEVEL_DETAIL1,
		   "slap_sasl2dn: search DN returned %d entries\n", rc ));
#else
	Debug( LDAP_DEBUG_TRACE,
	   "slap_sasl2dn: search DN returned %d entries\n", rc,0,0 );
#endif

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
#ifdef NEW_LOGGING
	LDAP_LOG(( "sasl", LDAP_LEVEL_ENTRY,
		   "slap_sasl2dn: Converted SASL name to %s\n", DN ? DN : "<nothing>" ));
#else
	Debug( LDAP_DEBUG_TRACE, "<==slap_sasl2dn: Converted SASL name to %s\n",
	   DN ? DN : "<nothing>", 0, 0 );
#endif

	return( DN );
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
int slap_sasl_match( char *rule, char *assertDN, char *authc )
{
	char *searchbase=NULL, *dn=NULL;
	int rc, scope;
	Backend *be;
	Filter *filter=NULL;
	Connection *conn=NULL;
	LDAP *client=NULL;
	LDAPMessage *res=NULL, *msg;
	regex_t reg;


#ifdef NEW_LOGGING
	LDAP_LOG(( "sasl", LDAP_LEVEL_ENTRY,
		   "slap_sasl_match: comparing DN %s to rule %s\n", assertDN, rule ));
#else
	Debug( LDAP_DEBUG_TRACE,
	   "===>slap_sasl_match: comparing DN %s to rule %s\n", assertDN, rule, 0 );
#endif


	rc = slap_parseURI( rule, &searchbase, &scope, &filter );
	if( rc != LDAP_SUCCESS )
		goto CONCLUDED;

	/* Massive shortcut: search scope == base */
	if( scope == LDAP_SCOPE_BASE ) {
		dn_normalize( searchbase );
		rc = regcomp(&reg, searchbase, REG_EXTENDED|REG_ICASE|REG_NOSUB);
		if ( rc == 0 ) {
			rc = regexec(&reg, assertDN, 0, NULL, 0);
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
		   searchbase, scope ));
#else
	Debug( LDAP_DEBUG_TRACE,
	   "slap_sasl_match: performing internal search (base=%s, scope=%d)\n",
	   searchbase, scope, 0 );
#endif


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
slap_sasl_check_authz(char *searchDN, char *assertDN, char *attr, char *authc)
{
	const char *errmsg;
	int i, rc;
	struct berval **vals=NULL;
	AttributeDescription *ad=NULL;


#ifdef NEW_LOGGING
	LDAP_LOG(( "sasl", LDAP_LEVEL_ENTRY,
		   "slap_sasl_check_authz: does %s match %s rule in %s?\n",
		   assertDN, attr, searchDN ));
#else
	Debug( LDAP_DEBUG_TRACE,
	   "==>slap_sasl_check_authz: does %s match %s rule in %s?\n",
	   assertDN, attr, searchDN);
#endif

	rc = slap_str2ad( attr, &ad, &errmsg );
	if( rc != LDAP_SUCCESS )
		goto COMPLETE;

	rc = backend_attribute( NULL, NULL, NULL, NULL, searchDN+3, ad, &vals );
	if( rc != LDAP_SUCCESS )
		goto COMPLETE;

	/* Check if the *assertDN matches any **vals */
	for( i=0; vals[i] != NULL; i++ ) {
		rc = slap_sasl_match( vals[i]->bv_val, assertDN+3, authc );
		if ( rc == LDAP_SUCCESS )
			goto COMPLETE;
	}
	rc = LDAP_INAPPROPRIATE_AUTH;

COMPLETE:
	if( vals ) ber_bvecfree( vals );
	if( ad ) ad_free( ad, 1 );

#ifdef NEW_LOGGING
	LDAP_LOG(( "sasl", LDAP_LEVEL_ENTRY,
		   "slap_sasl_check_authz: %s check returning %s\n", attr, rc ));
#else
	Debug( LDAP_DEBUG_TRACE,
	   "<==slap_sasl_check_authz: %s check returning %d\n", attr, rc, 0);
#endif

	return( rc );
}



#endif	/* HAVE_CYRUS_SASL */





/* Check if a bind can SASL authorize to another identity.
   Accepts authorization DN's with "dn:" prefix */

int slap_sasl_authorized( char *authcDN, char *authzDN )
{
	int rc;

#ifdef HAVE_CYRUS_SASL
	/* User binding as anonymous */
	if ( authzDN == NULL ) {
		rc = LDAP_SUCCESS;
		goto DONE;
	}

#ifdef NEW_LOGGING
	LDAP_LOG(( "sasl", LDAP_LEVEL_ENTRY,
		   "slap_sasl_authorized: can %s become %s?\n", authcDN, authzDN ));
#else
	Debug( LDAP_DEBUG_TRACE,
	   "==>slap_sasl_authorized: can %s become %s?\n", authcDN, authzDN, 0 );
#endif


	/* If person is authorizing to self, succeed */
	if ( !strcmp( authcDN, authzDN ) ) {
		rc = LDAP_SUCCESS;
		goto DONE;
	}

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
#ifdef NEW_LOGGING
	LDAP_LOG(( "sasl", LDAP_LEVEL_ENTRY,
		   "slap_sasl_authorized: return %d\n", rc ));
#else
	Debug( LDAP_DEBUG_TRACE, "<== slap_sasl_authorized: return %d\n",rc,0,0 );
#endif

	return( rc );
}
