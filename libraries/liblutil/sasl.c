/* $OpenLDAP$ */
/*
 * Copyright 2000 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "portable.h"

#ifdef HAVE_CYRUS_SASL

#include <stdio.h>
#include <ac/stdlib.h>
#include <ac/string.h>
#include <ac/unistd.h>

#include <sasl.h>

#include <ldap.h>
#include "lutil_ldap.h"


typedef struct lutil_sasl_defaults_s {
	char *mech;
	char *realm;
	char *authcid;
	char *passwd;
	char *authzid;
} lutilSASLdefaults;


void *
lutil_sasl_defaults(
	LDAP *ld,
	char *mech,
	char *realm,
	char *authcid,
	char *passwd,
	char *authzid )
{
	lutilSASLdefaults *defaults;
	
	defaults = ber_memalloc( sizeof( lutilSASLdefaults ) );

	if( defaults == NULL ) return NULL;

	defaults->mech = mech;
	defaults->realm = realm;
	defaults->authcid = authcid;
	defaults->passwd = passwd;
	defaults->authzid = authzid;

	if( defaults->mech == NULL ) {
		ldap_get_option( ld, LDAP_OPT_X_SASL_MECH, &defaults->mech );
	}
	if( defaults->realm == NULL ) {
		ldap_get_option( ld, LDAP_OPT_X_SASL_REALM, &defaults->realm );
	}
	if( defaults->authcid == NULL ) {
		ldap_get_option( ld, LDAP_OPT_X_SASL_AUTHCID, &defaults->authcid );
	}
	if( defaults->authzid == NULL ) {
		ldap_get_option( ld, LDAP_OPT_X_SASL_AUTHZID, &defaults->authzid );
	}

	return defaults;
}

static int interaction(
	unsigned flags,
	sasl_interact_t *interact,
	lutilSASLdefaults *defaults )
{
	const char *dflt = interact->defresult;
	char input[1024];

	int noecho=0;
	int challenge=0;

	switch( interact->id ) {
	case SASL_CB_GETREALM:
		if( defaults ) dflt = defaults->realm;
		break;
	case SASL_CB_AUTHNAME:
		if( defaults ) dflt = defaults->authcid;
		break;
	case SASL_CB_PASS:
		if( defaults ) dflt = defaults->passwd;
		noecho = 1;
		break;
	case SASL_CB_USER:
		if( defaults ) dflt = defaults->authzid;
		break;
	case SASL_CB_NOECHOPROMPT:
		noecho = 1;
		challenge = 1;
		break;
	case SASL_CB_ECHOPROMPT:
		challenge = 1;
		break;
	}

	if( dflt && !*dflt ) dflt = NULL;

	if( flags != LDAP_SASL_INTERACTIVE &&
		( dflt || interact->id == SASL_CB_USER ) )
	{
		goto use_default;
	}

	if( flags == LDAP_SASL_QUIET ) {
		/* don't prompt */
		return LDAP_OTHER;
	}

	if( challenge ) {
		if( interact->challenge ) {
			fprintf( stderr, "Challenge: %s\n", interact->challenge );
		}
	}

	if( dflt ) {
		fprintf( stderr, "Default: %s\n", dflt );
	}

	sprintf( input, "%s: ",
		interact->prompt ? interact->prompt : "Interact" );

	if( noecho ) {
		interact->result = (char *) getpassphrase( input );
		interact->len = interact->result
			? strlen( interact->result ) : 0;

	} else {
		/* prompt user */
		fputs( input, stderr );

		/* get input */
		interact->result = fgets( input, sizeof(input), stdin );

		if( interact->result == NULL ) {
			interact->len = 0;
			return LDAP_UNAVAILABLE;
		}

		/* len of input */
		interact->len = strlen(input); 

		if( interact->len > 0 && input[interact->len - 1] == '\n' ) {
			/* input includes '\n', trim it */
			interact->len--;
			input[interact->len] = '\0';
		}
	}


	if( interact->len > 0 ) {
		/* duplicate */
		char *p = interact->result;
		interact->result = strdup( p );

		/* zap */
		memset( p, '\0', interact->len );

	} else {
use_default:
		/* input must be empty */
		interact->result = strdup( (dflt && *dflt) ? dflt : "" );
		interact->len = interact->result
			? strlen( interact->result ) : 0;
	}

	if( defaults && defaults->passwd && interact->id == SASL_CB_PASS ) {
		/* zap password after first use */
		memset( defaults->passwd, '\0', strlen(defaults->passwd) );
		defaults->passwd = NULL;
	}

	return LDAP_SUCCESS;
}

int lutil_sasl_interact(
	LDAP *ld,
	unsigned flags,
	void *defaults,
	void *in )
{
	sasl_interact_t *interact = in;

	if( flags == LDAP_SASL_INTERACTIVE ) {
		fputs( "SASL Interaction\n", stderr );
	}

	while( interact->id != SASL_CB_LIST_END ) {
		int rc = interaction( flags, interact, defaults );

		if( rc )  return rc;
		interact++;
	}
	
	return LDAP_SUCCESS;
}
#endif
