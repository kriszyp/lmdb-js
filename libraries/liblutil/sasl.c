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

static int interaction(
	sasl_interact_t *interact )
{
	char input[1024];

	int noecho=0;
	int challenge=0;

	switch( interact->id ) {
	case SASL_CB_NOECHOPROMPT:
		noecho = 1;
		challenge = 1;
		break;
	case SASL_CB_ECHOPROMPT:
		challenge = 1;
		break;
	case SASL_CB_PASS:
		noecho = 1;
		break;
	}

	if( challenge ) {
		if( interact->challenge ) {
			fprintf( stderr, "Challenge: %s\n", interact->challenge );
		}
		if( interact->defresult ) {
			fprintf( stderr, "Default Result: %s\n", interact->defresult );
		}
	}

	sprintf( input, "%s: ",
		interact->prompt ? interact->prompt : "Interaction required" );

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
		/* must be empty */
		interact->result = strdup("");
	}

	return LDAP_SUCCESS;
}

int lutil_sasl_interact(
	LDAP *ld,
	void *in )
{
	sasl_interact_t *interact = in;

	fputs( "SASL Interaction\n", stderr );

	while( interact->id != SASL_CB_LIST_END ) {
		int rc = interaction( interact );

		if( rc )  return rc;
		interact++;
	}
	
	return LDAP_SUCCESS;
}

#endif
