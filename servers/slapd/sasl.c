#include "portable.h"

#include <ac/stdlib.h>
#include <stdio.h>

#include "slap.h"
#include "proto-slap.h"

#include <lber.h>
#include <ldap_log.h>

char **supportedSASLMechanisms = NULL;

#ifdef HAVE_CYRUS_SASL
#include <sasl.h>

int sasl_init( void )
{
	int rc;
	char *data;
	unsigned len, count;
	sasl_conn_t *server = NULL;

	rc = sasl_server_init( NULL, "slapd" );

	if( rc != SASL_OK ) {
		Debug( LDAP_DEBUG_ANY, "sasl_server_init failed\n",
			0, 0, 0 );
		return -1;
	}

	rc = sasl_server_new( "ldap", NULL, NULL, NULL,
		SASL_SECURITY_LAYER, 
		&server );

	if( rc != SASL_OK ) {
		Debug( LDAP_DEBUG_ANY, "sasl_server_new failed\n",
			0, 0, 0 );
		return -1;
	}

#ifdef RESTRICT_SASL
	{
		sasl_security_properties_t secprops;
		memset(&secprops, 0, sizeof(secprops));
		secprops.security_flags = SASL_SEC_NOPLAINTEXT | SASL_SEC_NOANONYMOUS;
		secprops.property_names = NULL;
		secprops.property_values = NULL;
	
		rc = sasl_setprop( server, SASL_SEC_PROPS, &secprops );

		if( rc != SASL_OK ) {
			Debug( LDAP_DEBUG_ANY, "sasl_setprop failed\n",
				0, 0, 0 );
			return -1;
		}
	}
#endif

	rc = sasl_listmech( server, NULL, NULL, ",", NULL,
		&data, &len, &count);

	if( rc != SASL_OK ) {
		Debug( LDAP_DEBUG_ANY, "sasl_listmech failed: %d\n",
			rc, 0, 0 );
		return -1;
	}

	Debug( LDAP_DEBUG_TRACE, "SASL mechanisms: %s\n",
		data, 0, 0 );

	supportedSASLMechanisms = str2charray( data, "," );
	sasl_dispose( &server );

	return 0;
}

int sasl_destroy( void )
{
	charray_free( supportedSASLMechanisms );
	return 0;
}

#else
/* no SASL support */
int sasl_init( void ) { return 0; }
int sasl_destroy( void ) { return 0; }
#endif
