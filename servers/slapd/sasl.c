#include "portable.h"

#ifdef HAVE_CYRUS_SASL

#include <stdio.h>

#include "slap.h"
#include "proto-slap.h"

#include <lber.h>
#include <ldap_log.h>

#ifdef MAIN
#undef Debug
#define Debug(x,s,a,b,c) fprintf(stderr, s, a, b, c)
#endif

#include <sasl.h>

/* sasl server context */
static sasl_conn_t *server = NULL;

int sasl_init( void )
{
	int rc;
	char *data;
	unsigned len, count;
	sasl_security_properties_t secprops;

	rc = sasl_server_init( NULL, "slapd" );

	if( rc != SASL_OK ) {
		Debug( LDAP_DEBUG_ANY, "sasl_server_init failed\n",
			0, 0, 0 );
		exit(-1);
	}

	rc = sasl_server_new( "ldap", NULL, NULL, NULL,
		SASL_SECURITY_LAYER, 
		&server );

	if( rc != SASL_OK ) {
		Debug( LDAP_DEBUG_ANY, "sasl_server_new failed\n",
			0, 0, 0 );
		exit(-1);
	}

	memset(&secprops, 0, sizeof(secprops));
	secprops.security_flags = SASL_SEC_NOPLAINTEXT | SASL_SEC_NOANONYMOUS;
	secprops.property_names = NULL;
	secprops.property_values = NULL;
	
	rc = sasl_setprop( server, SASL_SEC_PROPS, &secprops );

	if( rc != SASL_OK ) {
		Debug( LDAP_DEBUG_ANY, "sasl_setprop failed\n",
			0, 0, 0 );
		exit(-1);
	}

	rc = sasl_listmech( server, NULL, NULL, ",", NULL,
		&data, &len, &count);

	if( rc != SASL_OK ) {
		Debug( LDAP_DEBUG_ANY, "sasl_listmech failed: %d\n",
			rc, 0, 0 );
		exit(-1);
	}

	Debug( LDAP_DEBUG_TRACE, "SASL mechanisms: %s\n",
		data, 0, 0 );

	return 0;
}

int sasl_destory( void )
{
	if( server != NULL ) {
		sasl_dispose( &server );
	}
}

#ifdef MAIN
int main( int argc, char* argv[] )
{
	int rc = sasl_init();

	sasl_destory();

	exit(rc);
}
#endif
#endif
