/*
 * Copyright 1998-1999 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */
/*
 * LDAP controls
 */

#include "portable.h"

#include <stdlib.h>

#include <ac/time.h>
#include <ac/string.h>

#include "ldap-int.h"

/*
 * Free a LDAPControl
 */
void
ldap_control_free( LDAPControl *c )
{
	if ( c != NULL ) {
		if( c->ldctl_oid != NULL) {
			free( c->ldctl_oid );
		}

		if( c->ldctl_value.bv_val != NULL ) {
			free( c->ldctl_value.bv_val );
		}

		free( c );
	}
}

/*
 * Free an array of LDAPControl's
 */
void
ldap_controls_free( LDAPControl **controls )
{
	if ( controls != NULL ) {
		LDAPControl *c;

		for(c = *controls; c != NULL; c++) {
			ldap_control_free( c );
		}

		free( controls );
	}
}

/*
 * Duplicate an array of LDAPControl
 */
LDAPControl **ldap_controls_dup( LDAPControl **controls )
{
	LDAPControl **new;
	int i;

	if ( controls == NULL ) {
		return NULL;
	}

	/* count the controls */
	for(i=0; controls[i] != NULL; i++) /* empty */ ;

	if( i < 1 ) {
		/* no controls to duplicate */
		return NULL;
	}

	new = (LDAPControl **) malloc( i * sizeof(LDAPControl *) );

	if( new == NULL ) {
		/* memory allocation failure */
		return NULL;
	}

	/* duplicate the controls */
	for(i=0; controls[i] != NULL; i++) {
		new[i] = ldap_control_dup( controls[i] );

		if( new[i] == NULL ) {
			ldap_controls_free( new );
			return NULL;
		}
	}

	new[i] = NULL;

	return new;
}

/*
 * Duplicate a LDAPControl
 */
LDAPControl *ldap_control_dup( LDAPControl *c )
{
	LDAPControl *new;

	if ( c == NULL ) {
		return NULL;
	}

	new = (LDAPControl *) malloc( sizeof(LDAPControl) );

	if( new == NULL ) {
		return NULL;
	}

	if( c->ldctl_oid != NULL ) {
		new->ldctl_oid = strdup( c->ldctl_oid );

		if(new->ldctl_oid == NULL) {
			free( new );
			return NULL;
		}

	} else {
		new->ldctl_oid = NULL;
	}

	if( c->ldctl_value.bv_len > 0 ) {
		new->ldctl_value.bv_val = (char *) malloc( c->ldctl_value.bv_len );

		if(new->ldctl_value.bv_val == NULL) {
			if(new->ldctl_oid != NULL) {
				free( new->ldctl_oid );
			}
			free( new );
			return NULL;
		}
		
		SAFEMEMCPY( new->ldctl_value.bv_val, c->ldctl_value.bv_val, 
			c->ldctl_value.bv_len );

		new->ldctl_value.bv_len = c->ldctl_value.bv_len;

	} else {
		new->ldctl_value.bv_len = 0;
		new->ldctl_value.bv_val = NULL;
	}

	new->ldctl_iscritical = c->ldctl_iscritical;
	return new;
}

/* get the controls from the BerElement */
int ldap_get_ber_controls( BerElement *be, LDAPControl ***cp)
{
	return LDAP_NOT_SUPPORTED;
}
