#if !defined(lint)
static char copyright[] = "Copyright 1992 The University of Adelaide";
#endif

/*
 *			D E S C R I B E
 *
 * Author:	Mark R. Prior
 *		Communications and Systems Branch
 *		Information Technology Division
 *		The University of Adelaide
 * E-mail:	mrp@itd.adelaide.edu.au
 * Date:	October 1992
 * Version:	1.7
 * Description:
 *		A module implementing the describe whois++ command.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that the above copyright notice and this paragraph are
 * duplicated in all such forms and that any documentation,
 * advertising materials, and other materials related to such
 * distribution and use acknowledge that the software was developed
 * by the University of Adelaide. The name of the University may not
 * be used to endorse or promote products derived from this software
 * without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

#include "whois++.h"

int	displayDescribe( ld, organisation )
LDAP	*ld;
char	*organisation;
{

	int		i, len1, len2;
	LDAPMessage	*result, *entry;
	char		*value, *ptr;
	char		**values;
	static char	*masterDSA[] = { "masterDSA", NULL };
	static char	*manager[] = { "manager", NULL };
	static char	*roleOccupant[] = { "roleOccupant", NULL };
	static char	*attributes[] = { "postalAddress", "telephoneNumber",
			"facsimileTelephoneNumber", "mail", "lastModifiedBy",
#if defined(UOFA)
			"preferredName",
#endif
			NULL };
	extern char	*index();

	if ( !EQ( language, "english" ) ) 
		printFormatted( lineLength, TRUE, stdout,
			"The output of the DESCRIBE command must be in english \
according to the IAFA services template." );

	printFormatted( lineLength, FALSE, stdout,
		"%-19s Whois++", "Service-Name:" );
	if ( hostname != NULL )
		printFormatted( lineLength, FALSE, stdout, "%-19s %s",
			"Primary-Name:", hostname );
	else
		printFormatted( lineLength, FALSE, stdout,
			"%-19s <unknown>", "Primary-Name:" );
	printFormatted( lineLength, FALSE, stdout,
		"%-19s Whois++ service using LDAP to access a Quipu based",
		"Description:" );
	printFormatted( lineLength, FALSE, stdout,
		"%-19s X.500 Directory Service.", "" );
	printFormatted( lineLength, FALSE, stdout,
		"%-19s whois++ protocol on tcp port 43", "Access-Protocol:" );
	printFormatted( lineLength, FALSE, stdout,
		"%-19s whois, x.500, ldap", "Keywords:" );
	printFormatted( lineLength, FALSE, stdout,
		"%-19s 24 hours a day, 7 days a week", "Access-Times:" );
	printFormatted( lineLength, FALSE, stdout,
		"%-19s Open Access", "Policy:" );
	printFormatted( lineLength, FALSE, stdout,
		"%-19s ", "URI:" );
	if ( contact == NULL ) {
		/*
		 * The contact hasn't identified themselves in the tailor file
		 * so lets try to work it out by finding out who manages the
		 * DSA that masters the organisation's entry!
		 */
		if ( debug > 2 )
			printFormatted( lineLength, TRUE, stdout,
				"No contact info provided, searching ..." );
		ldap_search_s( ld, organisation, LDAP_SCOPE_BASE,
			"objectclass=*", masterDSA, 0, &result );
		if ( ld->ld_errno != LDAP_SUCCESS ) {
			printFormatted( lineLength, FALSE, stdout,
				"%-19s <Unknown>", "Contact:" );
			return TRUE;
		}
		if ( debug > 2 )
			printFormatted( lineLength, TRUE, stdout,
				"Looking for the master DSA ..." );
		if ( (values = ldap_get_values( ld, result, "masterDSA" )) == NULL
			|| values[0] == NULL ) {
			printFormatted( lineLength, FALSE, stdout,
				"%-19s <Unknown>", "Contact:" );
			return TRUE;
		}
		if ( debug > 2 )
			printFormatted( lineLength, TRUE, stdout,
				"Searching for the DSA manager ..." );
		ldap_search_s( ld, values[0], LDAP_SCOPE_BASE, "objectclass=*",
			manager, 0, &result );
		if ( ld->ld_errno != LDAP_SUCCESS ) {
			printFormatted( lineLength, FALSE, stdout,
				"%-19s <Unknown>", "Contact:" );
			printFormatted( lineLength, TRUE, stdout,
				"Search failed, %s",
				ldap_err2string( ld->ld_errno ) );
			return TRUE;
		}
		if ( (values = ldap_get_values( ld, result, "manager" )) == NULL ) {
			printFormatted( lineLength, FALSE, stdout,
				"%-19s <Unknown>", "Contact:" );
			return TRUE;
		}
		if ( debug > 2 )
			printFormatted( lineLength, TRUE, stdout,
				"Retrieving the DSA manager's entry ..." );
		/*
		 * we have at least one manager for this DSA but which one is
		 * the "correct" one to list?
		 */
		len1 = strlen( organisation );
		for ( i = 0; values[i] != NULL; i++ )
			if ( strlen( values[i] ) >= len1 ) {
				len2 = strlen( values[i] );
				if ( EQ( organisation, &values[i][len2-len1] ) )
					contact = strdup( values[i] );
			}
		ldap_value_free( values );
		if ( contact == NULL ) {
			printFormatted( lineLength, FALSE, stdout,
				"%-19s <Unknown>", "Contact:" );
			if ( debug )
				printFormatted( lineLength, TRUE, stdout,
					"Cannot find a suitable manager" );
			return TRUE;
		}
		ldap_search_s( ld, contact, LDAP_SCOPE_BASE, "objectclass=*",
			roleOccupant, 0, &result );
		if ( ld->ld_errno != LDAP_SUCCESS ) {
			printFormatted( lineLength, FALSE, stdout,
				"%-19s <Unknown>", "Contact:" );
			printFormatted( lineLength, TRUE, stdout,
				"Search failed, %s",
				ldap_err2string( ld->ld_errno ) );
			return TRUE;
		}
		if ( (values = ldap_get_values( ld, result, "roleOccupant" )) != NULL
			|| values[0] == NULL ) {
			free( contact );
			/* Just pick one! */
			contact = strdup( values[0] );
			ldap_value_free( values );
		}
		if ( debug > 2 )
			printFormatted( lineLength, TRUE, stdout,
				"The contact is %s", contact );
	}
	ldap_search_s( ld, contact, LDAP_SCOPE_BASE, "objectclass=*", 
		attributes, 0, &result );
	if ( ld->ld_errno != LDAP_SUCCESS ) {
		printFormatted( lineLength, FALSE, stdout, "%-19s <Unknown>",
			"Contact:" );
		printFormatted( lineLength, TRUE, stdout,
			"Read for \"%s\" returned error, %s", contact,
			ldap_err2string( ld->ld_errno ) );
	}
#if defined(UOFA)
	if ( (values = ldap_get_values( ld, result, "preferredName" )) != NULL
		&& values[0] != NULL ) {
		printFormatted( lineLength, FALSE, stdout, "%-19s %s",
			"Contact:", values[0] );
		ldap_value_free( values );
	} else {
#endif
		value = strdup( ldap_dn2ufn( ldap_get_dn( ld, result ) ) );
		if ( (ptr = index( value, ',' )) != NULL )
			*ptr = '\0';
		printFormatted( lineLength, FALSE, stdout, "%-19s %s",
			"Contact:", value );
#if defined(UOFA)
	}
#endif
	if ( ( values = ldap_get_values( ld, result, "postalAddress" )) != NULL ) {
		for ( i = 0; values[i] != NULL; i++ ) {
			printFormatted( lineLength, FALSE, stdout, "%-19s %s",
				"Postal-Address:",
				strtok( values[i], "$" ) );
			while ( ( ptr = strtok( NULL, "$" ) ) != NULL )
				printFormatted( lineLength, FALSE, stdout,
					"%-19s%s", "", ptr );
		}
		ldap_value_free( values );
	}
	if ( ( values = ldap_get_values( ld, result, "telephoneNumber" )) != NULL ) {
		for ( i = 0; values[i] != NULL; i++ )
			printFormatted( lineLength, FALSE, stdout, "%-19s %s",
				"Telephone:", values[i] );
		ldap_value_free( values );
	}
	if ( ( values = ldap_get_values( ld, result, "facsimileTelephoneNumber" )) != NULL ) {
		for ( i = 0; values[i] != NULL; i++ )
			printFormatted( lineLength, FALSE, stdout, "%-19s %s",
				"Fax:", values[i] );
		ldap_value_free( values );
	}
	if ( ( values = ldap_get_values( ld, result, "mail" )) != NULL ) {
		for ( i = 0; values[i] != NULL; i++ )
			printFormatted( lineLength, FALSE, stdout, "%-19s %s",
				"Electronic-Address:", values[i] );
		ldap_value_free( values );
	}
	if ( ( values = ldap_get_values( ld, result, "lastModifiedBy" )) != NULL ) {
		for ( i = 0; values[i] != NULL; i++ )
			printFormatted( lineLength, FALSE, stdout,
				"%-19s \"%s\"", "Modified-By:", values[i] );
		ldap_value_free( values );
	}
	return FALSE;
}
