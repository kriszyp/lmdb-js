#if !defined(lint)
static char copyright[] = "Copyright 1992 The University of Adelaide";
#endif

/*
 *			O U T P U T
 *
 * Author:	Mark R. Prior
 *		Communications and Systems Branch
 *		Information Technology Division
 *		The University of Adelaide
 * E-mail:	mrp@itd.adelaide.edu.au
 * Date:	October 1992
 * Version:	1.7
 * Description:
 *		The Output routines
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

#include <varargs.h>
#include "whois++.h"

extern char *index(), *rindex();

static displayEntry();
static printAttribute();

static char	*selectObjectClass( ld, entry )
LDAP		*ld;
LDAPMessage	*entry;

{
	static char	*objectClass[] = { "objectClass", NULL };
	LDAPMessage	*result;
	char		*dn, *template;
	char		**val;
	int		i;

	template = NULL;
	dn = strdup( ldap_get_dn( ld, entry ) );
	ldap_search_s( ld, dn, LDAP_SCOPE_BASE, "objectclass=*", objectClass,
		0, &result );
	if ( ld->ld_errno != LDAP_SUCCESS ) {
		printFormatted( lineLength, TRUE, stdout,
			"Read on object \"%s\" failed, %s",
			dn, ldap_err2string( ld->ld_errno ) );
		free( dn );
		return;
	} else
		free( dn );
	if ( ( val = ldap_get_values( ld, result, "objectClass" ) ) == NULL )
		return;
	for ( i = 0 ; val[i] != NULL ; i++ )
		if ( specifyAttributes( lowerCase( val[i] ) ) != NULL ) {
			template = strdup( val[i] );
			break;
		}
	ldap_value_free( val );
	return template;
}

int		displayResult( ld, result, outputFormat )
LDAP		*ld;
LDAPMessage	*result;
int		outputFormat;

{
	int		i, matches, number = 0;
	char		*dn;
	LDAPMessage	*e;
	char		*objectClass;
	char		**attributes, **objectClassTable;

	matches = ldap_count_entries( ld, result );
	if ( log )
		syslog( LOG_INFO, "%d match(es) to query", matches );
	if ( matches == 0 ) {
		printFormatted( lineLength, TRUE, stdout, "No matches found." );
		return FALSE;
	}
	if ( outputFormat == NULL ) {
		if ( matches == 1 )
			outputFormat = FULL;
		else if ( matches <= ABRIDGED_LIMIT )
			outputFormat = HANDLE;
		else
			outputFormat = SUMMARY;
	}
	switch (outputFormat) {
	case FULL:
		printFormatted( lineLength, FALSE, stdout,
			"#FULL %d", matches );
		for ( e = ldap_first_entry( ld, result ); e != NULL;
	      		e = ldap_next_entry( ld, e ) ) {
			objectClass = selectObjectClass( ld, e );
			dn = ldap_get_dn( ld, e );
			printFormatted( lineLength, FALSE, stdout,
				"#%s \"%s\"",
				objectClassToTemplate( objectClass ), dn );
			displayEntry( ld, dn,
				specifyAttributes( objectClass ) );
			if ( objectClass != NULL )
				free( objectClass );
		}
		printFormatted( lineLength, FALSE, stdout, "#END" );
		break;

	case ABRIDGED:
		/*
		 * As the DN contains most of the information wanted in 
		 * ABRIDGED format we use HANDLE format even if the client
		 * really specified ABRIDGED.
		 */
		printFormatted( lineLength, TRUE, stdout,
			"Abridged format is not really supported, the handle \
supplies most of the information specified in the abridged format description \
so we use the handle format instead." );

	case HANDLE:
		printFormatted( lineLength, FALSE, stdout,
			"#HANDLE %d", matches );
		for ( e = ldap_first_entry( ld, result ); e != NULL;
	      		e = ldap_next_entry( ld, e ) ) {
			objectClass = selectObjectClass( ld, e );
			printFormatted( lineLength, FALSE, stdout, " \"%s\" %s",
				ldap_get_dn( ld, e ),
				objectClassToTemplate( objectClass ) );
			if ( objectClass != NULL )
				free( objectClass );
		}
		printFormatted( lineLength, FALSE, stdout, "#END" );
		break;

	case SUMMARY:
		printFormatted( lineLength, FALSE, stdout, "#SUMMARY" );
		printFormatted( lineLength, FALSE, stdout, " matches:   %d",
			matches );
		e = ldap_first_entry( ld, result );
		objectClass = selectObjectClass( ld, e );
		if ( ( objectClassTable = (char **)malloc(sizeof(char **)*matches) ) == NULL ) {
			printFormatted( lineLength, TRUE, stdout, 
				"Malloc failed" );
			break;
		}
		objectClassTable[number++] = objectClass;
		printFormatted( lineLength, FALSE, stdout, " templates: %s",
			objectClassToTemplate( objectClass ) );
		while ( ( e = ldap_next_entry( ld, e ) ) != NULL ) {
			objectClass = selectObjectClass( ld, e );
			/* have we printed this before? If not do it now */
			for ( i = 0; i < number; i++ ) 
				if ( EQ( objectClass, objectClassTable[i] ) )
					break;
			if ( i < number ) {
				if ( objectClass != NULL )
					free( objectClass );
			} else {
				objectClassTable[number++] = objectClass;
				printFormatted( lineLength, FALSE, stdout,
					"            %s",
					objectClassToTemplate( objectClass ) );
			}
		}
		printFormatted( lineLength, FALSE, stdout, "#END" );
		for ( i = 0; i < number; i++ )
			if ( objectClassTable[i] != NULL )
				free( objectClassTable[i] );
		free( objectClassTable );
		break;

	}
	return TRUE;
}

static displayEntry( ld, dn, attributes )
LDAP	*ld;
char	*dn, *attributes[];
{
	char		*ufn;
	int		i;
	char		*s, *department;
	LDAPMessage	*result, *entry;

	ldap_search_s( ld, dn, LDAP_SCOPE_BASE, "objectclass=*", attributes,
		0, &result );
	if ( ld->ld_errno != LDAP_SUCCESS ) {
		printFormatted( lineLength, TRUE, stdout,
			"Read on object \"%s\" failed, %s", dn,
			ldap_err2string( ld->ld_errno ) );
		return;
	}

	entry = ldap_first_entry( ld, result );

	if ( entry == NULL ) {
		/* something very weird has happened */
		printFormatted( lineLength, TRUE, stdout,
			"Possible conflict with ACLs for \"%s\"", dn );
		return;
	}

	/*
	 * Get the UFN version of the DN and then cut it up into
	 * name and department.
	 */
	ufn = ldap_dn2ufn( dn );
	if ( ( s = index( ufn, ',' ) ) != NULL ) {
		*s++ = '\0';
		while ( *s != '\0' && isspace( *s ) )
			s++;
		department = s;
		while ( s != NULL && *s != '\0' && !EQ( s, organisation ) )
			if ( ( s = index( s, ',' ) ) != NULL ) {
				s++;
				while ( *s != '\0' && isspace( *s ) )
					s++;
			}
		if ( s != NULL )
			if ( s != department ) {
				while ( isspace( *--s ) )
					;
				*s = '\0';
			} else
				department = NULL;
	} else
		department = NULL;

/**/	/*
	 * Name, Organization, Department, Organization-Type, and Handle
	 * should be read in from language dictionary rather than hard coded.
	 */
	printFormatted( lineLength, FALSE, stdout, " %-19s %s", "Name", ufn );
	if ( department != NULL && *department != '\0' )
		printFormatted( lineLength, FALSE, stdout,
			" %-19s %s", "Department", department );
	printFormatted( lineLength, FALSE, stdout, " %-19s %s",
		"Organization", organisation );
	if ( category != NULL )
		for ( i = 0; category[i] != NULL; i++ )
			printFormatted( lineLength, FALSE, stdout, " %-19s %s",
				"Organization-type", category[i] );
	for ( i = 0; attributes != NULL && attributes[i] != NULL; i++ ) {
		printAttribute( ld, attributes[i], entry );
	}
	printFormatted( lineLength, FALSE, stdout, " %-19s \"%s\"",
		"Handle", dn );

	free( ufn );
}

char *attributeLabel( attribute )
char	*attribute;

{
/**/	/* need to get printable string from language dictionary */
	return attribute;
}

static printAttribute( ld, attribute, entry )
LDAP		*ld;
char		*attribute;
LDAPMessage	*entry;
{
	char	**val;
	char	*tag, *ptr;
	int	i;

/**/	/*
	 * We really should determine whether the attribute value needs line
	 * processing or not rather than just hard coding in a couple of cases
	 * but for the moment we will ignore the problem.
	 */
	if ( ( val = ldap_get_values( ld, entry, attribute )) == NULL )
		return;

	tag = attributeLabel( attribute );
	for ( i = 0; val[i] != NULL; i++ )
		if ( EQ( attribute, "lastModifiedTime" ) )
			printFormatted( lineLength, FALSE, stdout, " %-19s %s",
				tag, convertTime( val[i], locale ) );
		else if ( EQ( attribute, "postalAddress" )
			|| EQ( attribute, "homePostalAddress" ) ) {
			printFormatted( lineLength, FALSE, stdout, " %-19s %s",
				tag, strtok( val[i], "$" ) );
			while ( ( ptr = strtok( NULL, "$" ) ) != NULL )
				printFormatted( lineLength, FALSE, stdout,
					" %-19s%s", "", ptr );
		} else
			printFormatted( lineLength, FALSE, stdout, " %-19s %s",
				tag, val[i] );

	ldap_value_free( val );
}

printFormatted( lineLength, systemMessage, output, format, va_alist )
int	lineLength, systemMessage;
FILE	*output;
char	*format;
va_dcl

{
	va_list	ap;
	char	buffer[BUFSIZ];
	char	*head, *p, *q;
	char	*tag;
	int	count;

	if ( systemMessage ) {
		lineLength--;
		tag = "% ";
	} else
		tag = "";
	va_start( ap );
	vsprintf( buffer, format, ap );
	va_end( ap );
	if ( strlen( buffer ) < lineLength )
		fprintf( output, "%s%s\r\n", tag, buffer );
	else {
		head = buffer;
		do {
			count = strlen( tag );
			for ( q = head; *q && *q != ' '; q++ )
				count++;
			if ( *q == NULL ) {
				fprintf( output, "%s%s\r\n", tag, head );
				break;
			} else if ( count > lineLength ) {
				*q++ = '\0';
				fprintf( output, "%s%s\r\n", tag, head );
				head = q;
			} else {
				do {
					p = q++;
					count++;
					for (; *q && *q != ' '; q++ )
						count++;
				} while ( *p != '\0' && count <= lineLength );
				if ( *p != '\0' )
					*p++ = '\0';
				fprintf( output, "%s%s\r\n", tag, head );
				head = p;
			}
			if ( !systemMessage )
				tag = "+ ";
		} while ( *head != NULL );
	}
}
