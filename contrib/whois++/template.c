#if !defined(lint)
static char copyright[] = "Copyright 1992 The University of Adelaide";
#endif

/*
 *			T E M P L A T E
 *
 * Author:	Mark R. Prior
 *		Communications and Systems Branch
 *		Information Technology Division
 *		The University of Adelaide
 * E-mail:	mrp@itd.adelaide.edu.au
 * Date:	October 1992
 * Version:	1.7
 * Description:
 *		This module deals with whois++ templates
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

void	showTemplate( template )
char	*template;

{
	char	filename[MAXPATHLEN], buffer[BUFSIZ];
	FILE	*description;
	int	i;

	if ( template == NULL || *template == '\0' )
		return;
	sprintf( filename, "%s/templates/%s", configDir, template );
	if ( ( description = fopen( filename, "r" ) ) == NULL ) 
		printFormatted( lineLength, TRUE, stdout,
			"Cannot find template %s", template );
	else {
		while ( fgets( buffer, BUFSIZ, description ) != NULL ) {
			i = strlen( buffer );
			while ( i-- > 0 &&
				( buffer[i] == '\n' || buffer[i] == '\r' ) )
				buffer[i] = '\0';
			printFormatted( lineLength, FALSE, stdout,
				" %s", buffer );
		}
		fclose( description );
	}
}

void	listTemplates( query )
char	*query;

{
	char		filename[MAXPATHLEN];
	DIR		*dir;
	struct dirent	*entry;

	if ( query == NULL || *query == '\0' ) {
		sprintf( filename, "%s/templates", configDir );
		if ( ( dir = opendir( filename ) ) == NULL ) {
			printFormatted( lineLength, TRUE, stdout,
				"Cannot access template descriptions - %s",
				strerror( errno ) );
			return;
		}
		for ( entry = readdir( dir ); entry != NULL; entry = readdir( dir ) )
			if ( !EQ(entry->d_name, "." ) && !EQ(entry->d_name, ".." ) )
				printFormatted( lineLength, FALSE, stdout,
					" %s", lowerCase( entry->d_name ) );
		closedir( dir );
	} else {
		sprintf( filename, "%s/templates/%s", configDir, query );
		if ( fopen( filename, "r" ) == NULL )
			printFormatted( lineLength, TRUE, stdout,
				"No such template (%s)", query );
		else
			printFormatted( lineLength, FALSE, stdout,
				" %s", query );
	}
}

char	**specifyAttributes( objectClass )
char	*objectClass;

{
	FILE	*description;
	char	filename[MAXPATHLEN], buffer[BUFSIZ];
	char	**attributes;
	int	max = ATTRIBUTE_INCREMENT;
	int	i, number = 0;

	if ( objectClass == NULL || *objectClass == '\0' )
		return NULL;
	sprintf( filename, "%s/templates/%s", configDir,
		lowerCase( objectClass ) );
	if ( ( description = fopen( filename, "r" ) ) == NULL ) 
		return NULL;
	if ( ( attributes = (char **)malloc( max*sizeof(char *) ) ) == NULL ) {
		printFormatted( lineLength, TRUE, stdout,
			"Error while attempting to create attribute list - %s",
			strerror( errno ) );
		return NULL;
	}
	while ( fgets( buffer, BUFSIZ, description ) != NULL ) {
		i = strlen( buffer );
		while ( i-- > 0 && ( buffer[i] == '\n' || buffer[i] == '\r' ) )
			buffer[i] = '\0';
		attributes[number++] = strdup( buffer );
		if ( number == max ) {
			max += ATTRIBUTE_INCREMENT;
			if ( ( attributes = (char **)realloc( attributes, max*sizeof(char *)) ) == NULL ) {
				printFormatted( lineLength, TRUE, stdout,
					"Error while attempting to extend attribute list - %s",
					strerror( errno ) );
				return NULL;
			}
		}
	}
	attributes[number] = NULL;
	fclose( description );
	return attributes;
}

char	*templateToObjectClass( template )
char	*template;

{
	int	i;

	if ( template == NULL || *template == '\0' ) {
		printFormatted( lineLength, TRUE, stdout,
			"Unrecognised template" );
		return "unrecognised";
	}
	for ( i = 0; i < numberOfTemplates; i++ )
		if ( EQ( template, templateTranslationTable[i].key ) )
			return templateTranslationTable[i].value;
	printFormatted( lineLength, TRUE, stdout,
		"Template (%s) not recognised, assuming that it is already an objectClass",
		template );
	return template;
}

char	*objectClassToTemplate( objectClass )
char	*objectClass;

{
	int	i;

	if ( objectClass == NULL || *objectClass == '\0' ) {
		printFormatted( lineLength, TRUE, stdout,
			"Unrecognised template" );
		return "unrecognised";
	}
	for ( i = 0; i < numberOfTemplates; i++ )
		if ( EQ( objectClass, templateTranslationTable[i].value ) )
			return templateTranslationTable[i].key;
	return objectClass;
}
