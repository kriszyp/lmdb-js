#if !defined(lint)
static char copyright[] = "Copyright 1992 The University of Adelaide";
#endif

/*
 *			H E L P
 *
 * Author:	Mark R. Prior
 *		Communications and Systems Branch
 *		Information Technology Division
 *		The University of Adelaide
 * E-mail:	mrp@itd.adelaide.edu.au
 * Date:	October 1992
 * Version:	1.7
 * Description:
 *		The Help module
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

void	needHelp( reason )
char	*reason;
{
	char		filename[MAXPATHLEN];
	char		buffer[BUFSIZ];
	int		i;
	DIR		*dir;
	struct dirent	*entry;
	FILE		*help;

	if ( reason == NULL || *reason == '\0' ) {
		sprintf( filename, "%s/%s/general", helpDir, language );
		if ( ( help = fopen( filename, "r" ) ) == NULL ) {
			printFormatted( lineLength, TRUE, stdout,
				"Sorry cannot open general information help file" );
			return;
		}
	} else {
		sprintf( filename, "%s/%s/%s", helpDir, language,
			lowerCase( reason ) );
		if ( ( help = fopen( filename, "r" ) ) == NULL ) {
			sprintf( filename, "%s/%s/%s", helpDir, defaultLanguage,
				lowerCase( reason ) );
			if ( ( help = fopen( filename, "r" ) ) == NULL ) {
				printFormatted( lineLength, TRUE, stdout,
					"Sorry cannot open help file for topic \"%s\"",
					reason );
				return;
			} else {
				printFormatted( lineLength, TRUE, stdout,
					"Sorry no help in %s, using default language (%s).",
					language, defaultLanguage );
			}
		}
	}
	while ( fgets( buffer, BUFSIZ, help ) != NULL ) {
		i = strlen( buffer );
		while ( i-- > 0 && ( buffer[i] == '\n' || buffer[i] == '\r' ) )
			buffer[i] = '\0';
		printFormatted( lineLength, FALSE, stdout, "%s", buffer );
	}
	fclose( help );
	if ( reason == NULL || *reason == '\0' ) {
		sprintf( filename, "%s/%s", helpDir, language );
		if ( ( dir = opendir( filename ) ) == NULL )
			return;
		printFormatted( lineLength, FALSE, stdout, "" );
		printFormatted( lineLength, FALSE, stdout,
			"Further information is available on the following topics" );
		for ( entry = readdir( dir ); entry != NULL; entry = readdir( dir ) )
			if ( !EQ(entry->d_name, "." ) && !EQ(entry->d_name, ".." ) )
				printFormatted( lineLength, FALSE, stdout,
					" %s", lowerCase( entry->d_name ) );
		closedir( dir );
	}
	return;
}
