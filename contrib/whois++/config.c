#if !defined(lint)
static char copyright[] = "Copyright 1992 The University of Adelaide";
#endif

/*
 *			C O N F I G
 *
 * Author:	Mark R. Prior
 *		Communications and Systems Branch
 *		Information Technology Division
 *		The University of Adelaide
 * E-mail:	mrp@itd.adelaide.edu.au
 * Date:	October 1992
 * Version:	1.7
 * Description:
 *		Process the configuration file.
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

static struct {
	char	*str;
	int	cmd;
	} commands[] = {
#define CMD_BASE	1
		"base",		CMD_BASE,
#define	CMD_LDAP	2
		"ldaphost",	CMD_LDAP,
#define CMD_HELPDIR	3
		"helpdir",	CMD_HELPDIR,
#define	CMD_USER	4
		"user",		CMD_USER,
#define	CMD_PASSWORD	5
		"password",	CMD_PASSWORD,
#define CMD_CONFIGDIR	6
		"configdir",	CMD_CONFIGDIR,
#define CMD_CONTACT	7
		"contact",	CMD_CONTACT,
#define	CMD_HOSTNAME	8
		"hostname",	CMD_HOSTNAME,
#define	CMD_LANGUAGE	9
		"language",	CMD_LANGUAGE,
#define	CMD_BANNER	10
		"banner",	CMD_BANNER,
#define	CMD_TEMPLATE	11
		"template",	CMD_TEMPLATE,
		NULL,		NULL
	};

static	nextLine(fp)
FILE	*fp;
{
	/*
	 * We probably should check that the user hasn't put anything else
	 * on the line but I can't be bothered!
	 */
	register int c;

	while ((c = getc(fp)) != EOF && c != '\n')
		;
}

/*
 * Get next word, skipping blanks & comments.
 */
static int	getWord(buffer, size, fp)
char		*buffer;
int		size;
FILE		*fp;
{
	char	*cp;
	int	c, string;

	string = 0;
	cp = buffer;
	while ((c = getc(fp)) != EOF) {
		if (c == '#') {
			while ((c = getc(fp)) != EOF && c != '\n')
				;
			continue;
		}
		if (c == '\n') {
			if (cp != buffer)
				ungetc(c, fp);
			break;
		} else if (c == '\\') {
			c = getc(fp);
			if (c == EOF)
				c = '\n';
		} else if (c == '"') {
			string = !string;
			continue;
		}
		if (!string && isspace(c)) {
			while (isspace(c = getc(fp)) && c != '\n')
				;
			ungetc(c, fp);
			if (cp != buffer)	/* Trailing whitespace */
				break;
			continue;		/* Leading whitespace */
		}
		if (cp >= buffer+size-1)
			break;
		*cp++ = c;
	}
	*cp = '\0';
	return (cp != buffer);
}

void 	readConfiguration( config )
FILE	*config;

{
	char		buffer[BUFSIZ];
	char		*s;
	int		i;

	/*
	 * A procedure to read in the configuration parameters.
	 * At the moment this is just a "quick hack" and it should be
	 * replaced in the next version by a proper scanner.
	 */

	while ( getWord( buffer, BUFSIZ, config ) != NULL ) {
		for ( i = 0; commands[i].str != NULL; i++ )
			if ( EQ( buffer, commands[i].str ) )
				break;
		if ( commands[i].str == NULL ) {
			printFormatted( lineLength, TRUE, stdout,
				"Unrecognised command <%s>", buffer );
			exit( 1 );
		}
		if ( getWord( buffer, BUFSIZ, config ) == NULL ) {
			printFormatted( lineLength, TRUE, stdout,
				"value missing in configuration file" );
			exit( 1 );
		}
		switch ( commands[i].cmd ) {
		case CMD_BASE:
			base = strdup( buffer );
			break;

		case CMD_LDAP:
			ldaphost = strdup( buffer );
			break;

		case CMD_HELPDIR:
			helpDir = strdup( buffer );
			break;

		case CMD_USER:
			user = strdup( buffer );
			break;

		case CMD_PASSWORD:
			password = strdup( buffer );
			break;

		case CMD_CONFIGDIR:
			configDir = strdup( buffer );
			break;

		case CMD_CONTACT:
			contact = strdup( buffer );
			break;

		case CMD_HOSTNAME:
			hostname = strdup( buffer );
			break;

		case CMD_LANGUAGE:
			defaultLanguage = lowerCase( strdup( buffer ) );
			break;

		case CMD_BANNER:
			banner = strdup( buffer );
			break;

		case CMD_TEMPLATE:
			if ( templateTranslationTable == NULL
				&& ( templateTranslationTable = (table *)malloc(sizeof(table)*tableSize) ) == NULL ) {
				printFormatted( lineLength, TRUE, stdout,
					"Malloc failed" );
				exit( 1 );
			} else if ( numberOfTemplates+1 == tableSize ) {
				tableSize += TABLE_INCREMENT;
				if ( ( templateTranslationTable = (table *)realloc(templateTranslationTable, sizeof(table)*tableSize) ) == NULL ) {
					printFormatted( lineLength, TRUE, stdout,
						"Realloc failed" );
					exit( 1 );
				}
			}
			templateTranslationTable[numberOfTemplates].key =
				lowerCase( strdup( buffer ) );
			if ( getWord( buffer, BUFSIZ, config ) == NULL ) {
				printFormatted( lineLength, TRUE, stdout,
					"objectClass missing in config file" );
				exit( 1 );
			}
			templateTranslationTable[numberOfTemplates].value =
				lowerCase( strdup( buffer ) );
			numberOfTemplates++;
			break;

		default:
			printFormatted( lineLength, TRUE, stdout,
				"Attribute <%s> not recognised.",
				buffer );
			break;

		}
		nextLine( config );
	}
}
