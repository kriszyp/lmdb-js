#if !defined(lint)
static char copyright[] = "Copyright 1992 The University of Adelaide";
#endif

/*
 *			C O M M A N D
 *
 * Author:	Mark R. Prior
 *		Communications and Systems Branch
 *		Information Technology Division
 *		The University of Adelaide
 * E-mail:	mrp@itd.adelaide.edu.au
 * Date:	October 1992
 * Version:	1.8
 * Description:
 *		Interpret the command sent by the client
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

extern char	*index(), *rindex();

#define	isspecial(c)	( (c) == ',' || (c) == ';' || (c) == ':' || (c) == '=' )

static	char	**component = NULL;
static	int	numberOfComponents;
static	int	components = 10;

static int getToken( token )
char	*token;

{
	static char	*buffer = NULL;
	static int	idx;
	char		ch;
	fd_set		readfds;
	struct timeval	timeout;
	int		i, status, tablesize;

	if ( buffer == NULL ) {
		tablesize = getdtablesize();

#ifdef FD_SETSIZE
		if ( tablesize > FD_SETSIZE ) {
			tablesize = FD_SETSIZE;
		}
#endif	/* FD_SETSIZE */

		timeout.tv_sec = 60;
		timeout.tv_usec = 0;
		FD_ZERO( &readfds );
		FD_SET( fileno( stdin ), &readfds );

		if ( (status = select( tablesize, &readfds, 0, 0, &timeout )) <= 0 ) {
			if ( status < 0 )
				printFormatted( lineLength, TRUE, stdout,
					"select: %s", strerror( errno ) );
			else
				printFormatted( lineLength, TRUE, stdout,
					"Connection timed out waiting for input." );
			exit( 1 );
		}
/**/		/*
		 * We really should determine how many characters are
		 * waiting for us and then malloc that amount rather than
		 * just guessing!
		 */
		if ( ( buffer = (char *)malloc(BUFSIZ) ) == NULL
			|| fgets( buffer, BUFSIZ, stdin ) == NULL ) {
			*token = '\0';
			return EOF;
		}
		idx = 0;
		i = strlen( buffer );
		while ( i-- > 0 && ( buffer[i] == '\r' || buffer[i] == '\n' ) )
			buffer[i] = '\0';
		if ( log )
			syslog( LOG_INFO, "Whois++ Query: %s", buffer );
	}
	while ( buffer[idx] != '\0' && isspace( buffer[idx] ) )
		idx++;
	token[0] = buffer[idx++];
	token[1] = '\0';
	switch ( token[0] ) {
	case '\0':
		strcpy( token, "<end of line>" );
		free( buffer );
		buffer = NULL;
		return EOF;

	case '^':
		return TEMPLATE;

	case '!':
		return HANDLE;

	case '.':
		return ATTRIBUTE;

	case '#':
		return VALUE;

	case '*':
		return SEARCH_ALL;

	case '?':
		return HELP;

	case ':':
		return COLON;

	case ';':
		return SEMICOLON;

	case ',':
		return COMMA;

	case '=':
		return EQUALS;

	case '"':
		i = 0;
		do {
			ch = buffer[idx++];
			if ( ch == '\\' && buffer[idx] != '\0' )
				token[i++] = buffer[idx++];
			else
				token[i++] = ch;
		} while ( ch != '\0' && ch != '"' );
		if ( ch == '\0' ) {
			printFormatted( lineLength, TRUE, stdout,
				"Trailing \" missing" );
			idx--;
		}
		token[--i] = '\0';
		return SEARCH;

	default:
		i = 1;
		do {
			ch = buffer[idx++];
			if ( ch == '\\' && buffer[idx] != '\0' )
				token[i++] = buffer[idx++];
			else
				token[i++] = ch;
		} while ( ch != '\0' && !isspace( ch ) && !isspecial( ch ) );
		token[--i] = '\0';
		idx--;
/**/		/*
		 * The following is a brute force lookup, once the names
		 * have settled down this should change to a hash table,
		 * or something similar.
		 */
		if ( EQ( token, "help" ) )
			return HELP;
		else if ( EQ( token, "list" ) )
			return LIST;
		else if ( EQ( token, "show" ) )
			return SHOW;
		else if ( EQ( token, "constraints" ) )
			return CONSTRAINTS;
		else if ( EQ( token, "describe" ) )
			return DESCRIBE;
		else if ( EQ( token, "version" ) )
			return VERSION;
		else if ( EQ( token, "template" ) )
			return TEMPLATE;
		else if ( EQ( token, "handle" ) )
			return HANDLE;
		else if ( EQ( token, "attribute" ) )
			return ATTRIBUTE;
		else if ( EQ( token, "value" ) )
			return VALUE;
		else if ( EQ( token, "full" ) )
			return FULL;
		else if ( EQ( token, "abridged" ) )
			return ABRIDGED;
		else if ( EQ( token, "summary" ) )
			return SUMMARY;
		else if ( EQ( token, "format" ) )
			return FORMAT;
		else if ( EQ( token, "hold" ) )
			return HOLD;
		else if ( EQ( token, "maxhits" ) )
			return MAXHITS;
		else if ( EQ( token, "match" ) )
			return MATCH;
		else if ( EQ( token, "linelength" ) )
			return LINE_LENGTH;
		else if ( EQ( token, "command" ) )
			return COMMAND;
		else if ( EQ( token, "trace" ) )
			return TRACE;
		else
			return SEARCH;
	}
}

static int term( token, value, attribute, specifier, soundex )
int	token;
char	*value, *attribute;
int	*specifier, *soundex;
{
	char	buffer[BUFSIZ], temp[BUFSIZ];
	int	iterations;

	*soundex = FALSE;
	switch ( token ) {
	case ATTRIBUTE:	/* . */
	case VALUE:	/* # */
	case HANDLE:	/* ! */
	case TEMPLATE:	/* ^ */
	case SEARCH_ALL:/* * */
		*specifier = token;
		if ( strlen( value ) > 1 ) {
			/* fullname used, so expect an equals sign */
			if ( getToken( buffer ) != EQUALS ) {
				printFormatted( lineLength, TRUE, stdout,
					"\"=\" expected" );
				return ERROR;
			} else
				token = getToken( value );
		} else 
			token = getToken( value );
		if ( token != COMMA && token != SEMICOLON && token != EQUALS
			&& token != COLON && token != EOF ) {
			token = getToken( buffer );
			break;
		}

	case COMMA:
	case SEMICOLON:
	case EQUALS:
	case COLON:
	case EOF:
		printFormatted( lineLength, TRUE, stdout,
			"Expected search string but got \"%s\"", buffer );
		return ERROR;

	default:
		*specifier = SEARCH_ALL;
		if ( ( token = getToken( buffer ) ) == EQUALS ) {
			strcpy( attribute, value );
			token = getToken( value );
			if ( token == COMMA || token == SEMICOLON
				|| token == COLON || token == EOF ) {
				printFormatted( lineLength, TRUE, stdout,
					"Syntax error, string expected." );
				return ERROR;
			}
			token = getToken( buffer );
		}
	}

	while ( token != COMMA && token != SEMICOLON && token != COLON
		&& token != EOF ) {
		if ( *value != '\0' )
			strcat( value, " " );
		strcat( value, buffer );
		token = getToken( buffer );
	}
	iterations = 2;
	while ( token == COMMA ) {
		token = getToken( buffer );
		switch ( token ) {
		case MATCH:
			iterations = 0;
			if ( ( token = getToken( buffer ) ) != EQUALS ) {
				printFormatted( lineLength, TRUE, stdout,
					"\"=\" expected" );
			} else
				token = getToken( buffer );
			if ( EQ( buffer, "exact" ) )
				*soundex = FALSE;
			else if ( EQ( buffer, "fuzzy" ) )
				*soundex = TRUE;
			else
				printFormatted( lineLength, TRUE, stdout,
					"Unrecognised search type" );
			token = getToken( buffer );
			break;

		default:
			if ( iterations == 0 ) {
				/* obviously an unrecognised constraint */
				printFormatted( lineLength, TRUE, stdout,
					"Constraint \"%s\" not supported",
					buffer );
				while ( ( token = getToken( buffer ) ) != EOF
					&& token != COMMA && token != COLON
					&& token != SEMICOLON )
					;
			} else {
				strcpy( temp, buffer );
				token = getToken( buffer );
				if ( token == EQUALS ) {
					iterations = 0;
					printFormatted( lineLength, TRUE, stdout,
						"Constraint \"%s\" not supported",
						buffer );
				}
				while ( token != EOF && token != SEMICOLON
					&& token != COLON && token != COMMA ) {
					if ( iterations > 0 ) {
						strcat( temp, " " );
						strcat( temp, buffer );
					}
					token = getToken( buffer );
				}
				if ( iterations > 0 ) {
					printFormatted( lineLength, TRUE, stdout,
						"Assuming \"%s\" part of query and not an unrecognised constraint.", temp );
					strcat( value, "," );
					strcat( value, temp );
				}
			}
			break;

		}
		iterations--;
	}
	if ( *value == '\0' ) {
		printFormatted( lineLength, TRUE, stdout,
			"Value not specified" );
		return ERROR;
	}
	if ( *specifier == NULL )
		*specifier = SEARCH_ALL;
	return token;
}

static	int processTerm( specifier, soundex, buffer, attribute, value )
int	specifier, soundex;
char	*buffer, *attribute, *value;

{
	char	*s, *t;
	char	query[BUFSIZ];
	char	**reallocResult;

	switch ( specifier ) {
	case SEARCH_ALL:
		if ( numberOfComponents+3 >= components ) {
			components += 10;
			reallocResult = (char **)realloc(component, sizeof(char **)*components);
			if ( reallocResult == NULL ) {
				printFormatted( lineLength, TRUE, stdout,
					"Realloc failed" );
				return ERROR;
			} else
				component = reallocResult;
		}
		if ( attribute != NULL && *attribute != '\0' ) {
			/* The user obviously knows what they are doing */
			sprintf( query, "(%s%s%s)", attribute,
				(soundex)?"~=":"=", buffer );
		} else {
			if ( ( s = index( buffer, ',' ) ) != NULL ) {
				*s++ = '\0';
				while ( *s && isspace( *s ) )
					s++;
				sprintf( query, "(sn%s%s)",
					(soundex)?"~=":"=", buffer );
				component[numberOfComponents++] = strdup( query );
				/* let's just make sure there is no title */
				if ( ( t = rindex( s, ',' ) ) != NULL ) {
					*t++ = '\0';
					while ( *t && isspace( *t ) )
						t++;
					sprintf( query, "(personalTitle%s%s)",
						(soundex)?"~=":"=", t );
					component[numberOfComponents++] = strdup( query );
				}
				sprintf( query, "%s %s", s, buffer );
				strcpy( buffer, query );
			} else if ( strncasecmp( buffer, "first ", 6 ) == 0 ) {
				sprintf( query, "%s *", &buffer[6] );
				strcpy( buffer, query );
			}
			if ( ( s = index( buffer, '@' ) ) != NULL ) {
				*s++ = '\0';
				if ( *buffer == '\0' ) /* no username */
					sprintf( query, "(mail=*@%s)", s );
				else if ( *s == '\0' ) /* no host */
					sprintf( query, "(|(mail=%s@*)(userid=%s))",
						buffer, buffer );
				else
					sprintf( query, "(mail=%s@%s)",
						buffer, s );
				if ( soundex )
					printFormatted( lineLength, TRUE, stdout,
						"Fuzzy matching not supported on e-mail address queries" );
			} else if ( index( buffer, ' ' ) == NULL ) {
				sprintf( query,
					"(|(sn%s%s)(userid%s%s)(l%s%s)(ou%s%s)\
(&(cn%s%s)(!(objectClass=person))))",
					(soundex)?"~=":"=", buffer,
					(soundex)?"~=":"=", buffer,
					(soundex)?"~=":"=", buffer,
					(soundex)?"~=":"=", buffer,
					(soundex)?"~=":"=", buffer );
			} else {
#if defined(UOFA)
				sprintf( query, "(|(l%s%s)(ou%s%s)(preferredName%s%s)",
					(soundex)?"~=":"=", buffer,
					(soundex)?"~=":"=", buffer,
					(soundex)?"~=":"=", buffer );
#else
				sprintf( query, "(|(l%s%s)(ou%s%s)",
					(soundex)?"~=":"=", buffer,
					(soundex)?"~=":"=", buffer );
#endif
				/*
				 * If LDAP and/or Quipu didn't strip spaces
				 * then this would be different but as it does
				 * this is easy :-) but it also means we might
				 * get false hits.
				 */
				if ( soundex ) {
					strcat( query, "(cn~=" );
					strcat( query, buffer );
				} else {
					strcat( query, "(cn=*" );
					strcat( query, strtok( buffer, " " ) );
					while ( ( s = strtok( NULL, " " ) ) != NULL ) {
						strcat( query, " * " );
						strcat( query, s );
					}
				}
				strcat( query, "))" );
			}
		}
		component[numberOfComponents++] = strdup( query );
		break;

	case ATTRIBUTE:
		if ( numberOfComponents+1 >= components ) {
			components += 10;
			reallocResult = (char **)realloc(component, sizeof(char **)*components);
			if ( reallocResult == NULL ) {
				printFormatted( lineLength, TRUE, stdout,
					"Realloc failed" );
				return ERROR;
			} else
				component = reallocResult;
		}
		if ( *value != '\0' ) {
			sprintf( query, "(%s%s%s)", buffer,
				(soundex)?"~=":"=", value );
			component[numberOfComponents++] = strdup( query );
			*value = '\0';
		} else {
			if ( *attribute != '\0' ) {
				sprintf( query, "(%s%s*)", attribute,
					(soundex)?"~=":"=" );
				component[numberOfComponents++] = strdup( query );
			}
			strcpy( attribute, buffer );
		}
		break;

	case TEMPLATE:
		if ( numberOfComponents+1 >= components ) {
			components += 10;
			reallocResult = (char **)realloc(component, sizeof(char **)*components);
			if ( reallocResult == NULL ) {
				printFormatted( lineLength, TRUE, stdout,
					"Realloc failed" );
				return ERROR;
			} else
				component = reallocResult;
		}
		sprintf( query, "(objectClass%s%s)",
			(soundex)?"~=":"=", templateToObjectClass( buffer ) );
		component[numberOfComponents++] = strdup( query );
		break;

	case VALUE:
		if ( *attribute != '\0' ) {
			if ( numberOfComponents+1 >= components ) {
				components += 10;
				reallocResult = (char **)realloc(component, sizeof(char **)*components);
				if ( reallocResult == NULL ) {
					printFormatted( lineLength, TRUE, stdout,
						"Realloc failed" );
					return ERROR;
				} else
					component = reallocResult;
			}
			sprintf( query, "(%s%s%s)", attribute,
				(soundex)?"~=":"=", buffer );
			component[numberOfComponents++] = strdup( query );
			*attribute = '\0';
		} else {
			if ( *value != '\0' )
				printFormatted( lineLength, TRUE, stdout,
					"Ignoring old value (%s)", value );
			strcpy( value, buffer );
		}
		break;

	case HANDLE:
		if ( numberOfComponents+1 >= components ) {
			components += 10;
			reallocResult = (char **)realloc(component, sizeof(char **)*components);
			if ( reallocResult == NULL ) {
				printFormatted( lineLength, TRUE, stdout,
					"Realloc failed" );
				return ERROR;
			} else
				component = reallocResult;
		}
		component[numberOfComponents++] = strdup( buffer );
		return READ;

	}
	return SEARCH;
}

int	parseCommand( query )
char	*query;
{
	/*
	 * This procedure reads the string sent by the user and breaks it
	 * down into command to execute.
	 */
	char	buffer[BUFSIZ], attribute[BUFSIZ], objectClass[BUFSIZ],
		value[BUFSIZ];
	char	**reallocResult;
	int	command, specificName, length, token, i, j, specifier, soundex;
	int	trace = FALSE;

	switch ( command = getToken( buffer ) ) {
	case COMMAND:
	case CONSTRAINTS:
	case DESCRIBE:
	case VERSION:
		/* <command> */
		token = getToken( buffer );
		break;

	case HELP:
	case LIST:
		/* <command> [ <string> ] */
		if ( ( token = getToken( buffer ) ) != EOF && token != COLON ) {
			strcpy( query, buffer );
			token = getToken( buffer );
		} else
			*query = '\0';
		break;

	case SHOW:
		/* "show" <string> */
		if ( ( token = getToken( buffer ) ) != EOF && token != COLON ) {
			strcpy( query, buffer );
			token = getToken( buffer );
		} else {
			printFormatted( lineLength, TRUE, stdout,
				"Show must have a parameter" );
			return ERROR;
		}
		break;

	default:
		/* <term> [ ";" <term> ] */
		*attribute = '\0';
		*value = '\0';
		soundex = FALSE;
		numberOfComponents = 0;
		if ( ( component = (char **)malloc(sizeof(char **)*components) ) == NULL ) {
			printFormatted( lineLength, TRUE, stdout,
				"Malloc failed" );
			return ERROR;
		}
		if ( ( token = term( command, buffer, attribute, &specifier,
			&soundex ) ) != ERROR )
			command = processTerm( specifier, soundex, buffer,
				attribute, value );
		else
			return ERROR;
		if ( token == SEMICOLON ) {
			if ( command == READ ) {
				printFormatted( lineLength, TRUE, stdout,
					"Multiple components on a Handle query not supported." );
				return ERROR;
			}
			do {
				soundex = FALSE;
				token = getToken( buffer );
				token = term( token, buffer, attribute,
					&specifier, &soundex );
				command = processTerm( specifier, soundex,
					buffer, attribute, value );
				if ( command == READ ) {
					printFormatted( lineLength, TRUE, stdout,
						"Multiple components on a Handle query not supported." );
					return ERROR;
				} else if ( command == ERROR )
					return ERROR;
			} while ( token == SEMICOLON );
		}
		/*
		 * Need to tidy up outstanding single value or attribute terms
		 */
		if ( *attribute != '\0' ) {
			if ( numberOfComponents+1 >= components ) {
				components += 10;
				reallocResult = (char **)realloc(component, sizeof(char **)*components);
				if ( reallocResult == NULL ) {
					printFormatted( lineLength, TRUE, stdout,
						"Realloc failed" );
					return ERROR;
				} else
					component = reallocResult;
			}
			sprintf( query, "(%s%s*)", attribute,
				(soundex)?"~=":"=" );
			component[numberOfComponents++] = strdup( query );
		}
		if ( *value != '\0' )
			if ( processTerm( SEARCH_ALL, soundex, value, NULL, NULL ) == ERROR )
				return ERROR;
		if ( numberOfComponents == 0 ) {
			printFormatted( lineLength, TRUE, stdout,
				"NULL query." );
			return ERROR;
		} else if ( numberOfComponents == 1 )
			strcpy( query, component[0] );
		else {
			strcpy( query, "(&" );
			for ( i = 0; i < numberOfComponents; i++ )
				strcat( query, component[i] );
			strcat( query, ")" );
		}
		free( component );
		break;

	}
	if ( token == COLON ) { /* global constraints */
		do {
			token = getToken( buffer );
			switch ( token ) {
			case FORMAT:
				if ( ( token = getToken( buffer ) ) != EQUALS ) {
					printFormatted( lineLength, TRUE, stdout, "\"=\" expected" );
				} else
					token = getToken( buffer );
				switch ( token ) {
				case FULL:
				case ABRIDGED:
				case HANDLE:
				case SUMMARY:
					if ( outputFormat != NULL )
						printFormatted( lineLength, TRUE, stdout, "Only one response format can be specified." );
					else
						outputFormat = token;
					break;

				default:
					printFormatted( lineLength, TRUE, stdout, "Unrecognised format specifier" );
				}
				token = getToken( buffer );
				break;

			case HOLD:
				holdConnection = TRUE;
				token = getToken( buffer );
				break;

			case MAXHITS:
				if ( ( token = getToken( buffer ) ) != EQUALS ) {
					printFormatted( lineLength, TRUE, stdout, "\"=\" expected" );
				} else
					token = getToken( buffer );
				if ( (maxHits = atoi( buffer )) < 1 
					|| maxHits > maximumSize ) {
					printFormatted( lineLength, TRUE, stdout, "Invalid maxhits value, defaulting to %s", maximumSize );
					maxHits = maximumSize;
				}
				token = getToken( buffer );
				break;

			case LANGUAGE:
				if ( ( token = getToken( buffer ) ) != EQUALS ) {
					printFormatted( lineLength, TRUE, stdout, "\"=\" expected" );
				} else
					token = getToken( buffer );
/**/				/* need to save this value and lookup locale */
				printFormatted( lineLength, TRUE, stdout,
					"Language not currently implemented" );
				token = getToken( buffer );
				break;

			case LINE_LENGTH:
				if ( ( token = getToken( buffer ) ) != EQUALS ) {
					printFormatted( lineLength, TRUE, stdout, "\"=\" expected" );
				} else
					token = getToken( buffer );
				lineLength = atoi( buffer );
				if ( lineLength < MIN_LINE_LENGTH
					|| lineLength > MAX_LINE_LENGTH ) {
					printFormatted( lineLength, TRUE, stdout, "Invalid line length, using default %d", DEFAULT_LINE_LENGTH );
					lineLength = DEFAULT_LINE_LENGTH;
				}
				token = getToken( buffer );
				break;

			case TRACE:
				trace = TRUE;
				token = getToken( buffer );
				break;

			default:
				printFormatted( lineLength, TRUE, stdout, "Unrecognised global constraint \"%s\"", buffer );
				while ( ( token = getToken( buffer ) ) != EOF
					&& token != COMMA )
					;
				break;

			}
		} while ( token == COMMA );
	}
	if ( token != EOF ) {
		printFormatted( lineLength, TRUE, stdout,
			"Data following \"%s\" ignored.", buffer );
		while ( ( token = getToken( buffer ) ) != EOF )
			;
	}
	if ( trace && ( command == READ || command == SEARCH ) )
		switch (command) {
		case READ:
			printFormatted( lineLength, TRUE, stdout,
				"Attempting to read \"%s\"", query );
			break;

		case SEARCH:
			printFormatted( lineLength, TRUE, stdout,
				"Searching using LDAP query %s", query );
			break;

		}
	return command;
}
