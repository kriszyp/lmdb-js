/* $OpenLDAP$ */
/*
 * Copyright (c) 1990 Regents of the University of Michigan.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that this notice is preserved and that due credit is given
 * to the University of Michigan at Ann Arbor. The name of the University
 * may not be used to endorse or promote products derived from this
 * software without specific prior written permission. This software
 * is provided ``as is'' without express or implied warranty.
 *
 * Copyright 1998,1999 The OpenLDAP Foundation
 * COPYING RESTRICTIONS APPLY.  See COPYRIGHT File in top level directory
 * of this package for details.
 */

#include "portable.h"

#include <stdio.h>

#include <ac/stdlib.h>

#include <ac/ctype.h>
#include <ac/param.h>
#include <ac/signal.h>
#include <ac/string.h>
#include <ac/sysexits.h>
#include <ac/syslog.h>
#include <ac/time.h>
#include <ac/unistd.h>
#include <ac/wait.h>

#include <sys/stat.h>

#ifdef HAVE_SYS_RESOURCE_H
#include <sys/resource.h>
#endif

#include <ldap.h>

#include "ldap_defaults.h"

#ifndef MAIL500_BOUNCEFROM
#define MAIL500_BOUNCEFROM "<>"
#endif

#define USER		0x01
#define GROUP_ERRORS	0x02
#define GROUP_REQUEST	0x04
#define GROUP_MEMBERS	0x08
#define GROUP_OWNER	0x10

#define ERROR		"error"
#define ERRORS		"errors"
#define REQUEST		"request"
#define REQUESTS	"requests"
#define MEMBERS		"members"
#define OWNER		"owner"
#define OWNERS		"owners"

LDAP	*ld;
char	*vacationhost = NULL;
char	*errorsfrom = MAIL500_BOUNCEFROM;
char	*mailfrom = NULL;
char	*host = NULL;
char	*ldaphost = NULL;
int	hostlen = 0;
int	debug;

typedef struct errs {
	int		e_code;
#define E_USERUNKNOWN		1
#define E_AMBIGUOUS		2
#define E_NOEMAIL		3
#define E_NOREQUEST		4
#define E_NOERRORS		5
#define E_BADMEMBER		6
#define E_JOINMEMBERNOEMAIL	7
#define E_MEMBERNOEMAIL		8
#define E_LOOP			9
#define E_NOMEMBERS		10
#define	E_NOOWNER		11
#define E_GROUPUNKNOWN		12
	char		*e_addr;
	union e_union_u {
		char		*e_u_loop;
		LDAPMessage	*e_u_msg;
	} e_union;
#define e_msg	e_union.e_u_msg
#define e_loop	e_union.e_u_loop
} Error;

typedef struct groupto {
	char	*g_dn;
	char	*g_errorsto;
	char	**g_members;
	int	g_nmembers;
} Group;

typedef struct baseinfo {
	char	*b_url;
	int	b_m_entries;
	char	b_rdnpref;	/* give rdn's preference when searching? */
	int	b_search;	/* ORed with the type of thing the address */
				/*  looks like (USER, GROUP_ERRORS, etc.)  */
				/*  to see if this should be searched	   */
} Base;

/*
 * We should limit the search to objectclass=mailRecipient or
 * objectclass=mailGroup.
 */

/*
Base	base[] = {
	{"dc=StlInter, dc=Net",
		0, 0xff,
		{"mail=%s", "mailAlternateAddress=%s", NULL}},
	{NULL}
};
*/

Base	**base = NULL;

char	*sendmailargs[] = { MAIL500_SENDMAIL, "-oMrLDAP", "-odi", "-oi", "-f", NULL, NULL };

typedef struct attr_semantics {
	char	*as_name;
	int	as_m_valued;	/* Is multivalued? */
	int	as_priority;	/* Priority level of this attribut type */
	int	as_syntax;	/* How to interpret values */
	int	as_m_entries;	/* Can resolve to several entries? */
	int	as_kind;	/* Recipient, sender, etc. */
	char	*as_param;	/* Extra info for filters and things alike */
} AttrSemantics;

#define AS_SYNTAX_UNKNOWN	0	/* Unqualified mailbox name */
#define AS_SYNTAX_NATIVE_MB	1	/* Unqualified mailbox name */
#define AS_SYNTAX_RFC822	2	/* RFC822 mail address */
#define AS_SYNTAX_HOST		3
#define AS_SYNTAX_DN		4	/* A directory entry */
#define AS_SYNTAX_RFC822_EXT	5
#define AS_SYNTAX_URL		6	/* mailto: or ldap: URL */
#define AS_SYNTAX_BOOL_FILTER	7	/* For joinable, filter in as_param */

#define AS_KIND_UNKNOWN		0
#define AS_KIND_RECIPIENT	1
#define AS_KIND_ERRORS		2	/* For ErrorsTo and similar */
#define AS_KIND_REQUEST		3
#define AS_KIND_OWNER		4
#define AS_KIND_ROUTE_TO_HOST	5	/* Expand at some other host */
#define AS_KIND_ALLOWED_SENDER	6	/* Can send to group */
#define AS_KIND_MODERATOR	7
#define AS_KIND_ROUTE_TO_ADDR	8	/* Rewrite recipient address as */

AttrSemantics **attr_semantics = NULL;
int current_priority = 0;

typedef struct subst {
	char	sub_char;
	char	*sub_value;
} Subst;

char	**groupclasses = NULL;
char	**def_attr = NULL;
char	**mydomains = NULL;		/* FQDNs not to route elsewhere */

static void load_config( char *filespec );
static void split_address( char *address, char **localpart, char **domainpart);
static int entry_engine( LDAPMessage *e, char *dn, char *address, char ***to, int *nto, Group ***togroups, int *ngroups, Error **err, int *nerr, int type );
static void do_address( char *name, char ***to, int *nto, Group ***togroups, int *ngroups, Error **err, int *nerr, int type );
static void send_message( char **to );
static void send_errors( Error *err, int nerr );
static void do_noemail( FILE *fp, Error *err, int namelen );
static void do_ambiguous( FILE *fp, Error *err, int namelen );
static int count_values( char **list );
static void add_to( char ***list, int *nlist, char **new );
static void add_single_to( char ***list, char *new );
static int  isgroup( LDAPMessage *e );
static void add_error( Error **err, int *nerr, int code, char *addr, LDAPMessage *msg );
static void unbind_and_exit( int rc ) LDAP_GCCATTR((noreturn));
static void send_group( Group **group, int ngroup );

static int  connect_to_x500( void );


int
main ( int argc, char **argv )
{
	char		*myname;
	char		**tolist;
	Error		*errlist;
	Group		**togroups;
	int		numto, ngroups, numerr, nargs;
	int		i, j;
	char		*conffile = NULL;

	if ( (myname = strrchr( argv[0], '/' )) == NULL )
		myname = strdup( argv[0] );
	else
		myname = strdup( myname + 1 );

#ifdef SIGPIPE
	(void) SIGNAL( SIGPIPE, SIG_IGN );
#endif

#ifdef LOG_MAIL
	openlog( myname, OPENLOG_OPTIONS, LOG_MAIL );
#elif LOG_DEBUG
	openlog( myname, OPENLOG_OPTIONS );
#endif

	while ( (i = getopt( argc, argv, "d:C:f:h:l:m:v:" )) != EOF ) {
		switch( i ) {
		case 'd':	/* turn on debugging */
			debug = atoi( optarg );
			break;

		case 'C':	/* path to configuration file */
			conffile = strdup( optarg );
			break;

		case 'f':	/* who it's from & where errors should go */
			mailfrom = strdup( optarg );
			for ( j = 0; sendmailargs[j] != NULL; j++ ) {
				if ( strcmp( sendmailargs[j], "-f" ) == 0 ) {
					sendmailargs[j+1] = mailfrom;
					break;
				}
			}
			break;

		case 'h':	/* hostname */
			host = strdup( optarg );
			hostlen = strlen(host);
			break;

		case 'l':	/* ldap host */
			ldaphost = strdup( optarg );
			break;

				/* mailer-daemon address - who we should */
		case 'm':	/* say errors come from */
			errorsfrom = strdup( optarg );
			break;

		case 'v':	/* vacation host */
			vacationhost = strdup( optarg );
			break;

		default:
			syslog( LOG_ALERT, "unknown option" );
			break;
		}
	}

	if ( mailfrom == NULL ) {
		syslog( LOG_ALERT, "required argument -f not present" );
		exit( EX_TEMPFAIL );
	}
	if ( errorsfrom == NULL ) {
		syslog( LOG_ALERT, "required argument -m not present" );
		exit( EX_TEMPFAIL );
	}
/*  	if ( host == NULL ) { */
/*  		syslog( LOG_ALERT, "required argument -h not present" ); */
/*  		exit( EX_TEMPFAIL ); */
/*  	} */
	if ( conffile == NULL ) {
		syslog( LOG_ALERT, "required argument -C not present" );
		exit( EX_TEMPFAIL );
	}

	load_config( conffile );

	if ( connect_to_x500() != 0 )
		exit( EX_TEMPFAIL );

	setuid( geteuid() );

	if ( debug ) {
		char	buf[1024];
		int	i;

		syslog( LOG_ALERT, "running as %d", geteuid() );
		strcpy( buf, argv[0] );
		for ( i = 1; i < argc; i++ ) {
			strcat( buf, " " );
			strcat( buf, argv[i] );
		}

		syslog( LOG_ALERT, "args: (%s)", buf );
	}

	tolist = NULL;
	numto = 0;
	add_to( &tolist, &numto, sendmailargs );
	nargs = numto;
	ngroups = numerr = 0;
	togroups = NULL;
	errlist = NULL;
	for ( i = optind; i < argc; i++ ) {
		char	*s;
		int	type;
		char	*localpart, *domainpart;
		char	address[1024];

/*  TBC: Make this processing optional */
/*  		for ( j = 0; argv[i][j] != '\0'; j++ ) { */
/*  			if ( argv[i][j] == '.' || argv[i][j] == '_' ) */
/*  				argv[i][j] = ' '; */
/*  		} */

		type = USER;
		split_address( argv[i], &localpart, &domainpart );
		if ( (s = strrchr( localpart, '-' )) != NULL ) {
			s++;

			if ((strcasecmp(s, ERROR) == 0) ||
				(strcasecmp(s, ERRORS) == 0)) {
				type = GROUP_ERRORS;
				*(--s) = '\0';
			} else if ((strcasecmp(s, REQUEST) == 0) ||
				(strcasecmp(s, REQUESTS) == 0)) {
				type = GROUP_REQUEST;
				*(--s) = '\0';
			} else if ( strcasecmp( s, MEMBERS ) == 0 ) {
				type = GROUP_MEMBERS;
				*(--s) = '\0';
			} else if ((strcasecmp(s, OWNER) == 0) ||
				(strcasecmp(s, OWNERS) == 0)) {
				type = GROUP_OWNER;
				*(--s) = '\0';
			}
		}

		if ( domainpart ) {
			sprintf( address, "%s@%s", localpart, domainpart );
			free( localpart );
			free( domainpart );
		} else {
			sprintf( address, "%s@%s", localpart, domainpart );
			free( localpart );
		}
		do_address( address, &tolist, &numto, &togroups, &ngroups,
		    &errlist, &numerr, type );
	}

	/*
	 * If we have both errors and successful deliveries to make or if
	 * if there are any groups to deliver to, we basically need to read
	 * the message twice.  So, we have to put it in a tmp file.
	 */

	if ( numerr > 0 && numto > nargs || ngroups > 0 ) {
		FILE	*fp;
		char	buf[BUFSIZ];

		umask( 077 );
		if ( (fp = tmpfile()) == NULL ) {
			syslog( LOG_ALERT, "could not open tmp file" );
			unbind_and_exit( EX_TEMPFAIL );
		}

		/* copy the message to a temp file */
		while ( fgets( buf, sizeof(buf), stdin ) != NULL ) {
			if ( fputs( buf, fp ) == EOF ) {
				syslog( LOG_ALERT, "error writing tmpfile" );
				unbind_and_exit( EX_TEMPFAIL );
			}
		}

		if ( dup2( fileno( fp ), 0 ) == -1 ) {
			syslog( LOG_ALERT, "could not dup2 tmpfile" );
			unbind_and_exit( EX_TEMPFAIL );
		}

		fclose( fp );
	}

	/* deal with errors */
	if ( numerr > 0 ) {
		if ( debug ) {
			syslog( LOG_ALERT, "sending errors" );
		}
		(void) rewind( stdin );
		send_errors( errlist, numerr );
	}

	(void) ldap_unbind( ld );

	/* send to groups with errorsTo */
	if ( ngroups > 0 ) {
		if ( debug ) {
			syslog( LOG_ALERT, "sending to groups with errorsto" );
		}
		(void) rewind( stdin );
		send_group( togroups, ngroups );
	}

	/* send to expanded aliases and groups w/o errorsTo */
	if ( numto > nargs ) {
		if ( debug ) {
			syslog( LOG_ALERT, "sending to aliases and groups" );
		}
		(void) rewind( stdin );
		send_message( tolist );
	}

	return( EX_OK );
}

static char *
get_config_line( FILE *cf, int *lineno)
{
	static char	buf[2048];
	int		len;
	int		pos;
	int		room;

	pos = 0;
	room = sizeof( buf );
	while ( fgets( &buf[pos], room, cf ) ) {
		(*lineno)++;
		if ( pos > 0 ) {
			/* Delete whitespace at the beginning of new data */
			if ( isspace( buf[pos] ) ) {
				char *s, *d;
				for ( s = buf+pos; isspace(*s); s++ )
					;
				for ( d = buf+pos; *s; s++, d++ ) {
					*d = *s;
				}
				*d = *s;
			}
		}
		len = strlen( buf );
		if ( buf[len-1] != '\n' ) {
			syslog( LOG_ALERT, "Definition too long at line %d",
				*lineno );
			exit( EX_TEMPFAIL );
		}
		if ( buf[0] == '#' )
			continue;
		if ( strspn( buf, " \t\n" ) == len )
			continue;
		if ( buf[len-2] == '\\' ) {
			pos = len - 2;
			room = sizeof(buf) - pos;
			continue;
		}
		/* We have a real line, we will exit the loop */
		buf[len-1] = '\0';
		return( buf );
	}
	return( NULL );
}

static void
add_url ( char *url, int rdnpref, int typemask )
{
	Base		**list_temp;
	int		size;
	Base		*b;

	b = calloc(1, sizeof(Base));
	if ( !b ) {
		syslog( LOG_ALERT, "Out of memory" );
		exit( EX_TEMPFAIL );
	}
	b->b_url = strdup( url );
	b->b_rdnpref = rdnpref;
	b->b_search   = typemask;

	if ( base == NULL ) {
		base = calloc(2, sizeof(LDAPURLDesc *));
		if ( !base ) {
			syslog( LOG_ALERT, "Out of memory" );
			exit( EX_TEMPFAIL );
		}
		base[0] = b;
	} else {
		for ( size = 0; base[size]; size++ )
			;
		size += 2;
		list_temp = realloc( base, size*sizeof(LDAPURLDesc *) );
		if ( !list_temp ) {
			syslog( LOG_ALERT, "Out of memory" );
			exit( EX_TEMPFAIL );
		}
		base = list_temp;
		base[size-2] = b;
		base[size-1] = NULL;
	}
}

static void
add_def_attr( char *s )
{
	char *p, *q;

	p = s;
	while ( *p ) {
		p += strspn( p, "\t," );
		q = strpbrk( p, " \t," );
		if ( q ) {
			*q = '\0';
			add_single_to( &def_attr, p );
		} else {
			add_single_to( &def_attr, p );
			break;
		}
		p = q + 1;
	}
}

static void
add_attr_semantics( char *s )
{
	char *p, *q;
	AttrSemantics *as;

	as = calloc( 1, sizeof( AttrSemantics ) );
	as->as_priority = current_priority;
	p = s;
	while ( isspace ( *p ) )
		p++;
	q = p;
	while ( !isspace ( *q ) && *q != '\0' )
		q++;
	*q = '\0';
	as->as_name = strdup( p );
	p = q + 1;

	while ( *p ) {
		while ( isspace ( *p ) )
			p++;
		q = p;
		while ( !isspace ( *q ) && *q != '\0' )
			q++;
		*q = '\0';
		if ( !strcasecmp( p, "multivalued" ) ) {
			as->as_m_valued = 1;
		} else if ( !strcasecmp( p, "multiple-entries" ) ) {
			as->as_m_entries = 1;
		} else if ( !strcasecmp( p, "local-native-mailbox" ) ) {
			as->as_syntax = AS_SYNTAX_NATIVE_MB;
		} else if ( !strcasecmp( p, "rfc822" ) ) {
			as->as_syntax = AS_SYNTAX_RFC822;
		} else if ( !strcasecmp( p, "rfc822-extended" ) ) {
			as->as_syntax = AS_SYNTAX_RFC822_EXT;
		} else if ( !strcasecmp( p, "dn" ) ) {
			as->as_syntax = AS_SYNTAX_DN;
		} else if ( !strcasecmp( p, "url" ) ) {
			as->as_syntax = AS_SYNTAX_URL;
		} else if ( !strncasecmp( p, "search-with-filter=", 19 ) ) {
			as->as_syntax = AS_SYNTAX_BOOL_FILTER;
			q = strchr( p, '=' );
			if ( q ) {
				p = q + 1;
				while ( *q && !isspace( *q ) ) {
					q++;
				}
				if ( *q ) {
					*q = '\0';
					as->as_param = strdup( p );
					p = q + 1;
				} else {
					as->as_param = strdup( p );
					p = q;
				}
			} else {
				syslog( LOG_ALERT,
					"Missing filter in %s", s );
				exit( EX_TEMPFAIL );
			}
		} else if ( !strcasecmp( p, "host" ) ) {
			as->as_kind = AS_SYNTAX_HOST;
		} else if ( !strcasecmp( p, "route-to-host" ) ) {
			as->as_kind = AS_KIND_ROUTE_TO_HOST;
		} else if ( !strcasecmp( p, "route-to-address" ) ) {
			as->as_kind = AS_KIND_ROUTE_TO_ADDR;
		} else if ( !strcasecmp( p, "recipient" ) ) {
			as->as_kind = AS_KIND_RECIPIENT;
		} else if ( !strcasecmp( p, "errors" ) ) {
			as->as_kind = AS_KIND_ERRORS;
		} else if ( !strcasecmp( p, "request" ) ) {
			as->as_kind = AS_KIND_REQUEST;
		} else if ( !strcasecmp( p, "owner" ) ) {
			as->as_kind = AS_KIND_OWNER;
		} else {
			syslog( LOG_ALERT,
				"Unknown semantics word %s", p );
			exit( EX_TEMPFAIL );
		}
		p = q + 1;
	}
	if ( attr_semantics == NULL ) {
		attr_semantics = calloc(2, sizeof(AttrSemantics *));
		if ( !attr_semantics ) {
			syslog( LOG_ALERT, "Out of memory" );
			exit( EX_TEMPFAIL );
		}
		attr_semantics[0] = as;
	} else {
		int size;
		AttrSemantics **list_temp;
		for ( size = 0; attr_semantics[size]; size++ )
			;
		size += 2;
		list_temp = realloc( attr_semantics,
				     size*sizeof(AttrSemantics *) );
		if ( !list_temp ) {
			syslog( LOG_ALERT, "Out of memory" );
			exit( EX_TEMPFAIL );
		}
		attr_semantics = list_temp;
		attr_semantics[size-2] = as;
		attr_semantics[size-1] = NULL;
	}
}

static void
load_config( char *filespec )
{
	FILE		*cf;
	char		*line;
	int		lineno = 0;
	char		*p;
	int		rdnpref;
	int		typemask;

	cf = fopen( filespec, "r" );
	if ( !cf ) {
		perror( "Opening config file" );
		exit( EX_TEMPFAIL );
	}

	while ( ( line = get_config_line( cf,&lineno ) ) ) {
		p = strpbrk( line, " \t" );
		if ( !p ) {
			syslog( LOG_ALERT,
				"Missing space at line %d", lineno );
			exit( EX_TEMPFAIL );
		}
		if ( !strncmp( line, "search", p-line ) ) {
			p += strspn( p, " \t" );
			/* TBC, get these */
			rdnpref = 0;
			typemask = 0xFF;
			add_url( p, rdnpref, typemask );
		} else if ( !strncmp(line, "attribute", p-line) ) {
			p += strspn(p, " \t");
			add_attr_semantics( p );
		} else if ( !strncmp(line, "default-attributes", p-line) ) {
			p += strspn(p, " \t");
			add_def_attr( p );
		} else if ( !strncmp(line, "group-classes", p-line) ) {
			p += strspn(p, " \t");
			add_single_to( &groupclasses, p );
		} else if ( !strncmp(line, "priority", p-line) ) {
			p += strspn(p, " \t");
			current_priority = atoi(p);
		} else if ( !strncmp(line, "domain", p-line) ) {
			p += strspn(p, " \t");
			add_single_to( &mydomains, p );
		} else {
			syslog( LOG_ALERT,
				"Unparseable config definition at line %d",
				lineno );
			exit( EX_TEMPFAIL );
		}
	}
	fclose( cf );
}

static int
connect_to_x500( void )
{
	int opt;

	if ( (ld = ldap_init( ldaphost, 0 )) == NULL ) {
		syslog( LOG_ALERT, "ldap_init failed" );
		return( -1 );
	}

	/*  TBC: Set this only when it makes sense
	opt = MAIL500_MAXAMBIGUOUS;
	ldap_set_option(ld, LDAP_OPT_SIZELIMIT, &opt);
	*/
	opt = LDAP_DEREF_ALWAYS;
	ldap_set_option(ld, LDAP_OPT_DEREF, &opt);

	if ( ldap_simple_bind_s( ld, NULL, NULL ) != LDAP_SUCCESS ) {
		syslog( LOG_ALERT, "ldap_simple_bind_s failed" );
		return( -1 );
	}

	return( 0 );
}

static Group *
new_group( char *dn, Group ***list, int *nlist )
{
	int	i;
	Group	*this_group;

	for ( i = 0; i < *nlist; i++ ) {
		if ( strcmp( dn, (*list)[i]->g_dn ) == 0 ) {
			syslog( LOG_ALERT, "group loop 2 detected (%s)", dn );
			return NULL;
		}
	}

	this_group = (Group *) malloc( sizeof(Group) );

	if ( *nlist == 0 ) {
		*list = (Group **) malloc( sizeof(Group *) );
	} else {
		*list = (Group **) realloc( *list, (*nlist + 1) *
		    sizeof(Group *) );
	}

	this_group->g_errorsto = NULL;
	this_group->g_members = NULL;
	this_group->g_nmembers = 0;
	/* save the group's dn so we can check for loops above */
	this_group->g_dn = strdup( dn );

	(*list)[*nlist] = this_group;
	(*nlist)++;

	return( this_group );
}

static void
split_address(
	char	*address,
	char	**localpart,
	char	**domainpart
)
{
	char		*p;

	if ( ( p = strrchr( address, '@' ) ) == NULL ) {
		*localpart = strdup( address );
		*domainpart = NULL;
	} else {
		*localpart = malloc( p - address + 1 );
		strncpy( *localpart, address, p - address );
		(*localpart)[p - address] = '\0';
		p++;
		*domainpart = strdup( p );
	}
}

static int
dn_search(
	char	**dnlist, 
	char	*address,
	char	***to,
	int	*nto,
	Group	***togroups,
	int	*ngroups,
	Error	**err,
	int	*nerr
)
{
	int		rc;
	int		i;
	int		resolved = 0;
	LDAPMessage	*res, *e;
	struct timeval	timeout;

	timeout.tv_sec = MAIL500_TIMEOUT;
	timeout.tv_usec = 0;
	for ( i = 0; dnlist[i]; i++ ) {
		if ( (rc = ldap_search_st( ld, dnlist[i], LDAP_SCOPE_BASE,
			"(objectclass=*)", def_attr, 0,
			 &timeout, &res )) != LDAP_SUCCESS ) {
			if ( rc == LDAP_NO_SUCH_OBJECT ) {
				add_error( err, nerr, E_BADMEMBER, dnlist[i], NULL );
				continue;
			} else {
				syslog( LOG_ALERT, "member search return 0x%x", rc );

				unbind_and_exit( EX_TEMPFAIL );
			}
		} else {
			if ( (e = ldap_first_entry( ld, res )) == NULL ) {
				syslog( LOG_ALERT, "member search error parsing entry" );
				unbind_and_exit( EX_TEMPFAIL );
			}
			if ( entry_engine( e, dnlist[i], address, to, nto,
					   togroups, ngroups, err, nerr,
					   USER | GROUP_MEMBERS ) ) {
				resolved = 1;
			}
		}
	}
	return( resolved );
}

static int
search_ldap_url(
	char	*url,
	Subst	*substs,
	char	*address,
	int	rdnpref,
	int	multi_entry,
	char	***to,
	int	*nto,
	Group	***togroups,
	int	*ngroups,
	Error	**err,
	int	*nerr,
	int	type
)
{
	LDAPURLDesc	*ludp;
	char		*p, *s, *d;
	int		i;
	char		filter[1024];
	LDAPMessage	*e, *res;
	int		rc;
	char		**attrlist;
	struct timeval	timeout;
	int		match;
	int		resolved = 0;
	char		*dn;

	timeout.tv_sec = MAIL500_TIMEOUT;
	timeout.tv_usec = 0;

	rc = ldap_url_parse( url, &ludp );
	if ( rc ) {
		switch ( rc ) {
		case LDAP_URL_ERR_NOTLDAP:
			syslog( LOG_ALERT,
				"Not an LDAP URL: %s", url );
			break;
		case LDAP_URL_ERR_BADENCLOSURE:
			syslog( LOG_ALERT,
				"Bad Enclosure in URL: %s", url );
			break;
		case LDAP_URL_ERR_BADURL:
			syslog( LOG_ALERT,
				"Bad URL: %s", url );
			break;
		case LDAP_URL_ERR_BADHOST:
			syslog( LOG_ALERT,
				"Host is invalid in URL: %s", url );
			break;
		case LDAP_URL_ERR_BADATTRS:
			syslog( LOG_ALERT,
				"Attributes are invalid in URL: %s", url );
			break;
		case LDAP_URL_ERR_BADSCOPE:
			syslog( LOG_ALERT,
				"Scope is invalid in URL: %s", url );
			break;
		case LDAP_URL_ERR_BADFILTER:
			syslog( LOG_ALERT,
				"Filter is invalid in URL: %s", url );
			break;
		case LDAP_URL_ERR_BADEXTS:
			syslog( LOG_ALERT,
				"Extensions are invalid in URL: %s", url );
			break;
		case LDAP_URL_ERR_MEM:
			syslog( LOG_ALERT,
				"Out of memory parsing URL: %s", url );
			break;
		case LDAP_URL_ERR_PARAM:
			syslog( LOG_ALERT,
				"bad parameter parsing URL: %s", url );
			break;
		default:
			syslog( LOG_ALERT,
				"Unknown error %d parsing URL: %s",
				rc, url );
			break;
		}
		add_error( err, nerr, E_BADMEMBER,
			   url, NULL );
		return 0;
	}

	if ( substs ) {
		for ( s = ludp->lud_filter, d = filter; *s; s++,d++ ) {
			if ( *s == '%' ) {
				s++;
				if ( *s == '%' ) {
					*d = '%';
					continue;
				}
				for ( i = 0; substs[i].sub_char != '\0';
				      i++ ) {
					if ( *s == substs[i].sub_char ) {
						for ( p = substs[i].sub_value;
						      *p; p++,d++ ) {
							*d = *p;
						}
						d--;
						break;
					}
				}
				if ( substs[i].sub_char == '\0' ) {
					syslog( LOG_ALERT,
						"unknown format %c", *s );
				}
			} else {
				*d = *s;
			}
		}
		*d = *s;
	} else {
		strncpy( filter, ludp->lud_filter, sizeof( filter ) - 1 );
		filter[ sizeof( filter ) - 1 ] = '\0';
	}

	if ( ludp->lud_attrs ) {
		attrlist = ludp->lud_attrs;
	} else {
		attrlist = def_attr;
	}
	res = NULL;
	/* TBC: we don't read the host, dammit */
	rc = ldap_search_st( ld, ludp->lud_dn, ludp->lud_scope,
			     filter, attrlist, 0,
			     &timeout, &res );

	/* some other trouble - try again later */
	if ( rc != LDAP_SUCCESS &&
	     rc != LDAP_SIZELIMIT_EXCEEDED ) {
		syslog( LOG_ALERT, "return 0x%x from X.500",
			rc );
		unbind_and_exit( EX_TEMPFAIL );
	}

	match = ldap_count_entries( ld, res );

	/* trouble - try again later */
	if ( match == -1 ) {
		syslog( LOG_ALERT, "error parsing result from X.500" );
		unbind_and_exit( EX_TEMPFAIL );
	}

	if ( match == 1 || multi_entry ) {
		for ( e = ldap_first_entry( ld, res ); e != NULL;
		      e = ldap_next_entry( ld, e ) ) {
			dn = ldap_get_dn( ld, e );
			resolved = entry_engine( e, dn, address, to, nto,
						 togroups, ngroups,
						 err, nerr, type );
			if ( !resolved ) {
				add_error( err, nerr, E_NOEMAIL, address, res );
			}
		}
		return ( resolved );
	}

	/* more than one match - bounce with ambiguous user? */
	if ( match > 1 ) {
		LDAPMessage	*next, *tmpres = NULL;
		char		*dn;
		char		**xdn;

		/* not giving rdn preference - bounce with ambiguous user */
		if ( rdnpref == 0 ) {
			add_error( err, nerr, E_AMBIGUOUS, address, res );
			return 0;
		}

		/*
		 * giving rdn preference - see if any entries were matched
		 * because of their rdn.  If so, collect them to deal with
		 * later (== 1 we deliver, > 1 we bounce).
		 */

		for ( e = ldap_first_entry( ld, res ); e != NULL; e = next ) {
			next = ldap_next_entry( ld, e );
			dn = ldap_get_dn( ld, e );
			xdn = ldap_explode_dn( dn, 1 );

			/* XXX bad, but how else can we do it? XXX */
			if ( strcasecmp( xdn[0], address ) == 0 ) {
				ldap_delete_result_entry( &res, e );
				ldap_add_result_entry( &tmpres, e );
			}

			ldap_value_free( xdn );
			free( dn );
		}

		/* nothing matched by rdn - go ahead and bounce */
		if ( tmpres == NULL ) {
			add_error( err, nerr, E_AMBIGUOUS, address, res );
			return 0;

		/* more than one matched by rdn - bounce with rdn matches */
		} else if ( (match = ldap_count_entries( ld, tmpres )) > 1 ) {
			add_error( err, nerr, E_AMBIGUOUS, address, tmpres );
			return 0;

		/* trouble... */
		} else if ( match < 0 ) {
			syslog( LOG_ALERT, "error parsing result from X.500" );
			unbind_and_exit( EX_TEMPFAIL );
		}

		/* otherwise one matched by rdn - send to it */
		ldap_msgfree( res );
		res = tmpres;

		/* trouble */
		if ( (e = ldap_first_entry( ld, res )) == NULL ) {
			syslog( LOG_ALERT, "error parsing entry from X.500" );
			unbind_and_exit( EX_TEMPFAIL );
		}

		dn = ldap_get_dn( ld, e );

		resolved = entry_engine( e, dn, address, to, nto,
					 togroups, ngroups,
					 err, nerr, type );
		if ( !resolved ) {
			add_error( err, nerr, E_NOEMAIL, address, res );
			/* Don't free res if we passed it to add_error */
		} else {
			ldap_msgfree( res );
		}
	}
	return( resolved );
}

static int
url_list_search(
	char	**urllist, 
	char	*address,
	int	multi_entry,
	char	***to,
	int	*nto,
	Group	***togroups,
	int	*ngroups,
	Error	**err,
	int	*nerr,
	int	type
)
{
	int		i;
	int		resolved = 0;

	for ( i = 0; urllist[i]; i++ ) {

		if ( !strncasecmp( urllist[i], "mail:", 5 ) ) {
			char	*vals[2];

			vals[0] = urllist[i] + 5;
			vals[1] = NULL;
			add_to( to, nto, vals );
			resolved = 1;

		} else if ( ldap_is_ldap_url( urllist[i] ) ) {

			resolved = search_ldap_url( urllist[i], NULL,
						    address, 0, multi_entry,
						    to, nto, togroups, ngroups,
						    err, nerr, type );
		} else {
			/* Produce some sensible error here */
			resolved = 0;
		}
	}
	return( resolved );
}

static int
is_my_domain(
	char * domain
)
{
	char **d;

	if ( d == NULL )
		return 0;
	for ( d = mydomains; *d; d++ ) {
		if ( !strcmp(*d,domain) ) {
			return 1;
		}
	}
	return 0;
}

/*
 * The entry engine processes an entry.  Normally, each entry will resolve
 * to one or more values that will be added to the 'to' argument.  This
 * argument needs not be the global 'to' list, it may be the g_to field
 * in a group.  Groups have no special treatment, unless they require
 * a special sender.
 */

static int
entry_engine(
	LDAPMessage *e,
	char	*dn,
	char	*address,
	char	***to,
	int	*nto,
	Group	***togroups,
	int	*ngroups,
	Error	**err,
	int	*nerr,
	int	type
)
{
	char	**vals;
	int	i;
	int	resolved = 0;
	char	***current_to = to;
	int	*current_nto = nto;
	Group	*current_group = NULL;
	char	buf[1024];
	char	*localpart, *domainpart;
	Subst	substs[2];
	int	cur_priority = 0;
	char	*route_to_host = NULL;
	char	*route_to_address = NULL;
	char	*nvals[2];

	for ( i=0; attr_semantics[i] != NULL; i++ ) {
		AttrSemantics	*as = attr_semantics[i];
		int		nent;

		if ( as->as_priority < cur_priority ) {
			/*
			 * We already got higher priority information,
			 * so no further work to do, ignore the rest.
			 */
			break;
		}
		vals = ldap_get_values( ld, e, as->as_name );
		if ( !vals || vals[0] == NULL ) {
			continue;
		}
		nent = count_values( vals );
		if ( nent > 1 && !as->as_m_valued ) {
			add_error( err, nerr, E_AMBIGUOUS, address, e );
			return( 0 );
		}
		switch ( as->as_kind ) {
		case AS_KIND_RECIPIENT:
			cur_priority = as->as_priority;
			if ( ! ( type & ( USER | GROUP_MEMBERS ) ) )
				break;
			switch ( as->as_syntax ) {
			case AS_SYNTAX_RFC822:
				add_to( current_to, current_nto, vals );
				resolved = 1;
				break;
			case AS_SYNTAX_RFC822_EXT:
				add_to( current_to, current_nto, vals );
				resolved = 1;
				break;
			case AS_SYNTAX_NATIVE_MB:
				/* We used to concatenate mailHost if set here */
				/*
				 * We used to send a copy to the vacation host
				 * if onVacation to uid@vacationhost
				 */
				add_to( current_to, current_nto, vals );
				resolved = 1;
				break;

			case AS_SYNTAX_DN:
				if ( dn_search( vals, address,
						current_to, current_nto,
						togroups, ngroups,
						err, nerr ) ) {
					resolved = 1;
				}
				break;

			case AS_SYNTAX_URL:
				if ( url_list_search( vals, address,
						 as->as_m_entries,
						 current_to, current_nto,
						 togroups, ngroups,
						 err, nerr, type ) ) {
					resolved = 1;
				}
				break;

			case AS_SYNTAX_BOOL_FILTER:
				if ( strcasecmp( vals[0], "true" ) ) {
					break;
				}
				substs[0].sub_char = 'D';
				substs[0].sub_value = dn;
				substs[1].sub_char = '\0';
				substs[1].sub_value = NULL;
				if ( url_list_search( vals, address,
						 as->as_m_entries,
						 current_to, current_nto,
						 togroups, ngroups,
						 err, nerr, type ) ) {
					resolved = 1;
				}
				break;

			default:
				syslog( LOG_ALERT,
					"Invalid syntax %d for kind %d",
					as->as_syntax, as->as_kind );
				break;
			}
			break;

		case AS_KIND_ERRORS:
			cur_priority = as->as_priority;
			/* This is a group with special processing */
			if ( type & GROUP_ERRORS ) {
				switch (as->as_kind) {
				case AS_SYNTAX_RFC822:
					add_to( current_to, current_nto, vals );
					resolved = 1;
					break;
				case AS_SYNTAX_URL:
				default:
					syslog( LOG_ALERT,
						"Invalid syntax %d for kind %d",
						as->as_syntax, as->as_kind );
				}
			} else {
				current_group = new_group( dn, togroups,
							   ngroups );
				current_to = &current_group->g_members;
				current_nto = &current_group->g_nmembers;
				split_address( address,
					       &localpart, &domainpart );
				if ( domainpart ) {
					sprintf( buf, "%s-%s@%s",
						 localpart, ERRORS,
						 domainpart );
					free( localpart );
					free( domainpart );
				} else {
					sprintf( buf, "%s-%s@%s",
						 localpart, ERRORS,
						 host );
					free( localpart );
				}
				current_group->g_errorsto = strdup( buf );
			}
			break;

		case AS_KIND_REQUEST:
			cur_priority = as->as_priority;
			/* This is a group with special processing */
			if ( type & GROUP_REQUEST ) {
				add_to( current_to, current_nto, vals );
				resolved = 1;
			}
			break;

		case AS_KIND_OWNER:
			cur_priority = as->as_priority;
			/* This is a group with special processing */
			if ( type & GROUP_REQUEST ) {
				add_to( current_to, current_nto, vals );
				resolved = 1;
			}
			break;

		case AS_KIND_ROUTE_TO_HOST:
			if ( !is_my_domain( vals[0] ) ) {
				cur_priority = as->as_priority;
				route_to_host = strdup( vals[0] );
			}
			break;

		case AS_KIND_ROUTE_TO_ADDR:
			if ( strcmp( vals[0], address ) ) {
				cur_priority = as->as_priority;
				route_to_address = strdup( vals[0] );
			}
			break;

		default:
			syslog( LOG_ALERT,
				"Invalid kind %d", as->as_kind );
			/* Error, TBC */
		}
		ldap_value_free( vals );
	}
	if ( route_to_host ) {
		char *p;
		if ( !route_to_address ) {
			route_to_address = strdup( address );
		}
		/* This makes use of the percent hack, but there's no choice */
		p = strchr( route_to_address, '@' );
		if ( p ) {
			*p = '%';
		}
		sprintf( buf, "%s@%s", route_to_address, route_to_host );
		nvals[0] = buf;
		nvals[1] = NULL;
		add_to( current_to, current_nto, nvals );
		resolved = 1;
		free( route_to_host );
		free( route_to_address );
	} else if ( route_to_address ) {
		nvals[0] = route_to_address;
		nvals[1] = NULL;
		add_to( current_to, current_nto, nvals );
		resolved = 1;
		free( route_to_address );
	}
		  
	return( resolved );
}

static int
search_bases(
	char	*filter,
	Subst	*substs,
	char	*name,
	char	***to,
	int	*nto,
	Group	***togroups,
	int	*ngroups,
	Error	**err,
	int	*nerr,
	int	type
)
{
	int		b, resolved = 0;

	for ( b = 0; base[b] != NULL; b++ ) {

		if ( ! (base[b]->b_search & type) ) {
			continue;
		}

		resolved = search_ldap_url( base[b]->b_url, substs, name,
					    base[b]->b_rdnpref,
					    base[b]->b_m_entries,
					    to, nto, togroups, ngroups,
					    err, nerr, type );
		if ( resolved )
			break;
	}
	return( resolved );
}

static void
do_address(
	char	*name,
	char	***to,
	int	*nto,
	Group	***togroups,
	int	*ngroups,
	Error	**err,
	int	*nerr,
	int	type
)
{
	struct timeval	timeout;
	char		*localpart, *domainpart;
	int		resolved;
	Subst	substs[5];

	/*
	 * Look up the name in X.500, add the appropriate addresses found
	 * to the to list, or to the err list in case of error.  Groups are
	 * handled by the do_group routine, individuals are handled here.
	 * When looking up name, we follow the bases hierarchy, looking
	 * in base[0] first, then base[1], etc.  For each base, there is
	 * a set of search filters to try, in order.  If something goes
	 * wrong here trying to contact X.500, we exit with EX_TEMPFAIL.
	 * If the b_rdnpref flag is set, then we give preference to entries
	 * that matched name because it's their rdn, otherwise not.
	 */

	split_address( name, &localpart, &domainpart );
	timeout.tv_sec = MAIL500_TIMEOUT;
	timeout.tv_usec = 0;
	substs[0].sub_char = 'm';
	substs[0].sub_value = name;
	substs[1].sub_char = 'h';
	substs[1].sub_value = host;
	substs[2].sub_char = 'l';
	substs[2].sub_value = localpart;
	substs[3].sub_char = 'd';
	substs[3].sub_value = domainpart;
	substs[4].sub_char = '\0';
	substs[4].sub_value = NULL;

	resolved = search_bases( NULL, substs, name,
				 to, nto, togroups, ngroups,
				 err, nerr, type );

	if ( !resolved ) {
		/* not resolved - bounce with user unknown */
		if ( type == USER ) {
			add_error( err, nerr, E_USERUNKNOWN, name, NULL );
		} else {
			add_error( err, nerr, E_GROUPUNKNOWN, name, NULL );
		}
	}
}

static void
send_message( char **to )
{
	int	pid;
#ifndef HAVE_WAITPID
	WAITSTATUSTYPE	status;
#endif

	if ( debug ) {
		char	buf[1024];
		int	i;

		strcpy( buf, to[0] );
		for ( i = 1; to[i] != NULL; i++ ) {
			strcat( buf, " " );
			strcat( buf, to[i] );
		}

		syslog( LOG_ALERT, "send_message execing sendmail: (%s)", buf );
	}

	/* parent */
	if ( (pid = fork()) != 0 ) {
#ifdef HAVE_WAITPID
		waitpid( pid, (int *) NULL, 0 );
#else
		wait4( pid, &status, WAIT_FLAGS, 0 );
#endif
	/* child */
	} else {
		/* to includes sendmailargs */
		execv( MAIL500_SENDMAIL, to );

		syslog( LOG_ALERT, "execv failed" );

		exit( EX_TEMPFAIL );
	}
}

static void
send_group( Group **group, int ngroup )
{
	int	i, pid;
	char	**argv;
	int	argc;
	char	*iargv[7];
#ifndef HAVE_WAITPID
	WAITSTATUSTYPE	status;
#endif

	for ( i = 0; i < ngroup; i++ ) {
		(void) rewind( stdin );

		iargv[0] = MAIL500_SENDMAIL;
		iargv[1] = "-f";
		iargv[2] = group[i]->g_errorsto;
		iargv[3] = "-oMrX.500";
		iargv[4] = "-odi";
		iargv[5] = "-oi";
		iargv[6] = NULL;

		argv = NULL;
		argc = 0;
		add_to( &argv, &argc, iargv );
		add_to( &argv, &argc, group[i]->g_members );

		if ( debug ) {
			char	buf[1024];
			int	i;

			strcpy( buf, argv[0] );
			for ( i = 1; i < argc; i++ ) {
				strcat( buf, " " );
				strcat( buf, argv[i] );
			}

			syslog( LOG_ALERT, "execing sendmail: (%s)", buf );
		}

		/* parent */
		if ( (pid = fork()) != 0 ) {
#ifdef HAVE_WAITPID
			waitpid( pid, (int *) NULL, 0 );
#else
			wait4( pid, &status, WAIT_FLAGS, 0 );
#endif
		/* child */
		} else {
			execv( MAIL500_SENDMAIL, argv );

			syslog( LOG_ALERT, "execv failed" );

			exit( EX_TEMPFAIL );
		}
	}
}

static void
send_errors( Error *err, int nerr )
{
	int	pid, i, namelen;
	FILE	*fp;
	int	fd[2];
	char	*argv[8];
	char	buf[1024];
#ifndef HAVE_WAITPID
	WAITSTATUSTYPE	status;
#endif

	if ( strcmp( MAIL500_BOUNCEFROM, mailfrom ) == 0 ) {
	    mailfrom = errorsfrom;
	}

	argv[0] = MAIL500_SENDMAIL;
	argv[1] = "-oMrX.500";
	argv[2] = "-odi";
	argv[3] = "-oi";
	argv[4] = "-f";
	argv[5] = MAIL500_BOUNCEFROM;
	argv[6] = mailfrom;
	argv[7] = NULL;

	if ( debug ) {
		int	i;

		strcpy( buf, argv[0] );
		for ( i = 1; argv[i] != NULL; i++ ) {
			strcat( buf, " " );
			strcat( buf, argv[i] );
		}

		syslog( LOG_ALERT, "execing sendmail: (%s)", buf );
	}

	if ( pipe( fd ) == -1 ) {
		syslog( LOG_ALERT, "cannot create pipe" );
		exit( EX_TEMPFAIL );
	}

	if ( (pid = fork()) != 0 ) {
		if ( (fp = fdopen( fd[1], "w" )) == NULL ) {
			syslog( LOG_ALERT, "cannot fdopen pipe" );
			exit( EX_TEMPFAIL );
		}

		fprintf( fp, "To: %s\n", mailfrom );
		fprintf( fp, "From: %s\n", errorsfrom );
		fprintf( fp, "Subject: undeliverable mail\n" );
		fprintf( fp, "\n" );
		fprintf( fp, "The following errors occurred when trying to deliver the attached mail:\n" );
		for ( i = 0; i < nerr; i++ ) {
			namelen = strlen( err[i].e_addr );
			fprintf( fp, "\n" );

			switch ( err[i].e_code ) {
			case E_USERUNKNOWN:
				fprintf( fp, "%s: User unknown\n", err[i].e_addr );
				break;

			case E_GROUPUNKNOWN:
				fprintf( fp, "%s: Group unknown\n", err[i].e_addr );
				break;

			case E_BADMEMBER:
				fprintf( fp, "%s: Group member does not exist\n",
				    err[i].e_addr );
				fprintf( fp, "This could be because the distinguished name of the person has changed\n" );
				fprintf( fp, "If this is the case, the problem can be solved by removing and\n" );
				fprintf( fp, "then re-adding the person to the group.\n" );
				break;

			case E_NOREQUEST:
				fprintf( fp, "%s: Group exists but has no request address\n",
				    err[i].e_addr );
				break;

			case E_NOERRORS:
				fprintf( fp, "%s: Group exists but has no errors-to address\n",
				    err[i].e_addr );
				break;

			case E_NOOWNER:
				fprintf( fp, "%s: Group exists but has no owner\n",
				    err[i].e_addr );
				break;

			case E_AMBIGUOUS:
				do_ambiguous( fp, &err[i], namelen );
				break;

			case E_NOEMAIL:
				do_noemail( fp, &err[i], namelen );
				break;

			case E_MEMBERNOEMAIL:
				fprintf( fp, "%s: Group member exists but does not have an email address\n",
				    err[i].e_addr );
				break;

			case E_JOINMEMBERNOEMAIL:
				fprintf( fp, "%s: User has joined group but does not have an email address\n",
				    err[i].e_addr );
				break;

			case E_LOOP:
				fprintf( fp, "%s: User has created a mail loop by adding address %s to their X.500 entry\n",
				    err[i].e_addr, err[i].e_loop );
				break;

			case E_NOMEMBERS:
				fprintf( fp, "%s: Group has no members\n",
				    err[i].e_addr );
				break;

			default:
				syslog( LOG_ALERT, "unknown error %d", err[i].e_code );
				unbind_and_exit( EX_TEMPFAIL );
				break;
			}
		}

		fprintf( fp, "\n------- The original message sent:\n\n" );

		while ( fgets( buf, sizeof(buf), stdin ) != NULL ) {
			fputs( buf, fp );
		}
		fclose( fp );

#ifdef HAVE_WAITPID
		waitpid( pid, (int *) NULL, 0 );
#else
		wait4( pid, &status, WAIT_FLAGS, 0 );
#endif
	} else {
		dup2( fd[0], 0 );

		execv( MAIL500_SENDMAIL, argv );

		syslog( LOG_ALERT, "execv failed" );

		exit( EX_TEMPFAIL );
	}
}

static void
do_noemail( FILE *fp, Error *err, int namelen )
{
	int		i, last;
	char		*dn, *rdn;
	char		**ufn, **vals;

	fprintf(fp, "%s: User has no email address registered.\n",
	    err->e_addr );
	fprintf( fp, "%*s  Name, title, postal address and phone for '%s':\n\n",
	    namelen, " ", err->e_addr );

	/* name */
	dn = ldap_get_dn( ld, err->e_msg );
	ufn = ldap_explode_dn( dn, 1 );
	rdn = strdup( ufn[0] );
	if ( strcasecmp( rdn, err->e_addr ) == 0 ) {
		if ( (vals = ldap_get_values( ld, err->e_msg, "cn" ))
		    != NULL ) {
			for ( i = 0; vals[i]; i++ ) {
				last = strlen( vals[i] ) - 1;
				if ( isdigit((unsigned char) vals[i][last]) ) {
					rdn = strdup( vals[i] );
					break;
				}
			}

			ldap_value_free( vals );
		}
	}
	fprintf( fp, "%*s  %s\n", namelen, " ", rdn );
	free( dn );
	free( rdn );
	ldap_value_free( ufn );

	/* titles or descriptions */
	if ( (vals = ldap_get_values( ld, err->e_msg, "title" )) == NULL &&
	    (vals = ldap_get_values( ld, err->e_msg, "description" ))
	    == NULL ) {
		fprintf( fp, "%*s  No title or description registered\n",
		    namelen, " " );
	} else {
		for ( i = 0; vals[i] != NULL; i++ ) {
			fprintf( fp, "%*s  %s\n", namelen, " ", vals[i] );
		}

		ldap_value_free( vals );
	}

	/* postal address */
	if ( (vals = ldap_get_values( ld, err->e_msg, "postalAddress" ))
	    == NULL ) {
		fprintf( fp, "%*s  No postal address registered\n", namelen,
		    " " );
	} else {
		fprintf( fp, "%*s  ", namelen, " " );
		for ( i = 0; vals[0][i] != '\0'; i++ ) {
			if ( vals[0][i] == '$' ) {
				fprintf( fp, "\n%*s  ", namelen, " " );
				while ( isspace((unsigned char) vals[0][i+1]) )
					i++;
			} else {
				fprintf( fp, "%c", vals[0][i] );
			}
		}
		fprintf( fp, "\n" );

		ldap_value_free( vals );
	}

	/* telephone number */
	if ( (vals = ldap_get_values( ld, err->e_msg, "telephoneNumber" ))
	    == NULL ) {
		fprintf( fp, "%*s  No phone number registered\n", namelen,
		    " " );
	} else {
		for ( i = 0; vals[i] != NULL; i++ ) {
			fprintf( fp, "%*s  %s\n", namelen, " ", vals[i] );
		}

		ldap_value_free( vals );
	}
}

/* ARGSUSED */
static void
do_ambiguous( FILE *fp, Error *err, int namelen )
{
	int		i, last;
	char		*dn, *rdn;
	char		**ufn, **vals;
	LDAPMessage	*e;

	i = ldap_result2error( ld, err->e_msg, 0 );

	fprintf( fp, "%s: Ambiguous user.  %s%d matches found:\n\n",
	    err->e_addr, i == LDAP_SIZELIMIT_EXCEEDED ? "First " : "",
	    ldap_count_entries( ld, err->e_msg ) );

	for ( e = ldap_first_entry( ld, err->e_msg ); e != NULL;
	    e = ldap_next_entry( ld, e ) ) {
		dn = ldap_get_dn( ld, e );
		ufn = ldap_explode_dn( dn, 1 );
		rdn = strdup( ufn[0] );
		if ( strcasecmp( rdn, err->e_addr ) == 0 ) {
			if ( (vals = ldap_get_values( ld, e, "cn" )) != NULL ) {
				for ( i = 0; vals[i]; i++ ) {
					last = strlen( vals[i] ) - 1;
					if (isdigit((unsigned char) vals[i][last])) {
						rdn = strdup( vals[i] );
						break;
					}
				}

				ldap_value_free( vals );
			}
		}

		/* 
		if ( isgroup( e ) ) {
			vals = ldap_get_values( ld, e, "description" );
		} else {
			vals = ldap_get_values( ld, e, "title" );
		}
		*/
		vals = ldap_get_values( ld, e, "description" );

		fprintf( fp, "    %-20s %s\n", rdn, vals ? vals[0] : "" );
		for ( i = 1; vals && vals[i] != NULL; i++ ) {
			fprintf( fp, "                         %s\n", vals[i] );
		}

		free( dn );
		free( rdn );
		ldap_value_free( ufn );
		if ( vals != NULL )
			ldap_value_free( vals );
	}
}

static int
count_values( char **list )
{
	int	i;

	for ( i = 0; list && list[i] != NULL; i++ )
		;	/* NULL */

	return( i );
}

static void
add_to( char ***list, int *nlist, char **new )
{
	int	i, nnew, oldnlist;

	nnew = count_values( new );

	oldnlist = *nlist;
	if ( *list == NULL || *nlist == 0 ) {
		*list = (char **) malloc( (nnew + 1) * sizeof(char *) );
		*nlist = nnew;
	} else {
		*list = (char **) realloc( *list, *nlist * sizeof(char *) +
		    nnew * sizeof(char *) + sizeof(char *) );
		*nlist += nnew;
	}

	for ( i = 0; i < nnew; i++ )
		(*list)[i + oldnlist] = strdup( new[i] );
	(*list)[*nlist] = NULL;
}

static void
add_single_to( char ***list, char *new )
{
	int	nlist;

	if ( *list == NULL ) {
		nlist = 0;
		*list = (char **) malloc( 2 * sizeof(char *) );
	} else {
		nlist = count_values( *list );
		*list = (char **) realloc( *list,
					   ( nlist + 2 ) * sizeof(char *) );
	}

	(*list)[nlist] = strdup( new );
	(*list)[nlist+1] = NULL;
}

static int
isgroup( LDAPMessage *e )
{
	int	i, j;
	char	**oclist;

	if ( !groupclasses ) {
		return( 0 );
	}

	oclist = ldap_get_values( ld, e, "objectClass" );

	for ( i = 0; oclist[i] != NULL; i++ ) {
		for ( j = 0; groupclasses[j] != NULL; j++ ) {
			if ( strcasecmp( oclist[i], groupclasses[j] ) == 0 ) {
				ldap_value_free( oclist );
				return( 1 );
			}
		}
	}
	ldap_value_free( oclist );

	return( 0 );
}

static void
add_error( Error **err, int *nerr, int code, char *addr, LDAPMessage *msg )
{
	if ( *nerr == 0 ) {
		*err = (Error *) malloc( sizeof(Error) );
	} else {
		*err = (Error *) realloc( *err, (*nerr + 1) * sizeof(Error) );
	}

	(*err)[*nerr].e_code = code;
	(*err)[*nerr].e_addr = strdup( addr );
	(*err)[*nerr].e_msg = msg;
	(*nerr)++;
}

static void
unbind_and_exit( int rc )
{
	int	i;

	if ( (i = ldap_unbind( ld )) != LDAP_SUCCESS )
		syslog( LOG_ALERT, "ldap_unbind failed %d\n", i );

	exit( rc );
}
