/* acl.c - routines to parse and check acl's */


#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <regex.h>

#include "slap.h"
#include "portable.h"

extern Filter		*str2filter();
extern struct acl	*global_acl;
extern char		**str2charray();
extern char		*dn_upcase();

static void		split();
static void		acl_append();
static void		access_append();
static void		acl_usage();
#ifdef LDAP_DEBUG
static void		print_acl();
static void		print_access();
#endif

int
regtest(char *fname, int lineno, char *pat) {
	int e;
	regex_t re;

	char buf[512];
	int size;

	char *sp;
	char *dp;
	int  flag;

	sp = pat;
	dp = buf;
	size = 0;
	buf[0] = '\0';

	for (size = 0, flag = 0; (size < sizeof(buf)) && *sp; sp++) {
		if (flag) {
			if (*sp == '$'|| (*sp >= '0' && *sp <= '9')) {
				*dp++ = *sp;
				size++;
			}
			flag = 0;

		} else {
			if (*sp == '$') {
				flag = 1;
			} else {
				*dp++ = *sp;
				size++;
			}
		}
	}

	*dp = '\0';
	if ( size >= (sizeof(buf)-1) ) {
		fprintf( stderr,
			"%s: line %d: regular expression \"%s\" too large\n",
			fname, lineno, pat, 0 );
		acl_usage();
	}

	if ((e = regcomp(&re, buf, REG_EXTENDED|REG_ICASE))) {
		char error[512];
		regerror(e, &re, error, sizeof(error));
		fprintf( stderr,
			"%s: line %d: regular expression \"%s\" bad because of %s\n",
			fname, lineno, pat, error );
		acl_usage();
		return(0);
	}
	regfree(&re);
	return(1);
}

void
parse_acl(
    Backend	*be,
    char	*fname,
    int		lineno,
    int		argc,
    char	**argv
)
{
	int		i;
	char		*e, *left, *right;
	struct acl	*a;
	struct access	*b;

	a = NULL;
	for ( i = 1; i < argc; i++ ) {
		/* to clause - select which entries are protected */
		if ( strcasecmp( argv[i], "to" ) == 0 ) {
			if ( a != NULL ) {
				fprintf( stderr,
		"%s: line %d: only one to clause allowed in access line\n",
				    fname, lineno );
				acl_usage();
			}
			a = (struct acl *) ch_calloc( 1, sizeof(struct acl) );
			for ( ++i; i < argc; i++ ) {
				if ( strcasecmp( argv[i], "by" ) == 0 ) {
					i--;
					break;
				}

				if ( strcasecmp( argv[i], "*" ) == 0 ) {
					int e;
					if ((e = regcomp( &a->acl_dnre, ".*",
						REG_EXTENDED|REG_ICASE)))
					{
						char buf[512];
						regerror(e, &a->acl_dnre, buf, sizeof(buf));
						fprintf( stderr,
							"%s: line %d: regular expression \"%s\" bad because of %s\n",
							fname, lineno, right, buf );
						acl_usage();
					}
					a->acl_dnpat = strdup( ".*" );
					continue;
				}

				split( argv[i], '=', &left, &right );
				if ( right == NULL || *right == '\0' ) {
					fprintf( stderr,
	"%s: line %d: missing \"=\" in (or value after) \"%s\" in to clause\n",
					    fname, lineno, left );
					acl_usage();
				}

				if ( strcasecmp( left, "filter" ) == 0 ) {
					if ( (a->acl_filter = str2filter(
					    right )) == NULL ) {
						fprintf( stderr,
				"%s: line %d: bad filter \"%s\" in to clause\n",
						    fname, lineno, right );
						acl_usage();
					}
				} else if ( strcasecmp( left, "dn" ) == 0 ) {
					int e;
					if ((e = regcomp(&a->acl_dnre, right,
						REG_EXTENDED|REG_ICASE))) {
						char buf[512];
						regerror(e, &a->acl_dnre, buf, sizeof(buf));
						fprintf( stderr,
				"%s: line %d: regular expression \"%s\" bad because of %s\n",
							fname, lineno, right, buf );
						acl_usage();

					} else {
						a->acl_dnpat = dn_upcase(strdup( right ));
					}
				} else if ( strncasecmp( left, "attr", 4 )
				    == 0 ) {
					char	**alist;

					alist = str2charray( right, "," );
					charray_merge( &a->acl_attrs, alist );
					free( alist );
				} else {
					fprintf( stderr,
						"%s: line %d: expecting <what> got \"%s\"\n",
					    fname, lineno, left );
					acl_usage();
				}
			}

		/* by clause - select who has what access to entries */
		} else if ( strcasecmp( argv[i], "by" ) == 0 ) {
			if ( a == NULL ) {
				fprintf( stderr,
					"%s: line %d: to clause required before by clause in access line\n",
				    fname, lineno );
				acl_usage();
			}
			/*
			 * by clause consists of <who> and <access>
			 */

			b = (struct access *) ch_calloc( 1,
			    sizeof(struct access) );

			if ( ++i == argc ) {
				fprintf( stderr,
			    "%s: line %d: premature eol: expecting <who>\n",
				    fname, lineno );
				acl_usage();
			}

			/* get <who> */
			split( argv[i], '=', &left, &right );
			if ( strcasecmp( argv[i], "*" ) == 0 ) {
				b->a_dnpat = strdup( ".*" );
			} else if ( strcasecmp( argv[i], "self" ) == 0 ) {
				b->a_dnpat = strdup( "self" );
			} else if ( strcasecmp( left, "dn" ) == 0 ) {
				regtest(fname, lineno, right);
				b->a_dnpat = dn_upcase( strdup( right ) );
			} else if ( strcasecmp( left, "dnattr" ) == 0 ) {
				b->a_dnattr = strdup( right );

#ifdef ACLGROUP
			} else if ( strcasecmp( left, "group" ) == 0 ) {
				regtest(fname, lineno, right);
				b->a_group = dn_upcase(strdup( right ));
#endif /* ACLGROUP */
			} else if ( strcasecmp( left, "domain" ) == 0 ) {
				char	*s;
				regtest(fname, lineno, right);
				b->a_domainpat = strdup( right );

				/* normalize the domain */
				for ( s = b->a_domainpat; *s; s++ ) {
					*s = TOLOWER( *s );
				}
			} else if ( strcasecmp( left, "addr" ) == 0 ) {
				regtest(fname, lineno, right);
				b->a_addrpat = strdup( right );
			} else {
				fprintf( stderr,
				    "%s: line %d: expecting <who> got \"%s\"\n",
				    fname, lineno, left );
				acl_usage();
			}

			if ( ++i == argc ) {
				fprintf( stderr,
			    "%s: line %d: premature eol: expecting <access>\n",
				    fname, lineno );
				acl_usage();
			}

			/* get <access> */
			split( argv[i], '=', &left, &right );
			if ( (b->a_access = str2access( left )) == -1 ) {
				fprintf( stderr,
			    "%s: line %d: expecting <access> got \"%s\"\n",
				    fname, lineno, left );
				acl_usage();
			}
			access_append( &a->acl_access, b );

		} else {
			fprintf( stderr,
		    "%s: line %d: expecting \"to\" or \"by\" got \"%s\"\n",
			    fname, lineno, argv[i] );
			acl_usage();
		}
	}

	/* if we have no real access clause, complain and do nothing */
	if ( a == NULL ) {
			fprintf( stderr,
				"%s: line %d: warning: no access clause(s) specified in access line\n",
			    fname, lineno );

	} else {
	
		if ( a->acl_access == NULL ) {
			fprintf( stderr,
		    	"%s: line %d: warning: no by clause(s) specified in access line\n",
			    fname, lineno );
		}

		if ( be != NULL ) {
			acl_append( &be->be_acl, a );
		} else {
			acl_append( &global_acl, a );
		}
	}
}

char *
access2str( int access )
{
	static char	buf[12];

	if ( access & ACL_SELF ) {
		strcpy( buf, "self" );
	} else {
		buf[0] = '\0';
	}

	if ( access & ACL_NONE ) {
		strcat( buf, "none" );
	} else if ( access & ACL_COMPARE ) {
		strcat( buf, "compare" );
	} else if ( access & ACL_SEARCH ) {
		strcat( buf, "search" );
	} else if ( access & ACL_READ ) {
		strcat( buf, "read" );
	} else if ( access & ACL_WRITE ) {
		strcat( buf, "write" );
	} else {
		strcat( buf, "unknown" );
	}

	return( buf );
}

int
str2access( char *str )
{
	int	access;

	access = 0;
	if ( strncasecmp( str, "self", 4 ) == 0 ) {
		access |= ACL_SELF;
		str += 4;
	}

	if ( strcasecmp( str, "none" ) == 0 ) {
		access |= ACL_NONE;
	} else if ( strcasecmp( str, "compare" ) == 0 ) {
		access |= ACL_COMPARE;
	} else if ( strcasecmp( str, "search" ) == 0 ) {
		access |= ACL_SEARCH;
	} else if ( strcasecmp( str, "read" ) == 0 ) {
		access |= ACL_READ;
	} else if ( strcasecmp( str, "write" ) == 0 ) {
		access |= ACL_WRITE;
	} else {
		access = -1;
	}

	return( access );
}

static void
acl_usage()
{
	fprintf( stderr, "\n<access clause> ::= access to <what> [ by <who> <access> ]+ \n" );
	fprintf( stderr, "<what> ::= * | [dn=<regex>] [filter=<ldapfilter>] [attrs=<attrlist>]\n" );
	fprintf( stderr, "<attrlist> ::= <attr> | <attr> , <attrlist>\n" );
	fprintf( stderr, "<attr> ::= <attrname> | entry | children\n" );
	fprintf( stderr, "<who> ::= * | self | dn=<regex> | addr=<regex> |\n\tdomain=<regex> | dnattr=<dnattrname>\n" );
	fprintf( stderr, "<access> ::= [self]{none | compare | search | read | write }\n" );
	exit( 1 );
}

static void
split(
    char	*line,
    int		splitchar,
    char	**left,
    char	**right
)
{
	*left = line;
	if ( (*right = strchr( line, splitchar )) != NULL ) {
		*((*right)++) = '\0';
	}
}

static void
access_append( struct access **l, struct access *a )
{
	for ( ; *l != NULL; l = &(*l)->a_next )
		;	/* NULL */

	*l = a;
}

static void
acl_append( struct acl **l, struct acl *a )
{
	for ( ; *l != NULL; l = &(*l)->acl_next )
		;	/* NULL */

	*l = a;
}

#ifdef LDAP_DEBUG

static void
print_access( struct access *b )
{
	printf( "\tby" );
	if ( b->a_dnpat != NULL ) {
		printf( " dn=%s", b->a_dnpat );
	} else if ( b->a_addrpat != NULL ) {
		printf( " addr=%s", b->a_addrpat );
	} else if ( b->a_domainpat != NULL ) {
		printf( " domain=%s", b->a_domainpat );
	} else if ( b->a_dnattr != NULL ) {
		printf( " dnattr=%s", b->a_dnattr );
	}
	printf( " %s\n", access2str( b->a_access ) );
}

static void
print_acl( struct acl *a )
{
	int		i;
	struct access	*b;

	if ( a == NULL ) {
		printf( "NULL\n" );
	}
	printf( "access to" );
	if ( a->acl_filter != NULL ) {
		printf( " filter=" );
		filter_print( a->acl_filter );
	}
	if ( a->acl_dnpat != NULL ) {
		printf( " dn=" );
		printf( a->acl_dnpat );
	}
	if ( a->acl_attrs != NULL ) {
		int	first = 1;

		printf( " attrs=" );
		for ( i = 0; a->acl_attrs[i] != NULL; i++ ) {
			if ( ! first ) {
				printf( "," );
			}
			printf( a->acl_attrs[i] );
			first = 0;
		}
	}
	printf( "\n" );
	for ( b = a->acl_access; b != NULL; b = b->a_next ) {
		print_access( b );
	}
}

#endif /* LDAP_DEBUG */
