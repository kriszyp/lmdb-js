/* acl.c - routines to parse and check acl's */
/*
 * Copyright 1998-1999 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "portable.h"

#include <stdio.h>

#include <ac/ctype.h>
#include <ac/regex.h>
#include <ac/socket.h>
#include <ac/string.h>
#include <ac/unistd.h>

#include "slap.h"

static void		split(char *line, int splitchar, char **left, char **right);
static void		acl_append(AccessControl **l, AccessControl *a);
static void		access_append(Access **l, Access *a);
static void		acl_usage(void);
#ifdef LDAP_DEBUG
static void		print_acl(AccessControl *a);
static void		print_access(Access *b);
#endif

static int
regtest(const char *fname, int lineno, char *pat) {
	int e;
	regex_t re;

	char buf[512];
	unsigned size;

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
    const char	*fname,
    int		lineno,
    int		argc,
    char	**argv
)
{
	int		i;
	char		*left, *right;
	AccessControl	*a;
	Access	*b;

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
			a = (AccessControl *) ch_calloc( 1, sizeof(AccessControl) );
			for ( ++i; i < argc; i++ ) {
				if ( strcasecmp( argv[i], "by" ) == 0 ) {
					i--;
					break;
				}

				if ( strcasecmp( argv[i], "*" ) == 0 ) {
					a->acl_dn_pat = ch_strdup( ".*" );
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

					if ((e = regcomp(&a->acl_dn_re, right,
						REG_EXTENDED|REG_ICASE))) {
						char buf[512];
						regerror(e, &a->acl_dn_re, buf, sizeof(buf));
						fprintf( stderr,
				"%s: line %d: regular expression \"%s\" bad because of %s\n",
							fname, lineno, right, buf );
						acl_usage();

					} else {
						a->acl_dn_pat = ch_strdup( right );
					}

				} else if ( strncasecmp( left, "attr", 4 ) == 0 ) {
					char	**alist;

					alist = str2charray( right, "," );
					charray_merge( &a->acl_attrs, alist );
					charray_free( alist );

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

			b = (Access *) ch_calloc( 1, sizeof(Access) );

			if ( ++i == argc ) {
				fprintf( stderr,
			    "%s: line %d: premature eol: expecting <who>\n",
				    fname, lineno );
				acl_usage();
			}

			/* get <who> */
			for ( ; i < argc; i++ ) {
				char *pat;
				split( argv[i], '=', &left, &right );

				if ( strcasecmp( argv[i], "*" ) == 0 ) {
					pat = ch_strdup( ".*" );
				} else if ( strcasecmp( argv[i], "anonymous" ) == 0 ) {
					pat = ch_strdup( "anonymous" );
				} else if ( strcasecmp( argv[i], "self" ) == 0 ) {
					pat = ch_strdup( "self" );
				} else if ( strcasecmp( left, "dn" ) == 0 ) {
					regtest(fname, lineno, right);
					pat = ch_strdup( right );
				} else {
					pat = NULL;
				}

				if( pat != NULL ) {
					if( b->a_dn_pat != NULL ) {
						fprintf( stderr,
						    "%s: line %d: dn pattern already specified.\n",
						    fname, lineno );
						acl_usage();
					}

					b->a_dn_pat = pat;
					continue;
				}

				if ( strcasecmp( left, "dnattr" ) == 0 ) {
					if( b->a_dn_pat != NULL ) {
						fprintf( stderr,
							"%s: line %d: dnaddr already specified.\n",
							fname, lineno );
						acl_usage();
					}

					b->a_dn_at = ch_strdup( right );
					continue;
				}

				if ( strncasecmp( left, "group", sizeof("group")-1 ) == 0 ) {
					char *name = NULL;
					char *value = NULL;

					if( b->a_group_pat != NULL ) {
						fprintf( stderr,
							"%s: line %d: group pattern already specified.\n",
							fname, lineno );
						acl_usage();
					}

					/* format of string is "group/objectClassValue/groupAttrName" */
					if ((value = strchr(left, '/')) != NULL) {
						*value++ = '\0';
						if (value && *value
							&& (name = strchr(value, '/')) != NULL)
						{
							*name++ = '\0';
						}
					}

					regtest(fname, lineno, right);
					b->a_group_pat = ch_strdup( right );

					if (value && *value) {
						b->a_group_oc = ch_strdup(value);
						*--value = '/';
					} else {
						b->a_group_oc = ch_strdup("groupOfNames");

						if (name && *name) {
							b->a_group_at = ch_strdup(name);
							*--name = '/';

						} else {
							b->a_group_at = ch_strdup("member");
						}
					}
					continue;
				}

				if ( strcasecmp( left, "peername" ) == 0 ) {
					if( b->a_peername_pat != NULL ) {
						fprintf( stderr,
							"%s: line %d: peername pattern already specified.\n",
							fname, lineno );
						acl_usage();
					}

					regtest(fname, lineno, right);
					b->a_peername_pat = ch_strdup( right );
					continue;
				}

				if ( strcasecmp( left, "sockname" ) == 0 ) {
					if( b->a_sockname_pat != NULL ) {
						fprintf( stderr,
							"%s: line %d: sockname pattern already specified.\n",
							fname, lineno );
						acl_usage();
					}

					regtest(fname, lineno, right);
					b->a_sockname_pat = ch_strdup( right );
					continue;
				}

				if ( strcasecmp( left, "domain" ) == 0 ) {
					if( b->a_domain_pat != NULL ) {
						fprintf( stderr,
							"%s: line %d: domain pattern already specified.\n",
							fname, lineno );
						acl_usage();
					}

					regtest(fname, lineno, right);
					b->a_domain_pat = ch_strdup( right );
					continue;
				}

				if ( strcasecmp( left, "sockurl" ) == 0 ) {
					if( b->a_sockurl_pat != NULL ) {
						fprintf( stderr,
							"%s: line %d: sockurl pattern already specified.\n",
							fname, lineno );
						acl_usage();
					}

					regtest(fname, lineno, right);
					b->a_sockurl_pat = ch_strdup( right );
					continue;
				}

				/* get <access> */
				if ( ACL_IS_INVALID(ACL_SET(b->a_access, str2access( left ))) ) {
					fprintf( stderr,
					"%s: line %d: expecting <access> got \"%s\"\n",
						fname, lineno, left );
					acl_usage();
				}
				access_append( &a->acl_access, b );
				break;
			}
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

#ifdef LDAP_DEBUG
                if (ldap_debug & LDAP_DEBUG_ACL)
                    print_acl(a);
#endif
	
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

	if ( ACL_IS_SELF( access ) ) {
		strcpy( buf, "self" );
	} else {
		buf[0] = '\0';
	}

	if ( ACL_IS_NONE(access) ) {
		strcat( buf, "none" );
	} else if ( ACL_IS_AUTH(access) ) {
		strcat( buf, "auth" );
	} else if ( ACL_IS_COMPARE(access) ) {
		strcat( buf, "compare" );
	} else if ( ACL_IS_SEARCH(access) ) {
		strcat( buf, "search" );
	} else if ( ACL_IS_READ(access) ) {
		strcat( buf, "read" );
	} else if ( ACL_IS_WRITE(access) ) {
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

	ACL_CLR(access);

	if ( strncasecmp( str, "self", 4 ) == 0 ) {
		ACL_SET_SELF(access);
		str += 4;
	}

	if ( strcasecmp( str, "none" ) == 0 ) {
		ACL_SET_NONE(access);
	} else if ( strcasecmp( str, "auth" ) == 0 ) {
		ACL_SET_AUTH(access);
	} else if ( strcasecmp( str, "compare" ) == 0 ) {
		ACL_SET_COMPARE(access);
	} else if ( strcasecmp( str, "search" ) == 0 ) {
		ACL_SET_SEARCH(access);
	} else if ( strcasecmp( str, "read" ) == 0 ) {
		ACL_SET_READ(access);
	} else if ( strcasecmp( str, "write" ) == 0 ) {
		ACL_SET_WRITE(access);
	} else {
		ACL_SET_INVALID(access);
	}

	return( access );
}

static void
acl_usage( void )
{
	fprintf( stderr, "\n"
		"<access clause> ::= access to <what> [ by <who> <access> ]+ \n"
		"<what> ::= * | [dn=<regex>] [filter=<ldapfilter>] [attrs=<attrlist>]\n"
		"<attrlist> ::= <attr> | <attr> , <attrlist>\n"
		"<attr> ::= <attrname> | entry | children\n"
		"<who> ::= [ * | anonymous | self | dn=<regex> ]\n"
			"\t[dnattr=<attrname>]\n"
			"\t[group[/<objectclass>[/<attrname>]]=<regex>]\n"
			"\t[peername=<regex>] [sockname=<regex>]\n"
			"\t[domain=<regex>] [sockurl=<regex>]\n"
		"<access> ::= [self]{none|auth|compare|search|read|write}\n"
		);
	exit( EXIT_FAILURE );
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
access_append( Access **l, Access *a )
{
	for ( ; *l != NULL; l = &(*l)->a_next )
		;	/* NULL */

	*l = a;
}

static void
acl_append( AccessControl **l, AccessControl *a )
{
	for ( ; *l != NULL; l = &(*l)->acl_next )
		;	/* NULL */

	*l = a;
}

#ifdef LDAP_DEBUG

static void
print_access( Access *b )
{
	fprintf( stderr, "\tby" );

	if ( b->a_dn_pat != NULL ) {
		if( strcmp(b->a_dn_pat, "anonymous") == 0 ) {
			fprintf( stderr, " anonymous" );

		} else if( strcmp(b->a_dn_pat, "self") == 0 ) {
			fprintf( stderr, " self" );

		} else {
			fprintf( stderr, " dn=%s", b->a_dn_pat );
		}
	}

	if ( b->a_dn_at != NULL ) {
		fprintf( stderr, " dnattr=%s", b->a_dn_at );
	}

	if ( b->a_group_pat != NULL ) {
		fprintf( stderr, " group: %s", b->a_group_pat );

		if ( b->a_group_oc ) {
			fprintf( stderr, " objectClass: %s", b->a_group_oc );

			if ( b->a_group_at ) {
				fprintf( stderr, " attributeType: %s", b->a_group_at );
			}
		}
    }

	if ( b->a_peername_pat != NULL ) {
		fprintf( stderr, " peername=%s", b->a_peername_pat );
	}
	if ( b->a_sockname_pat != NULL ) {
		fprintf( stderr, " sockname=%s", b->a_sockname_pat );
	}

	if ( b->a_domain_pat != NULL ) {
		fprintf( stderr, " domain=%s", b->a_domain_pat );
	}

	if ( b->a_sockurl_pat != NULL ) {
		fprintf( stderr, " sockurl=%s", b->a_sockurl_pat );
	}

	fprintf( stderr, "\n" );
}

static void
print_acl( AccessControl *a )
{
	int		i;
	Access	*b;

	if ( a == NULL ) {
		fprintf( stderr, "NULL\n" );
	}
	fprintf( stderr, "ACL: access to" );
	if ( a->acl_filter != NULL ) {
		fprintf(  stderr," filter=" );
		filter_print( a->acl_filter );
	}
	if ( a->acl_dn_pat != NULL ) {
		fprintf( stderr, " dn=" );
		fprintf( stderr, a->acl_dn_pat );
	}
	if ( a->acl_attrs != NULL ) {
		int	first = 1;

		fprintf( stderr, "\n attrs=" );
		for ( i = 0; a->acl_attrs[i] != NULL; i++ ) {
			if ( ! first ) {
				fprintf( stderr, "," );
			}
			fprintf( stderr, a->acl_attrs[i] );
			first = 0;
		}
	}
	fprintf( stderr, "\n" );
	for ( b = a->acl_access; b != NULL; b = b->a_next ) {
		print_access( b );
	}
	fprintf( stderr, "\n" );
}

#endif /* LDAP_DEBUG */
