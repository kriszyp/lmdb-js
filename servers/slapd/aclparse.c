/* aclparse.c - routines to parse and check acl's */
/* $OpenLDAP$ */
/*
 * Copyright 1998-2000 The OpenLDAP Foundation, All Rights Reserved.
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
static void		access_append(Access **l, Access *a);
static void		acl_usage(void) LDAP_GCCATTR((noreturn));

#ifdef LDAP_DEBUG
static void		print_acl(Backend *be, AccessControl *a);
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
			fname, lineno, pat );
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
	char		*left, *right, *style;
	AccessControl	*a;
	Access	*b;
	int rc;
	const char *text;

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
			a->acl_filter = NULL;
			a->acl_dn_pat = NULL;
			a->acl_attrs  = NULL;
			a->acl_access = NULL;
			a->acl_next   = NULL;
			for ( ++i; i < argc; i++ ) {
				if ( strcasecmp( argv[i], "by" ) == 0 ) {
					i--;
					break;
				}

				if ( strcasecmp( argv[i], "*" ) == 0 ) {
					if( a->acl_dn_pat != NULL ) {
						fprintf( stderr,
							"%s: line %d: dn pattern"
							" already specified in to clause.\n",
							fname, lineno );
						acl_usage();
					}

					a->acl_dn_pat = ch_strdup( "*" );
					continue;
				}

				split( argv[i], '=', &left, &right );
				split( left, '.', &left, &style );

				if ( right == NULL || *right == '\0' ) {
					fprintf( stderr,
	"%s: line %d: missing \"=\" in (or value after) \"%s\" in to clause\n",
					    fname, lineno, left );
					acl_usage();
				}

				if ( strcasecmp( left, "dn" ) == 0 ) {
					if( a->acl_dn_pat != NULL ) {
						fprintf( stderr,
							"%s: line %d: dn pattern"
							" already specified in to clause.\n",
							fname, lineno );
						acl_usage();
					}

					if ( style == NULL || *style == '\0'
						|| strcasecmp( style, "regex" ) == 0 )
					{
						a->acl_dn_style = ACL_STYLE_REGEX;
						if ( strcmp(right, "*") == 0 
							|| strcmp(right, ".*") == 0 
							|| strcmp(right, ".*$") == 0 
							|| strcmp(right, "^.*") == 0 
							|| strcmp(right, "^.*$$") == 0
							|| strcmp(right, ".*$$") == 0 
							|| strcmp(right, "^.*$$") == 0 )
						{
							a->acl_dn_pat = ch_strdup( "*" );

						} else {
							a->acl_dn_pat = ch_strdup( right );
						}
					} else if ( strcasecmp( style, "base" ) == 0 ) {
						a->acl_dn_style = ACL_STYLE_BASE;
						a->acl_dn_pat = ch_strdup( right );

					} else if ( strcasecmp( style, "one" ) == 0 ) {
						a->acl_dn_style = ACL_STYLE_ONE;
						a->acl_dn_pat = ch_strdup( right );

					} else if ( strcasecmp( style, "subtree" ) == 0 ) {
						a->acl_dn_style = ACL_STYLE_SUBTREE;
						a->acl_dn_pat = ch_strdup( right );

					} else if ( strcasecmp( style, "children" ) == 0 ) {
						a->acl_dn_style = ACL_STYLE_CHILDREN;
						a->acl_dn_pat = ch_strdup( right );

					} else {
						fprintf( stderr,
	"%s: line %d: unknown dn style \"%s\" in to clause\n",
						    fname, lineno, style );
						acl_usage();
					}

					continue;
				}

				if ( strcasecmp( left, "filter" ) == 0 ) {
					if ( (a->acl_filter = str2filter(
					    right )) == NULL ) {
						fprintf( stderr,
				"%s: line %d: bad filter \"%s\" in to clause\n",
						    fname, lineno, right );
						acl_usage();
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

			if ( a->acl_dn_pat != NULL && strcmp(a->acl_dn_pat, "*") == 0) {
				free( a->acl_dn_pat );
				a->acl_dn_pat = NULL;
			}
			
			if( a->acl_dn_pat != NULL ) {
				if ( a->acl_dn_style != ACL_STYLE_REGEX )
				{
					dn_normalize(a->acl_dn_pat);

				} else {
					int e = regcomp( &a->acl_dn_re, a->acl_dn_pat,
					                 REG_EXTENDED | REG_ICASE );
					if ( e ) {
						char buf[512];
						regerror( e, &a->acl_dn_re, buf, sizeof(buf) );
						fprintf( stderr,
					"%s: line %d: regular expression \"%s\" bad because of %s\n",
						         fname, lineno, right, buf );
						acl_usage();
					}
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

			ACL_INVALIDATE( b->a_access_mask );

			if ( ++i == argc ) {
				fprintf( stderr,
			    "%s: line %d: premature eol: expecting <who>\n",
				    fname, lineno );
				acl_usage();
			}

			/* get <who> */
			for ( ; i < argc; i++ ) {
				char *pat;
				slap_style_t sty = ACL_STYLE_REGEX;

				split( argv[i], '=', &left, &right );
				split( left, '.', &left, &style );
				if ( style == NULL || *style == '\0'
					|| strcasecmp( style, "regex" ) == 0 )
				{
					sty = ACL_STYLE_REGEX;
				} else if ( strcasecmp( style, "exact" ) == 0 ) {
					sty = ACL_STYLE_EXACT;
				} else if ( strcasecmp( style, "base" ) == 0 ) {
					sty = ACL_STYLE_BASE;
				} else if ( strcasecmp( style, "one" ) == 0 ) {
					sty = ACL_STYLE_ONE;
				} else if ( strcasecmp( style, "subtree" ) == 0 ) {
					sty = ACL_STYLE_SUBTREE;
				} else if ( strcasecmp( style, "children" ) == 0 ) {
					sty = ACL_STYLE_CHILDREN;
				} else {
					fprintf( stderr,
						"%s: line %d: unknown style \"%s\" in by clause\n",
					    fname, lineno, style );
					acl_usage();
				}

				if ( strcasecmp( argv[i], "*" ) == 0 ) {
					pat = ch_strdup( "*" );

				} else if ( strcasecmp( argv[i], "anonymous" ) == 0 ) {
					pat = ch_strdup( "anonymous" );

				} else if ( strcasecmp( argv[i], "self" ) == 0 ) {
					pat = ch_strdup( "self" );

				} else if ( strcasecmp( argv[i], "users" ) == 0 ) {
					pat = ch_strdup( "users" );

				} else if ( strcasecmp( left, "dn" ) == 0 ) {
					if ( sty == ACL_STYLE_REGEX ) {
						b->a_dn_style = ACL_STYLE_REGEX;
						if( right == NULL ) {
							/* no '=' */
							pat = ch_strdup( "users" );

						} else if (*right == '\0' ) {
							/* dn="" */
							pat = ch_strdup( "anonymous" );

						} else if ( strcmp( right, "*" ) == 0 ) {
							/* dn=* */
							/* any or users?  users for now */
							pat = ch_strdup( "users" );

						} else if ( strcmp( right, ".+" ) == 0
							|| strcmp( right, "^.+" ) == 0
							|| strcmp( right, ".+$" ) == 0
							|| strcmp( right, "^.+$" ) == 0
							|| strcmp( right, ".+$$" ) == 0
							|| strcmp( right, "^.+$$" ) == 0 )
						{
							pat = ch_strdup( "users" );

						} else if ( strcmp( right, ".*" ) == 0
							|| strcmp( right, "^.*" ) == 0
							|| strcmp( right, ".*$" ) == 0
							|| strcmp( right, "^.*$" ) == 0
							|| strcmp( right, ".*$$" ) == 0
							|| strcmp( right, "^.*$$" ) == 0 )
						{
							pat = ch_strdup( "*" );

						} else {
							regtest(fname, lineno, right);
							pat = ch_strdup( right );
						}
					} else if ( right == NULL || *right == '\0' ) {
						fprintf( stderr,
							"%s: line %d: missing \"=\" in (or value after) \"%s\" in by clause\n",
						    fname, lineno, left );
						acl_usage();

					} else {
						pat = ch_strdup( right );
					}

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
					b->a_dn_style = sty;
					if ( sty != ACL_STYLE_REGEX )
						dn_normalize(pat);
					continue;
				}

				if ( strcasecmp( left, "dnattr" ) == 0 ) {
					if( b->a_dn_at != NULL ) {
						fprintf( stderr,
							"%s: line %d: dnattr already specified.\n",
							fname, lineno );
						acl_usage();
					}

					rc = slap_str2ad( right, &b->a_dn_at, &text );

					if( rc != LDAP_SUCCESS ) {
						fprintf( stderr,
							"%s: line %d: dnattr \"%s\": %s\n",
							fname, lineno, right, text );
						acl_usage();
					}


					if( !is_at_syntax( b->a_dn_at->ad_type,
						SLAPD_DN_SYNTAX ) )
					{
						fprintf( stderr,
							"%s: line %d: dnattr \"%s\": "
							"inappropriate syntax: %s\n",
							fname, lineno, right,
							b->a_dn_at->ad_type->sat_syntax_oid );
						acl_usage();
					}

					continue;
				}

				if (sty != ACL_STYLE_REGEX && sty != ACL_STYLE_BASE) {
					fprintf( stderr,
						"%s: line %d: inappropriate style \"%s\" in by clause\n",
					    fname, lineno, style );
					acl_usage();
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
						if (*value
							&& (name = strchr(value, '/')) != NULL)
						{
							*name++ = '\0';
						}
					}

					b->a_group_style = sty;
					if (sty == ACL_STYLE_REGEX) {
						regtest(fname, lineno, right);
						b->a_group_pat = ch_strdup( right );
					} else {
						b->a_group_pat = ch_strdup( right );
						dn_normalize(b->a_group_pat);
					}

					if (value && *value) {
						b->a_group_oc = oc_find( value );
						*--value = '/';

						if( b->a_group_oc == NULL ) {
							fprintf( stderr,
								"%s: line %d: group objectclass "
								"\"%s\" unknown\n",
								fname, lineno, value );
							acl_usage();
						}
					} else {
						b->a_group_oc = oc_find(SLAPD_GROUP_CLASS);

						if( b->a_group_oc == NULL ) {
							fprintf( stderr,
								"%s: line %d: group default objectclass "
								"\"%s\" unknown\n",
								fname, lineno, SLAPD_GROUP_CLASS );
							acl_usage();
						}
					}

					if( is_object_subclass( b->a_group_oc,
						slap_schema.si_oc_referral ) )
					{
						fprintf( stderr,
							"%s: line %d: group objectclass \"%s\" "
							"is subclass of referral\n",
							fname, lineno, value );
						acl_usage();
					}

					if( is_object_subclass( b->a_group_oc,
						slap_schema.si_oc_alias ) )
					{
						fprintf( stderr,
							"%s: line %d: group objectclass \"%s\" "
							"is subclass of alias\n",
							fname, lineno, value );
						acl_usage();
					}

					if (name && *name) {
						rc = slap_str2ad( name, &b->a_group_at, &text );

						if( rc != LDAP_SUCCESS ) {
							fprintf( stderr,
								"%s: line %d: group \"%s\": %s\n",
								fname, lineno, right, text );
							acl_usage();
						}
						*--name = '/';
					} else {
						rc = slap_str2ad( SLAPD_GROUP_ATTR, &b->a_group_at, &text );

						if( rc != LDAP_SUCCESS ) {
							fprintf( stderr,
								"%s: line %d: group \"%s\": %s\n",
								fname, lineno, SLAPD_GROUP_ATTR, text );
							acl_usage();
						}
					}

					if( !is_at_syntax( b->a_group_at->ad_type,
						SLAPD_DN_SYNTAX ) )
					{
						fprintf( stderr,
							"%s: line %d: group \"%s\": inappropriate syntax: %s\n",
							fname, lineno, right,
							b->a_group_at->ad_type->sat_syntax_oid );
						acl_usage();
					}


					{
						int rc;
						struct berval val;
						struct berval *vals[2];

						val.bv_val = b->a_group_oc->soc_oid;
						val.bv_len = strlen(val.bv_val);
						vals[0] = &val;
						vals[1] = NULL;


						rc = oc_check_allowed( b->a_group_at->ad_type, vals );

						if( rc != 0 ) {
							fprintf( stderr,
								"%s: line %d: group: \"%s\" not allowed by \"%s\"\n",
								fname, lineno,
								b->a_group_at->ad_cname->bv_val,
								b->a_group_oc->soc_oid );
							acl_usage();
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

					b->a_peername_style = sty;
					if (sty == ACL_STYLE_REGEX) {
						regtest(fname, lineno, right);
					}
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

					b->a_sockname_style = sty;
					if (sty == ACL_STYLE_REGEX) {
						regtest(fname, lineno, right);
					}
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

					b->a_domain_style = sty;
					if (sty == ACL_STYLE_REGEX) {
						regtest(fname, lineno, right);
					}
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

					b->a_sockurl_style = sty;
					if (sty == ACL_STYLE_REGEX) {
						regtest(fname, lineno, right);
					}
					b->a_sockurl_pat = ch_strdup( right );
					continue;
				}

				if ( strcasecmp( left, "set" ) == 0 ) {
					if( b->a_set_pat != NULL ) {
						fprintf( stderr,
							"%s: line %d: set attribute already specified.\n",
							fname, lineno );
						acl_usage();
					}

					if ( right == NULL || *right == '\0' ) {
						fprintf( stderr,
							"%s: line %d: no set is defined\n",
							fname, lineno );
						acl_usage();
					}

					b->a_set_style = sty;
					b->a_set_pat = ch_strdup(right);

					continue;
				}

#ifdef SLAPD_ACI_ENABLED
				if ( strcasecmp( left, "aci" ) == 0 ) {
					if( b->a_aci_at != NULL ) {
						fprintf( stderr,
							"%s: line %d: aci attribute already specified.\n",
							fname, lineno );
						acl_usage();
					}

					if ( right != NULL && *right != '\0' ) {
						rc = slap_str2ad( right, &b->a_aci_at, &text );

						if( rc != LDAP_SUCCESS ) {
							fprintf( stderr,
								"%s: line %d: aci \"%s\": %s\n",
								fname, lineno, right, text );
							acl_usage();
						}

					} else {
						rc = slap_str2ad( SLAPD_ACI_ATTR, &b->a_aci_at, &text );

						if( rc != LDAP_SUCCESS ) {
							fprintf( stderr,
								"%s: line %d: aci \"%s\": %s\n",
								fname, lineno, SLAPD_ACI_ATTR, text );
							acl_usage();
						}
					}

					if( !is_at_syntax( b->a_aci_at->ad_type,
						SLAPD_ACI_SYNTAX) )
					{
						fprintf( stderr,
							"%s: line %d: aci \"%s\": inappropriate syntax: %s\n",
							fname, lineno, right,
							b->a_aci_at->ad_type->sat_syntax_oid );
						acl_usage();
					}

					continue;
				}
#endif /* SLAPD_ACI_ENABLED */

				if ( strcasecmp( left, "ssf" ) == 0 ) {
					if( b->a_authz.sai_ssf ) {
						fprintf( stderr,
							"%s: line %d: ssf attribute already specified.\n",
							fname, lineno );
						acl_usage();
					}

					if ( right == NULL || *right == '\0' ) {
						fprintf( stderr,
							"%s: line %d: no ssf is defined\n",
							fname, lineno );
						acl_usage();
					}

					b->a_authz.sai_ssf = atoi( right );

					if( !b->a_authz.sai_ssf ) {
						fprintf( stderr,
							"%s: line %d: invalid ssf value (%s)\n",
							fname, lineno, right );
						acl_usage();
					}
					continue;
				}

				if ( strcasecmp( left, "transport_ssf" ) == 0 ) {
					if( b->a_authz.sai_transport_ssf ) {
						fprintf( stderr,
							"%s: line %d: transport_ssf attribute already specified.\n",
							fname, lineno );
						acl_usage();
					}

					if ( right == NULL || *right == '\0' ) {
						fprintf( stderr,
							"%s: line %d: no transport_ssf is defined\n",
							fname, lineno );
						acl_usage();
					}

					b->a_authz.sai_transport_ssf = atoi( right );

					if( !b->a_authz.sai_transport_ssf ) {
						fprintf( stderr,
							"%s: line %d: invalid transport_ssf value (%s)\n",
							fname, lineno, right );
						acl_usage();
					}
					continue;
				}

				if ( strcasecmp( left, "tls_ssf" ) == 0 ) {
					if( b->a_authz.sai_tls_ssf ) {
						fprintf( stderr,
							"%s: line %d: tls_ssf attribute already specified.\n",
							fname, lineno );
						acl_usage();
					}

					if ( right == NULL || *right == '\0' ) {
						fprintf( stderr,
							"%s: line %d: no tls_ssf is defined\n",
							fname, lineno );
						acl_usage();
					}

					b->a_authz.sai_tls_ssf = atoi( right );

					if( !b->a_authz.sai_tls_ssf ) {
						fprintf( stderr,
							"%s: line %d: invalid tls_ssf value (%s)\n",
							fname, lineno, right );
						acl_usage();
					}
					continue;
				}

				if ( strcasecmp( left, "sasl_ssf" ) == 0 ) {
					if( b->a_authz.sai_sasl_ssf ) {
						fprintf( stderr,
							"%s: line %d: sasl_ssf attribute already specified.\n",
							fname, lineno );
						acl_usage();
					}

					if ( right == NULL || *right == '\0' ) {
						fprintf( stderr,
							"%s: line %d: no sasl_ssf is defined\n",
							fname, lineno );
						acl_usage();
					}

					b->a_authz.sai_sasl_ssf = atoi( right );

					if( !b->a_authz.sai_sasl_ssf ) {
						fprintf( stderr,
							"%s: line %d: invalid sasl_ssf value (%s)\n",
							fname, lineno, right );
						acl_usage();
					}
					continue;
				}

				if( right != NULL ) {
					/* unsplit */
					right[-1] = '=';
				}
				break;
			}

			if( i == argc || ( strcasecmp( left, "stop" ) == 0 )) { 
				/* out of arguments or plain stop */

				ACL_PRIV_ASSIGN(b->a_access_mask, ACL_PRIV_ADDITIVE);
				b->a_type = ACL_STOP;

				access_append( &a->acl_access, b );
				continue;
			}

			if( strcasecmp( left, "continue" ) == 0 ) {
				/* plain continue */

				ACL_PRIV_ASSIGN(b->a_access_mask, ACL_PRIV_ADDITIVE);
				b->a_type = ACL_CONTINUE;

				access_append( &a->acl_access, b );
				continue;
			}

			if( strcasecmp( left, "break" ) == 0 ) {
				/* plain continue */

				ACL_PRIV_ASSIGN(b->a_access_mask, ACL_PRIV_ADDITIVE);
				b->a_type = ACL_BREAK;

				access_append( &a->acl_access, b );
				continue;
			}

			if ( strcasecmp( left, "by" ) == 0 ) {
				/* we've gone too far */
				--i;
				ACL_PRIV_ASSIGN(b->a_access_mask, ACL_PRIV_ADDITIVE);
				b->a_type = ACL_STOP;

				access_append( &a->acl_access, b );
				continue;
			}

			/* get <access> */
			if( strncasecmp( left, "self", 4 ) == 0 ) {
				b->a_dn_self = 1;
				ACL_PRIV_ASSIGN( b->a_access_mask, str2accessmask( &left[4] ) );

			} else {
				ACL_PRIV_ASSIGN( b->a_access_mask, str2accessmask( left ) );
			}

			if( ACL_IS_INVALID( b->a_access_mask ) ) {
				fprintf( stderr,
					"%s: line %d: expecting <access> got \"%s\"\n",
					fname, lineno, left );
				acl_usage();
			}

			b->a_type = ACL_STOP;

			if( ++i == argc ) {
				/* out of arguments or plain stop */
				access_append( &a->acl_access, b );
				continue;
			}

			if( strcasecmp( argv[i], "continue" ) == 0 ) {
				/* plain continue */
				b->a_type = ACL_CONTINUE;

			} else if( strcasecmp( argv[i], "break" ) == 0 ) {
				/* plain continue */
				b->a_type = ACL_BREAK;

			} else if ( strcasecmp( argv[i], "stop" ) != 0 ) {
				/* gone to far */
				i--;
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
#ifdef LDAP_DEBUG
		if (ldap_debug & LDAP_DEBUG_ACL)
			print_acl(be, a);
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
accessmask2str( slap_mask_t mask, char *buf )
{
	int none=1;

	assert( buf != NULL );

	if ( ACL_IS_INVALID( mask ) ) {
		return "invalid";
	}

	buf[0] = '\0';

	if ( ACL_IS_LEVEL( mask ) ) {
		if ( ACL_LVL_IS_NONE(mask) ) {
			strcat( buf, "none" );

		} else if ( ACL_LVL_IS_AUTH(mask) ) {
			strcat( buf, "auth" );

		} else if ( ACL_LVL_IS_COMPARE(mask) ) {
			strcat( buf, "compare" );

		} else if ( ACL_LVL_IS_SEARCH(mask) ) {
			strcat( buf, "search" );

		} else if ( ACL_LVL_IS_READ(mask) ) {
			strcat( buf, "read" );

		} else if ( ACL_LVL_IS_WRITE(mask) ) {
			strcat( buf, "write" );
		} else {
			strcat( buf, "unknown" );
		}
		
		strcat(buf, " (");
	}

	if( ACL_IS_ADDITIVE( mask ) ) {
		strcat( buf, "+" );

	} else if( ACL_IS_SUBTRACTIVE( mask ) ) {
		strcat( buf, "-" );

	} else {
		strcat( buf, "=" );
	}

	if ( ACL_PRIV_ISSET(mask, ACL_PRIV_WRITE) ) {
		none = 0;
		strcat( buf, "w" );
	} 

	if ( ACL_PRIV_ISSET(mask, ACL_PRIV_READ) ) {
		none = 0;
		strcat( buf, "r" );
	} 

	if ( ACL_PRIV_ISSET(mask, ACL_PRIV_SEARCH) ) {
		none = 0;
		strcat( buf, "s" );
	} 

	if ( ACL_PRIV_ISSET(mask, ACL_PRIV_COMPARE) ) {
		none = 0;
		strcat( buf, "c" );
	} 

	if ( ACL_PRIV_ISSET(mask, ACL_PRIV_AUTH) ) {
		none = 0;
		strcat( buf, "x" );
	} 

	if ( none && ACL_PRIV_ISSET(mask, ACL_PRIV_NONE) ) {
		none = 0;
		strcat( buf, "n" );
	} 

	if ( none ) {
		strcat( buf, "0" );
	}

	if ( ACL_IS_LEVEL( mask ) ) {
		strcat(buf, ")");
	} 
	return buf;
}

slap_mask_t
str2accessmask( const char *str )
{
	slap_mask_t	mask;

	if( !ASCII_ALPHA(str[0]) ) {
		int i;

		if ( str[0] == '=' ) {
			ACL_INIT(mask);

		} else if( str[0] == '+' ) {
			ACL_PRIV_ASSIGN(mask, ACL_PRIV_ADDITIVE);

		} else if( str[0] == '-' ) {
			ACL_PRIV_ASSIGN(mask, ACL_PRIV_SUBSTRACTIVE);

		} else {
			ACL_INVALIDATE(mask);
			return mask;
		}

		for( i=1; str[i] != '\0'; i++ ) {
			if( TOLOWER(str[i]) == 'w' ) {
				ACL_PRIV_SET(mask, ACL_PRIV_WRITE);

			} else if( TOLOWER(str[i]) == 'r' ) {
				ACL_PRIV_SET(mask, ACL_PRIV_READ);

			} else if( TOLOWER(str[i]) == 's' ) {
				ACL_PRIV_SET(mask, ACL_PRIV_SEARCH);

			} else if( TOLOWER(str[i]) == 'c' ) {
				ACL_PRIV_SET(mask, ACL_PRIV_COMPARE);

			} else if( TOLOWER(str[i]) == 'x' ) {
				ACL_PRIV_SET(mask, ACL_PRIV_AUTH);

			} else if( str[i] != '0' ) {
				ACL_INVALIDATE(mask);
				return mask;
			}
		}

		return mask;
	}

	if ( strcasecmp( str, "none" ) == 0 ) {
		ACL_LVL_ASSIGN_NONE(mask);

	} else if ( strcasecmp( str, "auth" ) == 0 ) {
		ACL_LVL_ASSIGN_AUTH(mask);

	} else if ( strcasecmp( str, "compare" ) == 0 ) {
		ACL_LVL_ASSIGN_COMPARE(mask);

	} else if ( strcasecmp( str, "search" ) == 0 ) {
		ACL_LVL_ASSIGN_SEARCH(mask);

	} else if ( strcasecmp( str, "read" ) == 0 ) {
		ACL_LVL_ASSIGN_READ(mask);

	} else if ( strcasecmp( str, "write" ) == 0 ) {
		ACL_LVL_ASSIGN_WRITE(mask);

	} else {
		ACL_INVALIDATE( mask );
	}

	return mask;
}

static void
acl_usage( void )
{
	fprintf( stderr, "\n"
		"<access clause> ::= access to <what> "
				"[ by <who> <access> <control> ]+ \n"
		"<what> ::= * | [dn=<regex>] [filter=<ldapfilter>] [attrs=<attrlist>]\n"
		"<attrlist> ::= <attr> | <attr> , <attrlist>\n"
		"<attr> ::= <attrname> | entry | children\n"
		"<who> ::= [ * | anonymous | users | self | dn=<regex> ]\n"
			"\t[dnattr=<attrname>]\n"
			"\t[group[/<objectclass>[/<attrname>]]=<regex>]\n"
			"\t[peername=<regex>] [sockname=<regex>]\n"
			"\t[domain=<regex>] [sockurl=<regex>]\n"
#ifdef SLAPD_ACI_ENABLED
			"\t[aci=<attrname>]\n"
#endif
			"\t[ssf=<n>] [transport_ssf=<n>] [tls_ssf=<n>] [sasl_ssf=<n>]\n"
		"<access> ::= [self]{<level>|<priv>}\n"
		"<level> ::= none | auth | compare | search | read | write\n"
		"<priv> ::= {=|+|-}{w|r|s|c|x}+\n"
		"<control> ::= [ stop | continue | break ]\n"
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

void
acl_append( AccessControl **l, AccessControl *a )
{
	for ( ; *l != NULL; l = &(*l)->acl_next )
		;	/* NULL */

	*l = a;
}

char *
access2str( slap_access_t access )
{
	if ( access == ACL_NONE ) {
		return "none";

	} else if ( access == ACL_AUTH ) {
		return "auth";

	} else if ( access == ACL_COMPARE ) {
		return "compare";

	} else if ( access == ACL_SEARCH ) {
		return "search";

	} else if ( access == ACL_READ ) {
		return "read";

	} else if ( access == ACL_WRITE ) {
		return "write";
	}

	return "unknown";
}

slap_access_t
str2access( const char *str )
{
	if ( strcasecmp( str, "none" ) == 0 ) {
		return ACL_NONE;

	} else if ( strcasecmp( str, "auth" ) == 0 ) {
		return ACL_AUTH;

	} else if ( strcasecmp( str, "compare" ) == 0 ) {
		return ACL_COMPARE;

	} else if ( strcasecmp( str, "search" ) == 0 ) {
		return ACL_SEARCH;

	} else if ( strcasecmp( str, "read" ) == 0 ) {
		return ACL_READ;

	} else if ( strcasecmp( str, "write" ) == 0 ) {
		return ACL_WRITE;
	}

	return( ACL_INVALID_ACCESS );
}

#ifdef LDAP_DEBUG

static char *style_strings[5] = {
			"regex",
			"base",
			"one",
			"subtree",
			"children"
		};


static void
print_access( Access *b )
{
	char maskbuf[ACCESSMASK_MAXLEN];

	fprintf( stderr, "\tby" );

	if ( b->a_dn_pat != NULL ) {
		if( strcmp(b->a_dn_pat, "*") == 0
			|| strcmp(b->a_dn_pat, "users") == 0 
			|| strcmp(b->a_dn_pat, "anonymous") == 0 
			|| strcmp(b->a_dn_pat, "self") == 0 )
		{
			fprintf( stderr, " %s", b->a_dn_pat );

		} else {
			fprintf( stderr, " dn.%s=%s", style_strings[b->a_dn_style], b->a_dn_pat );
		}
	}

	if ( b->a_dn_at != NULL ) {
		fprintf( stderr, " dnattr=%s", b->a_dn_at->ad_cname->bv_val );
	}

	if ( b->a_group_pat != NULL ) {
		fprintf( stderr, " group=%s", b->a_group_pat );

		if ( b->a_group_oc ) {
			fprintf( stderr, " objectClass: %s",
				b->a_group_oc->soc_oclass.oc_oid );

			if ( b->a_group_at ) {
				fprintf( stderr, " attributeType: %s", b->a_group_at->ad_cname->bv_val );
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

#ifdef SLAPD_ACI_ENABLED
	if ( b->a_aci_at != NULL ) {
		fprintf( stderr, " aci=%s", b->a_aci_at->ad_cname->bv_val );
	}
#endif

	/* Security Strength Factors */
	if ( b->a_authz.sai_ssf ) {
		fprintf( stderr, " ssf=%u",
			b->a_authz.sai_ssf );
	}
	if ( b->a_authz.sai_transport_ssf ) {
		fprintf( stderr, " transport_ssf=%u",
			b->a_authz.sai_transport_ssf );
	}
	if ( b->a_authz.sai_tls_ssf ) {
		fprintf( stderr, " tls_ssf=%u",
			b->a_authz.sai_tls_ssf );
	}
	if ( b->a_authz.sai_sasl_ssf ) {
		fprintf( stderr, " sasl_ssf=%u",
			b->a_authz.sai_sasl_ssf );
	}

	fprintf( stderr, " %s%s",
		b->a_dn_self ? "self" : "",
		accessmask2str( b->a_access_mask, maskbuf ) );

	if( b->a_type == ACL_BREAK ) {
		fprintf( stderr, " break" );

	} else if( b->a_type == ACL_CONTINUE ) {
		fprintf( stderr, " continue" );

	} else if( b->a_type != ACL_STOP ) {
		fprintf( stderr, " unknown-control" );
	}

	fprintf( stderr, "\n" );
}


static void
print_acl( Backend *be, AccessControl *a )
{
	int		to = 0;
	Access	*b;

	fprintf( stderr, "%s ACL: access to",
		be == NULL ? "Global" : "Backend" );

	if ( a->acl_dn_pat != NULL ) {
		to++;
		fprintf( stderr, " dn.%s=%s\n",
			style_strings[a->acl_dn_style], a->acl_dn_pat );
	}

	if ( a->acl_filter != NULL ) {
		to++;
		fprintf( stderr, " filter=" );
		filter_print( a->acl_filter );
		fprintf( stderr, "\n" );
	}

	if ( a->acl_attrs != NULL ) {
		int	i, first = 1;
		to++;

		fprintf( stderr, " attrs=" );
		for ( i = 0; a->acl_attrs[i] != NULL; i++ ) {
			if ( ! first ) {
				fprintf( stderr, "," );
			}
			fprintf( stderr, a->acl_attrs[i] );
			first = 0;
		}
		fprintf(  stderr, "\n" );
	}

	if( !to ) {
		fprintf( stderr, " *\n" );
	}

	for ( b = a->acl_access; b != NULL; b = b->a_next ) {
		print_access( b );
	}

	fprintf( stderr, "\n" );
}

#endif /* LDAP_DEBUG */
