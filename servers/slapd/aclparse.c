/* aclparse.c - routines to parse and check acl's */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1998-2003 The OpenLDAP Foundation.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted only as authorized by the OpenLDAP
 * Public License.
 *
 * A copy of this license is available in the file LICENSE in the
 * top-level directory of the distribution or, alternatively, at
 * <http://www.OpenLDAP.org/license.html>.
 */
/* Portions Copyright (c) 1995 Regents of the University of Michigan.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that this notice is preserved and that due credit is given
 * to the University of Michigan at Ann Arbor. The name of the University
 * may not be used to endorse or promote products derived from this
 * software without specific prior written permission. This software
 * is provided ``as is'' without express or implied warranty.
 */

#include "portable.h"

#include <stdio.h>

#include <ac/ctype.h>
#include <ac/regex.h>
#include <ac/socket.h>
#include <ac/string.h>
#include <ac/unistd.h>

#include "slap.h"
#include "lber_pvt.h"
#include "lutil.h"

static char *style_strings[] = { "regex",
	"base", "one", "subtree", "children", NULL };

static void		split(char *line, int splitchar, char **left, char **right);
static void		access_append(Access **l, Access *a);
static void		acl_usage(void) LDAP_GCCATTR((noreturn));

static void		acl_regex_normalized_dn(const char *src, struct berval *pat);

#ifdef LDAP_DEBUG
static void		print_acl(Backend *be, AccessControl *a);
static void		print_access(Access *b);
#endif

static void
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
	}
	regfree(&re);
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
	struct berval	bv;
	AccessControl	*a;
	Access	*b;
	int rc;
	const char *text;

	a = NULL;
	for ( i = 1; i < argc; i++ ) {
		/* to clause - select which entries are protected */
		if ( strcasecmp( argv[i], "to" ) == 0 ) {
			if ( a != NULL ) {
				fprintf( stderr, "%s: line %d: "
					"only one to clause allowed in access line\n",
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
					if( a->acl_dn_pat.bv_len ||
						( a->acl_dn_style != ACL_STYLE_REGEX ) )
					{
						fprintf( stderr,
							"%s: line %d: dn pattern"
							" already specified in to clause.\n",
							fname, lineno );
						acl_usage();
					}

					a->acl_dn_pat.bv_val = ch_strdup( "*" );
					a->acl_dn_pat.bv_len = 1;
					continue;
				}

				split( argv[i], '=', &left, &right );
				split( left, '.', &left, &style );

				if ( right == NULL ) {
					fprintf( stderr, "%s: line %d: "
						"missing \"=\" in \"%s\" in to clause\n",
					    fname, lineno, left );
					acl_usage();
				}

				if ( strcasecmp( left, "dn" ) == 0 ) {
					if( a->acl_dn_pat.bv_len != 0 ||
						( a->acl_dn_style != ACL_STYLE_REGEX ) )
					{
						fprintf( stderr,
							"%s: line %d: dn pattern"
							" already specified in to clause.\n",
							fname, lineno );
						acl_usage();
					}

					if ( style == NULL || *style == '\0' ||
						( strcasecmp( style, "base" ) == 0 ) ||
						( strcasecmp( style, "exact" ) == 0 ))
					{
						a->acl_dn_style = ACL_STYLE_BASE;
						ber_str2bv( right, 0, 1, &a->acl_dn_pat );

					} else if ( strcasecmp( style, "one" ) == 0 ) {
						a->acl_dn_style = ACL_STYLE_ONE;
						ber_str2bv( right, 0, 1, &a->acl_dn_pat );

					} else if ( strcasecmp( style, "subtree" ) == 0
						|| strcasecmp( style, "sub" ) == 0 )
					{
						if( *right == '\0' ) {
							a->acl_dn_pat.bv_val = ch_strdup( "*" );
							a->acl_dn_pat.bv_len = 1;

						} else {
							a->acl_dn_style = ACL_STYLE_SUBTREE;
							ber_str2bv( right, 0, 1, &a->acl_dn_pat );
						}

					} else if ( strcasecmp( style, "children" ) == 0 ) {
						a->acl_dn_style = ACL_STYLE_CHILDREN;
						ber_str2bv( right, 0, 1, &a->acl_dn_pat );

					} else if ( strcasecmp( style, "regex" ) == 0 ) {
						a->acl_dn_style = ACL_STYLE_REGEX;

						if ( *right == '\0' ) {
							/* empty regex should match empty DN */
							a->acl_dn_style = ACL_STYLE_BASE;
							ber_str2bv( right, 0, 1, &a->acl_dn_pat );

						} else if ( strcmp(right, "*") == 0 
							|| strcmp(right, ".*") == 0 
							|| strcmp(right, ".*$") == 0 
							|| strcmp(right, "^.*") == 0 
							|| strcmp(right, "^.*$") == 0
							|| strcmp(right, ".*$$") == 0 
							|| strcmp(right, "^.*$$") == 0 )
						{
							a->acl_dn_pat.bv_val = ch_strdup( "*" );
							a->acl_dn_pat.bv_len = sizeof("*")-1;

						} else {
							acl_regex_normalized_dn( right, &a->acl_dn_pat );
						}

					} else {
						fprintf( stderr, "%s: line %d: "
							"unknown dn style \"%s\" in to clause\n",
						    fname, lineno, style );
						acl_usage();
					}

					continue;
				}

				if ( strcasecmp( left, "filter" ) == 0 ) {
					if ( (a->acl_filter = str2filter( right )) == NULL ) {
						fprintf( stderr,
				"%s: line %d: bad filter \"%s\" in to clause\n",
						    fname, lineno, right );
						acl_usage();
					}

				} else if ( strncasecmp( left, "attr", 4 ) == 0 ) {
					a->acl_attrs = str2anlist( a->acl_attrs,
						right, "," );
					if ( a->acl_attrs == NULL ) {
						fprintf( stderr,
				"%s: line %d: unknown attr \"%s\" in to clause\n",
						    fname, lineno, right );
						acl_usage();
					}

				} else if ( strncasecmp( left, "val", 3 ) == 0 ) {
					if ( a->acl_attrval.bv_len ) {
						fprintf( stderr,
				"%s: line %d: attr val already specified in to clause.\n",
							fname, lineno );
						acl_usage();
					}
					if ( a->acl_attrs == NULL || a->acl_attrs[1].an_name.bv_val ) {
						fprintf( stderr,
				"%s: line %d: attr val requires a single attribute.\n",
							fname, lineno );
						acl_usage();
					}
					ber_str2bv( right, 0, 1, &a->acl_attrval );
					if ( style && strcasecmp( style, "regex" ) == 0 ) {
						int e = regcomp( &a->acl_attrval_re, a->acl_attrval.bv_val,
							REG_EXTENDED | REG_ICASE | REG_NOSUB );
						if ( e ) {
							char buf[512];
							regerror( e, &a->acl_attrval_re, buf, sizeof(buf) );
							fprintf( stderr, "%s: line %d: "
								"regular expression \"%s\" bad because of %s\n",
								fname, lineno, right, buf );
							acl_usage();
						}
						a->acl_attrval_style = ACL_STYLE_REGEX;
					} else {
						/* FIXME: if the attribute has DN syntax,
						 * we might allow one, subtree and children styles as well */
						if ( !strcasecmp( style, "exact" ) ) {
							a->acl_attrval_style = ACL_STYLE_BASE;

						} else if ( a->acl_attrs[0].an_desc->ad_type->sat_syntax == slap_schema.si_syn_distinguishedName ) {
							if ( !strcasecmp( style, "base" ) ) {
								a->acl_attrval_style = ACL_STYLE_BASE;
							} else if ( !strcasecmp( style, "onelevel" ) || !strcasecmp( style, "one" ) ) {
								a->acl_attrval_style = ACL_STYLE_ONE;
							} else if ( !strcasecmp( style, "subtree" ) || !strcasecmp( style, "sub" ) ) {
								a->acl_attrval_style = ACL_STYLE_SUBTREE;
							} else if ( !strcasecmp( style, "children" ) ) {
								a->acl_attrval_style = ACL_STYLE_CHILDREN;
							} else {
								fprintf( stderr, 
									"%s: line %d: unknown val.<style> \"%s\" "
									"for attributeType \"%s\" with DN syntax; using \"base\"\n",
									fname, lineno, style,
									a->acl_attrs[0].an_desc->ad_cname.bv_val );
								a->acl_attrval_style = ACL_STYLE_BASE;
							}
							
						} else {
							fprintf( stderr, 
								"%s: line %d: unknown val.<style> \"%s\" "
								"for attributeType \"%s\"; using \"exact\"\n",
								fname, lineno, style,
								a->acl_attrs[0].an_desc->ad_cname.bv_val );
							a->acl_attrval_style = ACL_STYLE_BASE;
						}
					}
					
				} else {
					fprintf( stderr,
						"%s: line %d: expecting <what> got \"%s\"\n",
					    fname, lineno, left );
					acl_usage();
				}
			}

			if ( a->acl_dn_pat.bv_len != 0 &&
				strcmp(a->acl_dn_pat.bv_val, "*") == 0 )
			{
				free( a->acl_dn_pat.bv_val );
				a->acl_dn_pat.bv_val = NULL;
				a->acl_dn_pat.bv_len = 0;
			}
			
			if( a->acl_dn_pat.bv_len != 0 ||
				( a->acl_dn_style != ACL_STYLE_REGEX ) )
			{
				if ( a->acl_dn_style != ACL_STYLE_REGEX ) {
					struct berval bv;
					rc = dnNormalize( 0, NULL, NULL, &a->acl_dn_pat, &bv, NULL);
					if ( rc != LDAP_SUCCESS ) {
						fprintf( stderr,
							"%s: line %d: bad DN \"%s\" in to DN clause\n",
							fname, lineno, a->acl_dn_pat.bv_val );
						acl_usage();
					}
					free( a->acl_dn_pat.bv_val );
					a->acl_dn_pat = bv;
				} else {
					int e = regcomp( &a->acl_dn_re, a->acl_dn_pat.bv_val,
						REG_EXTENDED | REG_ICASE );
					if ( e ) {
						char buf[512];
						regerror( e, &a->acl_dn_re, buf, sizeof(buf) );
						fprintf( stderr, "%s: line %d: "
							"regular expression \"%s\" bad because of %s\n",
							fname, lineno, right, buf );
						acl_usage();
					}
				}
			}

		/* by clause - select who has what access to entries */
		} else if ( strcasecmp( argv[i], "by" ) == 0 ) {
			if ( a == NULL ) {
				fprintf( stderr, "%s: line %d: "
					"to clause required before by clause in access line\n",
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
				slap_style_t sty = ACL_STYLE_REGEX;
				char *style_modifier = NULL;
				int expand = 0;

				split( argv[i], '=', &left, &right );
				split( left, '.', &left, &style );
				if ( style ) {
					split( style, ',', &style, &style_modifier);
				}

				if ( style == NULL || *style == '\0' ||
					strcasecmp( style, "exact" ) == 0 ||
					strcasecmp( style, "base" ) == 0 )
				{
					sty = ACL_STYLE_BASE;

				} else if ( strcasecmp( style, "one" ) == 0 ) {
					sty = ACL_STYLE_ONE;

				} else if ( strcasecmp( style, "subtree" ) == 0 ||
					strcasecmp( style, "sub" ) == 0 )
				{
					sty = ACL_STYLE_SUBTREE;

				} else if ( strcasecmp( style, "children" ) == 0 ) {
					sty = ACL_STYLE_CHILDREN;

				} else if ( strcasecmp( style, "regex" ) == 0 ) {
					sty = ACL_STYLE_REGEX;

				} else {
					fprintf( stderr,
						"%s: line %d: unknown style \"%s\" in by clause\n",
					    fname, lineno, style );
					acl_usage();
				}

				if ( style_modifier &&
					strcasecmp( style_modifier, "expand" ) == 0 )
				{
					expand = 1;
				}

				if ( strcasecmp( argv[i], "*" ) == 0 ) {
					bv.bv_val = ch_strdup( "*" );
					bv.bv_len = 1;
					sty = ACL_STYLE_REGEX;

				} else if ( strcasecmp( argv[i], "anonymous" ) == 0 ) {
					ber_str2bv("anonymous", sizeof("anonymous")-1, 1, &bv);
					sty = ACL_STYLE_REGEX;

				} else if ( strcasecmp( argv[i], "self" ) == 0 ) {
					ber_str2bv("self", sizeof("self")-1, 1, &bv);
					sty = ACL_STYLE_REGEX;

				} else if ( strcasecmp( argv[i], "users" ) == 0 ) {
					ber_str2bv("users", sizeof("users")-1, 1, &bv);
					sty = ACL_STYLE_REGEX;

				} else if ( strcasecmp( left, "dn" ) == 0 ) {
					if ( sty == ACL_STYLE_REGEX ) {
						b->a_dn_style = ACL_STYLE_REGEX;
						if( right == NULL ) {
							/* no '=' */
							ber_str2bv("users",
								sizeof("users")-1,
								1, &bv);
						} else if (*right == '\0' ) {
							/* dn="" */
							ber_str2bv("anonymous",
								sizeof("anonymous")-1,
								1, &bv);
						} else if ( strcmp( right, "*" ) == 0 ) {
							/* dn=* */
							/* any or users?  users for now */
							ber_str2bv("users",
								sizeof("users")-1,
								1, &bv);
						} else if ( strcmp( right, ".+" ) == 0
							|| strcmp( right, "^.+" ) == 0
							|| strcmp( right, ".+$" ) == 0
							|| strcmp( right, "^.+$" ) == 0
							|| strcmp( right, ".+$$" ) == 0
							|| strcmp( right, "^.+$$" ) == 0 )
						{
							ber_str2bv("users",
								sizeof("users")-1,
								1, &bv);
						} else if ( strcmp( right, ".*" ) == 0
							|| strcmp( right, "^.*" ) == 0
							|| strcmp( right, ".*$" ) == 0
							|| strcmp( right, "^.*$" ) == 0
							|| strcmp( right, ".*$$" ) == 0
							|| strcmp( right, "^.*$$" ) == 0 )
						{
							ber_str2bv("*",
								sizeof("*")-1,
								1, &bv);

						} else {
							acl_regex_normalized_dn( right, &bv );
							if ( !ber_bvccmp( &bv, '*' ) ) {
								regtest(fname, lineno, bv.bv_val);
							}
						}
					} else if ( right == NULL || *right == '\0' ) {
						fprintf( stderr, "%s: line %d: "
							"missing \"=\" in (or value after) \"%s\" "
							"in by clause\n",
						    fname, lineno, left );
						acl_usage();

					} else {
						ber_str2bv( right, 0, 1, &bv );
					}

				} else {
					bv.bv_val = NULL;
				}

				if( bv.bv_val != NULL ) {
					if( b->a_dn_pat.bv_len != 0 ) {
						fprintf( stderr,
						    "%s: line %d: dn pattern already specified.\n",
						    fname, lineno );
						acl_usage();
					}

					if ( sty != ACL_STYLE_REGEX && expand == 0 ) {
						rc = dnNormalize(0, NULL, NULL,
							&bv, &b->a_dn_pat, NULL);
						if ( rc != LDAP_SUCCESS ) {
							fprintf( stderr,
								"%s: line %d: bad DN \"%s\" in by DN clause\n",
								fname, lineno, bv.bv_val );
							acl_usage();
						}
						free(bv.bv_val);
					} else {
						b->a_dn_pat = bv;
					}
					b->a_dn_style = sty;
					b->a_dn_expand = expand;
					continue;
				}

				if ( strcasecmp( left, "dnattr" ) == 0 ) {
					if ( right == NULL || right[ 0 ] == '\0' ) {
						fprintf( stderr,
							"%s: line %d: missing \"=\" in (or value after) \"%s\" in by clause\n",
							fname, lineno, left );
						acl_usage();
					}

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
						SLAPD_DN_SYNTAX ) &&
						!is_at_syntax( b->a_dn_at->ad_type,
						SLAPD_NAMEUID_SYNTAX ))
					{
						fprintf( stderr,
							"%s: line %d: dnattr \"%s\": "
							"inappropriate syntax: %s\n",
							fname, lineno, right,
							b->a_dn_at->ad_type->sat_syntax_oid );
						acl_usage();
					}

					if( b->a_dn_at->ad_type->sat_equality == NULL ) {
						fprintf( stderr,
							"%s: line %d: dnattr \"%s\": "
							"inappropriate matching (no EQUALITY)\n",
							fname, lineno, right );
						acl_usage();
					}

					continue;
				}

				if ( strncasecmp( left, "group", sizeof("group")-1 ) == 0 ) {
					char *name = NULL;
					char *value = NULL;

					if (sty != ACL_STYLE_REGEX && sty != ACL_STYLE_BASE) {
						fprintf( stderr, "%s: line %d: "
							"inappropriate style \"%s\" in by clause\n",
						    fname, lineno, style );
						acl_usage();
					}

					if ( right == NULL || right[ 0 ] == '\0' ) {
						fprintf( stderr, "%s: line %d: "
							"missing \"=\" in (or value after) \"%s\" "
							"in by clause\n",
							fname, lineno, left );
						acl_usage();
					}

					if( b->a_group_pat.bv_len ) {
						fprintf( stderr,
							"%s: line %d: group pattern already specified.\n",
							fname, lineno );
						acl_usage();
					}

					/* format of string is
						"group/objectClassValue/groupAttrName" */
					if ((value = strchr(left, '/')) != NULL) {
						*value++ = '\0';
						if (*value && (name = strchr(value, '/')) != NULL) {
							*name++ = '\0';
						}
					}

					b->a_group_style = sty;
					if (sty == ACL_STYLE_REGEX) {
						acl_regex_normalized_dn( right, &bv );
						if ( !ber_bvccmp( &bv, '*' ) ) {
							regtest(fname, lineno, bv.bv_val);
						}
						b->a_group_pat = bv;
					} else {
						ber_str2bv( right, 0, 0, &bv );
						rc = dnNormalize( 0, NULL, NULL, &bv,
							&b->a_group_pat, NULL );
						if ( rc != LDAP_SUCCESS ) {
							fprintf( stderr,
								"%s: line %d: bad DN \"%s\"\n",
								fname, lineno, right );
							acl_usage();
						}
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

					if( is_object_subclass( slap_schema.si_oc_referral,
						b->a_group_oc ))
					{
						fprintf( stderr,
							"%s: line %d: group objectclass \"%s\" "
							"is subclass of referral\n",
							fname, lineno, value );
						acl_usage();
					}

					if( is_object_subclass( slap_schema.si_oc_alias,
						b->a_group_oc ))
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
						SLAPD_DN_SYNTAX ) &&
					    !is_at_syntax( b->a_group_at->ad_type,
						SLAPD_NAMEUID_SYNTAX ) &&
						!is_at_subtype( b->a_group_at->ad_type, slap_schema.si_ad_labeledURI->ad_type ))
					{
						fprintf( stderr,
							"%s: line %d: group \"%s\": inappropriate syntax: %s\n",
							fname, lineno, right,
							b->a_group_at->ad_type->sat_syntax_oid );
						acl_usage();
					}


					{
						int rc;
						struct berval vals[2];

						vals[0].bv_val = b->a_group_oc->soc_oid;
						vals[0].bv_len = strlen(vals[0].bv_val);
						vals[1].bv_val = NULL;


						rc = oc_check_allowed( b->a_group_at->ad_type,
							vals, NULL );

						if( rc != 0 ) {
							fprintf( stderr, "%s: line %d: "
								"group: \"%s\" not allowed by \"%s\"\n",
								fname, lineno,
								b->a_group_at->ad_cname.bv_val,
								b->a_group_oc->soc_oid );
							acl_usage();
						}
					}
					continue;
				}

				if ( strcasecmp( left, "peername" ) == 0 ) {
					if (sty != ACL_STYLE_REGEX && sty != ACL_STYLE_BASE) {
						fprintf( stderr, "%s: line %d: "
							"inappropriate style \"%s\" in by clause\n",
						    fname, lineno, style );
						acl_usage();
					}

					if ( right == NULL || right[ 0 ] == '\0' ) {
						fprintf( stderr, "%s: line %d: "
							"missing \"=\" in (or value after) \"%s\" "
							"in by clause\n",
							fname, lineno, left );
						acl_usage();
					}

					if( b->a_peername_pat.bv_len ) {
						fprintf( stderr, "%s: line %d: "
							"peername pattern already specified.\n",
							fname, lineno );
						acl_usage();
					}

					b->a_peername_style = sty;
					if (sty == ACL_STYLE_REGEX) {
						acl_regex_normalized_dn( right, &bv );
						if ( !ber_bvccmp( &bv, '*' ) ) {
							regtest(fname, lineno, bv.bv_val);
						}
						b->a_peername_pat = bv;
					} else {
						ber_str2bv( right, 0, 1, &b->a_peername_pat );
					}
					continue;
				}

				if ( strcasecmp( left, "sockname" ) == 0 ) {
					if (sty != ACL_STYLE_REGEX && sty != ACL_STYLE_BASE) {
						fprintf( stderr, "%s: line %d: "
							"inappropriate style \"%s\" in by clause\n",
						    fname, lineno, style );
						acl_usage();
					}

					if ( right == NULL || right[ 0 ] == '\0' ) {
						fprintf( stderr, "%s: line %d: "
							"missing \"=\" in (or value after) \"%s\" "
							"in by clause\n",
							fname, lineno, left );
						acl_usage();
					}

					if( b->a_sockname_pat.bv_len ) {
						fprintf( stderr, "%s: line %d: "
							"sockname pattern already specified.\n",
							fname, lineno );
						acl_usage();
					}

					b->a_sockname_style = sty;
					if (sty == ACL_STYLE_REGEX) {
						acl_regex_normalized_dn( right, &bv );
						if ( !ber_bvccmp( &bv, '*' ) ) {
							regtest(fname, lineno, bv.bv_val);
						}
						b->a_sockname_pat = bv;
					} else {
						ber_str2bv( right, 0, 1, &b->a_sockname_pat );
					}
					continue;
				}

				if ( strcasecmp( left, "domain" ) == 0 ) {
					switch ( sty ) {
					case ACL_STYLE_REGEX:
					case ACL_STYLE_BASE:
					case ACL_STYLE_SUBTREE:
						break;

					default:
						fprintf( stderr,
							"%s: line %d: inappropriate style \"%s\" in by clause\n",
						    fname, lineno, style );
						acl_usage();
					}

					if ( right == NULL || right[ 0 ] == '\0' ) {
						fprintf( stderr,
							"%s: line %d: missing \"=\" in (or value after) \"%s\" in by clause\n",
							fname, lineno, left );
						acl_usage();
					}

					if( b->a_domain_pat.bv_len ) {
						fprintf( stderr,
							"%s: line %d: domain pattern already specified.\n",
							fname, lineno );
						acl_usage();
					}

					b->a_domain_style = sty;
					b->a_domain_expand = expand;
					if (sty == ACL_STYLE_REGEX) {
						acl_regex_normalized_dn( right, &bv );
						if ( !ber_bvccmp( &bv, '*' ) ) {
							regtest(fname, lineno, bv.bv_val);
						}
						b->a_domain_pat = bv;
					} else {
						ber_str2bv( right, 0, 1, &b->a_domain_pat );
					}
					continue;
				}

				if ( strcasecmp( left, "sockurl" ) == 0 ) {
					if (sty != ACL_STYLE_REGEX && sty != ACL_STYLE_BASE) {
						fprintf( stderr,
							"%s: line %d: inappropriate style \"%s\" in by clause\n",
						    fname, lineno, style );
						acl_usage();
					}

					if ( right == NULL || right[ 0 ] == '\0' ) {
						fprintf( stderr,
							"%s: line %d: missing \"=\" in (or value after) \"%s\" in by clause\n",
							fname, lineno, left );
						acl_usage();
					}

					if( b->a_sockurl_pat.bv_len ) {
						fprintf( stderr,
							"%s: line %d: sockurl pattern already specified.\n",
							fname, lineno );
						acl_usage();
					}

					b->a_sockurl_style = sty;
					if (sty == ACL_STYLE_REGEX) {
						acl_regex_normalized_dn( right, &bv );
						if ( !ber_bvccmp( &bv, '*' ) ) {
							regtest(fname, lineno, bv.bv_val);
						}
						b->a_sockurl_pat = bv;
					} else {
						ber_str2bv( right, 0, 1, &b->a_sockurl_pat );
					}
					continue;
				}

				if ( strcasecmp( left, "set" ) == 0 ) {
					if (sty != ACL_STYLE_REGEX && sty != ACL_STYLE_BASE) {
						fprintf( stderr,
							"%s: line %d: inappropriate style \"%s\" in by clause\n",
						    fname, lineno, style );
						acl_usage();
					}

					if( b->a_set_pat.bv_len != 0 ) {
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
					ber_str2bv( right, 0, 1, &b->a_set_pat );

					continue;
				}

#ifdef SLAPD_ACI_ENABLED
				if ( strcasecmp( left, "aci" ) == 0 ) {
					if (sty != ACL_STYLE_REGEX && sty != ACL_STYLE_BASE) {
						fprintf( stderr,
							"%s: line %d: inappropriate style \"%s\" in by clause\n",
						    fname, lineno, style );
						acl_usage();
					}

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
						b->a_aci_at = slap_schema.si_ad_aci;
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
					if (sty != ACL_STYLE_REGEX && sty != ACL_STYLE_BASE) {
						fprintf( stderr,
							"%s: line %d: inappropriate style \"%s\" in by clause\n",
						    fname, lineno, style );
						acl_usage();
					}

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
					if (sty != ACL_STYLE_REGEX && sty != ACL_STYLE_BASE) {
						fprintf( stderr,
							"%s: line %d: inappropriate style \"%s\" in by clause\n",
						    fname, lineno, style );
						acl_usage();
					}

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
					if (sty != ACL_STYLE_REGEX && sty != ACL_STYLE_BASE) {
						fprintf( stderr,
							"%s: line %d: inappropriate style \"%s\" in by clause\n",
						    fname, lineno, style );
						acl_usage();
					}

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
					if (sty != ACL_STYLE_REGEX && sty != ACL_STYLE_BASE) {
						fprintf( stderr,
							"%s: line %d: inappropriate style \"%s\" in by clause\n",
						    fname, lineno, style );
						acl_usage();
					}

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
	char *ptr = buf;

	assert( buf != NULL );

	if ( ACL_IS_INVALID( mask ) ) {
		return "invalid";
	}

	buf[0] = '\0';

	if ( ACL_IS_LEVEL( mask ) ) {
		if ( ACL_LVL_IS_NONE(mask) ) {
			ptr = lutil_strcopy( ptr, "none" );

		} else if ( ACL_LVL_IS_AUTH(mask) ) {
			ptr = lutil_strcopy( ptr, "auth" );

		} else if ( ACL_LVL_IS_COMPARE(mask) ) {
			ptr = lutil_strcopy( ptr, "compare" );

		} else if ( ACL_LVL_IS_SEARCH(mask) ) {
			ptr = lutil_strcopy( ptr, "search" );

		} else if ( ACL_LVL_IS_READ(mask) ) {
			ptr = lutil_strcopy( ptr, "read" );

		} else if ( ACL_LVL_IS_WRITE(mask) ) {
			ptr = lutil_strcopy( ptr, "write" );
		} else {
			ptr = lutil_strcopy( ptr, "unknown" );
		}
		
		*ptr++ = '(';
	}

	if( ACL_IS_ADDITIVE( mask ) ) {
		*ptr++ = '+';

	} else if( ACL_IS_SUBTRACTIVE( mask ) ) {
		*ptr++ = '-';

	} else {
		*ptr++ = '=';
	}

	if ( ACL_PRIV_ISSET(mask, ACL_PRIV_WRITE) ) {
		none = 0;
		*ptr++ = 'w';
	} 

	if ( ACL_PRIV_ISSET(mask, ACL_PRIV_READ) ) {
		none = 0;
		*ptr++ = 'r';
	} 

	if ( ACL_PRIV_ISSET(mask, ACL_PRIV_SEARCH) ) {
		none = 0;
		*ptr++ = 's';
	} 

	if ( ACL_PRIV_ISSET(mask, ACL_PRIV_COMPARE) ) {
		none = 0;
		*ptr++ = 'c';
	} 

	if ( ACL_PRIV_ISSET(mask, ACL_PRIV_AUTH) ) {
		none = 0;
		*ptr++ = 'x';
	} 

	if ( none && ACL_PRIV_ISSET(mask, ACL_PRIV_NONE) ) {
		none = 0;
		*ptr++ = 'n';
	} 

	if ( none ) {
		*ptr++ = '0';
	}

	if ( ACL_IS_LEVEL( mask ) ) {
		*ptr++ = ')';
	}

	*ptr = '\0';

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
			if( TOLOWER((unsigned char) str[i]) == 'w' ) {
				ACL_PRIV_SET(mask, ACL_PRIV_WRITE);

			} else if( TOLOWER((unsigned char) str[i]) == 'r' ) {
				ACL_PRIV_SET(mask, ACL_PRIV_READ);

			} else if( TOLOWER((unsigned char) str[i]) == 's' ) {
				ACL_PRIV_SET(mask, ACL_PRIV_SEARCH);

			} else if( TOLOWER((unsigned char) str[i]) == 'c' ) {
				ACL_PRIV_SET(mask, ACL_PRIV_COMPARE);

			} else if( TOLOWER((unsigned char) str[i]) == 'x' ) {
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
	fprintf( stderr, "%s%s\n",
		"<access clause> ::= access to <what> "
				"[ by <who> <access> [ <control> ] ]+ \n"
		"<what> ::= * | [dn[.<dnstyle>]=<DN>] [filter=<filter>] [attrs=<attrlist>]\n"
		"<attrlist> ::= <attr> [val[.<style>]=<value>] | <attr> , <attrlist>\n"
		"<attr> ::= <attrname> | entry | children\n"
		"<who> ::= [ * | anonymous | users | self | dn[.<dnstyle>]=<DN> ]\n"
			"\t[dnattr=<attrname>]\n"
			"\t[group[/<objectclass>[/<attrname>]][.<style>]=<group>]\n"
			"\t[peername[.<style>]=<peer>] [sockname[.<style>]=<name>]\n",
			"\t[domain[.<style>]=<domain>] [sockurl[.<style>]=<url>]\n"
#ifdef SLAPD_ACI_ENABLED
			"\t[aci=<attrname>]\n"
#endif
			"\t[ssf=<n>] [transport_ssf=<n>] [tls_ssf=<n>] [sasl_ssf=<n>]\n"
		"<dnstyle> ::= base | exact | one | subtree | children | regex\n"
		"<style> ::= regex | base | exact\n"
		"<access> ::= [self]{<level>|<priv>}\n"
		"<level> ::= none | auth | compare | search | read | write\n"
		"<priv> ::= {=|+|-}{w|r|s|c|x|0}+\n"
		"<control> ::= [ stop | continue | break ]\n"
	);
	exit( EXIT_FAILURE );
}

/*
 * Set pattern to a "normalized" DN from src.
 * At present it simply eats the (optional) space after 
 * a RDN separator (,)
 * Eventually will evolve in a more complete normalization
 */
static void
acl_regex_normalized_dn(
	const char *src,
	struct berval *pattern
)
{
	char *str, *p;
	ber_len_t len;

	str = ch_strdup( src );
	len = strlen( src );

	for ( p = str; p && p[ 0 ]; p++ ) {
		/* escape */
		if ( p[ 0 ] == '\\' && p[ 1 ] ) {
			/* 
			 * if escaping a hex pair we should
			 * increment p twice; however, in that 
			 * case the second hex number does 
			 * no harm
			 */
			p++;
		}

		if ( p[ 0 ] == ',' ) {
			if ( p[ 1 ] == ' ' ) {
				char *q;
			
				/*
				 * too much space should be 
				 * an error if we are pedantic
				 */
				for ( q = &p[ 2 ]; q[ 0 ] == ' '; q++ ) {
					/* DO NOTHING */ ;
				}
				AC_MEMCPY( p+1, q, len-(q-str)+1);
			}
		}
	}
	pattern->bv_val = str;
	pattern->bv_len = p-str;

	return;
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

static void
access_free( Access *a )
{
	if ( a->a_dn_pat.bv_val )
		free ( a->a_dn_pat.bv_val );
	if ( a->a_peername_pat.bv_val )
		free ( a->a_peername_pat.bv_val );
	if ( a->a_sockname_pat.bv_val )
		free ( a->a_sockname_pat.bv_val );
	if ( a->a_domain_pat.bv_val )
		free ( a->a_domain_pat.bv_val );
	if ( a->a_sockurl_pat.bv_val )
		free ( a->a_sockurl_pat.bv_val );
	if ( a->a_set_pat.bv_len )
		free ( a->a_set_pat.bv_val );
	if ( a->a_group_pat.bv_len )
		free ( a->a_group_pat.bv_val );
	free( a );
}

void
acl_free( AccessControl *a )
{
	Access *n;
	AttributeName *an;

	if ( a->acl_filter )
		filter_free( a->acl_filter );
	if ( a->acl_dn_pat.bv_len )
		free ( a->acl_dn_pat.bv_val );
	if ( a->acl_attrs ) {
		for ( an = a->acl_attrs; an->an_name.bv_val; an++ ) {
			free( an->an_name.bv_val );
		}
		free( a->acl_attrs );
	}
	for (; a->acl_access; a->acl_access = n) {
		n = a->acl_access->a_next;
		access_free( a->acl_access );
	}
	free( a );
}

/* Because backend_startup uses acl_append to tack on the global_acl to
 * the end of each backend's acl, we cannot just take one argument and
 * merrily free our way to the end of the list. backend_destroy calls us
 * with the be_acl in arg1, and global_acl in arg2 to give us a stopping
 * point. config_destroy calls us with global_acl in arg1 and NULL in
 * arg2, so we then proceed to polish off the global_acl.
 */
void
acl_destroy( AccessControl *a, AccessControl *end )
{
	AccessControl *n;

	for (; a && a!= end; a=n) {
		n = a->acl_next;
		acl_free( a );
	}
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

static void
print_access( Access *b )
{
	char maskbuf[ACCESSMASK_MAXLEN];

	fprintf( stderr, "\tby" );

	if ( b->a_dn_pat.bv_len != 0 ) {
		if( strcmp(b->a_dn_pat.bv_val, "*") == 0
			|| strcmp(b->a_dn_pat.bv_val, "users") == 0 
			|| strcmp(b->a_dn_pat.bv_val, "anonymous") == 0 
			|| strcmp(b->a_dn_pat.bv_val, "self") == 0 )
		{
			fprintf( stderr, " %s", b->a_dn_pat.bv_val );

		} else {
			fprintf( stderr, " dn.%s=\"%s\"",
				style_strings[b->a_dn_style], b->a_dn_pat.bv_val );
		}
	}

	if ( b->a_dn_at != NULL ) {
		fprintf( stderr, " dnattr=%s", b->a_dn_at->ad_cname.bv_val );
	}

	if ( b->a_group_pat.bv_len ) {
		fprintf( stderr, " group/%s/%s.%s=\"%s\"",
			b->a_group_oc ? b->a_group_oc->soc_cname.bv_val : "groupOfNames",
			b->a_group_at ? b->a_group_at->ad_cname.bv_val : "member",
			style_strings[b->a_group_style],
			b->a_group_pat.bv_val );
    }

	if ( b->a_peername_pat.bv_len != 0 ) {
		fprintf( stderr, " peername=\"%s\"", b->a_peername_pat.bv_val );
	}

	if ( b->a_sockname_pat.bv_len != 0 ) {
		fprintf( stderr, " sockname=\"%s\"", b->a_sockname_pat.bv_val );
	}

	if ( b->a_domain_pat.bv_len != 0 ) {
		fprintf( stderr, " domain=%s", b->a_domain_pat.bv_val );
	}

	if ( b->a_sockurl_pat.bv_len != 0 ) {
		fprintf( stderr, " sockurl=\"%s\"", b->a_sockurl_pat.bv_val );
	}

#ifdef SLAPD_ACI_ENABLED
	if ( b->a_aci_at != NULL ) {
		fprintf( stderr, " aci=%s", b->a_aci_at->ad_cname.bv_val );
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

	if ( a->acl_dn_pat.bv_len != 0 ) {
		to++;
		fprintf( stderr, " dn.%s=\"%s\"\n",
			style_strings[a->acl_dn_style], a->acl_dn_pat.bv_val );
	}

	if ( a->acl_filter != NULL ) {
		struct berval bv = { 0, NULL };
		to++;
		filter2bv( a->acl_filter, &bv );
		fprintf( stderr, " filter=%s\n", bv.bv_val );
		ch_free( bv.bv_val );
	}

	if ( a->acl_attrs != NULL ) {
		int	first = 1;
		AttributeName *an;
		to++;

		fprintf( stderr, " attrs=" );
		for ( an = a->acl_attrs; an && an->an_name.bv_val; an++ ) {
			if ( ! first ) {
				fprintf( stderr, "," );
			}
			if (an->an_oc) {
				fputc( an->an_oc_exclude ? '!' : '@', stderr);
			}
			fputs( an->an_name.bv_val, stderr );
			first = 0;
		}
		fprintf(  stderr, "\n" );
	}

	if ( a->acl_attrval.bv_len != 0 ) {
		to++;
		fprintf( stderr, " val.%s=\"%s\"\n",
			style_strings[a->acl_attrval_style], a->acl_attrval.bv_val );

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
