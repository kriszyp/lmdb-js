/* config.c - configuration file handling routines */
/*
 * Copyright 1998-1999 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "portable.h"

#include <stdio.h>
#ifdef HAVE_LOCALE_H
#include <locale.h>
#endif

#include <ac/string.h>
#include <ac/ctype.h>
#include <ac/socket.h>

#include "ldap_pvt.h"
#include "ldap_defaults.h"
#include "slap.h"

#define MAXARGS	100

/*
 * defaults for various global variables
 */
int		defsize = SLAPD_DEFAULT_SIZELIMIT;
int		deftime = SLAPD_DEFAULT_TIMELIMIT;
AccessControl	*global_acl = NULL;
int		global_default_access = ACL_READ;
char		*replogfile;
int		global_lastmod = ON;
int		global_idletimeout = 0;
char	*global_realm = NULL;
char		*ldap_srvtab = "";

char   *slapd_pid_file  = NULL;
char   *slapd_args_file = NULL;

static char	*fp_getline(FILE *fp, int *lineno);
static void	fp_getline_init(int *lineno);
static int	fp_parse_line(char *line, int *argcp, char **argv);

static char	*strtok_quote(char *line, char *sep);

int
read_config( const char *fname )
{
	FILE	*fp;
	char	*line, *savefname, *saveline;
	int	cargc, savelineno;
	char	*cargv[MAXARGS];
	int	lineno, i;
#ifdef HAVE_TLS
	int rc;
#endif
	struct berval *vals[2];
	struct berval val;

	static BackendInfo *bi = NULL;
	static BackendDB	*be = NULL;

	vals[0] = &val;
	vals[1] = NULL;

	if ( (fp = fopen( fname, "r" )) == NULL ) {
		ldap_syslog = 1;
		Debug( LDAP_DEBUG_ANY,
		    "could not open config file \"%s\" - absolute path?\n",
		    fname, 0, 0 );
		perror( fname );
		return 1;
	}

	Debug( LDAP_DEBUG_CONFIG, "reading config file %s\n", fname, 0, 0 );

	if ( schema_init( ) != 0 ) {
		Debug( LDAP_DEBUG_ANY,
		    "error initializing the schema\n",
		    0, 0, 0 );
		return( 1 );
	}

	fp_getline_init( &lineno );

	while ( (line = fp_getline( fp, &lineno )) != NULL ) {
		/* skip comments and blank lines */
		if ( line[0] == '#' || line[0] == '\0' ) {
			continue;
		}

		Debug( LDAP_DEBUG_CONFIG, "line %d (%s)\n", lineno, line, 0 );

		/* fp_parse_line is destructive, we save a copy */
		saveline = ch_strdup( line );

		if ( fp_parse_line( line, &cargc, cargv ) != 0 ) {
			return( 1 );
		}

		if ( cargc < 1 ) {
			Debug( LDAP_DEBUG_ANY,
			    "%s: line %d: bad config line (ignored)\n",
			    fname, lineno, 0 );
			continue;
		}

		if ( strcasecmp( cargv[0], "backend" ) == 0 ) {
			if ( cargc < 2 ) {
				Debug( LDAP_DEBUG_ANY,
		"%s: line %d: missing type in \"backend <type>\" line\n",
				    fname, lineno, 0 );
				return( 1 );
			}

			if( be != NULL ) {
				Debug( LDAP_DEBUG_ANY,
"%s: line %d: backend line must appear before any database definition\n",
				    fname, lineno, 0 );
				return( 1 );
			}

			bi = backend_info( cargv[1] );

		/* start of a new database definition */
		} else if ( strcasecmp( cargv[0], "database" ) == 0 ) {
			if ( cargc < 2 ) {
				Debug( LDAP_DEBUG_ANY,
		"%s: line %d: missing type in \"database <type>\" line\n",
				    fname, lineno, 0 );
				return( 1 );
			}
			bi = NULL;
			be = backend_db_init( cargv[1] );

 		/* assign a default depth limit for alias deref */
		be->be_max_deref_depth = SLAPD_DEFAULT_MAXDEREFDEPTH; 

		/* get pid file name */
		} else if ( strcasecmp( cargv[0], "pidfile" ) == 0 ) {
			if ( cargc < 2 ) {
				Debug( LDAP_DEBUG_ANY,
	    "%s: line %d: missing file name in \"pidfile <file>\" line\n",
				    fname, lineno, 0 );
				return( 1 );
			}

			slapd_pid_file = ch_strdup( cargv[1] );

		/* get args file name */
		} else if ( strcasecmp( cargv[0], "argsfile" ) == 0 ) {
			if ( cargc < 2 ) {
				Debug( LDAP_DEBUG_ANY,
	    "%s: line %d: missing file name in \"argsfile <file>\" line\n",
				    fname, lineno, 0 );
				return( 1 );
			}

			slapd_args_file = ch_strdup( cargv[1] );

		/* set DIGEST realm */
		} else if ( strcasecmp( cargv[0], "digest-realm" ) == 0 ) {
			if ( cargc < 2 ) {
				Debug( LDAP_DEBUG_ANY,
	    "%s: line %d: missing realm in \"digest-realm <realm>\" line\n",
				    fname, lineno, 0 );
				return( 1 );
			}
			if ( be != NULL ) {
				be->be_realm = ch_strdup( cargv[1] );

			} else if ( global_realm != NULL ) {
				Debug( LDAP_DEBUG_ANY,
					"%s: line %d: already set global realm!\n",
					fname, lineno, 0 );
				return 1;

			} else {
				global_realm = ch_strdup( cargv[1] );
			}

		/* set time limit */
		} else if ( strcasecmp( cargv[0], "sizelimit" ) == 0 ) {
			if ( cargc < 2 ) {
				Debug( LDAP_DEBUG_ANY,
	    "%s: line %d: missing limit in \"sizelimit <limit>\" line\n",
				    fname, lineno, 0 );
				return( 1 );
			}
			if ( be == NULL ) {
				defsize = atoi( cargv[1] );
			} else {
				be->be_sizelimit = atoi( cargv[1] );
			}

		/* set time limit */
		} else if ( strcasecmp( cargv[0], "timelimit" ) == 0 ) {
			if ( cargc < 2 ) {
				Debug( LDAP_DEBUG_ANY,
	    "%s: line %d: missing limit in \"timelimit <limit>\" line\n",
				    fname, lineno, 0 );
				return( 1 );
			}
			if ( be == NULL ) {
				deftime = atoi( cargv[1] );
			} else {
				be->be_timelimit = atoi( cargv[1] );
			}

		/* set database suffix */
		} else if ( strcasecmp( cargv[0], "suffix" ) == 0 ) {
			Backend *tmp_be;
			if ( cargc < 2 ) {
				Debug( LDAP_DEBUG_ANY,
		    "%s: line %d: missing dn in \"suffix <dn>\" line\n",
				    fname, lineno, 0 );
				return( 1 );
			} else if ( cargc > 2 ) {
				Debug( LDAP_DEBUG_ANY,
    "%s: line %d: extra cruft after <dn> in \"suffix %s\" line (ignored)\n",
				    fname, lineno, cargv[1] );
			}
			if ( be == NULL ) {
				Debug( LDAP_DEBUG_ANY,
"%s: line %d: suffix line must appear inside a database definition (ignored)\n",
				    fname, lineno, 0 );
			} else if ( ( tmp_be = select_backend( cargv[1] ) ) == be ) {
				Debug( LDAP_DEBUG_ANY,
"%s: line %d: suffix already served by this backend (ignored)\n",
				    fname, lineno, 0 );
			} else if ( tmp_be  != NULL ) {
				Debug( LDAP_DEBUG_ANY,
"%s: line %d: suffix already served by a preceeding backend \"%s\" (ignored)\n",
				    fname, lineno, tmp_be->be_suffix[0] );
			} else {
				char *dn = ch_strdup( cargv[1] );
				(void) dn_normalize( dn );
				charray_add( &be->be_suffix, dn );
				(void) ldap_pvt_str2upper( dn );
				charray_add( &be->be_nsuffix, dn );
				free( dn );
			}

		/* set database suffixAlias */
		} else if ( strcasecmp( cargv[0], "suffixAlias" ) == 0 ) {
			Backend *tmp_be;
			if ( cargc < 2 ) {
				Debug( LDAP_DEBUG_ANY,
"%s: line %d: missing alias and aliased_dn in \"suffixAlias <alias> <aliased_dn>\" line\n",
					fname, lineno, 0 );
				return( 1 );
			} else if ( cargc < 3 ) {
				Debug( LDAP_DEBUG_ANY,
"%s: line %d: missing aliased_dn in \"suffixAlias <alias> <aliased_dn>\" line\n",
				fname, lineno, 0 );
				return( 1 );
			} else if ( cargc > 3 ) {
				Debug( LDAP_DEBUG_ANY,
					"%s: line %d: extra cruft in suffixAlias line (ignored)\n",
				fname, lineno, 0 );
			}

			if ( be == NULL ) {
				Debug( LDAP_DEBUG_ANY,
					"%s: line %d: suffixAlias line"
					" must appear inside a database definition (ignored)\n",
					fname, lineno, 0 );
			} else if ( (tmp_be = select_backend( cargv[1] )) != NULL ) {
				Debug( LDAP_DEBUG_ANY,
					"%s: line %d: suffixAlias served by"
					"  a preceeding backend \"%s\" (ignored)\n",
					fname, lineno, tmp_be->be_suffix[0] );

			} else if ( (tmp_be = select_backend( cargv[2] )) != NULL ) {
				Debug( LDAP_DEBUG_ANY,
					"%s: line %d: suffixAlias derefs to differnet backend"
					"  a preceeding backend \"%s\" (ignored)\n",
					fname, lineno, tmp_be->be_suffix[0] );

			} else {
				char *alias, *aliased_dn;

				alias = ch_strdup( cargv[1] );
				(void) dn_normalize( alias );

				aliased_dn = ch_strdup( cargv[2] );
				(void) dn_normalize( aliased_dn );

				(void) dn_normalize_case( alias );
				(void) dn_normalize_case( aliased_dn );
				charray_add( &be->be_suffixAlias, alias );
				charray_add( &be->be_suffixAlias, aliased_dn );

				free(alias);
				free(aliased_dn);
			}

               /* set max deref depth */
               } else if ( strcasecmp( cargv[0], "maxDerefDepth" ) == 0 ) {
					int i;
                       if ( cargc < 2 ) {
                               Debug( LDAP_DEBUG_ANY,
                   "%s: line %d: missing depth in \"maxDerefDepth <depth>\" line\n",
                                   fname, lineno, 0 );
                               return( 1 );
                       }
                       if ( be == NULL ) {
                               Debug( LDAP_DEBUG_ANY,
"%s: line %d: depth line must appear inside a database definition (ignored)\n",
                                   fname, lineno, 0 );
                       } else if ((i = atoi(cargv[1])) < 0) {
                               Debug( LDAP_DEBUG_ANY,
"%s: line %d: depth must be positive (ignored)\n",
                                   fname, lineno, 0 );

                       } else {
                           be->be_max_deref_depth = i;
					   }


		/* set magic "root" dn for this database */
		} else if ( strcasecmp( cargv[0], "rootdn" ) == 0 ) {
			if ( cargc < 2 ) {
				Debug( LDAP_DEBUG_ANY,
		    "%s: line %d: missing dn in \"rootdn <dn>\" line\n",
				    fname, lineno, 0 );
				return( 1 );
			}
			if ( be == NULL ) {
				Debug( LDAP_DEBUG_ANY,
"%s: line %d: rootdn line must appear inside a database definition (ignored)\n",
				    fname, lineno, 0 );
			} else {
				be->be_root_dn = ch_strdup( cargv[1] );
				be->be_root_ndn = ch_strdup( cargv[1] );

				if( dn_normalize_case( be->be_root_ndn ) == NULL ) {
					free( be->be_root_dn );
					free( be->be_root_ndn );
					Debug( LDAP_DEBUG_ANY,
"%s: line %d: rootdn DN is invalid\n",
					   fname, lineno, 0 );
					return( 1 );
				}
			}

		/* set super-secret magic database password */
		} else if ( strcasecmp( cargv[0], "rootpw" ) == 0 ) {
			if ( cargc < 2 ) {
				Debug( LDAP_DEBUG_ANY,
	    "%s: line %d: missing passwd in \"rootpw <passwd>\" line\n",
				    fname, lineno, 0 );
				return( 1 );
			}
			if ( be == NULL ) {
				Debug( LDAP_DEBUG_ANY,
"%s: line %d: rootpw line must appear inside a database definition (ignored)\n",
				    fname, lineno, 0 );
			} else {
				be->be_root_pw = ch_strdup( cargv[1] );
			}

		/* make this database read-only */
		} else if ( strcasecmp( cargv[0], "readonly" ) == 0 ) {
			if ( cargc < 2 ) {
				Debug( LDAP_DEBUG_ANY,
	    "%s: line %d: missing on|off in \"readonly <on|off>\" line\n",
				    fname, lineno, 0 );
				return( 1 );
			}
			if ( be == NULL ) {
				Debug( LDAP_DEBUG_ANY,
"%s: line %d: readonly line must appear inside a database definition (ignored)\n",
				    fname, lineno, 0 );
			} else {
				if ( strcasecmp( cargv[1], "on" ) == 0 ) {
					be->be_readonly = 1;
				} else {
					be->be_readonly = 0;
				}
			}

		/* where to send clients when we don't hold it */
		} else if ( strcasecmp( cargv[0], "referral" ) == 0 ) {
			if ( cargc < 2 ) {
				Debug( LDAP_DEBUG_ANY,
		    "%s: line %d: missing URL in \"referral <URL>\" line\n",
				    fname, lineno, 0 );
				return( 1 );
			}

			vals[0]->bv_val = cargv[1];
			vals[0]->bv_len = strlen( vals[0]->bv_val );
			value_add( &default_referral, vals );

		/* specify locale */
		} else if ( strcasecmp( cargv[0], "locale" ) == 0 ) {
#ifdef HAVE_LOCALE_H
			char *locale;
			if ( cargc < 2 ) {
				Debug( LDAP_DEBUG_ANY,
	"%s: line %d: missing locale in \"locale <name | on | off>\" line\n",
				       fname, lineno, 0 );
				return( 1 );
			}

			locale = (strcasecmp(   cargv[1], "on"  ) == 0 ? ""
				  : strcasecmp( cargv[1], "off" ) == 0 ? "C"
				  : ch_strdup( cargv[1] )                    );

			if ( setlocale( LC_CTYPE, locale ) == 0 ) {
				Debug( LDAP_DEBUG_ANY,
				       (*locale
					? "%s: line %d: bad locale \"%s\"\n"
					: "%s: line %d: bad locale\n"),
				       fname, lineno, locale );
				return( 1 );
			}
#else
			Debug( LDAP_DEBUG_ANY,
			       "%s: line %d: \"locale\" unsupported\n",
			       fname, lineno, 0 );
			return( 1 );
#endif
		/* specify an Object Identifier macro */
		} else if ( strcasecmp( cargv[0], "objectidentifier" ) == 0 ) {
			parse_oidm( fname, lineno, cargc, cargv );
		/* specify an objectclass */
		} else if ( strcasecmp( cargv[0], "objectclass" ) == 0 ) {
			if ( *cargv[1] == '(' ) {
				char * p;
				p = strchr(saveline,'(');
				parse_oc( fname, lineno, p, cargv );
			} else {
				parse_oc_old( be, fname, lineno, cargc, cargv );
			}

		/* specify an attribute */
		} else if ( strcasecmp( cargv[0], "attribute" ) == 0 ) {
			if ( *cargv[1] == '(' ) {
				char * p;
				p = strchr(saveline,'(');
				parse_at( fname, lineno, p, cargv );
			} else {
				attr_syntax_config( fname, lineno, cargc - 1,
				    &cargv[1] );
			}

		/* turn on/off schema checking */
		} else if ( strcasecmp( cargv[0], "schemacheck" ) == 0 ) {
			if ( cargc < 2 ) {
				Debug( LDAP_DEBUG_ANY,
    "%s: line %d: missing on|off in \"schemacheck <on|off>\" line\n",
				    fname, lineno, 0 );
				return( 1 );
			}
			if ( strcasecmp( cargv[1], "off" ) == 0 ) {
				global_schemacheck = 0;
			} else {
				global_schemacheck = 1;
			}

		/* specify access control info */
		} else if ( strcasecmp( cargv[0], "access" ) == 0 ) {
			parse_acl( be, fname, lineno, cargc, cargv );

		/* specify default access control info */
		} else if ( strcasecmp( cargv[0], "defaultaccess" ) == 0 ) {
			if ( cargc < 2 ) {
				Debug( LDAP_DEBUG_ANY,
	    "%s: line %d: missing limit in \"defaultaccess <access>\" line\n",
				    fname, lineno, 0 );
				return( 1 );
			}
			if ( be == NULL ) {
				if ( ACL_IS_INVALID(ACL_SET(global_default_access,
						str2access(cargv[1]))) )
				{
					Debug( LDAP_DEBUG_ANY,
"%s: line %d: bad access \"%s\" expecting [self]{none|auth|compare|search|read|write}\n",
					    fname, lineno, cargv[1] );
					return( 1 );
				}
			} else {
				if ( ACL_IS_INVALID(ACL_SET(be->be_dfltaccess,
						str2access(cargv[1]))) )
				{
					Debug( LDAP_DEBUG_ANY,
						"%s: line %d: bad access \"%s\", "
						"expecting [self]{none|auth|compare|search|read|write}\n",
					    fname, lineno, cargv[1] );
					return( 1 );
				}
			}

		/* debug level to log things to syslog */
		} else if ( strcasecmp( cargv[0], "loglevel" ) == 0 ) {
			if ( cargc < 2 ) {
				Debug( LDAP_DEBUG_ANY,
		    "%s: line %d: missing level in \"loglevel <level>\" line\n",
				    fname, lineno, 0 );
				return( 1 );
			}
			ldap_syslog = atoi( cargv[1] );

		/* list of replicas of the data in this backend (master only) */
		} else if ( strcasecmp( cargv[0], "replica" ) == 0 ) {
			if ( cargc < 2 ) {
				Debug( LDAP_DEBUG_ANY,
	    "%s: line %d: missing host in \"replica <host[:port]>\" line\n",
				    fname, lineno, 0 );
				return( 1 );
			}
			if ( be == NULL ) {
				Debug( LDAP_DEBUG_ANY,
"%s: line %d: replica line must appear inside a database definition (ignored)\n",
				    fname, lineno, 0 );
			} else {
				for ( i = 1; i < cargc; i++ ) {
					if ( strncasecmp( cargv[i], "host=", 5 )
					    == 0 ) {
						charray_add( &be->be_replica,
							     cargv[i] + 5 );
						break;
					}
				}
				if ( i == cargc ) {
					Debug( LDAP_DEBUG_ANY,
		    "%s: line %d: missing host in \"replica\" line (ignored)\n",
					    fname, lineno, 0 );
				}
			}

		/* dn of master entity allowed to write to replica */
		} else if ( strcasecmp( cargv[0], "updatedn" ) == 0 ) {
			if ( cargc < 2 ) {
				Debug( LDAP_DEBUG_ANY,
		    "%s: line %d: missing dn in \"updatedn <dn>\" line\n",
				    fname, lineno, 0 );
				return( 1 );
			}
			if ( be == NULL ) {
				Debug( LDAP_DEBUG_ANY,
"%s: line %d: updatedn line must appear inside a database definition (ignored)\n",
				    fname, lineno, 0 );
			} else {
				be->be_update_ndn = ch_strdup( cargv[1] );
				if( dn_normalize_case( be->be_update_ndn ) == NULL ) {
					Debug( LDAP_DEBUG_ANY,
"%s: line %d: updatedn DN is invalid\n",
					    fname, lineno, 0 );
					return 1;
				}
			}

		} else if ( strcasecmp( cargv[0], "updateref" ) == 0 ) {
			if ( cargc < 2 ) {
				Debug( LDAP_DEBUG_ANY,
		    "%s: line %d: missing dn in \"updateref <ldapurl>\" line\n",
				    fname, lineno, 0 );
				return( 1 );
			}
			if ( be == NULL ) {
				Debug( LDAP_DEBUG_ANY,
"%s: line %d: updateref line must appear inside a database definition (ignored)\n",
				    fname, lineno, 0 );
			} else if ( be->be_update_ndn == NULL ) {
				Debug( LDAP_DEBUG_ANY,
"%s: line %d: updateref line must after updatedn (ignored)\n",
				    fname, lineno, 0 );
			} else {
				vals[0]->bv_val = cargv[1];
				vals[0]->bv_len = strlen( vals[0]->bv_val );
				value_add( &be->be_update_refs, vals );
			}

		/* replication log file to which changes are appended */
		} else if ( strcasecmp( cargv[0], "replogfile" ) == 0 ) {
			if ( cargc < 2 ) {
				Debug( LDAP_DEBUG_ANY,
	    "%s: line %d: missing dn in \"replogfile <filename>\" line\n",
				    fname, lineno, 0 );
				return( 1 );
			}
			if ( be ) {
				be->be_replogfile = ch_strdup( cargv[1] );
			} else {
				replogfile = ch_strdup( cargv[1] );
			}

		/* maintain lastmodified{by,time} attributes */
		} else if ( strcasecmp( cargv[0], "lastmod" ) == 0 ) {
			if ( cargc < 2 ) {
				Debug( LDAP_DEBUG_ANY,
	    "%s: line %d: missing on|off in \"lastmod <on|off>\" line\n",
				    fname, lineno, 0 );
				return( 1 );
			}
			if ( strcasecmp( cargv[1], "on" ) == 0 ) {
				if ( be )
					be->be_lastmod = ON;
				else
					global_lastmod = ON;
			} else {
				if ( be )
					be->be_lastmod = OFF;
				else
					global_lastmod = OFF;
			}

		/* set idle timeout value */
		} else if ( strcasecmp( cargv[0], "idletimeout" ) == 0 ) {
			int i;
			if ( cargc < 2 ) {
				Debug( LDAP_DEBUG_ANY,
	    "%s: line %d: missing timeout value in \"idletimeout <seconds>\" line\n",
				    fname, lineno, 0 );
				return( 1 );
			}

			i = atoi( cargv[1] );

			if( i < 0 ) {
				Debug( LDAP_DEBUG_ANY,
	    "%s: line %d: timeout value (%d) invalid \"idletimeout <seconds>\" line\n",
				    fname, lineno, i );
				return( 1 );
			}

			global_idletimeout = i;

		/* include another config file */
		} else if ( strcasecmp( cargv[0], "include" ) == 0 ) {
			if ( cargc < 2 ) {
				Debug( LDAP_DEBUG_ANY,
    "%s: line %d: missing filename in \"include <filename>\" line\n",
				    fname, lineno, 0 );
				return( 1 );
			}
			savefname = ch_strdup( cargv[1] );
			savelineno = lineno;

			if ( read_config( savefname ) != 0 ) {
				return( 1 );
			}

			free( savefname );
			lineno = savelineno - 1;

		/* location of kerberos srvtab file */
		} else if ( strcasecmp( cargv[0], "srvtab" ) == 0 ) {
			if ( cargc < 2 ) {
				Debug( LDAP_DEBUG_ANY,
	    "%s: line %d: missing filename in \"srvtab <filename>\" line\n",
				    fname, lineno, 0 );
				return( 1 );
			}
			ldap_srvtab = ch_strdup( cargv[1] );

#ifdef SLAPD_MODULES
                } else if (strcasecmp( cargv[0], "moduleload") == 0 ) {
                   if ( cargc < 2 ) {
                      Debug( LDAP_DEBUG_ANY,
                             "%s: line %d: missing filename in \"moduleload <filename>\" line\n",
                             fname, lineno, 0 );
                      exit( EXIT_FAILURE );
                   }
                   if (module_load(cargv[1], cargc - 2, (cargc > 2) ? cargv + 2 : NULL)) {
                      Debug( LDAP_DEBUG_ANY,
                             "%s: line %d: failed to load or initialize module %s\n",
                             fname, lineno, cargv[1]);
                      exit( EXIT_FAILURE );
                   }
                } else if (strcasecmp( cargv[0], "modulepath") == 0 ) {
                   if ( cargc != 2 ) {
                      Debug( LDAP_DEBUG_ANY,
                             "%s: line %d: missing path in \"modulepath <path>\" line\n",
                             fname, lineno, 0 );
                      exit( EXIT_FAILURE );
                   }
                   if (module_path( cargv[1] )) {
                      Debug( LDAP_DEBUG_ANY,
                             "%s: line %d: failed to set module search path to %s\n",
                             fname, lineno, cargv[1]);
                      exit( EXIT_FAILURE );
                   }
		   
#endif /*SLAPD_MODULES*/

#ifdef HAVE_TLS
		} else if ( !strcasecmp( cargv[0], "TLSProtocol" ) ) {
			rc = ldap_pvt_tls_set_option( NULL,
						      LDAP_OPT_X_TLS_PROTOCOL,
						      cargv[1] );
			if ( rc )
				return rc;

		} else if ( !strcasecmp( cargv[0], "TLSCipherSuite" ) ) {
			rc = ldap_pvt_tls_set_option( NULL,
						      LDAP_OPT_X_TLS_CIPHER_SUITE,
						      cargv[1] );
			if ( rc )
				return rc;

		} else if ( !strcasecmp( cargv[0], "TLSCertificateFile" ) ) {
			rc = ldap_pvt_tls_set_option( NULL,
						      LDAP_OPT_X_TLS_CERTFILE,
						      cargv[1] );
			if ( rc )
				return rc;

		} else if ( !strcasecmp( cargv[0], "TLSCertificateKeyFile" ) ) {
			rc = ldap_pvt_tls_set_option( NULL,
						      LDAP_OPT_X_TLS_KEYFILE,
						      cargv[1] );
			if ( rc )
				return rc;

		} else if ( !strcasecmp( cargv[0], "TLSCACertificatePath" ) ) {
			rc = ldap_pvt_tls_set_option( NULL,
						      LDAP_OPT_X_TLS_CACERTDIR,
						      cargv[1] );
			if ( rc )
				return rc;

		} else if ( !strcasecmp( cargv[0], "TLSCACertificateFile" ) ) {
			rc = ldap_pvt_tls_set_option( NULL,
						      LDAP_OPT_X_TLS_CACERTFILE,
						      cargv[1] );
			if ( rc )
				return rc;
		} else if ( !strcasecmp( cargv[0], "TLSVerifyClient" ) ) {
			rc = ldap_pvt_tls_set_option( NULL,
						      LDAP_OPT_X_TLS_REQUIRE_CERT,
						      cargv[1] );
			if ( rc )
				return rc;

#endif

		/* pass anything else to the current backend info/db config routine */
		} else {
			if ( bi != NULL ) {
				if ( bi->bi_config == 0 ) {
					Debug( LDAP_DEBUG_ANY,
"%s: line %d: unknown directive \"%s\" inside backend info definition (ignored)\n",
				   		fname, lineno, cargv[0] );
				} else {
					if ( (*bi->bi_config)( bi, fname, lineno, cargc, cargv )
						!= 0 )
					{
						return( 1 );
					}
				}
			} else if ( be != NULL ) {
				if ( be->be_config == 0 ) {
					Debug( LDAP_DEBUG_ANY,
"%s: line %d: unknown directive \"%s\" inside backend database definition (ignored)\n",
				    	fname, lineno, cargv[0] );
				} else {
					if ( (*be->be_config)( be, fname, lineno, cargc, cargv )
						!= 0 )
					{
						return( 1 );
					}
				}
			} else {
				Debug( LDAP_DEBUG_ANY,
"%s: line %d: unknown directive \"%s\" outside backend info and database definitions (ignored)\n",
				    fname, lineno, cargv[0] );
			}
		}
		free( saveline );
	}
	fclose( fp );
	return( 0 );
}

static int
fp_parse_line(
    char	*line,
    int		*argcp,
    char	**argv
)
{
	char *	token;

	*argcp = 0;
	for ( token = strtok_quote( line, " \t" ); token != NULL;
	    token = strtok_quote( NULL, " \t" ) ) {
		if ( *argcp == MAXARGS ) {
			Debug( LDAP_DEBUG_ANY, "Too many tokens (max %d)\n",
			    MAXARGS, 0, 0 );
			return( 1 );
		}
		argv[(*argcp)++] = token;
	}
	argv[*argcp] = NULL;
	return 0;
}

static char *
strtok_quote( char *line, char *sep )
{
	int		inquote;
	char		*tmp;
	static char	*next;

	if ( line != NULL ) {
		next = line;
	}
	while ( *next && strchr( sep, *next ) ) {
		next++;
	}

	if ( *next == '\0' ) {
		next = NULL;
		return( NULL );
	}
	tmp = next;

	for ( inquote = 0; *next; ) {
		switch ( *next ) {
		case '"':
			if ( inquote ) {
				inquote = 0;
			} else {
				inquote = 1;
			}
			SAFEMEMCPY( next, next + 1, strlen( next + 1 ) + 1 );
			break;

		case '\\':
			if ( next[1] )
				SAFEMEMCPY( next,
					    next + 1, strlen( next + 1 ) + 1 );
			next++;		/* dont parse the escaped character */
			break;

		default:
			if ( ! inquote ) {
				if ( strchr( sep, *next ) != NULL ) {
					*next++ = '\0';
					return( tmp );
				}
			}
			next++;
			break;
		}
	}

	return( tmp );
}

static char	buf[BUFSIZ];
static char	*line;
static int	lmax, lcur;

#define CATLINE( buf )	{ \
	int	len; \
	len = strlen( buf ); \
	while ( lcur + len + 1 > lmax ) { \
		lmax += BUFSIZ; \
		line = (char *) ch_realloc( line, lmax ); \
	} \
	strcpy( line + lcur, buf ); \
	lcur += len; \
}

static char *
fp_getline( FILE *fp, int *lineno )
{
	char		*p;

	lcur = 0;
	CATLINE( buf );
	(*lineno)++;

	/* hack attack - keeps us from having to keep a stack of bufs... */
	if ( strncasecmp( line, "include", 7 ) == 0 ) {
		buf[0] = '\0';
		return( line );
	}

	while ( fgets( buf, sizeof(buf), fp ) != NULL ) {
		if ( (p = strchr( buf, '\n' )) != NULL ) {
			*p = '\0';
		}
		if ( ! isspace( (unsigned char) buf[0] ) ) {
			return( line );
		}

		CATLINE( buf );
		(*lineno)++;
	}
	buf[0] = '\0';

	return( line[0] ? line : NULL );
}

static void
fp_getline_init( int *lineno )
{
	*lineno = -1;
	buf[0] = '\0';
}
