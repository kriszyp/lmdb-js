/* config.c - configuration file handling routines */
/* $OpenLDAP$ */
/*
 * Copyright 1998-2000 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "portable.h"

#include <stdio.h>

#include <ac/string.h>
#include <ac/ctype.h>
#include <ac/socket.h>

#include "lutil.h"
#include "ldap_pvt.h"
#include "slap.h"

#define MAXARGS	200

/*
 * defaults for various global variables
 */
int		defsize = SLAPD_DEFAULT_SIZELIMIT;
int		deftime = SLAPD_DEFAULT_TIMELIMIT;
AccessControl	*global_acl = NULL;
slap_access_t		global_default_access = ACL_READ;
slap_mask_t		global_restrictops = 0;
slap_mask_t		global_allows = 0;
slap_mask_t		global_disallows = 0;
slap_mask_t		global_requires = 0;
slap_ssf_set_t	global_ssf_set;
char		*replogfile;
int		global_lastmod = ON;
int		global_idletimeout = 0;
char	*global_host = NULL;
char	*global_realm = NULL;
char		*ldap_srvtab = "";
char		*default_passwd_hash;
char		*default_search_base = NULL;
char		*default_search_nbase = NULL;

char   *slapd_pid_file  = NULL;
char   *slapd_args_file = NULL;

int nSaslRegexp = 0;
SaslRegexp_t *SaslRegexp = NULL;
int sasl_external_x509dn_convert;

static char	*fp_getline(FILE *fp, int *lineno);
static void	fp_getline_init(int *lineno);
static int	fp_parse_line(char *line, int *argcp, char **argv);

static char	*strtok_quote(char *line, char *sep);
static int      load_ucdata(char *path);

int
read_config( const char *fname )
{
	FILE	*fp;
	char	*line, *savefname, *saveline;
	int	cargc, savelineno;
	char	*cargv[MAXARGS+1];
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

#ifdef NEW_LOGGING
	LDAP_LOG(( "config", LDAP_LEVEL_ENTRY,
		   "read_config: reading config file %s\n", fname ));
#else
	Debug( LDAP_DEBUG_CONFIG, "reading config file %s\n", fname, 0, 0 );
#endif


	fp_getline_init( &lineno );

	while ( (line = fp_getline( fp, &lineno )) != NULL ) {
		/* skip comments and blank lines */
		if ( line[0] == '#' || line[0] == '\0' ) {
			continue;
		}

#ifdef NEW_LOGGING
		LDAP_LOG(( "config", LDAP_LEVEL_DETAIL1,
			   "line %d (%s)\n", lineno, line ));
#else
		Debug( LDAP_DEBUG_CONFIG, "line %d (%s)\n", lineno, line, 0 );
#endif


		/* fp_parse_line is destructive, we save a copy */
		saveline = ch_strdup( line );

		if ( fp_parse_line( line, &cargc, cargv ) != 0 ) {
			return( 1 );
		}

		if ( cargc < 1 ) {
#ifdef NEW_LOGGING
			LDAP_LOG(( "config", LDAP_LEVEL_INFO,
				   "%s: line %d: bad config line (ignored)\n",
				   fname, lineno ));
#else
			Debug( LDAP_DEBUG_ANY,
			    "%s: line %d: bad config line (ignored)\n",
			    fname, lineno, 0 );
#endif

			continue;
		}

		if ( strcasecmp( cargv[0], "backend" ) == 0 ) {
			if ( cargc < 2 ) {
#ifdef NEW_LOGGING
				LDAP_LOG(( "config", LDAP_LEVEL_CRIT,
					   "%s : line %d: missing type in \"backend\" line.\n",
					   fname, lineno ));
#else
				Debug( LDAP_DEBUG_ANY,
		"%s: line %d: missing type in \"backend <type>\" line\n",
				    fname, lineno, 0 );
#endif

				return( 1 );
			}

			if( be != NULL ) {
#ifdef NEW_LOGGING
				LDAP_LOG(( "config", LDAP_LEVEL_CRIT,
					   "%s: line %d: backend line must appear before any "
					   "database definition.\n", fname, lineno ));
#else
				Debug( LDAP_DEBUG_ANY,
"%s: line %d: backend line must appear before any database definition\n",
				    fname, lineno, 0 );
#endif

				return( 1 );
			}

			bi = backend_info( cargv[1] );

			if( bi == NULL ) {
#ifdef NEW_LOGGING
				LDAP_LOG(( "config", LDAP_LEVEL_CRIT,
					   "read_config: backend %s initialization failed.\n",
					   cargv[1] ));
#else
				Debug( LDAP_DEBUG_ANY,
					"backend %s initialization failed.\n",
				    cargv[1], 0, 0 );
#endif

				return( 1 );
			}
		} else if ( strcasecmp( cargv[0], "database" ) == 0 ) {
			if ( cargc < 2 ) {
#ifdef NEW_LOGGING
				LDAP_LOG(( "config", LDAP_LEVEL_CRIT,
					   "%s: line %d: missing type in \"database <type>\" line\n",
					   fname, lineno ));
#else
				Debug( LDAP_DEBUG_ANY,
		"%s: line %d: missing type in \"database <type>\" line\n",
				    fname, lineno, 0 );
#endif

				return( 1 );
			}

			bi = NULL;
			be = backend_db_init( cargv[1] );

			if( be == NULL ) {
#ifdef NEW_LOGGING
				LDAP_LOG(( "config", LDAP_LEVEL_CRIT,
					   "database %s initialization failed.\n",
					   cargv[1] ));
#else
				Debug( LDAP_DEBUG_ANY,
					"database %s initialization failed.\n",
				    cargv[1], 0, 0 );
#endif

				return( 1 );
			}

		/* set thread concurrency */
		} else if ( strcasecmp( cargv[0], "concurrency" ) == 0 ) {
			int c;
			if ( cargc < 2 ) {
#ifdef NEW_LOGGING
				LDAP_LOG(( "config", LDAP_LEVEL_CRIT,
					   "%s: line %d: missing level in \"concurrency <level\" line\n",
					   fname, lineno ));
#else
				Debug( LDAP_DEBUG_ANY,
	    "%s: line %d: missing level in \"concurrency <level>\" line\n",
				    fname, lineno, 0 );
#endif

				return( 1 );
			}

			c = atoi( cargv[1] );

			if( c < 1 ) {
#ifdef NEW_LOGGING
				LDAP_LOG(( "config", LDAP_LEVEL_CRIT,
					   "%s: line %d: invalid level (%d) in "
					   "\"concurrency <level>\" line.\n",
					   fname, lineno, c ));
#else
				Debug( LDAP_DEBUG_ANY,
	    "%s: line %d: invalid level (%d) in \"concurrency <level>\" line\n",
				    fname, lineno, c );
#endif

				return( 1 );
			}

			ldap_pvt_thread_set_concurrency( c );

		/* default search base */
		} else if ( strcasecmp( cargv[0], "defaultSearchBase" ) == 0 ) {
			if ( cargc < 2 ) {
#ifdef NEW_LOGGING
				LDAP_LOG(( "config", LDAP_LEVEL_CRIT,
					   "%s: line %d: missing dn in \"defaultSearchBase <dn\" "
					   "line\n", fname, lineno ));
#else
				Debug( LDAP_DEBUG_ANY, "%s: line %d: "
					"missing dn in \"defaultSearchBase <dn>\" line\n",
					fname, lineno, 0 );
#endif

				return 1;

			} else if ( cargc > 2 ) {
#ifdef NEW_LOGGING
				LDAP_LOG(( "config", LDAP_LEVEL_INFO,
					   "%s: line %d: extra cruft after <dn> in "
					   "\"defaultSearchBase %s\" line (ignored)\n",
					   fname, lineno, cargv[1] ));
#else
				Debug( LDAP_DEBUG_ANY, "%s: line %d: "
					"extra cruft after <dn> in \"defaultSearchBase %s\", "
					"line (ignored)\n",
					fname, lineno, cargv[1] );
#endif

			}

			if ( bi != NULL || be != NULL ) {
#ifdef NEW_LOGGING
				LDAP_LOG(( "config", LDAP_LEVEL_CRIT,
					   "%s: line %d: defaultSearchBase line must appear "
					   "prior to any backend or database definitions\n",
					   fname, lineno ));
#else
				Debug( LDAP_DEBUG_ANY, "%s: line %d: "
					"defaultSearchBaase line must appear prior to "
					"any backend or database definition\n",
				    fname, lineno, 0 );
#endif

				return 1;
			}

			if ( default_search_nbase != NULL ) {
#ifdef NEW_LOGGING
				LDAP_LOG(( "config", LDAP_LEVEL_INFO,
					   "%s: line %d: default search base \"%s\" already defined "
					   "(discarding old)\n", fname, lineno, default_search_base ));
#else
				Debug( LDAP_DEBUG_ANY, "%s: line %d: "
					"default search base \"%s\" already defined "
					"(discarding old)\n",
					fname, lineno, default_search_base );
#endif

				free( default_search_base );
				free( default_search_nbase );
			}

			default_search_base = ch_strdup( cargv[1] );
			default_search_nbase = ch_strdup( cargv[1] );

			if ( load_ucdata( NULL ) < 0 ) {
				return( 1 );
			}
			if( dn_normalize( default_search_nbase ) == NULL ) {
#ifdef NEW_LOGGING
				LDAP_LOG(( "config", LDAP_LEVEL_CRIT,
					   "%s:  %d: invalid default search base \"%s\"\n",
					   fname, lineno, default_search_base ));
#else
				Debug( LDAP_DEBUG_ANY, "%s: line %d: "
					"invalid default search base \"%s\"\n",
					fname, lineno, default_search_base );
#endif

				return 1;
			}
	       
		/* set maximum threads in thread pool */
		} else if ( strcasecmp( cargv[0], "threads" ) == 0 ) {
			int c;
			if ( cargc < 2 ) {
#ifdef NEW_LOGGING
				LDAP_LOG(( "config", LDAP_LEVEL_CRIT,
					   "%s: line %d: missing count in \"threads <count>\" line\n",
					   fname, lineno ));
#else
				Debug( LDAP_DEBUG_ANY,
	    "%s: line %d: missing count in \"threads <count>\" line\n",
				    fname, lineno, 0 );
#endif

				return( 1 );
			}

			c = atoi( cargv[1] );

			if( c < 0 ) {
#ifdef NEW_LOGGING
				LDAP_LOG(( "config", LDAP_LEVEL_CRIT,
					   "%s: line %d: invalid level (%d) in \"threads <count>\""
					   "line\n",fname, lineno, c ));
#else
				Debug( LDAP_DEBUG_ANY,
	    "%s: line %d: invalid level (%d) in \"threads <count>\" line\n",
				    fname, lineno, c );
#endif

				return( 1 );
			}

			ldap_pvt_thread_pool_maxthreads( &connection_pool, c );

		/* get pid file name */
		} else if ( strcasecmp( cargv[0], "pidfile" ) == 0 ) {
			if ( cargc < 2 ) {
#ifdef NEW_LOGGING
				LDAP_LOG(( "config", LDAP_LEVEL_CRIT,
					   "%s: line %d missing file name in \"pidfile <file>\" line.\n",
					   fname, lineno ));
#else
				Debug( LDAP_DEBUG_ANY,
	    "%s: line %d: missing file name in \"pidfile <file>\" line\n",
				    fname, lineno, 0 );
#endif

				return( 1 );
			}

			slapd_pid_file = ch_strdup( cargv[1] );

		/* get args file name */
		} else if ( strcasecmp( cargv[0], "argsfile" ) == 0 ) {
			if ( cargc < 2 ) {
#ifdef NEW_LOGGING
				LDAP_LOG(( "config", LDAP_LEVEL_CRIT,
					   "%s: %d: missing file name in "
					   "\"argsfile <file>\" line.\n",
					   fname, lineno ));
#else
				Debug( LDAP_DEBUG_ANY,
	    "%s: line %d: missing file name in \"argsfile <file>\" line\n",
				    fname, lineno, 0 );
#endif

				return( 1 );
			}

			slapd_args_file = ch_strdup( cargv[1] );

		/* default password hash */
		} else if ( strcasecmp( cargv[0], "password-hash" ) == 0 ) {
			if ( cargc < 2 ) {
#ifdef NEW_LOGGING
				LDAP_LOG(( "config", LDAP_LEVEL_CRIT,
					   "%s: line %d: missing hash in "
					   "\"password-hash <hash>\" line.\n",
					   fname, lineno ));
#else
				Debug( LDAP_DEBUG_ANY,
	    "%s: line %d: missing hash in \"password-hash <hash>\" line\n",
				    fname, lineno, 0 );
#endif

				return( 1 );
			}
			if ( default_passwd_hash != NULL ) {
#ifdef NEW_LOGGING
				LDAP_LOG(( "config", LDAP_LEVEL_CRIT,
					   "%s: line %d: already set default password_hash!\n",
					   fname, lineno ));
#else
				Debug( LDAP_DEBUG_ANY,
					"%s: line %d: already set default password_hash!\n",
					fname, lineno, 0 );
#endif

				return 1;

			} else {
				default_passwd_hash = ch_strdup( cargv[1] );
			}

		/* set SASL host */
		} else if ( strcasecmp( cargv[0], "sasl-host" ) == 0 ) {
			if ( cargc < 2 ) {
#ifdef NEW_LOGGING
				LDAP_LOG(( "config", LDAP_LEVEL_CRIT,
					   "%s: line %d: missing host in \"sasl-host <host>\" line\n",
					   fname, lineno ));
#else
				Debug( LDAP_DEBUG_ANY,
	    "%s: line %d: missing host in \"sasl-host <host>\" line\n",
				    fname, lineno, 0 );
#endif

				return( 1 );
			}

			if ( global_host != NULL ) {
#ifdef NEW_LOGGING
				LDAP_LOG(( "config", LDAP_LEVEL_CRIT,
					   "%s: line %d: already set sasl-host!\n",
					   fname, lineno ));
#else
				Debug( LDAP_DEBUG_ANY,
					"%s: line %d: already set sasl-host!\n",
					fname, lineno, 0 );
#endif

				return 1;

			} else {
				global_host = ch_strdup( cargv[1] );
			}

		/* set SASL realm */
		} else if ( strcasecmp( cargv[0], "sasl-realm" ) == 0 ) {
			if ( cargc < 2 ) {
#ifdef NEW_LOGGING
				LDAP_LOG(( "config", LDAP_LEVEL_CRIT,
					   "%s: line %d: missing realm in \"sasl-realm <realm>\" line.\n",
					   fname, lineno ));
#else
				Debug( LDAP_DEBUG_ANY,
	    "%s: line %d: missing realm in \"sasl-realm <realm>\" line\n",
				    fname, lineno, 0 );
#endif

				return( 1 );
			}

			if ( global_realm != NULL ) {
#ifdef NEW_LOGGING
				LDAP_LOG(( "config", LDAP_LEVEL_CRIT,
					   "%s: line %d: already set sasl-realm!\n",
					   fname, lineno ));
#else
				Debug( LDAP_DEBUG_ANY,
					"%s: line %d: already set sasl-realm!\n",
					fname, lineno, 0 );
#endif

				return 1;

			} else {
				global_realm = ch_strdup( cargv[1] );
			}

		} else if ( !strcasecmp( cargv[0], "sasl-regexp" ) 
			|| !strcasecmp( cargv[0], "saslregexp" ) )
		{
			int rc;
			if ( cargc != 3 ) {
#ifdef NEW_LOGGING
				LDAP_LOG(( "config", LDAP_LEVEL_CRIT,
					   "%s: line %d: need 2 args in "
					   "\"saslregexp <match> <replace>\"\n",
					   fname, lineno ));
#else
				Debug( LDAP_DEBUG_ANY, 
				"%s: line %d: need 2 args in \"saslregexp <match> <replace>\"\n",
				    fname, lineno, 0 );
#endif

				return( 1 );
			}
			rc = slap_sasl_regexp_config( cargv[1], cargv[2] );
			if ( rc ) {
				return rc;
			}

		/* SASL security properties */
		} else if ( strcasecmp( cargv[0], "sasl-secprops" ) == 0 ) {
			char *txt;

			if ( cargc < 2 ) {
#ifdef NEW_LOGGING
				LDAP_LOG(( "config", LDAP_LEVEL_CRIT,
					   "%s: line %d: missing flags in "
					   "\"sasl-secprops <properties>\" line\n",
					   fname, lineno ));
#else
				Debug( LDAP_DEBUG_ANY,
	    "%s: line %d: missing flags in \"sasl-secprops <properties>\" line\n",
				    fname, lineno, 0 );
#endif

				return 1;
			}

			txt = slap_sasl_secprops( cargv[1] );
			if ( txt != NULL ) {
#ifdef NEW_LOGGING
				LDAP_LOG(( "config", LDAP_LEVEL_CRIT,
					   "%s: line %d sas-secprops: %s\n",
					   fname, lineno, txt ));
#else
				Debug( LDAP_DEBUG_ANY,
	    "%s: line %d: sasl-secprops: %s\n",
				    fname, lineno, txt );
#endif

				return 1;
			}

		} else if ( strcasecmp( cargv[0], "sasl-external-x509dn-convert" ) == 0 ) {
			sasl_external_x509dn_convert++;

		/* set UCDATA path */
		} else if ( strcasecmp( cargv[0], "ucdata-path" ) == 0 ) {
			int err;
			if ( cargc < 2 ) {
#ifdef NEW_LOGGING
				LDAP_LOG(( "config", LDAP_LEVEL_CRIT,
					   "%s: line %d: missing path in "
					   "\"ucdata-path <path>\" line.\n",
					   fname, lineno ));
#else
				Debug( LDAP_DEBUG_ANY,
	    "%s: line %d: missing path in \"ucdata-path <path>\" line\n",
				    fname, lineno, 0 );
#endif

				return( 1 );
			}

			err = load_ucdata( cargv[1] );
			if ( err <= 0 ) {
				if ( err == 0 ) {
#ifdef NEW_LOGGING
					LDAP_LOG(( "config", LDAP_LEVEL_CRIT,
						   "%s: line %d: ucdata already loaded, ucdata-path "
						   "must be set earlier in the file and/or be "
						   "specified only once!\n",
						   fname, lineno ));
#else
					Debug( LDAP_DEBUG_ANY,
					       "%s: line %d: ucdata already loaded, ucdata-path must be set earlier in the file and/or be specified only once!\n",
					       fname, lineno, 0 );
#endif

				}
				return( 1 );
			}

		/* set time limit */
		} else if ( strcasecmp( cargv[0], "sizelimit" ) == 0 ) {
			if ( cargc < 2 ) {
#ifdef NEW_LOGGING
				LDAP_LOG(( "config", LDAP_LEVEL_CRIT,
					   "%s: line %d: missing limit in \"sizelimit <limit>\" line.\n",
					   fname, lineno ));
#else
				Debug( LDAP_DEBUG_ANY,
	    "%s: line %d: missing limit in \"sizelimit <limit>\" line\n",
				    fname, lineno, 0 );
#endif

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
#ifdef NEW_LOGGING
				LDAP_LOG(( "config", LDAP_LEVEL_CRIT,
					   "%s: line %d missing limit in \"timelimit <limit>\" line.\n",
					   fname, lineno ));
#else
				Debug( LDAP_DEBUG_ANY,
	    "%s: line %d: missing limit in \"timelimit <limit>\" line\n",
				    fname, lineno, 0 );
#endif

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
#ifdef NEW_LOGGING
				LDAP_LOG(( "config", LDAP_LEVEL_CRIT,
					   "%s: line %d: missing dn in \"suffix <dn>\" line.\n",
					   fname, lineno ));
#else
				Debug( LDAP_DEBUG_ANY,
		    "%s: line %d: missing dn in \"suffix <dn>\" line\n",
				    fname, lineno, 0 );
#endif

				return( 1 );
			} else if ( cargc > 2 ) {
#ifdef NEW_LOGGING
				LDAP_LOG(( "config", LDAP_LEVEL_INFO,
					   "%s: line %d: extra cruft after <dn> in \"suffix %s\""
					   " line (ignored).\n", fname, lineno, cargv[1] ));
#else
				Debug( LDAP_DEBUG_ANY,
    "%s: line %d: extra cruft after <dn> in \"suffix %s\" line (ignored)\n",
				    fname, lineno, cargv[1] );
#endif

			}
			if ( be == NULL ) {
#ifdef NEW_LOGGING
				LDAP_LOG(( "config", LDAP_LEVEL_INFO,
					   "%s: line %d: suffix line must appear inside a database "
					   "definition (ignored).\n", fname, lineno ));
#else
				Debug( LDAP_DEBUG_ANY,
"%s: line %d: suffix line must appear inside a database definition (ignored)\n",
				    fname, lineno, 0 );
#endif

			} else if ( ( tmp_be = select_backend( cargv[1], 0 ) ) == be ) {
#ifdef NEW_LOGGING
				LDAP_LOG(( "config", LDAP_LEVEL_INFO,
					   "%s: line %d: suffix already served by this backend "
					   "(ignored)\n", fname, lineno ));
#else
				Debug( LDAP_DEBUG_ANY,
"%s: line %d: suffix already served by this backend (ignored)\n",
				    fname, lineno, 0 );
#endif

			} else if ( tmp_be  != NULL ) {
#ifdef NEW_LOGGING
				LDAP_LOG(( "config", LDAP_LEVEL_INFO,
					   "%s: line %d: suffix already served by a preceding "
					   "backend \"%s\" (ignored)\n", fname, lineno,
					   tmp_be->be_suffix[0] ));
#else
				Debug( LDAP_DEBUG_ANY,
"%s: line %d: suffix already served by a preceeding backend \"%s\" (ignored)\n",
				    fname, lineno, tmp_be->be_suffix[0] );
#endif

			} else {
				char *dn = ch_strdup( cargv[1] );
				if ( load_ucdata( NULL ) < 0 ) {
					return( 1 );
				}
				if( dn_validate( dn ) == NULL ) {
#ifdef NEW_LOGGING
					LDAP_LOG(( "config", LDAP_LEVEL_CRIT,
						   "%s: line %d: suffix DN invalid\"%s\"\n",
						   fname, lineno, cargv[1] ));
#else
					Debug( LDAP_DEBUG_ANY, "%s: line %d: "
						"suffix DN invalid \"%s\"\n",
				    	fname, lineno, cargv[1] );
#endif

					return 1;

				} else if( *dn == '\0' && default_search_nbase != NULL ) {
#ifdef NEW_LOGGING
					LDAP_LOG(( "config", LDAP_LEVEL_INFO,
						   "%s: line %d: suffix DN empty and default search "
						   "base provided \"%s\" (assuming okay).\n",
						   fname, lineno, default_search_base ));
#else
					Debug( LDAP_DEBUG_ANY, "%s: line %d: "
						"suffix DN empty and default "
						"search base provided \"%s\" (assuming okay)\n",
			    		fname, lineno, default_search_base );
#endif

				}
				charray_add( &be->be_suffix, dn );
				(void) ldap_pvt_str2upper( dn );
				charray_add( &be->be_nsuffix, dn );
				free( dn );
			}

		/* set database suffixAlias */
		} else if ( strcasecmp( cargv[0], "suffixAlias" ) == 0 ) {
			Backend *tmp_be;
			if ( cargc < 2 ) {
#ifdef NEW_LOGGING
				LDAP_LOG(( "config", LDAP_LEVEL_CRIT,
					   "%s: line %d: missing alias and aliased_dn in "
					   "\"suffixAlias <alias> <aliased_dn>\" line.\n",
					   fname, lineno ));
#else
				Debug( LDAP_DEBUG_ANY,
"%s: line %d: missing alias and aliased_dn in \"suffixAlias <alias> <aliased_dn>\" line\n",
					fname, lineno, 0 );
#endif

				return( 1 );
			} else if ( cargc < 3 ) {
#ifdef NEW_LOGGING
				LDAP_LOG(( "config", LDAP_LEVEL_CRIT,
					   "%s: line %d: missing aliased_dn in "
					   "\"suffixAlias <alias> <aliased_dn>\" line\n",
					   fname, lineno ));
#else
				Debug( LDAP_DEBUG_ANY,
"%s: line %d: missing aliased_dn in \"suffixAlias <alias> <aliased_dn>\" line\n",
				fname, lineno, 0 );
#endif

				return( 1 );
			} else if ( cargc > 3 ) {
#ifdef NEW_LOGGING
				LDAP_LOG(( "config", LDAP_LEVEL_CRIT,
					   "%s: line %d: extra cruft in suffixAlias line (ignored)\n",
					   fname, lineno ));
#else
				Debug( LDAP_DEBUG_ANY,
					"%s: line %d: extra cruft in suffixAlias line (ignored)\n",
				fname, lineno, 0 );
#endif

			}

			if ( be == NULL ) {
#ifdef NEW_LOGGING
				LDAP_LOG(( "config", LDAP_LEVEL_INFO,
					   "%s: line %d: suffixAlias line must appear inside a "
					   "database definition (ignored).\n", fname, lineno ));
#else
				Debug( LDAP_DEBUG_ANY,
					"%s: line %d: suffixAlias line"
					" must appear inside a database definition (ignored)\n",
					fname, lineno, 0 );
#endif

			} else if ( (tmp_be = select_backend( cargv[1], 0 )) != NULL ) {
#ifdef NEW_LOGGING
				LDAP_LOG(( "config", LDAP_LEVEL_INFO,
					   "%s: line %d: suffixAlias served by a preceeding "
					   "backend \"%s\" (ignored).\n", fname, lineno,
					   tmp_be->be_suffix[0] ));
#else
				Debug( LDAP_DEBUG_ANY,
					"%s: line %d: suffixAlias served by"
					"  a preceeding backend \"%s\" (ignored)\n",
					fname, lineno, tmp_be->be_suffix[0] );
#endif


			} else if ( (tmp_be = select_backend( cargv[2], 0 )) != NULL ) {
#ifdef NEW_LOGGING
				LDAP_LOG(( "config", LDAP_LEVEL_INFO,
					   "%s: line %d: suffixAlias derefs to a different backend "
					   "a preceeding backend \"%s\" (ignored)\n",
					   fname, lineno, tmp_be->be_suffix[0] ));
#else
				Debug( LDAP_DEBUG_ANY,
					"%s: line %d: suffixAlias derefs to differnet backend"
					"  a preceeding backend \"%s\" (ignored)\n",
					fname, lineno, tmp_be->be_suffix[0] );
#endif


			} else {
				char *alias, *aliased_dn;

				alias = ch_strdup( cargv[1] );
				if ( load_ucdata( NULL ) < 0 ) {
					return( 1 );
				}
				(void) dn_normalize( alias );

				aliased_dn = ch_strdup( cargv[2] );
				(void) dn_normalize( aliased_dn );

				charray_add( &be->be_suffixAlias, alias );
				charray_add( &be->be_suffixAlias, aliased_dn );

				free(alias);
				free(aliased_dn);
			}

               /* set max deref depth */
               } else if ( strcasecmp( cargv[0], "maxDerefDepth" ) == 0 ) {
					int i;
                       if ( cargc < 2 ) {
#ifdef NEW_LOGGING
			       LDAP_LOG(( "config", LDAP_LEVEL_CRIT,
					  "%s: line %d: missing depth in \"maxDerefDepth <depth>\""
					  " line\n", fname, lineno ));
#else
                               Debug( LDAP_DEBUG_ANY,
                   "%s: line %d: missing depth in \"maxDerefDepth <depth>\" line\n",
                                   fname, lineno, 0 );
#endif

                               return( 1 );
                       }
                       if ( be == NULL ) {
#ifdef NEW_LOGGING
			       LDAP_LOG(( "config", LDAP_LEVEL_INFO,
					  "%s: line %d: depth line must appear inside a database "
					  "definition (ignored)\n", fname, lineno ));
#else
                               Debug( LDAP_DEBUG_ANY,
"%s: line %d: depth line must appear inside a database definition (ignored)\n",
                                   fname, lineno, 0 );
#endif

                       } else if ((i = atoi(cargv[1])) < 0) {
#ifdef NEW_LOGGING
			       LDAP_LOG(( "config", LDAP_LEVEL_INFO,
					  "%s: line %d: depth must be positive (ignored).\n",
					  fname, lineno ));
#else
                               Debug( LDAP_DEBUG_ANY,
"%s: line %d: depth must be positive (ignored)\n",
                                   fname, lineno, 0 );
#endif


                       } else {
                           be->be_max_deref_depth = i;
					   }


		/* set magic "root" dn for this database */
		} else if ( strcasecmp( cargv[0], "rootdn" ) == 0 ) {
			if ( cargc < 2 ) {
#ifdef NEW_LOGGING
				LDAP_LOG(( "config", LDAP_LEVEL_INFO,
					   "%s: line %d: missing dn in \"rootdn <dn>\" line.\n",
					   fname, lineno ));
#else
				Debug( LDAP_DEBUG_ANY,
		    "%s: line %d: missing dn in \"rootdn <dn>\" line\n",
				    fname, lineno, 0 );
#endif

				return( 1 );
			}
			if ( be == NULL ) {
#ifdef NEW_LOGGING
				LDAP_LOG(( "config", LDAP_LEVEL_INFO,
					   "%s: line %d: rootdn line must appear inside a database "
					   "definition (ignored).\n", fname, lineno ));
#else
				Debug( LDAP_DEBUG_ANY,
"%s: line %d: rootdn line must appear inside a database definition (ignored)\n",
				    fname, lineno, 0 );
#endif

			} else {
				be->be_root_dn = ch_strdup( cargv[1] );
				be->be_root_ndn = ch_strdup( cargv[1] );

				if ( load_ucdata( NULL ) < 0 ) {
					return( 1 );
				}
				if( dn_normalize( be->be_root_ndn ) == NULL ) {
					free( be->be_root_dn );
					free( be->be_root_ndn );
#ifdef NEW_LOGGING
					LDAP_LOG(( "config", LDAP_LEVEL_CRIT,
						   "%s: line %d: rootdn DN is invalid.\n",
						   fname, lineno ));
#else
					Debug( LDAP_DEBUG_ANY,
"%s: line %d: rootdn DN is invalid\n",
					   fname, lineno, 0 );
#endif

					return( 1 );
				}
			}

		/* set super-secret magic database password */
		} else if ( strcasecmp( cargv[0], "rootpw" ) == 0 ) {
			if ( cargc < 2 ) {
#ifdef NEW_LOGGING
				LDAP_LOG(( "config", LDAP_LEVEL_CRIT,
					   "%s: line %d: missing passwd in \"rootpw <passwd>\""
					   " line\n", fname, lineno ));
#else
				Debug( LDAP_DEBUG_ANY,
	    "%s: line %d: missing passwd in \"rootpw <passwd>\" line\n",
				    fname, lineno, 0 );
#endif

				return( 1 );
			}
			if ( be == NULL ) {
#ifdef NEW_LOGGING
				LDAP_LOG(( "config", LDAP_LEVEL_INFO,
					   "%s: line %d: rootpw line must appear inside a database "
					   "definition (ignored)\n", fname, lineno ));
#else
				Debug( LDAP_DEBUG_ANY,
"%s: line %d: rootpw line must appear inside a database definition (ignored)\n",
				    fname, lineno, 0 );
#endif

			} else {
				be->be_root_pw.bv_val = ch_strdup( cargv[1] );
				be->be_root_pw.bv_len = strlen( be->be_root_pw.bv_val );
			}

		/* make this database read-only */
		} else if ( strcasecmp( cargv[0], "readonly" ) == 0 ) {
			if ( cargc < 2 ) {
#ifdef NEW_LOGGING
				LDAP_LOG(( "config", LDAP_LEVEL_CRIT,
					   "%s: line %d: missing on|off in \"readonly <on|off>\" line.\n",
					   fname, lineno ));
#else
				Debug( LDAP_DEBUG_ANY,
	    "%s: line %d: missing on|off in \"readonly <on|off>\" line\n",
				    fname, lineno, 0 );
#endif

				return( 1 );
			}
			if ( be == NULL ) {
				if ( strcasecmp( cargv[1], "on" ) == 0 ) {
					global_restrictops |= SLAP_RESTRICT_OP_WRITES;
				} else {
					global_restrictops &= ~SLAP_RESTRICT_OP_WRITES;
				}
			} else {
				if ( strcasecmp( cargv[1], "on" ) == 0 ) {
					be->be_restrictops |= SLAP_RESTRICT_OP_WRITES;
				} else {
					be->be_restrictops &= ~SLAP_RESTRICT_OP_WRITES;
				}
			}


		/* allow these features */
		} else if ( strcasecmp( cargv[0], "allows" ) == 0 ||
			strcasecmp( cargv[0], "allow" ) == 0 )
		{
			slap_mask_t	allows;

			if ( be != NULL ) {
#ifdef NEW_LOGGING
				LDAP_LOG(( "config", LDAP_LEVEL_INFO,
					   "%s: line %d: allow line must appear prior to "
					   "database definitions.\n", fname, lineno ));
#else
				Debug( LDAP_DEBUG_ANY,
"%s: line %d: allow line must appear prior to database definitions\n",
				    fname, lineno, 0 );
#endif

			}

			if ( cargc < 2 ) {
#ifdef NEW_LOGGING
				LDAP_LOG(( "config", LDAP_LEVEL_CRIT,
					   "%s: line %d: missing feature(s) in \"allow <features>\""
					   " line\n", fname, lineno ));
#else
				Debug( LDAP_DEBUG_ANY,
	    "%s: line %d: missing feature(s) in \"allow <features>\" line\n",
				    fname, lineno, 0 );
#endif

				return( 1 );
			}

			allows = 0;

			for( i=1; i < cargc; i++ ) {
				if( strcasecmp( cargv[i], "tls_2_anon" ) == 0 ) {
					allows |= SLAP_ALLOW_TLS_2_ANON;

				} else if( strcasecmp( cargv[i], "none" ) != 0 ) {
#ifdef NEW_LOGGING
					LDAP_LOG(( "config", LDAP_LEVEL_CRIT,
						   "%s: line %d: unknown feature %s in "
						   "\"allow <features>\" line.\n",
						   fname, lineno, cargv[1] ));
#else
					Debug( LDAP_DEBUG_ANY,
		    "%s: line %d: unknown feature %s in \"allow <features>\" line\n",
					    fname, lineno, cargv[i] );
#endif

					return( 1 );
				}
			}

			global_allows = allows;

		/* disallow these features */
		} else if ( strcasecmp( cargv[0], "disallows" ) == 0 ||
			strcasecmp( cargv[0], "disallow" ) == 0 )
		{
			slap_mask_t	disallows;

			if ( be != NULL ) {
#ifdef NEW_LOGGING
				LDAP_LOG(( "config", LDAP_LEVEL_INFO,
					   "%s: line %d: disallow line must appear prior to "
					   "database definitions.\n", fname, lineno ));
#else
				Debug( LDAP_DEBUG_ANY,
"%s: line %d: disallow line must appear prior to database definitions\n",
				    fname, lineno, 0 );
#endif

			}

			if ( cargc < 2 ) {
#ifdef NEW_LOGGING
				LDAP_LOG(( "config", LDAP_LEVEL_CRIT,
					   "%s: line %d: missing feature(s) in \"disallow <features>\""
					   " line.\n", fname, lineno ));
#else
				Debug( LDAP_DEBUG_ANY,
	    "%s: line %d: missing feature(s) in \"disallow <features>\" line\n",
				    fname, lineno, 0 );
#endif

				return( 1 );
			}

			disallows = 0;

			for( i=1; i < cargc; i++ ) {
				if( strcasecmp( cargv[i], "bind_v2" ) == 0 ) {
					disallows |= SLAP_DISALLOW_BIND_V2;

				} else if( strcasecmp( cargv[i], "bind_anon" ) == 0 ) {
					disallows |= SLAP_DISALLOW_BIND_ANON;

				} else if( strcasecmp( cargv[i], "bind_anon_cred" ) == 0 ) {
					disallows |= SLAP_DISALLOW_BIND_ANON_CRED;

				} else if( strcasecmp( cargv[i], "bind_anon_dn" ) == 0 ) {
					disallows |= SLAP_DISALLOW_BIND_ANON_DN;

				} else if( strcasecmp( cargv[i], "bind_simple" ) == 0 ) {
					disallows |= SLAP_DISALLOW_BIND_SIMPLE;

				} else if( strcasecmp( cargv[i], "bind_krbv4" ) == 0 ) {
					disallows |= SLAP_DISALLOW_BIND_KRBV4;

				} else if( strcasecmp( cargv[i], "tls_authc" ) == 0 ) {
					disallows |= SLAP_DISALLOW_TLS_AUTHC;

				} else if( strcasecmp( cargv[i], "none" ) != 0 ) {
#ifdef NEW_LOGGING
					LDAP_LOG(( "config", LDAP_LEVEL_CRIT,
						   "%s: line %d: unknownfeature %s in "
						   "\"disallow <features>\" line.\n",
						   fname, lineno ));
#else
					Debug( LDAP_DEBUG_ANY,
		    "%s: line %d: unknown feature %s in \"disallow <features>\" line\n",
					    fname, lineno, cargv[i] );
#endif

					return( 1 );
				}
			}

			global_disallows = disallows;

		/* require these features */
		} else if ( strcasecmp( cargv[0], "requires" ) == 0 ||
			strcasecmp( cargv[0], "require" ) == 0 )
		{
			slap_mask_t	requires;

			if ( cargc < 2 ) {
#ifdef NEW_LOGGING
				LDAP_LOG(( "config", LDAP_LEVEL_CRIT,
					   "%s: line %d: missing feature(s) in "
					   "\"require <features>\" line.\n", fname, lineno ));
#else
				Debug( LDAP_DEBUG_ANY,
	    "%s: line %d: missing feature(s) in \"require <features>\" line\n",
				    fname, lineno, 0 );
#endif

				return( 1 );
			}

			requires = 0;

			for( i=1; i < cargc; i++ ) {
				if( strcasecmp( cargv[i], "bind" ) == 0 ) {
					requires |= SLAP_REQUIRE_BIND;

				} else if( strcasecmp( cargv[i], "LDAPv3" ) == 0 ) {
					requires |= SLAP_REQUIRE_LDAP_V3;

				} else if( strcasecmp( cargv[i], "authc" ) == 0 ) {
					requires |= SLAP_REQUIRE_AUTHC;

				} else if( strcasecmp( cargv[i], "SASL" ) == 0 ) {
					requires |= SLAP_REQUIRE_SASL;

				} else if( strcasecmp( cargv[i], "strong" ) == 0 ) {
					requires |= SLAP_REQUIRE_STRONG;

				} else if( strcasecmp( cargv[i], "none" ) != 0 ) {
#ifdef NEW_LOGGING
					LDAP_LOG(( "config", LDAP_LEVEL_CRIT,
						   "%s: line %d: unknown feature %s in "
						   "\"require <features>\" line.\n",
						   fname, lineno ));
#else
					Debug( LDAP_DEBUG_ANY,
		    "%s: line %d: unknown feature %s in \"require <features>\" line\n",
					    fname, lineno, cargv[i] );
#endif

					return( 1 );
				}
			}

			if ( be == NULL ) {
				global_requires = requires;
			} else {
				be->be_requires = requires;
			}

		/* required security factors */
		} else if ( strcasecmp( cargv[0], "security" ) == 0 ) {
			slap_ssf_set_t *set;

			if ( cargc < 2 ) {
#ifdef NEW_LOGGING
				LDAP_LOG(( "config", LDAP_LEVEL_CRIT,
					   "%s: line %d: missing factor(s) in \"security <factors>\""
					   " line.\n", fname, lineno ));
#else
				Debug( LDAP_DEBUG_ANY,
	    "%s: line %d: missing factor(s) in \"security <factors>\" line\n",
				    fname, lineno, 0 );
#endif

				return( 1 );
			}

			if ( be == NULL ) {
				set = &global_ssf_set;
			} else {
				set = &be->be_ssf_set;
			}

			for( i=1; i < cargc; i++ ) {
				if( strncasecmp( cargv[i], "ssf=",
					sizeof("ssf") ) == 0 )
				{
					set->sss_ssf =
						atoi( &cargv[i][sizeof("ssf")] );

				} else if( strncasecmp( cargv[i], "transport=",
					sizeof("transport") ) == 0 )
				{
					set->sss_transport =
						atoi( &cargv[i][sizeof("transport")] );

				} else if( strncasecmp( cargv[i], "tls=",
					sizeof("tls") ) == 0 )
				{
					set->sss_tls =
						atoi( &cargv[i][sizeof("tls")] );

				} else if( strncasecmp( cargv[i], "sasl=",
					sizeof("sasl") ) == 0 )
				{
					set->sss_sasl =
						atoi( &cargv[i][sizeof("sasl")] );

				} else if( strncasecmp( cargv[i], "update_ssf=",
					sizeof("update_ssf") ) == 0 )
				{
					set->sss_update_ssf =
						atoi( &cargv[i][sizeof("update_ssf")] );

				} else if( strncasecmp( cargv[i], "update_transport=",
					sizeof("update_transport") ) == 0 )
				{
					set->sss_update_transport =
						atoi( &cargv[i][sizeof("update_transport")] );

				} else if( strncasecmp( cargv[i], "update_tls=",
					sizeof("update_tls") ) == 0 )
				{
					set->sss_update_tls =
						atoi( &cargv[i][sizeof("update_tls")] );

				} else if( strncasecmp( cargv[i], "update_sasl=",
					sizeof("update_sasl") ) == 0 )
				{
					set->sss_update_sasl =
						atoi( &cargv[i][sizeof("update_sasl")] );

				} else {
#ifdef NEW_LOGGING
					LDAP_LOG(( "config", LDAP_LEVEL_CRIT,
						   "%s: line %d: unknown factor %S in "
						   "\"security <factors>\" line.\n",
						   fname, lineno, cargv[1] ));
#else
					Debug( LDAP_DEBUG_ANY,
		    "%s: line %d: unknown factor %s in \"security <factors>\" line\n",
					    fname, lineno, cargv[i] );
#endif

					return( 1 );
				}
			}
		/* where to send clients when we don't hold it */
		} else if ( strcasecmp( cargv[0], "referral" ) == 0 ) {
			if ( cargc < 2 ) {
#ifdef NEW_LOGGING
				LDAP_LOG(( "config", LDAP_LEVEL_CRIT,
					   "%s: line %d: missing URL in \"referral <URL>\""
					   " line.\n", fname, lineno ));
#else
				Debug( LDAP_DEBUG_ANY,
		    "%s: line %d: missing URL in \"referral <URL>\" line\n",
				    fname, lineno, 0 );
#endif

				return( 1 );
			}

			vals[0]->bv_val = cargv[1];
			vals[0]->bv_len = strlen( vals[0]->bv_val );
			value_add( &default_referral, vals );

#ifdef NEW_LOGGING
                } else if ( strcasecmp( cargv[0], "logfile" ) == 0 ) {
                        FILE *logfile;
                        if ( cargc < 2 ) {
#ifdef NEW_LOGGING
				LDAP_LOG(( "config", LDAP_LEVEL_CRIT,
					   "%s: line %d: Error in logfile directive, "
					   "\"logfile <filename>\"\n", fname, lineno ));
#else
				Debug( LDAP_DEBUG_ANY,
				       "%s: line %d: Error in logfile directive, \"logfile filename\"\n",
				       fname, lineno, 0 );
#endif

				return( 1 );
                        }
                        logfile = fopen( cargv[1], "w" );
                        if ( logfile != NULL ) lutil_debug_file( logfile );

#endif
		/* start of a new database definition */
		} else if ( strcasecmp( cargv[0], "debug" ) == 0 ) {
                        int level;
			if ( cargc < 3 ) {
#ifdef NEW_LOGGING
				LDAP_LOG(( "config", LDAP_LEVEL_CRIT,
					   "%s: line %d: Error in debug directive, "
					   "\"debug <subsys> <level>\"\n", fname, lineno ));
#else
				Debug( LDAP_DEBUG_ANY,
					"%s: line %d: Error in debug directive, \"debug subsys level\"\n",
					fname, lineno, 0 );
#endif

				return( 1 );
			}
                        level = atoi( cargv[2] );
                        if ( level <= 0 ) level = lutil_mnem2level( cargv[2] );
                        lutil_set_debug_level( cargv[1], level );
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
#ifdef NEW_LOGGING
				LDAP_LOG(( "config", LDAP_LEVEL_INFO,
					   "%s: line %d: old objectclass format not supported\n",
					   fname, lineno ));
#else
				Debug( LDAP_DEBUG_ANY,
				       "%s: line %d: old objectclass format not supported.\n",
				       fname, lineno, 0 );
#endif

			}

		/* specify an attribute type */
		} else if (( strcasecmp( cargv[0], "attributetype" ) == 0 )
			|| ( strcasecmp( cargv[0], "attribute" ) == 0 ))
		{
			if ( *cargv[1] == '(' ) {
				char * p;
				p = strchr(saveline,'(');
				parse_at( fname, lineno, p, cargv );
			} else {
#ifdef NEW_LOGGING
				LDAP_LOG(( "config", LDAP_LEVEL_INFO,
					   "%s: line %d: old attribute type format not supported.\n",
					   fname, lineno ));
#else
				Debug( LDAP_DEBUG_ANY,
    "%s: line %d: old attribute type format not supported.\n",
				    fname, lineno, 0 );
#endif

			}

		/* turn on/off schema checking */
		} else if ( strcasecmp( cargv[0], "schemacheck" ) == 0 ) {
			if ( cargc < 2 ) {
#ifdef NEW_LOGGING
				LDAP_LOG(( "config", LDAP_LEVEL_CRIT,
					   "%s: line %d: missing on|off in "
					   "\"schemacheck <on|off>\" line.\n",
					   fname, lineno ));
#else
				Debug( LDAP_DEBUG_ANY,
    "%s: line %d: missing on|off in \"schemacheck <on|off>\" line\n",
				    fname, lineno, 0 );
#endif

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

		/* debug level to log things to syslog */
		} else if ( strcasecmp( cargv[0], "loglevel" ) == 0 ) {
			if ( cargc < 2 ) {
#ifdef NEW_LOGGING
				LDAP_LOG(( "config", LDAP_LEVEL_CRIT,
					   "%s: line %d: missing level in \"loglevel <level>\""
					   " line.\n", fname, lineno ));
#else
				Debug( LDAP_DEBUG_ANY,
		    "%s: line %d: missing level in \"loglevel <level>\" line\n",
				    fname, lineno, 0 );
#endif

				return( 1 );
			}

			ldap_syslog = 0;

			for( i=1; i < cargc; i++ ) {
				ldap_syslog += atoi( cargv[1] );
			}

		/* list of replicas of the data in this backend (master only) */
		} else if ( strcasecmp( cargv[0], "replica" ) == 0 ) {
			if ( cargc < 2 ) {
#ifdef NEW_LOGGING
				LDAP_LOG(( "config", LDAP_LEVEL_CRIT,
					   "%s: line %d: missing host in \"replica "
					   " <host[:port]\" line\n", fname, lineno ));
#else
				Debug( LDAP_DEBUG_ANY,
	    "%s: line %d: missing host in \"replica <host[:port]>\" line\n",
				    fname, lineno, 0 );
#endif

				return( 1 );
			}
			if ( be == NULL ) {
#ifdef NEW_LOGGING
				LDAP_LOG(( "config", LDAP_LEVEL_INFO,
					   "%s: line %d: replica line must appear inside "
					   "a database definition (ignored).\n", fname, lineno ));
#else
				Debug( LDAP_DEBUG_ANY,
"%s: line %d: replica line must appear inside a database definition (ignored)\n",
				    fname, lineno, 0 );
#endif

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
#ifdef NEW_LOGGING
					LDAP_LOG(( "config", LDAP_LEVEL_INFO,
						   "%s: line %d: missing host in \"replica\" "
						   "line (ignored)\n", fname, lineno ));
#else
					Debug( LDAP_DEBUG_ANY,
		    "%s: line %d: missing host in \"replica\" line (ignored)\n",
					    fname, lineno, 0 );
#endif

				}
			}

		/* dn of master entity allowed to write to replica */
		} else if ( strcasecmp( cargv[0], "updatedn" ) == 0 ) {
			if ( cargc < 2 ) {
#ifdef NEW_LOGGING
				LDAP_LOG(( "config", LDAP_LEVEL_CRIT,
					   "%s: line %d: missing dn in \"updatedn <dn>\""
					   " line.\n", fname, lineno ));
#else
				Debug( LDAP_DEBUG_ANY,
		    "%s: line %d: missing dn in \"updatedn <dn>\" line\n",
				    fname, lineno, 0 );
#endif

				return( 1 );
			}
			if ( be == NULL ) {
#ifdef NEW_LOGGING
				LDAP_LOG(( "config", LDAP_LEVEL_INFO,
					   "%s: line %d: updatedn line must appear inside "
					   "a database definition (ignored)\n",
					   fname, lineno ));
#else
				Debug( LDAP_DEBUG_ANY,
"%s: line %d: updatedn line must appear inside a database definition (ignored)\n",
				    fname, lineno, 0 );
#endif

			} else {
				be->be_update_ndn = ch_strdup( cargv[1] );
				if ( load_ucdata( NULL ) < 0 ) {
					return( 1 );
				}
				if( dn_normalize( be->be_update_ndn ) == NULL ) {
#ifdef NEW_LOGGING
					LDAP_LOG(( "config", LDAP_LEVEL_CRIT,
						   "%s: line %d: updatedn DN is invalid.\n",
						   fname, lineno ));
#else
					Debug( LDAP_DEBUG_ANY,
"%s: line %d: updatedn DN is invalid\n",
					    fname, lineno, 0 );
#endif

					return 1;
				}
			}

		} else if ( strcasecmp( cargv[0], "updateref" ) == 0 ) {
			if ( cargc < 2 ) {
#ifdef NEW_LOGGING
				LDAP_LOG(( "config", LDAP_LEVEL_CRIT,
					   "%s: line %d: missing dn in \"updateref <ldapurl>\" "
					   "line.\n", fname, lineno ));
#else
				Debug( LDAP_DEBUG_ANY,
		    "%s: line %d: missing dn in \"updateref <ldapurl>\" line\n",
				    fname, lineno, 0 );
#endif

				return( 1 );
			}
			if ( be == NULL ) {
#ifdef NEW_LOGGING
				LDAP_LOG(( "config", LDAP_LEVEL_INFO,
					   "%s: line %d: updateref line must appear inside "
					   "a database definition (ignored)\n", fname, lineno ));
#else
				Debug( LDAP_DEBUG_ANY,
"%s: line %d: updateref line must appear inside a database definition (ignored)\n",
				    fname, lineno, 0 );
#endif

			} else if ( be->be_update_ndn == NULL ) {
#ifdef NEW_LOGGING
				LDAP_LOG(( "config", LDAP_LEVEL_INFO,
					   "%s: line %d: updateref line must come after updatedn "
					   "(ignored).\n", fname, lineno ));
#else
				Debug( LDAP_DEBUG_ANY,
"%s: line %d: updateref line must after updatedn (ignored)\n",
				    fname, lineno, 0 );
#endif

			} else {
				vals[0]->bv_val = cargv[1];
				vals[0]->bv_len = strlen( vals[0]->bv_val );
				value_add( &be->be_update_refs, vals );
			}

		/* replication log file to which changes are appended */
		} else if ( strcasecmp( cargv[0], "replogfile" ) == 0 ) {
			if ( cargc < 2 ) {
#ifdef NEW_LOGGING
				LDAP_LOG(( "config", LDAP_LEVEL_CRIT,
					   "%s: line %d: missing filename in \"replogfile <filename>\""
					   " line.\n", fname, lineno ));
#else
				Debug( LDAP_DEBUG_ANY,
	    "%s: line %d: missing dn in \"replogfile <filename>\" line\n",
				    fname, lineno, 0 );
#endif

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
#ifdef NEW_LOGGING
				LDAP_LOG(( "config", LDAP_LEVEL_CRIT,
					   "%s: line %d: missing on|off in \"lastmod <on|off>\""
					   " line.\n", fname, lineno ));
#else
				Debug( LDAP_DEBUG_ANY,
	    "%s: line %d: missing on|off in \"lastmod <on|off>\" line\n",
				    fname, lineno, 0 );
#endif

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
#ifdef NEW_LOGGING
				LDAP_LOG(( "config", LDAP_LEVEL_CRIT,
					   "%s: line %d: missing timeout value in "
					   "\"idletimeout <seconds>\" line.\n", fname, lineno ));
#else
				Debug( LDAP_DEBUG_ANY,
	    "%s: line %d: missing timeout value in \"idletimeout <seconds>\" line\n",
				    fname, lineno, 0 );
#endif

				return( 1 );
			}

			i = atoi( cargv[1] );

			if( i < 0 ) {
#ifdef NEW_LOGGING
				LDAP_LOG(( "config", LDAP_LEVEL_CRIT,
					   "%s: line %d: timeout value (%d) invalid "
					   "\"idletimeout <seconds>\" line.\n",
					   fname, lineno, i ));
#else
				Debug( LDAP_DEBUG_ANY,
	    "%s: line %d: timeout value (%d) invalid \"idletimeout <seconds>\" line\n",
				    fname, lineno, i );
#endif

				return( 1 );
			}

			global_idletimeout = i;

		/* include another config file */
		} else if ( strcasecmp( cargv[0], "include" ) == 0 ) {
			if ( cargc < 2 ) {
#ifdef NEW_LOGGING
				LDAP_LOG(( "config", LDAP_LEVEL_CRIT,
					   "%s: line %d: missing filename in \"include "
					   "<filename>\" line.\n", fname, lineno ));
#else
				Debug( LDAP_DEBUG_ANY,
    "%s: line %d: missing filename in \"include <filename>\" line\n",
				    fname, lineno, 0 );
#endif

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
#ifdef NEW_LOGGING
				LDAP_LOG(( "config", LDAP_LEVEL_CRIT,
					   "%s: line %d: missing filename in \"srvtab "
					   "<filename>\" line.\n", fname, lineno ));
#else
				Debug( LDAP_DEBUG_ANY,
	    "%s: line %d: missing filename in \"srvtab <filename>\" line\n",
				    fname, lineno, 0 );
#endif

				return( 1 );
			}
			ldap_srvtab = ch_strdup( cargv[1] );

#ifdef SLAPD_MODULES
                } else if (strcasecmp( cargv[0], "moduleload") == 0 ) {
                   if ( cargc < 2 ) {
#ifdef NEW_LOGGING
			   LDAP_LOG(( "config", LDAP_LEVEL_INFO,
				      "%s: line %d: missing filename in \"moduleload "
				      "<filename>\" line.\n", fname, lineno ));
#else
                      Debug( LDAP_DEBUG_ANY,
                             "%s: line %d: missing filename in \"moduleload <filename>\" line\n",
                             fname, lineno, 0 );
#endif

                      exit( EXIT_FAILURE );
                   }
                   if (module_load(cargv[1], cargc - 2, (cargc > 2) ? cargv + 2 : NULL)) {
#ifdef NEW_LOGGING
			   LDAP_LOG(( "config", LDAP_LEVEL_CRIT,
				      "%s: line %d: failed to load or initialize module %s\n"<
				      fname, lineno, cargv[1] ));
#else
                      Debug( LDAP_DEBUG_ANY,
                             "%s: line %d: failed to load or initialize module %s\n",
                             fname, lineno, cargv[1]);
#endif

                      exit( EXIT_FAILURE );
                   }
                } else if (strcasecmp( cargv[0], "modulepath") == 0 ) {
                   if ( cargc != 2 ) {
#ifdef NEW_LOGGING
			   LDAP_LOG(( "config", LDAP_LEVEL_INFO,
				      "%s: line %d: missing path in \"modulepath <path>\""
				      " line\n", fname, lineno ));
#else
                      Debug( LDAP_DEBUG_ANY,
                             "%s: line %d: missing path in \"modulepath <path>\" line\n",
                             fname, lineno, 0 );
#endif

                      exit( EXIT_FAILURE );
                   }
                   if (module_path( cargv[1] )) {
#ifdef NEW_LOGGING
			   LDAP_LOG(( "cofig", LDAP_LEVEL_CRIT,
				      "%s: line %d: failed to set module search path to %s.\n",
				      fname, lineno, cargv[1] ));
#else
			   Debug( LDAP_DEBUG_ANY,
				  "%s: line %d: failed to set module search path to %s\n",
				  fname, lineno, cargv[1]);
#endif

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
			i = atoi(cargv[1]);
			rc = ldap_pvt_tls_set_option( NULL,
						      LDAP_OPT_X_TLS_REQUIRE_CERT,
						      &i );
			if ( rc )
				return rc;

#endif

		/* pass anything else to the current backend info/db config routine */
		} else {
			if ( bi != NULL ) {
				if ( bi->bi_config == 0 ) {
#ifdef NEW_LOGGING
					LDAP_LOG(( "config", LDAP_LEVEL_INFO,
						   "%s: line %d: unknown directive \"%s\" inside "
						   "backend info definition (ignored).\n",
						   fname, lineno, cargv[0] ));
#else
					Debug( LDAP_DEBUG_ANY,
"%s: line %d: unknown directive \"%s\" inside backend info definition (ignored)\n",
				   		fname, lineno, cargv[0] );
#endif

				} else {
					if ( (*bi->bi_config)( bi, fname, lineno, cargc, cargv )
						!= 0 )
					{
						return( 1 );
					}
				}
			} else if ( be != NULL ) {
				if ( be->be_config == 0 ) {
#ifdef NEW_LOGGING
					LDAP_LOG(( "config", LDAP_LEVEL_INFO,
						   "%s: line %d: uknown directive \"%s\" inside "
						   "backend database definition (ignored).\n",
						   fname, lineno, cargv[0] ));
#else
					Debug( LDAP_DEBUG_ANY,
"%s: line %d: unknown directive \"%s\" inside backend database definition (ignored)\n",
				    	fname, lineno, cargv[0] );
#endif

				} else {
					if ( (*be->be_config)( be, fname, lineno, cargc, cargv )
						!= 0 )
					{
						return( 1 );
					}
				}
			} else {
#ifdef NEW_LOGGING
				LDAP_LOG(( "config", LDAP_LEVEL_INFO,
					   "%s: line %d: unknown directive \"%s\" outside backend "
					   "info and database definitions (ignored).\n",
					   fname, lineno, cargv[0] ));
#else
				Debug( LDAP_DEBUG_ANY,
"%s: line %d: unknown directive \"%s\" outside backend info and database definitions (ignored)\n",
				    fname, lineno, cargv[0] );
#endif

			}
		}
		free( saveline );
	}
	fclose( fp );
	if ( load_ucdata( NULL ) < 0 ) {
		return( 1 );
	}
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
#ifdef NEW_LOGGING
			LDAP_LOG(( "config", LDAP_LEVEL_CRIT,
				   "fp_parse_line: too many tokens (%d max).\n",
				   MAXARGS ));
#else
			Debug( LDAP_DEBUG_ANY, "Too many tokens (max %d)\n",
			    MAXARGS, 0, 0 );
#endif

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
			AC_MEMCPY( next, next + 1, strlen( next + 1 ) + 1 );
			break;

		case '\\':
			if ( next[1] )
				AC_MEMCPY( next,
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

/* Loads ucdata, returns 1 if loading, 0 if already loaded, -1 on error */
static int
load_ucdata( char *path )
{
	static int loaded = 0;
	int err;
	
	if ( loaded ) {
		return( 0 );
	}
	err = ucdata_load( path ? path : SLAPD_DEFAULT_UCDATA,
			   UCDATA_CASE|UCDATA_CTYPE|UCDATA_NUM|UCDATA_COMP );
	if ( err ) {
#ifdef NEW_LOGGING
		LDAP_LOG(( "config", LDAP_LEVEL_CRIT,
			   "load_ucdata: Error %d loading ucdata.\n", err ));
#else
		Debug( LDAP_DEBUG_ANY, "error loading ucdata (error %d)\n",
		       err, 0, 0 );
#endif

		return( -1 );
	}
	loaded = 1;
	return( 1 );
}
