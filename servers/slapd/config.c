/* config.c - configuration file handling routines */
/* $OpenLDAP$ */
/*
 * Copyright 1998-2003 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "portable.h"

#include <stdio.h>

#include <ac/string.h>
#include <ac/ctype.h>
#include <ac/signal.h>
#include <ac/socket.h>
#include <ac/errno.h>

#include "ldap_pvt.h"
#include "slap.h"
#ifdef LDAP_SLAPI
#include "slapi.h"
#endif
#include "lutil.h"

#define ARGS_STEP	512

/*
 * defaults for various global variables
 */
struct slap_limits_set deflimit = {
	SLAPD_DEFAULT_TIMELIMIT,	/* backward compatible limits */
	0,

	SLAPD_DEFAULT_SIZELIMIT,	/* backward compatible limits */
	0,
	-1,				/* no limit on unchecked size */
	0,				/* page limit */
	0				/* hide number of entries left */
};

AccessControl	*global_acl = NULL;
slap_access_t		global_default_access = ACL_READ;
slap_mask_t		global_restrictops = 0;
slap_mask_t		global_allows = 0;
slap_mask_t		global_disallows = 0;
slap_mask_t		global_requires = 0;
slap_ssf_set_t	global_ssf_set;
char		*replogfile;
int		global_gentlehup = 0;
int		global_idletimeout = 0;
char	*global_host = NULL;
char	*global_realm = NULL;
char		*ldap_srvtab = "";
char		*default_passwd_hash = NULL;
int		cargc = 0, cargv_size = 0;
char	**cargv;
struct berval default_search_base = { 0, NULL };
struct berval default_search_nbase = { 0, NULL };
unsigned		num_subordinates = 0;
struct berval global_schemadn = { 0, NULL };
struct berval global_schemandn = { 0, NULL };

ber_len_t sockbuf_max_incoming = SLAP_SB_MAX_INCOMING_DEFAULT;
ber_len_t sockbuf_max_incoming_auth= SLAP_SB_MAX_INCOMING_AUTH;

int	slap_conn_max_pending = SLAP_CONN_MAX_PENDING_DEFAULT;
int	slap_conn_max_pending_auth = SLAP_CONN_MAX_PENDING_AUTH;

char   *slapd_pid_file  = NULL;
char   *slapd_args_file = NULL;

char   *strtok_quote_ptr;

int use_reverse_lookup = 0;

#ifdef LDAP_SLAPI
int slapi_plugins_used = 0;
#endif

static char	*fp_getline(FILE *fp, int *lineno);
static void	fp_getline_init(int *lineno);
static int	fp_parse_line(int lineno, char *line);

static char	*strtok_quote(char *line, char *sep);
static int      load_ucdata(char *path);

static int     add_syncrepl LDAP_P(( Backend *, char **, int ));
static int      parse_syncrepl_line LDAP_P(( char **, int, syncinfo_t *));

int
read_config( const char *fname, int depth )
{
	FILE	*fp;
	char	*line, *savefname, *saveline;
	int savelineno;
	int	lineno, i;
	int rc;
	struct berval vals[2];
	char *replicahost;
	LDAPURLDesc *ludp;
	static int lastmod = 1;
	static BackendInfo *bi = NULL;
	static BackendDB	*be = NULL;

	vals[1].bv_val = NULL;

	if ( depth == 0 ) {
		cargv = ch_calloc( ARGS_STEP + 1, sizeof(*cargv) );
		cargv_size = ARGS_STEP + 1;
	}

	if ( (fp = fopen( fname, "r" )) == NULL ) {
		ldap_syslog = 1;
#ifdef NEW_LOGGING
		LDAP_LOG( CONFIG, ENTRY, 
			"read_config: " "could not open config file \"%s\": %s (%d)\n",
		    fname, strerror(errno), errno );
#else
		Debug( LDAP_DEBUG_ANY,
		    "could not open config file \"%s\": %s (%d)\n",
		    fname, strerror(errno), errno );
#endif
		return 1;
	}

#ifdef NEW_LOGGING
	LDAP_LOG( CONFIG, ENTRY, 
		"read_config: reading config file %s\n", fname, 0, 0 );
#else
	Debug( LDAP_DEBUG_CONFIG, "reading config file %s\n", fname, 0, 0 );
#endif


	fp_getline_init( &lineno );

	while ( (line = fp_getline( fp, &lineno )) != NULL ) {
		/* skip comments and blank lines */
		if ( line[0] == '#' || line[0] == '\0' ) {
			continue;
		}

		/* fp_parse_line is destructive, we save a copy */
		saveline = ch_strdup( line );

		if ( fp_parse_line( lineno, line ) != 0 ) {
			return( 1 );
		}

		if ( cargc < 1 ) {
#ifdef NEW_LOGGING
			LDAP_LOG( CONFIG, INFO, 
				"%s: line %d: bad config line (ignored)\n", fname, lineno, 0 );
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
				LDAP_LOG( CONFIG, CRIT, 
					   "%s : line %d: missing type in \"backend\" line.\n",
					   fname, lineno, 0 );
#else
				Debug( LDAP_DEBUG_ANY,
		"%s: line %d: missing type in \"backend <type>\" line\n",
				    fname, lineno, 0 );
#endif

				return( 1 );
			}

			if( be != NULL ) {
#ifdef NEW_LOGGING
				LDAP_LOG( CONFIG, CRIT, 
					   "%s: line %d: backend line must appear before any "
					   "database definition.\n", fname, lineno , 0 );
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
				LDAP_LOG( CONFIG, CRIT, 
					   "read_config: backend %s initialization failed.\n",
					   cargv[1], 0, 0 );
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
				LDAP_LOG( CONFIG, CRIT, 
					"%s: line %d: missing type in \"database <type>\" line\n",
					fname, lineno, 0 );
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
				LDAP_LOG( CONFIG, CRIT, 
					"database %s initialization failed.\n", cargv[1], 0, 0 );
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
				LDAP_LOG( CONFIG, CRIT, 
					"%s: line %d: missing level in \"concurrency <level\" "
					" line\n", fname, lineno, 0 );
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
				LDAP_LOG( CONFIG, CRIT, 
					"%s: line %d: invalid level (%d) in "
					"\"concurrency <level>\" line.\n", fname, lineno, c );
#else
				Debug( LDAP_DEBUG_ANY,
	    "%s: line %d: invalid level (%d) in \"concurrency <level>\" line\n",
				    fname, lineno, c );
#endif

				return( 1 );
			}

			ldap_pvt_thread_set_concurrency( c );

		/* set sockbuf max */
		} else if ( strcasecmp( cargv[0], "sockbuf_max_incoming" ) == 0 ) {
			long max;
			if ( cargc < 2 ) {
#ifdef NEW_LOGGING
				LDAP_LOG( CONFIG, CRIT, 
				   "%s: line %d: missing max in \"sockbuf_max_incoming "
				   "<bytes>\" line\n", fname, lineno, 0 );
#else
				Debug( LDAP_DEBUG_ANY,
					   "%s: line %d: missing max in \"sockbuf_max_incoming <bytes>\" line\n",
				    fname, lineno, 0 );
#endif

				return( 1 );
			}

			max = atol( cargv[1] );

			if( max < 0 ) {
#ifdef NEW_LOGGING
				LDAP_LOG( CONFIG, CRIT, 
					   "%s: line %d: invalid max value (%ld) in "
					   "\"sockbuf_max_incoming <bytes>\" line.\n",
					   fname, lineno, max );
#else
				Debug( LDAP_DEBUG_ANY,
					"%s: line %d: invalid max value (%ld) in "
					"\"sockbuf_max_incoming <bytes>\" line.\n",
				    fname, lineno, max );
#endif

				return( 1 );
			}

			sockbuf_max_incoming = max;

		/* set sockbuf max authenticated */
		} else if ( strcasecmp( cargv[0], "sockbuf_max_incoming_auth" ) == 0 ) {
			long max;
			if ( cargc < 2 ) {
#ifdef NEW_LOGGING
				LDAP_LOG( CONFIG, CRIT, 
				   "%s: line %d: missing max in \"sockbuf_max_incoming_auth "
				   "<bytes>\" line\n", fname, lineno, 0 );
#else
				Debug( LDAP_DEBUG_ANY,
					   "%s: line %d: missing max in \"sockbuf_max_incoming_auth <bytes>\" line\n",
				    fname, lineno, 0 );
#endif

				return( 1 );
			}

			max = atol( cargv[1] );

			if( max < 0 ) {
#ifdef NEW_LOGGING
				LDAP_LOG( CONFIG, CRIT, 
					   "%s: line %d: invalid max value (%ld) in "
					   "\"sockbuf_max_incoming_auth <bytes>\" line.\n",
					   fname, lineno, max );
#else
				Debug( LDAP_DEBUG_ANY,
					"%s: line %d: invalid max value (%ld) in "
					"\"sockbuf_max_incoming_auth <bytes>\" line.\n",
				    fname, lineno, max );
#endif

				return( 1 );
			}

			sockbuf_max_incoming_auth = max;

		/* set conn pending max */
		} else if ( strcasecmp( cargv[0], "conn_max_pending" ) == 0 ) {
			long max;
			if ( cargc < 2 ) {
#ifdef NEW_LOGGING
				LDAP_LOG( CONFIG, CRIT, 
				   "%s: line %d: missing max in \"conn_max_pending "
				   "<requests>\" line\n", fname, lineno, 0 );
#else
				Debug( LDAP_DEBUG_ANY,
					   "%s: line %d: missing max in \"conn_max_pending <requests>\" line\n",
				    fname, lineno, 0 );
#endif

				return( 1 );
			}

			max = atol( cargv[1] );

			if( max < 0 ) {
#ifdef NEW_LOGGING
				LDAP_LOG( CONFIG, CRIT, 
					   "%s: line %d: invalid max value (%ld) in "
					   "\"conn_max_pending <requests>\" line.\n",
					   fname, lineno, max );
#else
				Debug( LDAP_DEBUG_ANY,
					"%s: line %d: invalid max value (%ld) in "
					"\"conn_max_pending <requests>\" line.\n",
				    fname, lineno, max );
#endif

				return( 1 );
			}

			slap_conn_max_pending = max;

		/* set conn pending max authenticated */
		} else if ( strcasecmp( cargv[0], "conn_max_pending_auth" ) == 0 ) {
			long max;
			if ( cargc < 2 ) {
#ifdef NEW_LOGGING
				LDAP_LOG( CONFIG, CRIT, 
				   "%s: line %d: missing max in \"conn_max_pending_auth "
				   "<requests>\" line\n", fname, lineno, 0 );
#else
				Debug( LDAP_DEBUG_ANY,
					   "%s: line %d: missing max in \"conn_max_pending_auth <requests>\" line\n",
				    fname, lineno, 0 );
#endif

				return( 1 );
			}

			max = atol( cargv[1] );

			if( max < 0 ) {
#ifdef NEW_LOGGING
				LDAP_LOG( CONFIG, CRIT, 
					   "%s: line %d: invalid max value (%ld) in "
					   "\"conn_max_pending_auth <requests>\" line.\n",
					   fname, lineno, max );
#else
				Debug( LDAP_DEBUG_ANY,
					"%s: line %d: invalid max value (%ld) in "
					"\"conn_max_pending_auth <requests>\" line.\n",
				    fname, lineno, max );
#endif

				return( 1 );
			}

			slap_conn_max_pending_auth = max;

		/* default search base */
		} else if ( strcasecmp( cargv[0], "defaultSearchBase" ) == 0 ) {
			if ( cargc < 2 ) {
#ifdef NEW_LOGGING
				LDAP_LOG( CONFIG, CRIT, 
					"%s: line %d: missing dn in \"defaultSearchBase <dn\" "
					"line\n", fname, lineno, 0 );
#else
				Debug( LDAP_DEBUG_ANY, "%s: line %d: "
					"missing dn in \"defaultSearchBase <dn>\" line\n",
					fname, lineno, 0 );
#endif

				return 1;

			} else if ( cargc > 2 ) {
#ifdef NEW_LOGGING
				LDAP_LOG( CONFIG, INFO, 
					"%s: line %d: extra cruft after <dn> in "
					"\"defaultSearchBase %s\" line (ignored)\n",
					fname, lineno, cargv[1] );
#else
				Debug( LDAP_DEBUG_ANY, "%s: line %d: "
					"extra cruft after <dn> in \"defaultSearchBase %s\", "
					"line (ignored)\n",
					fname, lineno, cargv[1] );
#endif
			}

			if ( bi != NULL || be != NULL ) {
#ifdef NEW_LOGGING
				LDAP_LOG( CONFIG, CRIT, 
					"%s: line %d: defaultSearchBase line must appear "
					"prior to any backend or database definitions\n",
					fname, lineno, 0 );
#else
				Debug( LDAP_DEBUG_ANY, "%s: line %d: "
					"defaultSearchBaase line must appear prior to "
					"any backend or database definition\n",
				    fname, lineno, 0 );
#endif

				return 1;
			}

			if ( default_search_nbase.bv_len ) {
#ifdef NEW_LOGGING
				LDAP_LOG( CONFIG, INFO, "%s: line %d: "
					"default search base \"%s\" already defined "
					"(discarding old)\n", fname, lineno,
					default_search_base.bv_val );
#else
				Debug( LDAP_DEBUG_ANY, "%s: line %d: "
					"default search base \"%s\" already defined "
					"(discarding old)\n",
					fname, lineno, default_search_base.bv_val );
#endif

				free( default_search_base.bv_val );
				free( default_search_nbase.bv_val );
			}

			if ( load_ucdata( NULL ) < 0 ) return 1;

			{
				struct berval dn;

				dn.bv_val = cargv[1];
				dn.bv_len = strlen( dn.bv_val );

				rc = dnPrettyNormal( NULL, &dn,
					&default_search_base,
					&default_search_nbase, NULL );

				if( rc != LDAP_SUCCESS ) {
#ifdef NEW_LOGGING
					LDAP_LOG( CONFIG, CRIT, 
						"%s: line %d: defaultSearchBase DN is invalid.\n",
						fname, lineno, 0 );
#else
					Debug( LDAP_DEBUG_ANY,
						"%s: line %d: defaultSearchBase DN is invalid\n",
					   fname, lineno, 0 );
#endif
					return( 1 );
				}
			}

		/* set maximum threads in thread pool */
		} else if ( strcasecmp( cargv[0], "threads" ) == 0 ) {
			int c;
			if ( cargc < 2 ) {
#ifdef NEW_LOGGING
				LDAP_LOG( CONFIG, CRIT, 
					"%s: line %d: missing count in \"threads <count>\" line\n",
					fname, lineno, 0 );
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
				LDAP_LOG( CONFIG, CRIT, 
					   "%s: line %d: invalid level (%d) in \"threads <count>\""
					   "line\n", fname, lineno, c );
#else
				Debug( LDAP_DEBUG_ANY,
	    "%s: line %d: invalid level (%d) in \"threads <count>\" line\n",
				    fname, lineno, c );
#endif

				return( 1 );
			}

			ldap_pvt_thread_pool_maxthreads( &connection_pool, c );

			/* save for later use */
			connection_pool_max = c;

		/* get pid file name */
		} else if ( strcasecmp( cargv[0], "pidfile" ) == 0 ) {
			if ( cargc < 2 ) {
#ifdef NEW_LOGGING
				LDAP_LOG( CONFIG, CRIT, 
					"%s: line %d missing file name in \"pidfile <file>\" "
					"line.\n", fname, lineno, 0 );
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
				LDAP_LOG( CONFIG, CRIT, 
					   "%s: %d: missing file name in "
					   "\"argsfile <file>\" line.\n",
					   fname, lineno, 0 );
#else
				Debug( LDAP_DEBUG_ANY,
	    "%s: line %d: missing file name in \"argsfile <file>\" line\n",
				    fname, lineno, 0 );
#endif

				return( 1 );
			}

			slapd_args_file = ch_strdup( cargv[1] );

		} else if ( strcasecmp( cargv[0], "replica-pidfile" ) == 0 ) {
			/* ignore */ ;

		} else if ( strcasecmp( cargv[0], "replica-argsfile" ) == 0 ) {
			/* ignore */ ;

		/* default password hash */
		} else if ( strcasecmp( cargv[0], "password-hash" ) == 0 ) {
			if ( cargc < 2 ) {
#ifdef NEW_LOGGING
				LDAP_LOG( CONFIG, CRIT, 
					   "%s: line %d: missing hash in "
					   "\"password-hash <hash>\" line.\n",
					   fname, lineno, 0 );
#else
				Debug( LDAP_DEBUG_ANY,
	    "%s: line %d: missing hash in \"password-hash <hash>\" line\n",
				    fname, lineno, 0 );
#endif

				return( 1 );
			}
			if ( default_passwd_hash != NULL ) {
#ifdef NEW_LOGGING
				LDAP_LOG( CONFIG, CRIT, 
					   "%s: line %d: already set default password_hash!\n",
					   fname, lineno, 0 );
#else
				Debug( LDAP_DEBUG_ANY,
					"%s: line %d: already set default password_hash!\n",
					fname, lineno, 0 );
#endif

				return 1;

			}

			if ( lutil_passwd_scheme( cargv[1] ) == 0 ) {
#ifdef NEW_LOGGING
				LDAP_LOG( CONFIG, CRIT, 
					   "%s: line %d: password scheme \"%s\" not available\n",
					   fname, lineno, cargv[1] );
#else
				Debug( LDAP_DEBUG_ANY,
					"%s: line %d: password scheme \"%s\" not available\n",
					fname, lineno, cargv[1] );
#endif
				return 1;
			}

			default_passwd_hash = ch_strdup( cargv[1] );

		} else if ( strcasecmp( cargv[0], "password-crypt-salt-format" ) == 0 ) 
		{
			if ( cargc < 2 ) {
#ifdef NEW_LOGGING
				LDAP_LOG( CONFIG, CRIT, 
					"%s: line %d: missing format in "
					"\"password-crypt-salt-format <format>\" line\n",
					fname, lineno, 0 );
#else
				Debug( LDAP_DEBUG_ANY, "%s: line %d: missing format in "
					"\"password-crypt-salt-format <format>\" line\n",
				    fname, lineno, 0 );
#endif

				return 1;
			}

			lutil_salt_format( cargv[1] );

		/* SASL config options */
		} else if ( strncasecmp( cargv[0], "sasl", 4 ) == 0 ) {
			if ( slap_sasl_config( cargc, cargv, line, fname, lineno ) )
				return 1;

		} else if ( strcasecmp( cargv[0], "schemadn" ) == 0 ) {
			struct berval dn;
			if ( cargc < 2 ) {
#ifdef NEW_LOGGING
				LDAP_LOG( CONFIG, CRIT, 
					   "%s: line %d: missing dn in "
					   "\"schemadn <dn>\" line.\n", fname, lineno, 0  );
#else
				Debug( LDAP_DEBUG_ANY,
	    "%s: line %d: missing dn in \"schemadn <dn>\" line\n",
				    fname, lineno, 0 );
#endif
				return 1 ;
			}
			ber_str2bv( cargv[1], 0, 0, &dn );
			if ( be ) {
				rc = dnPrettyNormal( NULL, &dn, &be->be_schemadn,
					&be->be_schemandn, NULL );
			} else {
				rc = dnPrettyNormal( NULL, &dn, &global_schemadn,
					&global_schemandn, NULL );
			}
			if ( rc != LDAP_SUCCESS ) {
#ifdef NEW_LOGGING
				LDAP_LOG( CONFIG, CRIT, 
					"%s: line %d: schemadn DN is invalid.\n",
					fname, lineno , 0 );
#else
				Debug( LDAP_DEBUG_ANY,
					"%s: line %d: schemadn DN is invalid\n",
					fname, lineno, 0 );
#endif
				return 1;
			}

		/* set UCDATA path */
		} else if ( strcasecmp( cargv[0], "ucdata-path" ) == 0 ) {
			int err;
			if ( cargc < 2 ) {
#ifdef NEW_LOGGING
				LDAP_LOG( CONFIG, CRIT, 
					   "%s: line %d: missing path in "
					   "\"ucdata-path <path>\" line.\n", fname, lineno, 0  );
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
					LDAP_LOG( CONFIG, CRIT, 
						   "%s: line %d: ucdata already loaded, ucdata-path "
						   "must be set earlier in the file and/or be "
						   "specified only once!\n", fname, lineno, 0 );
#else
					Debug( LDAP_DEBUG_ANY,
					       "%s: line %d: ucdata already loaded, ucdata-path must be set earlier in the file and/or be specified only once!\n",
					       fname, lineno, 0 );
#endif

				}
				return( 1 );
			}

		/* set size limit */
		} else if ( strcasecmp( cargv[0], "sizelimit" ) == 0 ) {
			int rc = 0, i;
			struct slap_limits_set *lim;
			
			if ( cargc < 2 ) {
#ifdef NEW_LOGGING
				LDAP_LOG( CONFIG, CRIT, 
				   "%s: line %d: missing limit in \"sizelimit <limit>\" "
				   "line.\n", fname, lineno, 0 );
#else
				Debug( LDAP_DEBUG_ANY,
	    "%s: line %d: missing limit in \"sizelimit <limit>\" line\n",
				    fname, lineno, 0 );
#endif

				return( 1 );
			}

			if ( be == NULL ) {
				lim = &deflimit;
			} else {
				lim = &be->be_def_limit;
			}

			for ( i = 1; i < cargc; i++ ) {
				if ( strncasecmp( cargv[i], "size", 4 ) == 0 ) {
					rc = parse_limit( cargv[i], lim );
					if ( rc ) {
#ifdef NEW_LOGGING
						LDAP_LOG( CONFIG, CRIT, 
						    	"%s: line %d: unable "
							   "to parse value \"%s\" in \"sizelimit "
							   "<limit>\" line.\n", fname, lineno, cargv[i] );
#else
						Debug( LDAP_DEBUG_ANY,
						    	"%s: line %d: unable "
							"to parse value \"%s\" "
							"in \"sizelimit "
							"<limit>\" line\n",
    							fname, lineno, cargv[i] );
#endif
						return( 1 );
					}

				} else {
					if ( strcasecmp( cargv[i], "unlimited" ) == 0 ) {
						lim->lms_s_soft = -1;
					} else {
						char *next;

						lim->lms_s_soft = strtol( cargv[i] , &next, 0 );
						if ( next == cargv[i] ) {
#ifdef NEW_LOGGING
							LDAP_LOG( CONFIG, CRIT, 
							   "%s: line %d: unable to parse limit \"%s\" in \"sizelimit <limit>\" "
							   "line.\n", fname, lineno, cargv[i] );
#else
							Debug( LDAP_DEBUG_ANY,
							    "%s: line %d: unable to parse limit \"%s\" in \"sizelimit <limit>\" line\n",
							    fname, lineno, cargv[i] );
#endif
							return( 1 );

						} else if ( next[0] != '\0' ) {
#ifdef NEW_LOGGING
							LDAP_LOG( CONFIG, CRIT, 
							   "%s: line %d: trailing chars \"%s\" in \"sizelimit <limit>\" "
							   "line ignored.\n", fname, lineno, next );
#else
							Debug( LDAP_DEBUG_ANY,
							    "%s: line %d: trailing chars \"%s\" in \"sizelimit <limit>\" line ignored\n",
							    fname, lineno, next );
#endif
						}
					}
					lim->lms_s_hard = 0;
				}
			}

		/* set time limit */
		} else if ( strcasecmp( cargv[0], "timelimit" ) == 0 ) {
			int rc = 0, i;
			struct slap_limits_set *lim;
			
			if ( cargc < 2 ) {
#ifdef NEW_LOGGING
				LDAP_LOG( CONFIG, CRIT, 
					"%s: line %d missing limit in \"timelimit <limit>\" "
					"line.\n", fname, lineno, 0 );
#else
				Debug( LDAP_DEBUG_ANY,
	    "%s: line %d: missing limit in \"timelimit <limit>\" line\n",
				    fname, lineno, 0 );
#endif

				return( 1 );
			}
			
			if ( be == NULL ) {
				lim = &deflimit;
			} else {
				lim = &be->be_def_limit;
			}

			for ( i = 1; i < cargc; i++ ) {
				if ( strncasecmp( cargv[i], "time", 4 ) == 0 ) {
					rc = parse_limit( cargv[i], lim );
					if ( rc ) {
#ifdef NEW_LOGGING
						LDAP_LOG( CONFIG, CRIT, 
							    "%s: line %d: unable to parse value \"%s\" "
							   "in \"timelimit <limit>\" line.\n",
							   fname, lineno, cargv[i] );
#else
						Debug( LDAP_DEBUG_ANY,
							"%s: line %d: unable "
							"to parse value \"%s\" "
							"in \"timelimit "
							"<limit>\" line\n",
							fname, lineno, cargv[i] );
#endif
						return( 1 );
					}

				} else {
					if ( strcasecmp( cargv[i], "unlimited" ) == 0 ) {
						lim->lms_t_soft = -1;
					} else {
						char *next;

						lim->lms_t_soft = strtol( cargv[i] , &next, 0 );
						if ( next == cargv[i] ) {
#ifdef NEW_LOGGING
							LDAP_LOG( CONFIG, CRIT, 
							   "%s: line %d: unable to parse limit \"%s\" in \"timelimit <limit>\" "
							   "line.\n", fname, lineno, cargv[i] );
#else
							Debug( LDAP_DEBUG_ANY,
							    "%s: line %d: unable to parse limit \"%s\" in \"timelimit <limit>\" line\n",
							    fname, lineno, cargv[i] );
#endif
							return( 1 );

						} else if ( next[0] != '\0' ) {
#ifdef NEW_LOGGING
							LDAP_LOG( CONFIG, CRIT, 
							   "%s: line %d: trailing chars \"%s\" in \"timelimit <limit>\" "
							   "line ignored.\n", fname, lineno, next );
#else
							Debug( LDAP_DEBUG_ANY,
							    "%s: line %d: trailing chars \"%s\" in \"timelimit <limit>\" line ignored\n",
							    fname, lineno, next );
#endif
						}
					}
					lim->lms_t_hard = 0;
				}
			}

		/* set regex-based limits */
		} else if ( strcasecmp( cargv[0], "limits" ) == 0 ) {
			if ( be == NULL ) {
#ifdef NEW_LOGGING
				LDAP_LOG( CONFIG, WARNING, 
					   "%s: line %d \"limits\" allowed only in database "
					   "environment.\n", fname, lineno, 0 );
#else
				Debug( LDAP_DEBUG_ANY,
	"%s: line %d \"limits\" allowed only in database environment.\n%s",
					fname, lineno, "" );
#endif
				return( 1 );
			}

			if ( parse_limits( be, fname, lineno, cargc, cargv ) ) {
				return( 1 );
			}

		/* mark this as a subordinate database */
		} else if ( strcasecmp( cargv[0], "subordinate" ) == 0 ) {
			if ( be == NULL ) {
#ifdef NEW_LOGGING
				LDAP_LOG( CONFIG, INFO, "%s: line %d: "
					"subordinate keyword must appear inside a database "
					"definition.\n", fname, lineno, 0 );
#else
				Debug( LDAP_DEBUG_ANY, "%s: line %d: subordinate keyword "
					"must appear inside a database definition.\n",
				    fname, lineno, 0 );
#endif
				return 1;

			} else {
				be->be_flags |= SLAP_BFLAG_GLUE_SUBORDINATE;
				num_subordinates++;
			}

		/* add an overlay to this backend */
		} else if ( strcasecmp( cargv[0], "overlay" ) == 0 ) {
			if ( be == NULL ) {
#ifdef NEW_LOGGING
				LDAP_LOG( CONFIG, INFO, "%s: line %d: "
					"overlay keyword must appear inside a database "
					"definition.\n", fname, lineno, 0 );
#else
				Debug( LDAP_DEBUG_ANY, "%s: line %d: overlay keyword "
					"must appear inside a database definition.\n",
				    fname, lineno, 0 );
#endif
				return 1;

			} else if ( overlay_config( be, cargv[1] )) {
				return 1;
			}

		/* set database suffix */
		} else if ( strcasecmp( cargv[0], "suffix" ) == 0 ) {
			Backend *tmp_be;
			struct berval dn, pdn, ndn;

			if ( cargc < 2 ) {
#ifdef NEW_LOGGING
				LDAP_LOG( CONFIG, CRIT, 
					"%s: line %d: missing dn in \"suffix <dn>\" line.\n",
					fname, lineno, 0 );
#else
				Debug( LDAP_DEBUG_ANY, "%s: line %d: "
					"missing dn in \"suffix <dn>\" line\n",
				    fname, lineno, 0 );
#endif

				return( 1 );

			} else if ( cargc > 2 ) {
#ifdef NEW_LOGGING
				LDAP_LOG( CONFIG, INFO, 
					"%s: line %d: extra cruft after <dn> in \"suffix %s\""
					" line (ignored).\n", fname, lineno, cargv[1] );
#else
				Debug( LDAP_DEBUG_ANY, "%s: line %d: extra cruft "
					"after <dn> in \"suffix %s\" line (ignored)\n",
				    fname, lineno, cargv[1] );
#endif
			}

			if ( be == NULL ) {
#ifdef NEW_LOGGING
				LDAP_LOG( CONFIG, INFO, 
					"%s: line %d: suffix line must appear inside a database "
					"definition.\n", fname, lineno, 0 );
#else
				Debug( LDAP_DEBUG_ANY, "%s: line %d: suffix line "
					"must appear inside a database definition\n",
				    fname, lineno, 0 );
#endif
				return( 1 );

#if defined(SLAPD_MONITOR_DN)
			/* "cn=Monitor" is reserved for monitoring slap */
			} else if ( strcasecmp( cargv[1], SLAPD_MONITOR_DN ) == 0 ) {
#ifdef NEW_LOGGING
				LDAP_LOG( CONFIG, CRIT, "%s: line %d: \""
					"%s\" is reserved for monitoring slapd\n", 
					fname, lineno, SLAPD_MONITOR_DN );
#else
				Debug( LDAP_DEBUG_ANY, "%s: line %d: \""
					"%s\" is reserved for monitoring slapd\n", 
					fname, lineno, SLAPD_MONITOR_DN );
#endif
				return( 1 );
#endif /* SLAPD_MONITOR_DN */
			}

			if ( load_ucdata( NULL ) < 0 ) return 1;

			dn.bv_val = cargv[1];
			dn.bv_len = strlen( cargv[1] );

			rc = dnPrettyNormal( NULL, &dn, &pdn, &ndn, NULL );
			if( rc != LDAP_SUCCESS ) {
#ifdef NEW_LOGGING
				LDAP_LOG( CONFIG, CRIT, 
					"%s: line %d: suffix DN is invalid.\n",
					fname, lineno, 0 );
#else
				Debug( LDAP_DEBUG_ANY,
					"%s: line %d: suffix DN is invalid\n",
				   fname, lineno, 0 );
#endif
				return( 1 );
			}

			tmp_be = select_backend( &ndn, 0, 0 );
			if ( tmp_be == be ) {
#ifdef NEW_LOGGING
				LDAP_LOG( CONFIG, INFO, 
					"%s: line %d: suffix already served by this backend "
					"(ignored)\n", fname, lineno, 0 );
#else
				Debug( LDAP_DEBUG_ANY, "%s: line %d: suffix "
					"already served by this backend (ignored)\n",
				    fname, lineno, 0 );
#endif
				free( pdn.bv_val );
				free( ndn.bv_val );

			} else if ( tmp_be  != NULL ) {
#ifdef NEW_LOGGING
				LDAP_LOG( CONFIG, INFO, 
					"%s: line %d: suffix already served by a preceding "
					"backend \"%s\"\n", fname, lineno,
					tmp_be->be_suffix[0].bv_val );
#else
				Debug( LDAP_DEBUG_ANY, "%s: line %d: suffix "
					"already served by a preceeding backend \"%s\"\n",
				    fname, lineno, tmp_be->be_suffix[0].bv_val );
#endif
				free( pdn.bv_val );
				free( ndn.bv_val );
				return( 1 );

			} else if( pdn.bv_len == 0 && default_search_nbase.bv_len ) {
#ifdef NEW_LOGGING
					LDAP_LOG( CONFIG, INFO, 
						"%s: line %d: suffix DN empty and default search "
						"base provided \"%s\" (assuming okay).\n",
						fname, lineno, default_search_base.bv_val );
#else
					Debug( LDAP_DEBUG_ANY, "%s: line %d: "
						"suffix DN empty and default "
						"search base provided \"%s\" (assuming okay)\n",
			    		fname, lineno, default_search_base.bv_val );
#endif
			}

			ber_bvarray_add( &be->be_suffix, &pdn );
			ber_bvarray_add( &be->be_nsuffix, &ndn );

               /* set max deref depth */
               } else if ( strcasecmp( cargv[0], "maxDerefDepth" ) == 0 ) {
					int i;
                       if ( cargc < 2 ) {
#ifdef NEW_LOGGING
			       LDAP_LOG( CONFIG, CRIT, 
					  "%s: line %d: missing depth in \"maxDerefDepth <depth>\""
					  " line\n", fname, lineno, 0 );
#else
                               Debug( LDAP_DEBUG_ANY,
                   "%s: line %d: missing depth in \"maxDerefDepth <depth>\" line\n",
                                   fname, lineno, 0 );
#endif

                               return( 1 );
                       }
                       if ( be == NULL ) {
#ifdef NEW_LOGGING
			       LDAP_LOG( CONFIG, INFO, 
					  "%s: line %d: depth line must appear inside a database "
					  "definition.\n", fname, lineno ,0 );
#else
                               Debug( LDAP_DEBUG_ANY,
"%s: line %d: depth line must appear inside a database definition.\n",
                                   fname, lineno, 0 );
#endif
							return 1;

                       } else if ((i = atoi(cargv[1])) < 0) {
#ifdef NEW_LOGGING
			       LDAP_LOG( CONFIG, INFO, 
					  "%s: line %d: depth must be positive.\n",
					  fname, lineno ,0 );
#else
                               Debug( LDAP_DEBUG_ANY,
"%s: line %d: depth must be positive.\n",
                                   fname, lineno, 0 );
#endif
							return 1;


                       } else {
                           be->be_max_deref_depth = i;
					   }


		/* set magic "root" dn for this database */
		} else if ( strcasecmp( cargv[0], "rootdn" ) == 0 ) {
			if ( cargc < 2 ) {
#ifdef NEW_LOGGING
				LDAP_LOG( CONFIG, INFO, 
					   "%s: line %d: missing dn in \"rootdn <dn>\" line.\n",
					   fname, lineno ,0 );
#else
				Debug( LDAP_DEBUG_ANY,
		    "%s: line %d: missing dn in \"rootdn <dn>\" line\n",
				    fname, lineno, 0 );
#endif

				return( 1 );
			}

			if ( be == NULL ) {
#ifdef NEW_LOGGING
				LDAP_LOG( CONFIG, INFO, 
					   "%s: line %d: rootdn line must appear inside a database "
					   "definition.\n", fname, lineno ,0 );
#else
				Debug( LDAP_DEBUG_ANY,
"%s: line %d: rootdn line must appear inside a database definition.\n",
				    fname, lineno, 0 );
#endif
				return 1;

			} else {
				struct berval dn;
				
				if ( load_ucdata( NULL ) < 0 ) return 1;

				dn.bv_val = cargv[1];
				dn.bv_len = strlen( cargv[1] );

				rc = dnPrettyNormal( NULL, &dn,
					&be->be_rootdn,
					&be->be_rootndn, NULL );

				if( rc != LDAP_SUCCESS ) {
#ifdef NEW_LOGGING
					LDAP_LOG( CONFIG, CRIT, 
						"%s: line %d: rootdn DN is invalid.\n", 
						fname, lineno ,0 );
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
				LDAP_LOG( CONFIG, CRIT, 
					"%s: line %d: missing passwd in \"rootpw <passwd>\""
					" line\n", fname, lineno ,0 );
#else
				Debug( LDAP_DEBUG_ANY, "%s: line %d: "
					"missing passwd in \"rootpw <passwd>\" line\n",
				    fname, lineno, 0 );
#endif

				return( 1 );
			}

			if ( be == NULL ) {
#ifdef NEW_LOGGING
				LDAP_LOG( CONFIG, INFO, "%s: line %d: "
					"rootpw line must appear inside a database "
					"definition.\n", fname, lineno ,0 );
#else
				Debug( LDAP_DEBUG_ANY, "%s: line %d: "
					"rootpw line must appear inside a database "
					"definition.\n",
				    fname, lineno, 0 );
#endif
				return 1;

			} else {
				Backend *tmp_be = select_backend( &be->be_rootndn, 0, 0 );

				if( tmp_be != be ) {
#ifdef NEW_LOGGING
					LDAP_LOG( CONFIG, INFO,
						"%s: line %d: "
						"rootpw can only be set when rootdn is under suffix\n",
						fname, lineno, "" );
#else
					Debug( LDAP_DEBUG_ANY, "%s: line %d: "
						"rootpw can only be set when rootdn is under suffix\n",
				    	fname, lineno, 0 );
#endif
					return 1;
				}

				be->be_rootpw.bv_val = ch_strdup( cargv[1] );
				be->be_rootpw.bv_len = strlen( be->be_rootpw.bv_val );
			}

		/* make this database read-only */
		} else if ( strcasecmp( cargv[0], "readonly" ) == 0 ) {
			if ( cargc < 2 ) {
#ifdef NEW_LOGGING
				LDAP_LOG( CONFIG, CRIT, 
					"%s: line %d: missing on|off in \"readonly <on|off>\" "
					"line.\n", fname, lineno ,0 );
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
				LDAP_LOG( CONFIG, INFO, 
					   "%s: line %d: allow line must appear prior to "
					   "database definitions.\n", fname, lineno ,0 );
#else
				Debug( LDAP_DEBUG_ANY,
"%s: line %d: allow line must appear prior to database definitions\n",
				    fname, lineno, 0 );
#endif

			}

			if ( cargc < 2 ) {
#ifdef NEW_LOGGING
				LDAP_LOG( CONFIG, CRIT, 
					   "%s: line %d: missing feature(s) in \"allow <features>\""
					   " line\n", fname, lineno ,0 );
#else
				Debug( LDAP_DEBUG_ANY,
	    "%s: line %d: missing feature(s) in \"allow <features>\" line\n",
				    fname, lineno, 0 );
#endif

				return( 1 );
			}

			allows = 0;

			for( i=1; i < cargc; i++ ) {
				if( strcasecmp( cargv[i], "bind_v2" ) == 0 ) {
					allows |= SLAP_ALLOW_BIND_V2;

				} else if( strcasecmp( cargv[i], "bind_anon_cred" ) == 0 ) {
					allows |= SLAP_ALLOW_BIND_ANON_CRED;

				} else if( strcasecmp( cargv[i], "bind_anon_dn" ) == 0 ) {
					allows |= SLAP_ALLOW_BIND_ANON_DN;

				} else if( strcasecmp( cargv[i], "update_anon" ) == 0 ) {
					allows |= SLAP_ALLOW_UPDATE_ANON;

				} else if( strcasecmp( cargv[i], "none" ) != 0 ) {
#ifdef NEW_LOGGING
					LDAP_LOG( CONFIG, CRIT, "%s: line %d: "
						"unknown feature %s in \"allow <features>\" line.\n",
						fname, lineno, cargv[1] );
#else
					Debug( LDAP_DEBUG_ANY, "%s: line %d: "
						"unknown feature %s in \"allow <features>\" line\n",
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
				LDAP_LOG( CONFIG, INFO, 
					   "%s: line %d: disallow line must appear prior to "
					   "database definitions.\n", fname, lineno ,0 );
#else
				Debug( LDAP_DEBUG_ANY,
"%s: line %d: disallow line must appear prior to database definitions\n",
				    fname, lineno, 0 );
#endif

			}

			if ( cargc < 2 ) {
#ifdef NEW_LOGGING
				LDAP_LOG( CONFIG, CRIT, 
					"%s: line %d: missing feature(s) in \"disallow <features>\""
					" line.\n", fname, lineno ,0 );
#else
				Debug( LDAP_DEBUG_ANY,
	    "%s: line %d: missing feature(s) in \"disallow <features>\" line\n",
				    fname, lineno, 0 );
#endif

				return( 1 );
			}

			disallows = 0;

			for( i=1; i < cargc; i++ ) {
				if( strcasecmp( cargv[i], "bind_anon" ) == 0 ) {
					disallows |= SLAP_DISALLOW_BIND_ANON;

				} else if( strcasecmp( cargv[i], "bind_simple" ) == 0 ) {
					disallows |= SLAP_DISALLOW_BIND_SIMPLE;

				} else if( strcasecmp( cargv[i], "bind_krbv4" ) == 0 ) {
					disallows |= SLAP_DISALLOW_BIND_KRBV4;

				} else if( strcasecmp( cargv[i], "tls_2_anon" ) == 0 ) {
					disallows |= SLAP_DISALLOW_TLS_2_ANON;

				} else if( strcasecmp( cargv[i], "tls_authc" ) == 0 ) {
					disallows |= SLAP_DISALLOW_TLS_AUTHC;

				} else if( strcasecmp( cargv[i], "none" ) != 0 ) {
#ifdef NEW_LOGGING
					LDAP_LOG( CONFIG, CRIT, 
						"%s: line %d: unknown feature %s in "
						"\"disallow <features>\" line.\n",
						fname, lineno, cargv[i] );
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
				LDAP_LOG( CONFIG, CRIT, 
					   "%s: line %d: missing feature(s) in "
					   "\"require <features>\" line.\n", fname, lineno ,0 );
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
					LDAP_LOG( CONFIG, CRIT, 
						   "%s: line %d: unknown feature %s in "
						   "\"require <features>\" line.\n", 
						   fname, lineno , cargv[i] );
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
				LDAP_LOG( CONFIG, CRIT, 
					"%s: line %d: missing factor(s) in \"security <factors>\""
					" line.\n", fname, lineno ,0 );
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

				} else if( strncasecmp( cargv[i], "simple_bind=",
					sizeof("simple_bind") ) == 0 )
				{
					set->sss_simple_bind =
						atoi( &cargv[i][sizeof("simple_bind")] );

				} else {
#ifdef NEW_LOGGING
					LDAP_LOG( CONFIG, CRIT, 
						   "%s: line %d: unknown factor %S in "
						   "\"security <factors>\" line.\n",
						   fname, lineno, cargv[1] );
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
				LDAP_LOG( CONFIG, CRIT, 
					"%s: line %d: missing URL in \"referral <URL>\""
					" line.\n", fname, lineno , 0 );
#else
				Debug( LDAP_DEBUG_ANY,
		    "%s: line %d: missing URL in \"referral <URL>\" line\n",
				    fname, lineno, 0 );
#endif

				return( 1 );
			}

			if( validate_global_referral( cargv[1] ) ) {
#ifdef NEW_LOGGING
				LDAP_LOG( CONFIG, CRIT, 
					"%s: line %d: invalid URL (%s) in \"referral\" line.\n",
					fname, lineno, cargv[1]  );
#else
				Debug( LDAP_DEBUG_ANY, "%s: line %d: "
					"invalid URL (%s) in \"referral\" line.\n",
				    fname, lineno, cargv[1] );
#endif
				return 1;
			}

			vals[0].bv_val = cargv[1];
			vals[0].bv_len = strlen( vals[0].bv_val );
			if( value_add( &default_referral, vals ) )
				return LDAP_OTHER;

#ifdef NEW_LOGGING
                } else if ( strcasecmp( cargv[0], "logfile" ) == 0 ) {
                        FILE *logfile;
                        if ( cargc < 2 ) {
#ifdef NEW_LOGGING
				LDAP_LOG( CONFIG, CRIT, 
					"%s: line %d: Error in logfile directive, "
					"\"logfile <filename>\"\n", fname, lineno , 0 );
#else
				Debug( LDAP_DEBUG_ANY,
				       "%s: line %d: Error in logfile directive, \"logfile filename\"\n",
				       fname, lineno, 0 );
#endif

				return( 1 );
                        }
                        logfile = fopen( cargv[1], "w" );
                        if ( logfile != NULL ) lutil_debug_file( logfile  );

#endif
		/* start of a new database definition */
		} else if ( strcasecmp( cargv[0], "debug" ) == 0 ) {
                        int level;
			if ( cargc < 3 ) {
#ifdef NEW_LOGGING
				LDAP_LOG( CONFIG, CRIT, 
					   "%s: line %d: Error in debug directive, "
					   "\"debug <subsys> <level>\"\n", fname, lineno , 0 );
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
			rc = parse_oidm( fname, lineno, cargc, cargv );
			if( rc ) return rc;

		/* specify an objectclass */
		} else if ( strcasecmp( cargv[0], "objectclass" ) == 0 ) {
			if ( cargc < 2 ) {
#ifdef NEW_LOGGING
				LDAP_LOG( CONFIG, INFO, 
					"%s: line %d: illegal objectclass format.\n",
					fname, lineno , 0 );
#else
				Debug( LDAP_DEBUG_ANY,
				       "%s: line %d: illegal objectclass format.\n",
				       fname, lineno, 0 );
#endif
				return( 1 );

			} else if ( *cargv[1] == '('  /*')'*/) {
				char * p;
				p = strchr(saveline,'(' /*')'*/);
				rc = parse_oc( fname, lineno, p, cargv );
				if( rc ) return rc;

			} else {
#ifdef NEW_LOGGING
				LDAP_LOG( CONFIG, INFO, 
					"%s: line %d: old objectclass format not supported\n",
					fname, lineno , 0 );
#else
				Debug( LDAP_DEBUG_ANY,
				       "%s: line %d: old objectclass format not supported.\n",
				       fname, lineno, 0 );
#endif
			}

		} else if ( strcasecmp( cargv[0], "ditcontentrule" ) == 0 ) {
			char * p;
			p = strchr(saveline,'(' /*')'*/);
			rc = parse_cr( fname, lineno, p, cargv );
			if( rc ) return rc;

		/* specify an attribute type */
		} else if (( strcasecmp( cargv[0], "attributetype" ) == 0 )
			|| ( strcasecmp( cargv[0], "attribute" ) == 0 ))
		{
			if ( cargc < 2 ) {
#ifdef NEW_LOGGING
				LDAP_LOG( CONFIG, INFO, "%s: line %d: "
					"illegal attribute type format.\n",
					fname, lineno , 0 );
#else
				Debug( LDAP_DEBUG_ANY, "%s: line %d: "
					"illegal attribute type format.\n",
					fname, lineno, 0 );
#endif
				return( 1 );

			} else if ( *cargv[1] == '(' /*')'*/) {
				char * p;
				p = strchr(saveline,'(' /*')'*/);
				rc = parse_at( fname, lineno, p, cargv );
				if( rc ) return rc;

			} else {
#ifdef NEW_LOGGING
				LDAP_LOG( CONFIG, INFO, 
					"%s: line %d: old attribute type format not supported.\n",
					fname, lineno , 0 );
#else
				Debug( LDAP_DEBUG_ANY,
    "%s: line %d: old attribute type format not supported.\n",
				    fname, lineno, 0 );
#endif

			}

		/* define attribute option(s) */
		} else if ( strcasecmp( cargv[0], "attributeoptions" ) == 0 ) {
			ad_define_option( NULL, NULL, 0 );
			for ( i = 1; i < cargc; i++ )
				if ( ad_define_option( cargv[i], fname, lineno ) != 0 )
					return 1;

		/* turn on/off schema checking */
		} else if ( strcasecmp( cargv[0], "schemacheck" ) == 0 ) {
			if ( cargc < 2 ) {
#ifdef NEW_LOGGING
				LDAP_LOG( CONFIG, CRIT, 
					"%s: line %d: missing on|off in \"schemacheck <on|off>\""
					" line.\n", fname, lineno , 0 );
#else
				Debug( LDAP_DEBUG_ANY,
    "%s: line %d: missing on|off in \"schemacheck <on|off>\" line\n",
				    fname, lineno, 0 );
#endif

				return( 1 );
			}
			if ( strcasecmp( cargv[1], "off" ) == 0 ) {
#ifdef NEW_LOGGING
				LDAP_LOG( CONFIG, CRIT, 
					"%s: line %d: schema checking disabled! your mileage may "
					"vary!\n", fname, lineno , 0 );
#else
				Debug( LDAP_DEBUG_ANY,
					"%s: line %d: schema checking disabled! your mileage may vary!\n",
				    fname, lineno, 0 );
#endif
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
				LDAP_LOG( CONFIG, CRIT, 
					"%s: line %d: missing level in \"loglevel <level>\""
					" line.\n", fname, lineno , 0 );
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

		/* list of sync replication information in this backend (slave only) */
		} else if ( strcasecmp( cargv[0], "syncrepl" ) == 0 ) {

			if ( be == NULL ) {
#ifdef NEW_LOGGING
				LDAP_LOG( CONFIG, INFO, 
					    "%s: line %d: syncrepl line must appear inside "
					    "a database definition.\n", fname, lineno, 0);
#else
				Debug( LDAP_DEBUG_ANY,
					    "%s: line %d: syncrepl line must appear inside "
					    "a database definition.\n", fname, lineno, 0);
#endif
				return 1;
			} else {
				if ( add_syncrepl( be, cargv, cargc )) {
					return 1;
				}
			}

		/* list of replicas of the data in this backend (master only) */
		} else if ( strcasecmp( cargv[0], "replica" ) == 0 ) {
			if ( cargc < 2 ) {
#ifdef NEW_LOGGING
				LDAP_LOG( CONFIG, CRIT, 
					"%s: line %d: missing host or uri in \"replica "
					" <host[:port]\" line\n", fname, lineno , 0 );
#else
				Debug( LDAP_DEBUG_ANY,
	    "%s: line %d: missing host or uri in \"replica <host[:port]>\" line\n",
				    fname, lineno, 0 );
#endif

				return( 1 );
			}
			if ( be == NULL ) {
#ifdef NEW_LOGGING
				LDAP_LOG( CONFIG, INFO, 
					    "%s: line %d: replica line must appear inside "
					    "a database definition.\n", fname, lineno, 0);
#else
				Debug( LDAP_DEBUG_ANY,
"%s: line %d: replica line must appear inside a database definition\n",
				    fname, lineno, 0 );
#endif
				return 1;

			} else {
				int nr = -1;

				for ( i = 1; i < cargc; i++ ) {
					if ( strncasecmp( cargv[i], "host=", 5 )
					    == 0 ) {
						nr = add_replica_info( be, 
							cargv[i] + 5 );
						break;
					} else if (strncasecmp( cargv[i], "uri=", 4 )
					    == 0 ) {
					    if ( ldap_url_parse( cargv[ i ] + 4, &ludp )
					    	!= LDAP_SUCCESS ) {
#ifdef NEW_LOGGING
							LDAP_LOG( CONFIG, INFO, 
					    		"%s: line %d: replica line contains invalid "
					    		"uri definition.\n", fname, lineno, 0);
#else
							Debug( LDAP_DEBUG_ANY,
					    		"%s: line %d: replica line contains invalid "
					    		"uri definition.\n", fname, lineno, 0);
#endif
							return 1;
						}
						if (ludp->lud_host == NULL ) {
#ifdef NEW_LOGGING
							LDAP_LOG( CONFIG, INFO, 
					    		"%s: line %d: replica line contains invalid "
					    		"uri definition - missing hostname.\n", 
					    		fname, lineno, 0);
#else
							Debug( LDAP_DEBUG_ANY,
					    		"%s: line %d: replica line contains invalid "
					    		"uri definition - missing hostname.\n", fname, lineno, 0);
#endif
							return 1;
						}
				    	replicahost = ch_malloc( strlen( cargv[ i ] ) );
						if ( replicahost == NULL ) {
#ifdef NEW_LOGGING
							LDAP_LOG( CONFIG, ERR, 
							"out of memory in read_config\n", 0, 0,0 );
#else
							Debug( LDAP_DEBUG_ANY, 
							"out of memory in read_config\n", 0, 0, 0 );
#endif
							ldap_free_urldesc( ludp );				
							exit( EXIT_FAILURE );
						}
						sprintf(replicahost, "%s:%d", 
							ludp->lud_host, ludp->lud_port);
						nr = add_replica_info( be, replicahost );
						ldap_free_urldesc( ludp );				
						ch_free(replicahost);
						break;
					}
				}
				if ( i == cargc ) {
#ifdef NEW_LOGGING
					LDAP_LOG( CONFIG, INFO, 
						"%s: line %d: missing host or uri in \"replica\" line\n", 
						fname, lineno , 0 );
#else
					Debug( LDAP_DEBUG_ANY,
		    "%s: line %d: missing host or uri in \"replica\" line\n",
					    fname, lineno, 0 );
#endif
					return 1;

				} else if ( nr == -1 ) {
#ifdef NEW_LOGGING
					LDAP_LOG( CONFIG, INFO, 
						   "%s: line %d: unable to add"
						   " replica \"%s\"\n",
						   fname, lineno, 
						   cargv[i] + 5 );
#else
					Debug( LDAP_DEBUG_ANY,
		"%s: line %d: unable to add replica \"%s\"\n",
						fname, lineno, cargv[i] + 5 );
#endif
					return 1;
				} else {
					for ( i = 1; i < cargc; i++ ) {
						if ( strncasecmp( cargv[i], "suffix=", 7 ) == 0 ) {

							switch ( add_replica_suffix( be, nr, cargv[i] + 7 ) ) {
							case 1:
#ifdef NEW_LOGGING
								LDAP_LOG( CONFIG, INFO, 
									"%s: line %d: suffix \"%s\" in \"replica\""
									" line is not valid for backend(ignored)\n",
									fname, lineno, cargv[i] + 7 );
#else
								Debug( LDAP_DEBUG_ANY,
										"%s: line %d: suffix \"%s\" in \"replica\" line is not valid for backend (ignored)\n",
										fname, lineno, cargv[i] + 7 );
#endif
								break;

							case 2:
#ifdef NEW_LOGGING
								LDAP_LOG( CONFIG, INFO, 
									"%s: line %d: unable to normalize suffix"
								   	" in \"replica\" line (ignored)\n",
									fname, lineno , 0 );
#else
								Debug( LDAP_DEBUG_ANY,
										 "%s: line %d: unable to normalize suffix in \"replica\" line (ignored)\n",
										 fname, lineno, 0 );
#endif
								break;
							}

						} else if ( strncasecmp( cargv[i], "attr", 4 ) == 0 ) {
							int exclude = 0;
							char *arg = cargv[i] + 4;

							if ( arg[0] == '!' ) {
								arg++;
								exclude = 1;
							}

							if ( arg[0] != '=' ) {
								continue;
							}

							if ( add_replica_attrs( be, nr, arg + 1, exclude ) ) {
#ifdef NEW_LOGGING
								LDAP_LOG( CONFIG, INFO, 
									"%s: line %d: attribute \"%s\" in "
									"\"replica\" line is unknown\n",
									fname, lineno, arg + 1 ); 
#else
								Debug( LDAP_DEBUG_ANY,
										"%s: line %d: attribute \"%s\" in \"replica\" line is unknown\n",
										fname, lineno, arg + 1 );
#endif
								return( 1 );
							}
						}
					}
				}
			}

		/* dn of master entity allowed to write to replica */
		} else if ( strcasecmp( cargv[0], "updatedn" ) == 0 ) {
			if ( cargc < 2 ) {
#ifdef NEW_LOGGING
				LDAP_LOG( CONFIG, CRIT, 
					"%s: line %d: missing dn in \"updatedn <dn>\""
					" line.\n", fname, lineno , 0 );
#else
				Debug( LDAP_DEBUG_ANY,
		    "%s: line %d: missing dn in \"updatedn <dn>\" line\n",
				    fname, lineno, 0 );
#endif

				return( 1 );
			}
			if ( be == NULL ) {
#ifdef NEW_LOGGING
				LDAP_LOG( CONFIG, INFO, 
					"%s: line %d: updatedn line must appear inside "
					"a database definition\n", 
					fname, lineno , 0 );
#else
				Debug( LDAP_DEBUG_ANY,
"%s: line %d: updatedn line must appear inside a database definition\n",
				    fname, lineno, 0 );
#endif
				return 1;

			} else {
				struct berval dn;

				if ( load_ucdata( NULL ) < 0 ) return 1;

				dn.bv_val = cargv[1];
				dn.bv_len = strlen( cargv[1] );

				rc = dnNormalize( 0, NULL, NULL, &dn, &be->be_update_ndn, NULL );
				if( rc != LDAP_SUCCESS ) {
#ifdef NEW_LOGGING
					LDAP_LOG( CONFIG, CRIT, 
						"%s: line %d: updatedn DN is invalid.\n",
						fname, lineno , 0 );
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
				LDAP_LOG( CONFIG, CRIT, "%s: line %d: "
					"missing url in \"updateref <ldapurl>\" line.\n",
					fname, lineno , 0 );
#else
				Debug( LDAP_DEBUG_ANY, "%s: line %d: "
					"missing url in \"updateref <ldapurl>\" line\n",
				    fname, lineno, 0 );
#endif

				return( 1 );
			}
			if ( be == NULL ) {
#ifdef NEW_LOGGING
				LDAP_LOG( CONFIG, INFO, "%s: line %d: updateref"
					" line must appear inside a database definition\n",
					fname, lineno , 0 );
#else
				Debug( LDAP_DEBUG_ANY, "%s: line %d: updateref"
					" line must appear inside a database definition\n",
					fname, lineno, 0 );
#endif
				return 1;

			} else if ( !be->be_update_ndn.bv_len ) {
#ifdef NEW_LOGGING
				LDAP_LOG( CONFIG, INFO, "%s: line %d: "
					"updateref line must come after updatedn.\n",
					fname, lineno , 0 );
#else
				Debug( LDAP_DEBUG_ANY, "%s: line %d: "
					"updateref line must after updatedn.\n",
				    fname, lineno, 0 );
#endif
				return 1;
			}

			if( validate_global_referral( cargv[1] ) ) {
#ifdef NEW_LOGGING
				LDAP_LOG( CONFIG, CRIT, "%s: line %d: "
					"invalid URL (%s) in \"updateref\" line.\n",
					fname, lineno, cargv[1] );
#else
				Debug( LDAP_DEBUG_ANY, "%s: line %d: "
					"invalid URL (%s) in \"updateref\" line.\n",
				    fname, lineno, cargv[1] );
#endif
				return 1;
			}

			vals[0].bv_val = cargv[1];
			vals[0].bv_len = strlen( vals[0].bv_val );
			if( value_add( &be->be_update_refs, vals ) )
				return LDAP_OTHER;

		/* replication log file to which changes are appended */
		} else if ( strcasecmp( cargv[0], "replogfile" ) == 0 ) {
			if ( cargc < 2 ) {
#ifdef NEW_LOGGING
				LDAP_LOG( CONFIG, CRIT, 
					"%s: line %d: missing filename in \"replogfile <filename>\""
					" line.\n", fname, lineno , 0 );
#else
				Debug( LDAP_DEBUG_ANY,
	    "%s: line %d: missing filename in \"replogfile <filename>\" line\n",
				    fname, lineno, 0 );
#endif

				return( 1 );
			}
			if ( be ) {
				be->be_replogfile = ch_strdup( cargv[1] );
			} else {
				replogfile = ch_strdup( cargv[1] );
			}

		/* file from which to read additional rootdse attrs */
		} else if ( strcasecmp( cargv[0], "rootDSE" ) == 0) {
			if ( cargc < 2 ) {
#ifdef NEW_LOGGING
				LDAP_LOG( CONFIG, CRIT, "%s: line %d: "
					"missing filename in \"rootDSE <filename>\" line.\n",
					fname, lineno , 0 );
#else
				Debug( LDAP_DEBUG_ANY, "%s: line %d: "
					"missing filename in \"rootDSE <filename>\" line.\n",
				    fname, lineno, 0 );
#endif
				return 1;
			}

			if( read_root_dse_file( cargv[1] ) ) {
#ifdef NEW_LOGGING
				LDAP_LOG( CONFIG, CRIT, "%s: line %d: "
					"could not read \"rootDSE <filename>\" line.\n",
					fname, lineno , 0 );
#else
				Debug( LDAP_DEBUG_ANY, "%s: line %d: "
					"could not read \"rootDSE <filename>\" line\n",
				    fname, lineno, 0 );
#endif
				return 1;
			}

		/* maintain lastmodified{by,time} attributes */
		} else if ( strcasecmp( cargv[0], "lastmod" ) == 0 ) {
			if ( cargc < 2 ) {
#ifdef NEW_LOGGING
				LDAP_LOG( CONFIG, CRIT, 
					   "%s: line %d: missing on|off in \"lastmod <on|off>\""
					   " line.\n", fname, lineno , 0 );
#else
				Debug( LDAP_DEBUG_ANY,
	    "%s: line %d: missing on|off in \"lastmod <on|off>\" line\n",
				    fname, lineno, 0 );
#endif

				return( 1 );
			}
			if ( strcasecmp( cargv[1], "on" ) == 0 ) {
				if ( be ) {
					be->be_flags &= ~SLAP_BFLAG_NOLASTMOD;
				} else {
					lastmod = 1;
				}
			} else {
				if ( be ) {
					be->be_flags |= SLAP_BFLAG_NOLASTMOD;
				} else {
					lastmod = 0;
				}
			}

#ifdef SIGHUP
		/* turn on/off gentle SIGHUP handling */
		} else if ( strcasecmp( cargv[0], "gentlehup" ) == 0 ) {
			if ( cargc < 2 ) {
				Debug( LDAP_DEBUG_ANY,
    "%s: line %d: missing on|off in \"gentlehup <on|off>\" line\n",
				    fname, lineno, 0 );
				return( 1 );
			}
			if ( strcasecmp( cargv[1], "off" ) == 0 ) {
				global_gentlehup = 0;
			} else {
				global_gentlehup = 1;
			}
#endif

		/* set idle timeout value */
		} else if ( strcasecmp( cargv[0], "idletimeout" ) == 0 ) {
			int i;
			if ( cargc < 2 ) {
#ifdef NEW_LOGGING
				LDAP_LOG( CONFIG, CRIT, 
					"%s: line %d: missing timeout value in "
					"\"idletimeout <seconds>\" line.\n", fname, lineno , 0 );
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
				LDAP_LOG( CONFIG, CRIT, 
					"%s: line %d: timeout value (%d) invalid "
					"\"idletimeout <seconds>\" line.\n", fname, lineno, i );
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
				LDAP_LOG( CONFIG, CRIT, 
					"%s: line %d: missing filename in \"include "
					"<filename>\" line.\n", fname, lineno , 0 );
#else
				Debug( LDAP_DEBUG_ANY,
    "%s: line %d: missing filename in \"include <filename>\" line\n",
				    fname, lineno, 0 );
#endif

				return( 1 );
			}
			savefname = ch_strdup( cargv[1] );
			savelineno = lineno;

			if ( read_config( savefname, depth+1 ) != 0 ) {
				return( 1 );
			}

			free( savefname );
			lineno = savelineno - 1;

		/* location of kerberos srvtab file */
		} else if ( strcasecmp( cargv[0], "srvtab" ) == 0 ) {
			if ( cargc < 2 ) {
#ifdef NEW_LOGGING
				LDAP_LOG( CONFIG, CRIT, 
					"%s: line %d: missing filename in \"srvtab "
					"<filename>\" line.\n", fname, lineno , 0 );
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
			   LDAP_LOG( CONFIG, INFO, 
				   "%s: line %d: missing filename in \"moduleload "
				   "<filename>\" line.\n", fname, lineno , 0 );
#else
                      Debug( LDAP_DEBUG_ANY,
                             "%s: line %d: missing filename in \"moduleload <filename>\" line\n",
                             fname, lineno, 0 );
#endif

                      exit( EXIT_FAILURE );
                   }
                   if (module_load(cargv[1], cargc - 2, (cargc > 2) ? cargv + 2 : NULL)) {
#ifdef NEW_LOGGING
			   LDAP_LOG( CONFIG, CRIT, 
				   "%s: line %d: failed to load or initialize module %s\n",
				   fname, lineno, cargv[1] );
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
			   LDAP_LOG( CONFIG, INFO, 
				  "%s: line %d: missing path in \"modulepath <path>\""
				  " line\n", fname, lineno , 0 );
#else
                      Debug( LDAP_DEBUG_ANY,
                             "%s: line %d: missing path in \"modulepath <path>\" line\n",
                             fname, lineno, 0 );
#endif

                      exit( EXIT_FAILURE );
                   }
                   if (module_path( cargv[1] )) {
#ifdef NEW_LOGGING
			   LDAP_LOG( CONFIG, CRIT, 
				  "%s: line %d: failed to set module search path to %s.\n",
				  fname, lineno, cargv[1] );
#else
			   Debug( LDAP_DEBUG_ANY,
				  "%s: line %d: failed to set module search path to %s\n",
				  fname, lineno, cargv[1]);
#endif

                      exit( EXIT_FAILURE );
                   }
		   
#endif /*SLAPD_MODULES*/

#ifdef HAVE_TLS
		} else if ( !strcasecmp( cargv[0], "TLSRandFile" ) ) {
			rc = ldap_pvt_tls_set_option( NULL,
						      LDAP_OPT_X_TLS_RANDOM_FILE,
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
			if ( isdigit( (unsigned char) cargv[1][0] ) ) {
				i = atoi(cargv[1]);
				rc = ldap_pvt_tls_set_option( NULL,
						      LDAP_OPT_X_TLS_REQUIRE_CERT,
						      &i );
			} else {
				rc = ldap_int_tls_config( NULL,
						      LDAP_OPT_X_TLS_REQUIRE_CERT,
						      cargv[1] );
			}

			if ( rc )
				return rc;

#endif

		} else if ( !strcasecmp( cargv[0], "reverse-lookup" ) ) {
#ifdef SLAPD_RLOOKUPS
			if ( cargc < 2 ) {
#ifdef NEW_LOGGING
				LDAP_LOG( CONFIG, INFO, 
					"%s: line %d: reverse-lookup: missing \"on\" or \"off\"\n",
					fname, lineno , 0 );
#else
				Debug( LDAP_DEBUG_ANY,
"%s: line %d: reverse-lookup: missing \"on\" or \"off\"\n",
		   			fname, lineno, 0 );
#endif
				return( 1 );
			}

			if ( !strcasecmp( cargv[1], "on" ) ) {
				use_reverse_lookup = 1;
			} else if ( !strcasecmp( cargv[1], "off" ) ) {
				use_reverse_lookup = 0;
			} else {
#ifdef NEW_LOGGING
				LDAP_LOG( CONFIG, INFO, 
					"%s: line %d: reverse-lookup: "
					"must be \"on\" (default) or \"off\"\n", fname, lineno, 0 );
#else
				Debug( LDAP_DEBUG_ANY,
"%s: line %d: reverse-lookup: must be \"on\" (default) or \"off\"\n",
		   			fname, lineno, 0 );
#endif
				return( 1 );
			}

#else /* !SLAPD_RLOOKUPS */
#ifdef NEW_LOGGING
			LDAP_LOG( CONFIG, INFO, 
				"%s: line %d: reverse lookups "
				"are not configured (ignored).\n", fname, lineno , 0 );
#else
			Debug( LDAP_DEBUG_ANY,
"%s: line %d: reverse lookups are not configured (ignored).\n",
		   		fname, lineno, 0 );
#endif
#endif /* !SLAPD_RLOOKUPS */

		/* Netscape plugins */
		} else if ( strcasecmp( cargv[0], "plugin" ) == 0 ) {
#if defined( LDAP_SLAPI )

#ifdef notdef /* allow global plugins, too */
			/*
			 * a "plugin" line must be inside a database
			 * definition, since we implement pre-,post- 
			 * and extended operation plugins
			 */
			if ( be == NULL ) {
#ifdef NEW_LOGGING
				LDAP_LOG( CONFIG, INFO, 
					"%s: line %d: plugin line must appear "
					"insid a database definition.\n",
					fname, lineno, 0 );
#else
				Debug( LDAP_DEBUG_ANY, "%s: line %d: plugin "
				    "line must appear inside a database "
				    "definition\n", fname, lineno, 0 );
#endif
				return( 1 );
			}
#endif /* notdef */

			if ( netscape_plugin( be, fname, lineno, cargc, cargv ) 
					!= LDAP_SUCCESS ) {
				return( 1 );
			}
			slapi_plugins_used++;

#else /* !defined( LDAP_SLAPI ) */
#ifdef NEW_LOGGING
			LDAP_LOG( CONFIG, INFO, 
				"%s: line %d: SLAPI not supported.\n",
				fname, lineno, 0 );
#else
			Debug( LDAP_DEBUG_ANY, "%s: line %d: SLAPI "
			    "not supported.\n", fname, lineno, 0 );
#endif
			return( 1 );
			
#endif /* !defined( LDAP_SLAPI ) */

		/* Netscape plugins */
		} else if ( strcasecmp( cargv[0], "pluginlog" ) == 0 ) {
#if defined( LDAP_SLAPI )
			if ( cargc < 2 ) {
#ifdef NEW_LOGGING
				LDAP_LOG( CONFIG, INFO, 
					"%s: line %d: missing file name "
					"in pluginlog <filename> line.\n",
					fname, lineno, 0 );
#else
				Debug( LDAP_DEBUG_ANY, 
					"%s: line %d: missing file name "
					"in pluginlog <filename> line.\n",
					fname, lineno, 0 );
#endif
				return( 1 );
			}

			if ( slapi_log_file != NULL ) {
				ch_free( slapi_log_file );
			}

			slapi_log_file = ch_strdup( cargv[1] );
#endif /* !defined( LDAP_SLAPI ) */

		/* pass anything else to the current backend info/db config routine */
		} else {
			if ( bi != NULL ) {
				if ( bi->bi_config == 0 ) {
#ifdef NEW_LOGGING
					LDAP_LOG( CONFIG, INFO, 
						"%s: line %d: unknown directive \"%s\" inside "
						"backend info definition (ignored).\n",
						fname, lineno, cargv[0] );
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
					LDAP_LOG( CONFIG, INFO, 
						"%s: line %d: uknown directive \"%s\" inside "
						"backend database definition (ignored).\n",
						fname, lineno, cargv[0] );
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
				LDAP_LOG( CONFIG, INFO, 
					"%s: line %d: unknown directive \"%s\" outside backend "
					"info and database definitions (ignored).\n",
					fname, lineno, cargv[0] );
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

	if ( depth == 0 ) ch_free( cargv );

	if ( !global_schemadn.bv_val ) {
		ber_str2bv( SLAPD_SCHEMA_DN, sizeof(SLAPD_SCHEMA_DN)-1, 1,
			&global_schemadn );
		dnNormalize( 0, NULL, NULL, &global_schemadn, &global_schemandn, NULL );
	}

	if ( load_ucdata( NULL ) < 0 ) return 1;
	return( 0 );
}

static int
fp_parse_line(
    int		lineno,
    char	*line
)
{
	char *	token;
	char *	logline;
	char	logbuf[sizeof("pseudorootpw ***")];

	cargc = 0;
	token = strtok_quote( line, " \t" );

	logline = line;

	if ( token && ( strcasecmp( token, "rootpw" ) == 0 ||
		strcasecmp( token, "replica" ) == 0 ||		/* contains "credentials" */
		strcasecmp( token, "bindpw" ) == 0 ||		/* used in back-ldap */
		strcasecmp( token, "pseudorootpw" ) == 0 ||	/* used in back-meta */
		strcasecmp( token, "dbpasswd" ) == 0 ) )	/* used in back-sql */
	{
		snprintf( logline = logbuf, sizeof logbuf, "%s ***", token );
	}

	if ( strtok_quote_ptr ) {
		*strtok_quote_ptr = ' ';
	}

#ifdef NEW_LOGGING
	LDAP_LOG( CONFIG, DETAIL1, "line %d (%s)\n", lineno, logline , 0 );
#else
	Debug( LDAP_DEBUG_CONFIG, "line %d (%s)\n", lineno, logline, 0 );
#endif

	if ( strtok_quote_ptr ) {
		*strtok_quote_ptr = '\0';
	}

	for ( ; token != NULL; token = strtok_quote( NULL, " \t" ) ) {
		if ( cargc == cargv_size - 1 ) {
			char **tmp;
			tmp = ch_realloc( cargv, (cargv_size + ARGS_STEP) *
			                    sizeof(*cargv) );
			if ( tmp == NULL ) {
#ifdef NEW_LOGGING
				LDAP_LOG( CONFIG, ERR, "line %d: out of memory\n", lineno, 0,0 );
#else
				Debug( LDAP_DEBUG_ANY, 
						"line %d: out of memory\n", 
						lineno, 0, 0 );
#endif
				return -1;
			}
			cargv = tmp;
			cargv_size += ARGS_STEP;
		}
		cargv[cargc++] = token;
	}
	cargv[cargc] = NULL;
	return 0;
}

static char *
strtok_quote( char *line, char *sep )
{
	int		inquote;
	char		*tmp;
	static char	*next;

	strtok_quote_ptr = NULL;
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
					strtok_quote_ptr = next;
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
static size_t lmax, lcur;

#define CATLINE( buf ) \
	do { \
		size_t len = strlen( buf ); \
		while ( lcur + len + 1 > lmax ) { \
			lmax += BUFSIZ; \
			line = (char *) ch_realloc( line, lmax ); \
		} \
		strcpy( line + lcur, buf ); \
		lcur += len; \
	} while( 0 )

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
		/* trim off \r\n or \n */
		if ( (p = strchr( buf, '\n' )) != NULL ) {
			if( p > buf && p[-1] == '\r' ) --p;
			*p = '\0';
		}
		
		/* trim off trailing \ and append the next line */
		if ( line[ 0 ] != '\0' 
				&& (p = line + strlen( line ) - 1)[ 0 ] == '\\'
				&& p[ -1 ] != '\\' ) {
			p[ 0 ] = '\0';
			lcur--;

		} else {
			if ( ! isspace( (unsigned char) buf[0] ) ) {
				return( line );
			}

			/* change leading whitespace to a space */
			buf[0] = ' ';
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
	err = ucdata_load( path ? path : SLAPD_DEFAULT_UCDATA, UCDATA_ALL );
	if ( err ) {
#ifdef NEW_LOGGING
		LDAP_LOG( CONFIG, CRIT, 
			"load_ucdata: Error %d loading ucdata.\n", err, 0,0 );
#else
		Debug( LDAP_DEBUG_ANY, "error loading ucdata (error %d)\n",
		       err, 0, 0 );
#endif

		return( -1 );
	}
	loaded = 1;
	return( 1 );
}

void
config_destroy( )
{
	ucdata_unload( UCDATA_ALL );
	free( global_schemandn.bv_val );
	free( global_schemadn.bv_val );
	free( line );
	if ( slapd_args_file )
		free ( slapd_args_file );
	if ( slapd_pid_file )
		free ( slapd_pid_file );
	if ( default_passwd_hash )
		free( default_passwd_hash );
	acl_destroy( global_acl, NULL );
}

static int
add_syncrepl(
	Backend *be,
	char    **cargv,
	int     cargc
)
{
	syncinfo_t *si;

	if ( be->be_syncinfo ) {
#ifdef NEW_LOGGING
		LDAP_LOG( CONFIG, INFO, 
			    "add_syncrepl: multiple syncrepl lines in a database "
				"definition are yet to be supported.\n", 0, 0, 0 );
#else
		Debug( LDAP_DEBUG_ANY,
			    "add_syncrepl: multiple syncrepl lines in a database "
				"definition are yet to be supported.\n", 0, 0, 0 );
#endif
		return 1;
	}

	si = be->be_syncinfo = (syncinfo_t *) ch_calloc( 1, sizeof( syncinfo_t ) );

	if ( si == NULL ) {
#ifdef NEW_LOGGING
		LDAP_LOG( CONFIG, ERR, "out of memory in add_syncrepl\n", 0, 0,0 );
#else
		Debug( LDAP_DEBUG_ANY, "out of memory in add_syncrepl\n", 0, 0, 0 );
#endif
		return 1;
	}

	si->si_tls = SYNCINFO_TLS_OFF;
	if ( be->be_rootndn.bv_val ) {
		ber_dupbv( &si->si_updatedn, &be->be_rootndn );
	}
	si->si_bindmethod = LDAP_AUTH_SIMPLE;
	si->si_schemachecking = 0;
	ber_str2bv( "(objectclass=*)", sizeof("(objectclass=*)")-1, 0,
		&si->si_filterstr );
	if ( be->be_suffix && be->be_suffix[0].bv_val ) {
		ber_dupbv( &si->si_base, &be->be_nsuffix[0] );
	}
	si->si_scope = LDAP_SCOPE_SUBTREE;
	si->si_attrsonly = 0;
	si->si_attrs = (char **) ch_calloc( 1, sizeof( char * ));
	si->si_attrs[0] = NULL;
	si->si_type = LDAP_SYNC_REFRESH_ONLY;
	si->si_interval = 86400;
	si->si_syncCookie.ctxcsn = NULL;
	si->si_syncCookie.octet_str = NULL;
	si->si_syncCookie.sid = -1;
	si->si_manageDSAit = 0;
	si->si_tlimit = -1;
	si->si_slimit = -1;
	si->si_syncUUID_ndn.bv_val = NULL;
	si->si_syncUUID_ndn.bv_len = 0;
	si->si_sync_mode = LDAP_SYNC_STATE_MODE;

	si->si_presentlist = NULL;
	LDAP_LIST_INIT( &si->si_nonpresentlist );

	if ( parse_syncrepl_line( cargv, cargc, si ) < 0 ) {
		/* Something bad happened - back out */
#ifdef NEW_LOGGING
		LDAP_LOG( CONFIG, ERR, "failed to add syncinfo\n", 0, 0,0 );
#else
		Debug( LDAP_DEBUG_ANY, "failed to add syncinfo\n", 0, 0, 0 );
#endif
		free( si );
		be->be_syncinfo = NULL;
		return 1;
	} else {
#ifdef NEW_LOGGING
		LDAP_LOG ( CONFIG, RESULTS,
			"add_syncrepl: Config: ** successfully added syncrepl \"%s\"\n",
			si->si_provideruri == NULL ? "(null)" : si->si_provideruri, 0, 0 );
#else
		Debug( LDAP_DEBUG_CONFIG,
			"Config: ** successfully added syncrepl \"%s\"\n",
			si->si_provideruri == NULL ? "(null)" : si->si_provideruri, 0, 0 );
#endif
		if ( !si->si_schemachecking ) {
			be->be_flags |= SLAP_BFLAG_NO_SCHEMA_CHECK;
		}
		si->si_be = be;
		return 0;
	}
}

#define IDSTR			"id"
#define PROVIDERSTR		"provider"
#define SUFFIXSTR		"suffix"
#define UPDATEDNSTR		"updatedn"
#define BINDMETHSTR		"bindmethod"
#define SIMPLESTR		"simple"
#define SASLSTR			"sasl"
#define BINDDNSTR		"binddn"
#define CREDSTR			"credentials"
#define OLDAUTHCSTR		"bindprincipal"
#define AUTHCSTR		"authcID"
#define AUTHZSTR		"authzID"
#define SRVTABSTR		"srvtab"
#define SASLMECHSTR		"saslmech"
#define REALMSTR		"realm"
#define SECPROPSSTR		"secprops"
#define STARTTLSSTR		"starttls"
#define CRITICALSTR		"critical"

#define SCHEMASTR		"schemachecking"
#define FILTERSTR		"filter"
#define SEARCHBASESTR	"searchbase"
#define SCOPESTR		"scope"
#define ATTRSSTR		"attrs"
#define ATTRSONLYSTR	"attrsonly"
#define TYPESTR			"type"
#define INTERVALSTR		"interval"
#define LASTMODSTR		"lastmod"
#define LMREQSTR		"req"
#define LMGENSTR		"gen"
#define LMNOSTR			"no"
#define MANAGEDSAITSTR	"manageDSAit"
#define SLIMITSTR		"sizelimit"
#define TLIMITSTR		"timelimit"

#define GOT_ID			0x0001
#define GOT_PROVIDER	0x0002
#define GOT_METHOD		0x0004
#define GOT_ALL			0x0007

static int
parse_syncrepl_line(
	char		**cargv,
	int		cargc,
	syncinfo_t	*si
)
{
	int	gots = 0;
	int	i, j;
	char	*hp, *val;
	int	nr_attr = 0;

	for ( i = 1; i < cargc; i++ ) {
		if ( !strncasecmp( cargv[ i ], IDSTR, sizeof( IDSTR ) - 1 )) {
			int tmp;
			/* '\0' string terminator accounts for '=' */
			val = cargv[ i ] + sizeof( IDSTR );
			tmp= atoi( val );
			if ( tmp >= 1000 || tmp < 0 ) {
				fprintf( stderr, "Error: parse_syncrepl_line: "
					 "syncrepl id %d is out of range [0..999]\n", tmp );
				return -1;
			}
			si->si_id = tmp;
			gots |= GOT_ID;
		} else if ( !strncasecmp( cargv[ i ], PROVIDERSTR,
					sizeof( PROVIDERSTR ) - 1 )) {
			val = cargv[ i ] + sizeof( PROVIDERSTR );
			si->si_provideruri = ch_strdup( val );
			si->si_provideruri_bv = (BerVarray)
				ch_calloc( 2, sizeof( struct berval ));
			ber_str2bv( si->si_provideruri, strlen( si->si_provideruri ),
				0, &si->si_provideruri_bv[0] );
			si->si_provideruri_bv[1].bv_len = 0;
			si->si_provideruri_bv[1].bv_val = NULL;
			gots |= GOT_PROVIDER;
		} else if ( !strncasecmp( cargv[ i ], STARTTLSSTR,
			sizeof(STARTTLSSTR) - 1 ) )
		{
			val = cargv[ i ] + sizeof( STARTTLSSTR );
			if( !strcasecmp( val, CRITICALSTR ) ) {
				si->si_tls = SYNCINFO_TLS_CRITICAL;
			} else {
				si->si_tls = SYNCINFO_TLS_ON;
			}
		} else if ( !strncasecmp( cargv[ i ],
			UPDATEDNSTR, sizeof( UPDATEDNSTR ) - 1 ) )
		{
			struct berval updatedn = {0, NULL};
			val = cargv[ i ] + sizeof( UPDATEDNSTR );
			ber_str2bv( val, 0, 0, &updatedn );
			ch_free( si->si_updatedn.bv_val );
			dnNormalize( 0, NULL, NULL, &updatedn, &si->si_updatedn, NULL );
		} else if ( !strncasecmp( cargv[ i ], BINDMETHSTR,
				sizeof( BINDMETHSTR ) - 1 ) )
		{
			val = cargv[ i ] + sizeof( BINDMETHSTR );
			if ( !strcasecmp( val, SIMPLESTR )) {
				si->si_bindmethod = LDAP_AUTH_SIMPLE;
				gots |= GOT_METHOD;
			} else if ( !strcasecmp( val, SASLSTR )) {
#ifdef HAVE_CYRUS_SASL
				si->si_bindmethod = LDAP_AUTH_SASL;
				gots |= GOT_METHOD;
#else /* HAVE_CYRUS_SASL */
				fprintf( stderr, "Error: parse_syncrepl_line: "
					"not compiled with SASL support\n" );
				return 1;
#endif /* HAVE_CYRUS_SASL */
			} else {
				si->si_bindmethod = -1;
			}
		} else if ( !strncasecmp( cargv[ i ],
				BINDDNSTR, sizeof( BINDDNSTR ) - 1 ) ) {
			val = cargv[ i ] + sizeof( BINDDNSTR );
			si->si_binddn = ch_strdup( val );
		} else if ( !strncasecmp( cargv[ i ],
				CREDSTR, sizeof( CREDSTR ) - 1 ) ) {
			val = cargv[ i ] + sizeof( CREDSTR );
			si->si_passwd = ch_strdup( val );
		} else if ( !strncasecmp( cargv[ i ],
				SASLMECHSTR, sizeof( SASLMECHSTR ) - 1 ) ) {
			val = cargv[ i ] + sizeof( SASLMECHSTR );
			si->si_saslmech = ch_strdup( val );
		} else if ( !strncasecmp( cargv[ i ],
				SECPROPSSTR, sizeof( SECPROPSSTR ) - 1 ) ) {
			val = cargv[ i ] + sizeof( SECPROPSSTR );
			si->si_secprops = ch_strdup( val );
		} else if ( !strncasecmp( cargv[ i ],
				REALMSTR, sizeof( REALMSTR ) - 1 ) ) {
			val = cargv[ i ] + sizeof( REALMSTR );
			si->si_realm = ch_strdup( val );
		} else if ( !strncasecmp( cargv[ i ],
				AUTHCSTR, sizeof( AUTHCSTR ) - 1 ) ) {
			val = cargv[ i ] + sizeof( AUTHCSTR );
			si->si_authcId = ch_strdup( val );
		} else if ( !strncasecmp( cargv[ i ],
				OLDAUTHCSTR, sizeof( OLDAUTHCSTR ) - 1 ) ) {
			/* Old authcID is provided for some backwards compatibility */
			val = cargv[ i ] + sizeof( OLDAUTHCSTR );
			si->si_authcId = ch_strdup( val );
		} else if ( !strncasecmp( cargv[ i ],
				AUTHZSTR, sizeof( AUTHZSTR ) - 1 ) ) {
			val = cargv[ i ] + sizeof( AUTHZSTR );
			si->si_authzId = ch_strdup( val );
		} else if ( !strncasecmp( cargv[ i ],
				SCHEMASTR, sizeof( SCHEMASTR ) - 1 ) )
		{
			val = cargv[ i ] + sizeof( SCHEMASTR );
			if ( !strncasecmp( val, "on", sizeof( "on" ) - 1 )) {
				si->si_schemachecking = 1;
			} else if ( !strncasecmp( val, "off", sizeof( "off" ) - 1 ) ) {
				si->si_schemachecking = 0;
			} else {
				si->si_schemachecking = 1;
			}
		} else if ( !strncasecmp( cargv[ i ],
			FILTERSTR, sizeof( FILTERSTR ) - 1 ) )
		{
			val = cargv[ i ] + sizeof( FILTERSTR );
			ber_str2bv( val, 0, 1, &si->si_filterstr );
		} else if ( !strncasecmp( cargv[ i ],
			SEARCHBASESTR, sizeof( SEARCHBASESTR ) - 1 ) )
		{
			struct berval bv;
			val = cargv[ i ] + sizeof( SEARCHBASESTR );
			ch_free( si->si_base.bv_val );
			ber_str2bv( val, 0, 0, &bv );
			if ( dnNormalize( 0, NULL, NULL, &bv, &si->si_base, NULL )) {
				fprintf( stderr, "Invalid base DN \"%s\"\n", val );
				return 1;
			}
		} else if ( !strncasecmp( cargv[ i ],
			SCOPESTR, sizeof( SCOPESTR ) - 1 ) )
		{
			val = cargv[ i ] + sizeof( SCOPESTR );
			if ( !strncasecmp( val, "base", sizeof( "base" ) - 1 )) {
				si->si_scope = LDAP_SCOPE_BASE;
			} else if ( !strncasecmp( val, "one", sizeof( "one" ) - 1 )) {
				si->si_scope = LDAP_SCOPE_ONELEVEL;
			} else if ( !strncasecmp( val, "sub", sizeof( "sub" ) - 1 )) {
				si->si_scope = LDAP_SCOPE_SUBTREE;
			} else {
				fprintf( stderr, "Error: parse_syncrepl_line: "
					"unknown scope \"%s\"\n", val);
				return 1;
			}
		} else if ( !strncasecmp( cargv[ i ],
			ATTRSONLYSTR, sizeof( ATTRSONLYSTR ) - 1 ) )
		{
			si->si_attrsonly = 1;
		} else if ( !strncasecmp( cargv[ i ],
			ATTRSSTR, sizeof( ATTRSSTR ) - 1 ) )
		{
			val = cargv[ i ] + sizeof( ATTRSSTR );
			str2clist( &si->si_attrs, val, "," );
		} else if ( !strncasecmp( cargv[ i ],
			TYPESTR, sizeof( TYPESTR ) - 1 ) )
		{
			val = cargv[ i ] + sizeof( TYPESTR );
			if ( !strncasecmp( val, "refreshOnly", sizeof("refreshOnly")-1 )) {
				si->si_type = LDAP_SYNC_REFRESH_ONLY;
			} else if ( !strncasecmp( val, "refreshAndPersist",
				sizeof("refreshAndPersist")-1 ))
			{
				si->si_type = LDAP_SYNC_REFRESH_AND_PERSIST;
				si->si_interval = 60;
			} else {
				fprintf( stderr, "Error: parse_syncrepl_line: "
					"unknown sync type \"%s\"\n", val);
				return 1;
			}
		} else if ( !strncasecmp( cargv[ i ],
			INTERVALSTR, sizeof( INTERVALSTR ) - 1 ) )
		{
			val = cargv[ i ] + sizeof( INTERVALSTR );
			if ( si->si_type == LDAP_SYNC_REFRESH_AND_PERSIST ) {
				si->si_interval = 0;
			} else {
				char *hstr;
				char *mstr;
				char *dstr;
				char *sstr;
				int dd, hh, mm, ss;
				dstr = val;
				hstr = strchr( dstr, ':' );
				if ( hstr == NULL ) {
					fprintf( stderr, "Error: parse_syncrepl_line: "
						"invalid interval \"%s\"\n", val );
					return 1;
				}
				*hstr++ = '\0';
				mstr = strchr( hstr, ':' );
				if ( mstr == NULL ) {
					fprintf( stderr, "Error: parse_syncrepl_line: "
						"invalid interval \"%s\"\n", val );
					return 1;
				}
				*mstr++ = '\0';
				sstr = strchr( mstr, ':' );
				if ( sstr == NULL ) {
					fprintf( stderr, "Error: parse_syncrepl_line: "
						"invalid interval \"%s\"\n", val );
					return 1;
				}
				*sstr++ = '\0';

				dd = atoi( dstr );
				hh = atoi( hstr );
				mm = atoi( mstr );
				ss = atoi( sstr );
				if (( hh > 24 ) || ( hh < 0 ) ||
					( mm > 60 ) || ( mm < 0 ) ||
					( ss > 60 ) || ( ss < 0 ) || ( dd < 0 )) {
					fprintf( stderr, "Error: parse_syncrepl_line: "
						"invalid interval \"%s\"\n", val );
					return 1;
				}
				si->si_interval = (( dd * 24 + hh ) * 60 + mm ) * 60 + ss;
			}
			if ( si->si_interval < 0 ) {
				fprintf( stderr, "Error: parse_syncrepl_line: "
					"invalid interval \"%ld\"\n",
					(long) si->si_interval);
				return 1;
			}
		} else if ( !strncasecmp( cargv[ i ],
			MANAGEDSAITSTR, sizeof( MANAGEDSAITSTR ) - 1 ) )
		{
			val = cargv[ i ] + sizeof( MANAGEDSAITSTR );
			si->si_manageDSAit = atoi( val );
		} else if ( !strncasecmp( cargv[ i ],
			SLIMITSTR, sizeof( SLIMITSTR ) - 1 ) )
		{
			val = cargv[ i ] + sizeof( SLIMITSTR );
			si->si_slimit = atoi( val );
		} else if ( !strncasecmp( cargv[ i ],
			TLIMITSTR, sizeof( TLIMITSTR ) - 1 ) )
		{
			val = cargv[ i ] + sizeof( TLIMITSTR );
			si->si_tlimit = atoi( val );
		} else {
			fprintf( stderr, "Error: parse_syncrepl_line: "
				"unknown keyword \"%s\"\n", cargv[ i ] );
		}
	}

	if ( gots != GOT_ALL ) {
		fprintf( stderr,
			"Error: Malformed \"syncrepl\" line in slapd config file" );
		return -1;
	}

	return 0;
}

char **
str2clist( char ***out, char *in, const char *brkstr )
{
	char	*str;
	char	*s;
	char	*lasts;
	int	i, j;
	const char *text;
	char	**new;

	/* find last element in list */
	for (i = 0; *out && *out[i]; i++);

	/* protect the input string from strtok */
	str = ch_strdup( in );

	if ( *str == '\0' ) {
		free( str );
		return( *out );
	}

	/* Count words in string */
	j=1;
	for ( s = str; *s; s++ ) {
		if ( strchr( brkstr, *s ) != NULL ) {
			j++;
		}
	}

	*out = ch_realloc( *out, ( i + j + 1 ) * sizeof( char * ) );
	new = *out + i;
	for ( s = ldap_pvt_strtok( str, brkstr, &lasts );
		s != NULL;
		s = ldap_pvt_strtok( NULL, brkstr, &lasts ) )
	{
		*new = ch_strdup( s );
		new++;
	}

	*new = NULL;
	free( str );
	return( *out );
}
