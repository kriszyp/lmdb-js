/* config.c - configuration file handling routines */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1998-2004 The OpenLDAP Foundation.
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

#include <ac/string.h>
#include <ac/ctype.h>
#include <ac/signal.h>
#include <ac/socket.h>
#include <ac/errno.h>

#include "ldap_pvt.h"
#include "slap.h"
#ifdef LDAP_SLAPI
#include "slapi/slapi.h"
#endif
#include "lutil.h"

#define ARGS_STEP	512

/*
 * defaults for various global variables
 */
slap_mask_t		global_allows = 0;
slap_mask_t		global_disallows = 0;
char		*replogfile;
int		global_gentlehup = 0;
int		global_idletimeout = 0;
char	*global_host = NULL;
char	*global_realm = NULL;
char		*ldap_srvtab = "";
char		**default_passwd_hash = NULL;
int		cargc = 0, cargv_size = 0;
char	**cargv;
struct berval default_search_base = BER_BVNULL;
struct berval default_search_nbase = BER_BVNULL;
unsigned		num_subordinates = 0;

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

static char *fp_getline(FILE *fp, int *lineno);
static void fp_getline_init(int *lineno);
static int fp_parse_line(int lineno, char *line);

static char	*strtok_quote(char *line, char *sep);
static int load_ucdata(char *path);

static int add_syncrepl LDAP_P(( Backend *, char **, int ));
static int parse_syncrepl_line LDAP_P(( char **, int, syncinfo_t *));

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
	static BackendInfo *bi = NULL;
	static BackendDB	*be = NULL;
	char	*next;


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
					"%s: line %d: missing level in \"concurrency <level>\" "
					" line\n", fname, lineno, 0 );
#else
				Debug( LDAP_DEBUG_ANY,
	    "%s: line %d: missing level in \"concurrency <level>\" line\n",
				    fname, lineno, 0 );
#endif

				return( 1 );
			}

			c = strtol( cargv[1], &next, 10 );
			if ( next == NULL || next[0] != '\0' ) {
#ifdef NEW_LOGGING
				LDAP_LOG( CONFIG, CRIT, 
					"%s: line %d: unable to parse level \"%s\" in \"concurrency <level>\" "
					" line\n", fname, lineno, cargv[1] );
#else
				Debug( LDAP_DEBUG_ANY,
	    "%s: line %d: unable to parse level \"%s\" in \"concurrency <level>\" line\n",
				    fname, lineno, cargv[1] );
#endif
				return( 1 );
			}

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

			c = strtol( cargv[1], &next, 10 );
			if (next == NULL || next[0] != '\0' ) {
#ifdef NEW_LOGGING
				LDAP_LOG( CONFIG, CRIT, 
					"%s: line %d: unable to parse count \"%s\" in \"threads <count>\" line\n",
					fname, lineno, cargv[1] );
#else
				Debug( LDAP_DEBUG_ANY,
	    "%s: line %d: unable to parse count \"%s\" in \"threads <count>\" line\n",
				    fname, lineno, cargv[1] );
#endif
				return( 1 );
			}

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
			for(i = 1; i < cargc; i++) {
				if ( lutil_passwd_scheme( cargv[i] ) == 0 ) {
#ifdef NEW_LOGGING
					LDAP_LOG( CONFIG, CRIT, 
					   	"%s: line %d: password scheme \"%s\" not available\n",
					   	fname, lineno, cargv[i] );
#else
					Debug( LDAP_DEBUG_ANY,
						"%s: line %d: password scheme \"%s\" not available\n",
						fname, lineno, cargv[i] );
#endif
				} else {
					ldap_charray_add( &default_passwd_hash, cargv[i] );
				}
			}
			if( !default_passwd_hash ) {
#ifdef NEW_LOGGING
				LDAP_LOG( CONFIG, CRIT, 
				   	"%s: line %d: no valid hashes found\n",
				   	fname, lineno, 0 );
#else
				Debug( LDAP_DEBUG_ANY,
					"%s: line %d: no valid hashes found\n",
					fname, lineno, 0 );
				return 1;
#endif
			}

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

#ifdef SLAP_AUTH_REWRITE
		/* use authid rewrite instead of sasl regexp */
		} else if ( strncasecmp( cargv[0], "auth-rewrite",
			STRLENOF("auth-rewrite") ) == 0 )
		{
			int rc = slap_sasl_rewrite_config( fname, lineno,
					cargc, cargv );
			if ( rc ) {
				return rc;
			}
#endif /* SLAP_AUTH_REWRITE */

		/* Auth + SASL config options */
		} else if ( !strncasecmp( cargv[0], "auth", STRLENOF("auth") ) ||
			!strncasecmp( cargv[0], "sasl", STRLENOF("sasl") ))
		{
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
				rc = dnPrettyNormal( NULL, &dn, &frontendDB->be_schemadn,
					&frontendDB->be_schemandn, NULL );
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
				lim = &frontendDB->be_def_limit;
			} else {
				lim = &be->be_def_limit;
			}

			for ( i = 1; i < cargc; i++ ) {
				if ( strncasecmp( cargv[i], "size", 4 ) == 0 ) {
					rc = limits_parse_one( cargv[i], lim );
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
				lim = &frontendDB->be_def_limit;
			} else {
				lim = &be->be_def_limit;
			}

			for ( i = 1; i < cargc; i++ ) {
				if ( strncasecmp( cargv[i], "time", 4 ) == 0 ) {
					rc = limits_parse_one( cargv[i], lim );
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

			if ( limits_parse( be, fname, lineno, cargc, cargv ) ) {
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
				SLAP_DBFLAGS(be) |= SLAP_DBFLAG_GLUE_SUBORDINATE;
				num_subordinates++;
			}

		/* add an overlay to this backend */
		} else if ( strcasecmp( cargv[0], "overlay" ) == 0 ) {
			if ( be == NULL ) {
				if ( cargv[1][0] == '-' && overlay_config( frontendDB, &cargv[1][1] ) ) {
					/* log error */
#ifdef NEW_LOGGING
					LDAP_LOG( CONFIG, INFO, "%s: line %d: "
						"(optional) global overlay \"%s\" configuration "
						"failed (ignored)\n", fname, lineno, &cargv[1][1] );
#else
					Debug( LDAP_DEBUG_ANY, "%s: line %d: "
						"(optional) global overlay \"%s\" configuration "
						"failed (ignored)\n", fname, lineno, &cargv[1][1] );
#endif
				} else if ( overlay_config( frontendDB, cargv[1] ) ) {
					return 1;
				}

			} else {
				if ( cargv[1][0] == '-' && overlay_config( be, &cargv[1][1] ) ) {
					/* log error */
#ifdef NEW_LOGGING
					LDAP_LOG( CONFIG, INFO, "%s: line %d: "
						"(optional) overlay \"%s\" configuration "
						"failed (ignored)\n", fname, lineno, &cargv[1][1] );
#else
					Debug( LDAP_DEBUG_ANY, "%s: line %d: "
						"(optional) overlay \"%s\" configuration "
						"failed (ignored)\n", fname, lineno, &cargv[1][1] );
#endif
				} else if ( overlay_config( be, cargv[1] ) ) {
					return 1;
				}
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
                       }

		       i = strtol( cargv[1], &next, 10 );
		       if ( next == NULL || next[0] != '\0' ) {
#ifdef NEW_LOGGING
			       LDAP_LOG( CONFIG, INFO, 
					  "%s: line %d: unable to parse depth \"%s\" in \"maxDerefDepth <depth>\" "
					  "line.\n", fname, lineno, cargv[1] );
#else
                               Debug( LDAP_DEBUG_ANY,
					  "%s: line %d: unable to parse depth \"%s\" in \"maxDerefDepth <depth>\" "
					  "line.\n", fname, lineno, cargv[1] );
#endif
				return 1;
		       }

		       if (i < 0) {
#ifdef NEW_LOGGING
			       LDAP_LOG( CONFIG, INFO, 
					  "%s: line %d: depth must be positive.\n",
					  fname, lineno, 0 );
#else
                               Debug( LDAP_DEBUG_ANY,
"%s: line %d: depth must be positive.\n",
                                   fname, lineno, 0 );
#endif
				return 1;


                       }
                       be->be_max_deref_depth = i;

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
					frontendDB->be_restrictops |= SLAP_RESTRICT_OP_WRITES;
				} else {
					frontendDB->be_restrictops &= ~SLAP_RESTRICT_OP_WRITES;
				}

			} else {
				if ( strcasecmp( cargv[1], "on" ) == 0 ) {
					be->be_restrictops |= SLAP_RESTRICT_OP_WRITES;
				} else {
					be->be_restrictops &= ~SLAP_RESTRICT_OP_WRITES;
				}
			}

		/* restricts specific operations */
		} else if ( strcasecmp( cargv[0], "restrict" ) == 0 ) {
			slap_mask_t	restrict = 0;
			struct restrictable_exops_t {
				char	*name;
				int	flag;
			} restrictable_exops[] = {
				{ LDAP_EXOP_START_TLS,		SLAP_RESTRICT_EXOP_START_TLS },
				{ LDAP_EXOP_MODIFY_PASSWD,	SLAP_RESTRICT_EXOP_MODIFY_PASSWD },
				{ LDAP_EXOP_X_WHO_AM_I,		SLAP_RESTRICT_EXOP_WHOAMI },
				{ LDAP_EXOP_X_CANCEL,		SLAP_RESTRICT_EXOP_CANCEL },
				{ NULL,				0 }
			};
			int		i;

			if ( cargc < 2 ) {
#ifdef NEW_LOGGING
				LDAP_LOG( CONFIG, CRIT, 
					"%s: line %d: missing <op_list> in \"restrict <op_list>\" "
					"line.\n", fname, lineno ,0 );
#else
				Debug( LDAP_DEBUG_ANY,
					"%s: line %d: missing <op_list> in \"restrict <op_list>\" "
					"line.\n", fname, lineno, 0 );
#endif

				return( 1 );
			}

			for ( i = 1; i < cargc; i++ ) {
				if ( strcasecmp( cargv[ i ], "read" ) == 0 ) {
					restrict |= SLAP_RESTRICT_OP_READS;

				} else if ( strcasecmp( cargv[ i ], "write" ) == 0 ) {
					restrict |= SLAP_RESTRICT_OP_WRITES;

				} else if ( strcasecmp( cargv[ i ], "add" ) == 0 ) {
					restrict |= SLAP_RESTRICT_OP_ADD;

				} else if ( strcasecmp( cargv[ i ], "bind" ) == 0 ) {
					restrict |= SLAP_RESTRICT_OP_BIND;

				} else if ( strcasecmp( cargv[ i ], "compare" ) == 0 ) {
					restrict |= SLAP_RESTRICT_OP_COMPARE;

				} else if ( strcasecmp( cargv[ i ], "delete" ) == 0 ) {
					restrict |= SLAP_RESTRICT_OP_DELETE;

				} else if ( strncasecmp( cargv[ i ], "extended",
							STRLENOF( "extended" ) ) == 0 ) {
					char	*e = cargv[ i ] + STRLENOF( "extended" );

					if ( e[0] == '=' ) {
						int	j;

						e++;
						for ( j = 0; restrictable_exops[ j ].name; j++ ) {
							if ( strcmp( e, restrictable_exops[ j ].name ) == 0 ) {
								restrict |= restrictable_exops[ j ].flag;
								break;
							}
						}

						if ( restrictable_exops[ j ].name == NULL ) {
							goto restrict_unknown;
						}

						restrict &= ~SLAP_RESTRICT_OP_EXTENDED;

					} else if ( e[0] == '\0' ) {
						restrict &= ~SLAP_RESTRICT_EXOP_MASK;
						restrict |= SLAP_RESTRICT_OP_EXTENDED;
						
					} else {
						goto restrict_unknown;
					}

				} else if ( strcasecmp( cargv[ i ], "modify" ) == 0 ) {
					restrict |= SLAP_RESTRICT_OP_MODIFY;

				} else if ( strcasecmp( cargv[ i ], "rename" ) == 0
						|| strcasecmp( cargv[ i ], "modrdn" ) == 0 ) {
					restrict |= SLAP_RESTRICT_OP_RENAME;

				} else if ( strcasecmp( cargv[ i ], "search" ) == 0 ) {
					restrict |= SLAP_RESTRICT_OP_SEARCH;

				} else {
restrict_unknown:;

#ifdef NEW_LOGGING
					LDAP_LOG( CONFIG, CRIT, "%s: line %d: "
						"unknown operation %s in \"allow <features>\" line.\n",
						fname, lineno, cargv[i] );
#else
					Debug( LDAP_DEBUG_ANY, "%s: line %d: "
						"unknown operation %s in \"allow <features>\" line\n",
						fname, lineno, cargv[i] );
#endif
					return 1;
				}
			}

			if ( be == NULL ) {
				frontendDB->be_restrictops |= restrict;

			} else {
				be->be_restrictops |= restrict;
			}

		/* allow these features */
		} else if ( strcasecmp( cargv[0], "allows" ) == 0 ||
			strcasecmp( cargv[0], "allow" ) == 0 )
		{
			slap_mask_t	allows = 0;

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

			for( i=1; i < cargc; i++ ) {
				if( strcasecmp( cargv[i], "bind_v2" ) == 0 ) {
					allows |= SLAP_ALLOW_BIND_V2;

				} else if( strcasecmp( cargv[i], "bind_anon_cred" ) == 0 ) {
					allows |= SLAP_ALLOW_BIND_ANON_CRED;

				} else if( strcasecmp( cargv[i], "bind_anon_dn" ) == 0 ) {
					allows |= SLAP_ALLOW_BIND_ANON_DN;

				} else if( strcasecmp( cargv[i], "update_anon" ) == 0 ) {
					allows |= SLAP_ALLOW_UPDATE_ANON;

				} else {
#ifdef NEW_LOGGING
					LDAP_LOG( CONFIG, CRIT, "%s: line %d: "
						"unknown feature %s in \"allow <features>\" line.\n",
						fname, lineno, cargv[i] );
#else
					Debug( LDAP_DEBUG_ANY, "%s: line %d: "
						"unknown feature %s in \"allow <features>\" line\n",
						fname, lineno, cargv[i] );
#endif

					return 1;
				}
			}

			global_allows |= allows;

		/* disallow these features */
		} else if ( strcasecmp( cargv[0], "disallows" ) == 0 ||
			strcasecmp( cargv[0], "disallow" ) == 0 )
		{
			slap_mask_t	disallows = 0; 

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

				} else {
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

					return 1;
				}
			}

			global_disallows |= disallows;

		/* require these features */
		} else if ( strcasecmp( cargv[0], "requires" ) == 0 ||
			strcasecmp( cargv[0], "require" ) == 0 )
		{
			slap_mask_t	requires = 0; 

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
				frontendDB->be_requires = requires;
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
				set = &frontendDB->be_ssf_set;
			} else {
				set = &be->be_ssf_set;
			}

			for( i=1; i < cargc; i++ ) {
				slap_ssf_t	*tgt;
				char		*src;

				if ( strncasecmp( cargv[i], "ssf=",
						STRLENOF("ssf=") ) == 0 )
				{
					tgt = &set->sss_ssf;
					src = &cargv[i][STRLENOF("ssf=")];

				} else if ( strncasecmp( cargv[i], "transport=",
						STRLENOF("transport=") ) == 0 )
				{
					tgt = &set->sss_transport;
					src = &cargv[i][STRLENOF("transport=")];

				} else if ( strncasecmp( cargv[i], "tls=",
						STRLENOF("tls=") ) == 0 )
				{
					tgt = &set->sss_tls;
					src = &cargv[i][STRLENOF("tls=")];

				} else if ( strncasecmp( cargv[i], "sasl=",
						STRLENOF("sasl=") ) == 0 )
				{
					tgt = &set->sss_sasl;
					src = &cargv[i][STRLENOF("sasl=")];

				} else if ( strncasecmp( cargv[i], "update_ssf=",
						STRLENOF("update_ssf=") ) == 0 )
				{
					tgt = &set->sss_update_ssf;
					src = &cargv[i][STRLENOF("update_ssf=")];

				} else if ( strncasecmp( cargv[i], "update_transport=",
						STRLENOF("update_transport=") ) == 0 )
				{
					tgt = &set->sss_update_transport;
					src = &cargv[i][STRLENOF("update_transport=")];

				} else if ( strncasecmp( cargv[i], "update_tls=",
						STRLENOF("update_tls=") ) == 0 )
				{
					tgt = &set->sss_update_tls;
					src = &cargv[i][STRLENOF("update_tls=")];

				} else if ( strncasecmp( cargv[i], "update_sasl=",
						STRLENOF("update_sasl=") ) == 0 )
				{
					tgt = &set->sss_update_sasl;
					src = &cargv[i][STRLENOF("update_sasl=")];

				} else if ( strncasecmp( cargv[i], "simple_bind=",
						STRLENOF("simple_bind=") ) == 0 )
				{
					tgt = &set->sss_simple_bind;
					src = &cargv[i][STRLENOF("simple_bind=")];

				} else {
#ifdef NEW_LOGGING
					LDAP_LOG( CONFIG, CRIT, 
						   "%s: line %d: unknown factor %s in "
						   "\"security <factors>\" line.\n",
						   fname, lineno, cargv[1] );
#else
					Debug( LDAP_DEBUG_ANY,
		    "%s: line %d: unknown factor %s in \"security <factors>\" line\n",
					    fname, lineno, cargv[i] );
#endif

					return( 1 );
				}

				*tgt = strtol( src, &next, 10 );
				if ( next == NULL || next[0] != '\0' ) {
#ifdef NEW_LOGGING
					LDAP_LOG( CONFIG, CRIT, 
						   "%s: line %d: unable to parse factor \"%s\" in "
						   "\"security <factors>\" line.\n",
						   fname, lineno, cargv[1] );
#else
					Debug( LDAP_DEBUG_ANY,
		    "%s: line %d: unable to parse factor \"%s\" in \"security <factors>\" line\n",
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
                        level = strtol( cargv[2], &next, 10 );
			if ( next == NULL || next[0] != '\0' ){
#ifdef NEW_LOGGING
				LDAP_LOG( CONFIG, CRIT, 
					   "%s: line %d: unable to parse level \"%s\" in debug directive, "
					   "\"debug <subsys> <level>\"\n", fname, lineno , cargv[2] );
#else
				Debug( LDAP_DEBUG_ANY,
					   "%s: line %d: unable to parse level \"%s\" in debug directive, "
					   "\"debug <subsys> <level>\"\n", fname, lineno , cargv[2] );
#endif
				return( 1 );
			}

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
					"%s: line %d: missing level(s) in \"loglevel <level> [...]\""
					" line.\n", fname, lineno , 0 );
#else
				Debug( LDAP_DEBUG_ANY,
		    "%s: line %d: missing level(s) in \"loglevel <level> [...]\" line\n",
				    fname, lineno, 0 );
#endif

				return( 1 );
			}

			ldap_syslog = 0;

			for( i=1; i < cargc; i++ ) {
				int	level;

				if ( isdigit( cargv[i][0] ) ) {
					level = strtol( cargv[i], &next, 10 );
					if ( next == NULL || next[0] != '\0' ) {
#ifdef NEW_LOGGING
						LDAP_LOG( CONFIG, CRIT, 
							"%s: line %d: unable to parse level \"%s\" "
							"in \"loglevel <level> [...]\" line.\n",
							fname, lineno , cargv[i] );
#else
						Debug( LDAP_DEBUG_ANY,
							"%s: line %d: unable to parse level \"%s\" "
							"in \"loglevel <level> [...]\" line.\n",
							fname, lineno , cargv[i] );
#endif
						return( 1 );
					}
					
				} else {
					static struct {
						int	i;
						char	*s;
					} int_2_level[] = {
						{ LDAP_DEBUG_TRACE,	"Trace"		},
						{ LDAP_DEBUG_PACKETS,	"Packets"	},
						{ LDAP_DEBUG_ARGS,	"Args"		},
						{ LDAP_DEBUG_CONNS,	"Conns"		},
						{ LDAP_DEBUG_BER,	"BER"		},
						{ LDAP_DEBUG_FILTER,	"Filter"	},
						{ LDAP_DEBUG_CONFIG,	"Config"	},
						{ LDAP_DEBUG_ACL,	"ACL"		},
						{ LDAP_DEBUG_STATS,	"Stats"		},
						{ LDAP_DEBUG_STATS2,	"Stats2"	},
						{ LDAP_DEBUG_SHELL,	"Shell"		},
						{ LDAP_DEBUG_PARSE,	"Parse"		},
						{ LDAP_DEBUG_CACHE,	"Cache"		},
						{ LDAP_DEBUG_INDEX,	"Index"		},
						{ -1,			"Any"		},
						{ 0,			NULL		}
					};
					int	j;

					for ( j = 0; int_2_level[j].s; j++ ) {
						if ( strcasecmp( cargv[i], int_2_level[j].s ) == 0 ) {
							level = int_2_level[j].i;
							break;
						}
					}

					if ( int_2_level[j].s == NULL ) {
#ifdef NEW_LOGGING
						LDAP_LOG( CONFIG, CRIT, 
							"%s: line %d: unknown level \"%s\" "
							"in \"loglevel <level> [...]\" line.\n",
							fname, lineno , cargv[i] );
#else
						Debug( LDAP_DEBUG_ANY,
							"%s: line %d: unknown level \"%s\" "
							"in \"loglevel <level> [...]\" line.\n",
							fname, lineno , cargv[i] );
#endif
						return( 1 );
					}
				}

				ldap_syslog |= level;
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

			} else if ( SLAP_SHADOW( be )) {
#ifdef NEW_LOGGING
				LDAP_LOG( CONFIG, INFO, 
					"%s: line %d: syncrepl: database already shadowed.\n",
					fname, lineno, 0);
#else
				Debug( LDAP_DEBUG_ANY,
					"%s: line %d: syncrepl: database already shadowed.\n",
					fname, lineno, 0);
#endif
				return 1;

			} else if ( add_syncrepl( be, cargv, cargc )) {
				return 1;
			}

			SLAP_DBFLAGS(be) |= ( SLAP_DBFLAG_SHADOW | SLAP_DBFLAG_SYNC_SHADOW );

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

		} else if ( strcasecmp( cargv[0], "replicationInterval" ) == 0 ) {
			/* ignore */

		/* dn of slave entity allowed to write to replica */
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

			} else if ( SLAP_SHADOW(be) ) {
#ifdef NEW_LOGGING
				LDAP_LOG( CONFIG, INFO, 
					"%s: line %d: updatedn: database already shadowed.\n",
					fname, lineno, 0);
#else
				Debug( LDAP_DEBUG_ANY,
					"%s: line %d: updatedn: database already shadowed.\n",
					fname, lineno, 0);
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
			SLAP_DBFLAGS(be) |= ( SLAP_DBFLAG_SHADOW | SLAP_DBFLAG_SLURP_SHADOW );

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

			} else if ( !SLAP_SHADOW(be) ) {
#ifdef NEW_LOGGING
				LDAP_LOG( CONFIG, INFO, "%s: line %d: "
					"updateref line must come after syncrepl or updatedn.\n",
					fname, lineno , 0 );
#else
				Debug( LDAP_DEBUG_ANY, "%s: line %d: "
					"updateref line must after syncrepl or updatedn.\n",
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
			if( value_add( &be->be_update_refs, vals ) ) {
				return LDAP_OTHER;
			}

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

			if ( be == NULL ) {
#ifdef NEW_LOGGING
				LDAP_LOG( CONFIG, INFO, "%s: line %d: lastmod"
					" line must appear inside a database definition\n",
					fname, lineno , 0 );
#else
				Debug( LDAP_DEBUG_ANY, "%s: line %d: lastmod"
					" line must appear inside a database definition\n",
					fname, lineno, 0 );
#endif
				return 1;

			} else if ( SLAP_NOLASTMODCMD(be) ) {
#ifdef NEW_LOGGING
				LDAP_LOG( CONFIG, INFO, "%s: line %d: lastmod"
					" not available for %s database\n",
					fname, lineno , be->bd_info->bi_type );
#else
				Debug( LDAP_DEBUG_ANY, "%s: line %d: lastmod"
					" not available for %s databases\n",
					fname, lineno, be->bd_info->bi_type );
#endif
				return 1;
			}

			if ( strcasecmp( cargv[1], "on" ) == 0 ) {
				SLAP_DBFLAGS(be) &= ~SLAP_DBFLAG_NOLASTMOD;
			} else {
				SLAP_DBFLAGS(be) |= SLAP_DBFLAG_NOLASTMOD;
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

			if ( slapi_int_read_config( be, fname, lineno, cargc, cargv ) 
					!= LDAP_SUCCESS )
			{
#ifdef NEW_LOGGING
				LDAP_LOG( CONFIG, INFO,
						"%s: line %d: SLAPI config read failed.\n",
						fname, lineno, 0 );
#else
				Debug( LDAP_DEBUG_ANY, "%s: line %d: SLAPI "
						"config read failed.\n", fname, lineno, 0 );
#endif
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
				if ( bi->bi_config ) {
					rc = (*bi->bi_config)( bi, fname, lineno, cargc, cargv );

					switch ( rc ) {
					case 0:
						break;

					case SLAP_CONF_UNKNOWN:
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
						break;

					default:
						return 1;
					}
				}

			} else if ( be != NULL ) {
				if ( be->be_config ) {
					rc = (*be->be_config)( be, fname, lineno, cargc, cargv );

					switch ( rc ) {
					case 0:
						break;

					case SLAP_CONF_UNKNOWN:
#ifdef NEW_LOGGING
						LDAP_LOG( CONFIG, INFO, 
							"%s: line %d: unknown directive \"%s\" inside "
							"backend database definition (ignored).\n",
							fname, lineno, cargv[0] );
#else
						Debug( LDAP_DEBUG_ANY,
"%s: line %d: unknown directive \"%s\" inside backend database definition (ignored)\n",
							fname, lineno, cargv[0] );
#endif
						break;

					default:
						return 1;
					}
				}

			} else {
				if ( frontendDB->be_config ) {
					rc = (*frontendDB->be_config)( frontendDB, fname, lineno, cargc, cargv );

					switch ( rc ) {
					case 0:
						break;

					case SLAP_CONF_UNKNOWN:
#ifdef NEW_LOGGING
						LDAP_LOG( CONFIG, INFO, 
							"%s: line %d: unknown directive \"%s\" inside "
							"global database definition (ignored).\n",
							fname, lineno, cargv[0] );
#else
						Debug( LDAP_DEBUG_ANY,
"%s: line %d: unknown directive \"%s\" inside global database definition (ignored)\n",
							fname, lineno, cargv[0] );
#endif
						break;

					default:
						return 1;
					}
				}
			}
		}
		free( saveline );
	}
	fclose( fp );

	if ( depth == 0 ) ch_free( cargv );

	if ( BER_BVISNULL( &frontendDB->be_schemadn ) ) {
		ber_str2bv( SLAPD_SCHEMA_DN, sizeof(SLAPD_SCHEMA_DN)-1, 1,
			&frontendDB->be_schemadn );
		dnNormalize( 0, NULL, NULL, &frontendDB->be_schemadn, &frontendDB->be_schemandn, NULL );
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
#if 0
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
#else
	/* ucdata is now hardcoded */
	return( 0 );
#endif
}

void
config_destroy( )
{
	ucdata_unload( UCDATA_ALL );
	if ( frontendDB ) {
		/* NOTE: in case of early exit, frontendDB can be NULL */
		if ( frontendDB->be_schemandn.bv_val )
			free( frontendDB->be_schemandn.bv_val );
		if ( frontendDB->be_schemadn.bv_val )
			free( frontendDB->be_schemadn.bv_val );
		if ( frontendDB->be_acl )
			acl_destroy( frontendDB->be_acl, NULL );
	}
	free( line );
	if ( slapd_args_file )
		free ( slapd_args_file );
	if ( slapd_pid_file )
		free ( slapd_pid_file );
	if ( default_passwd_hash )
		ldap_charray_free( default_passwd_hash );
}

static int
add_syncrepl(
	Backend *be,
	char    **cargv,
	int     cargc
)
{
	syncinfo_t *si;
	syncinfo_t *si_entry;
	int	rc = 0;
	int duplicated_replica_id = 0;

	si = (syncinfo_t *) ch_calloc( 1, sizeof( syncinfo_t ) );

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
	ber_str2bv( "(objectclass=*)", STRLENOF("(objectclass=*)"), 0,
		&si->si_filterstr );
	si->si_base.bv_val = NULL;
	si->si_scope = LDAP_SCOPE_SUBTREE;
	si->si_attrsonly = 0;
	si->si_attrs = (char **) ch_calloc( 1, sizeof( char * ));
	si->si_attrs[0] = NULL;
	si->si_exattrs = (char **) ch_calloc( 1, sizeof( char * ));
	si->si_exattrs[0] = NULL;
	si->si_type = LDAP_SYNC_REFRESH_ONLY;
	si->si_interval = 86400;
	si->si_retryinterval = 0;
	si->si_retrynum_init = 0;
	si->si_retrynum = 0;
	si->si_syncCookie.ctxcsn = NULL;
	si->si_syncCookie.octet_str = NULL;
	si->si_syncCookie.sid = -1;
	si->si_manageDSAit = 0;
	si->si_tlimit = 0;
	si->si_slimit = 0;
	si->si_syncUUID_ndn.bv_val = NULL;
	si->si_syncUUID_ndn.bv_len = 0;

	si->si_presentlist = NULL;
	LDAP_LIST_INIT( &si->si_nonpresentlist );

	rc = parse_syncrepl_line( cargv, cargc, si );

	LDAP_STAILQ_FOREACH( si_entry, &be->be_syncinfo, si_next ) {
		if ( si->si_rid == si_entry->si_rid ) {
#ifdef NEW_LOGGING
			LDAP_LOG( CONFIG, ERR,
				"add_syncrepl: duplicated replica id\n", 0, 0,0 );
#else
			Debug( LDAP_DEBUG_ANY,
				"add_syncrepl: duplicated replica id\n",0, 0, 0 );
#endif
			duplicated_replica_id = 1;
			break;
		}
	}

	if ( rc < 0 || duplicated_replica_id ) {
		syncinfo_t *si_entry;
		/* Something bad happened - back out */
#ifdef NEW_LOGGING
		LDAP_LOG( CONFIG, ERR, "failed to add syncinfo\n", 0, 0,0 );
#else
		Debug( LDAP_DEBUG_ANY, "failed to add syncinfo\n", 0, 0, 0 );
#endif

		/* If error, remove all syncinfo */
		LDAP_STAILQ_FOREACH( si_entry, &be->be_syncinfo, si_next ) {
			if ( si_entry->si_updatedn.bv_val ) {
				ch_free( si->si_updatedn.bv_val );
			}
			if ( si_entry->si_filterstr.bv_val ) {
				ch_free( si->si_filterstr.bv_val );
			}
			if ( si_entry->si_attrs ) {
				int i = 0;
				while ( si_entry->si_attrs[i] != NULL ) {
					ch_free( si_entry->si_attrs[i] );
					i++;
				}
				ch_free( si_entry->si_attrs );
			}
			if ( si_entry->si_exattrs ) {
				int i = 0;
				while ( si_entry->si_exattrs[i] != NULL ) {
					ch_free( si_entry->si_exattrs[i] );
					i++;
				}
				ch_free( si_entry->si_exattrs );
			}
		}

		while ( !LDAP_STAILQ_EMPTY( &be->be_syncinfo )) {
			si_entry = LDAP_STAILQ_FIRST( &be->be_syncinfo );
			LDAP_STAILQ_REMOVE_HEAD( &be->be_syncinfo, si_next );
			ch_free( si_entry );
		}
		LDAP_STAILQ_INIT( &be->be_syncinfo );
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
			SLAP_DBFLAGS(be) |= SLAP_DBFLAG_NO_SCHEMA_CHECK;
		}
		si->si_be = be;
		LDAP_STAILQ_INSERT_TAIL( &be->be_syncinfo, si, si_next );
		return 0;
	}
}

#define IDSTR			"rid"
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
#define EXATTRSSTR		"exattrs"
#define TYPESTR			"type"
#define INTERVALSTR		"interval"
#define LASTMODSTR		"lastmod"
#define LMREQSTR		"req"
#define LMGENSTR		"gen"
#define LMNOSTR			"no"
#define MANAGEDSAITSTR	"manageDSAit"
#define SLIMITSTR		"sizelimit"
#define TLIMITSTR		"timelimit"

#define RETRYSTR		"retry"

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
			si->si_rid = tmp;
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
			if ( !strncasecmp( val, "on", STRLENOF( "on" ) )) {
				si->si_schemachecking = 1;
			} else if ( !strncasecmp( val, "off", STRLENOF( "off" ) ) ) {
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
			if ( si->si_base.bv_val ) {
				ch_free( si->si_base.bv_val );
			}
			ber_str2bv( val, 0, 0, &bv );
			if ( dnNormalize( 0, NULL, NULL, &bv, &si->si_base, NULL )) {
				fprintf( stderr, "Invalid base DN \"%s\"\n", val );
				return 1;
			}
		} else if ( !strncasecmp( cargv[ i ],
			SCOPESTR, sizeof( SCOPESTR ) - 1 ) )
		{
			val = cargv[ i ] + sizeof( SCOPESTR );
			if ( !strncasecmp( val, "base", STRLENOF( "base" ) )) {
				si->si_scope = LDAP_SCOPE_BASE;
			} else if ( !strncasecmp( val, "one", STRLENOF( "one" ) )) {
				si->si_scope = LDAP_SCOPE_ONELEVEL;
#ifdef LDAP_SCOPE_SUBORDINATE
			} else if ( !strcasecmp( val, "subordinate" ) ||
				!strcasecmp( val, "children" ))
			{
				si->si_scope = LDAP_SCOPE_SUBORDINATE;
#endif
			} else if ( !strncasecmp( val, "sub", STRLENOF( "sub" ) )) {
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
			EXATTRSSTR, sizeof( EXATTRSSTR ) - 1 ) )
		{
			val = cargv[ i ] + sizeof( EXATTRSSTR );
			str2clist( &si->si_exattrs, val, "," );
		} else if ( !strncasecmp( cargv[ i ],
			TYPESTR, sizeof( TYPESTR ) - 1 ) )
		{
			val = cargv[ i ] + sizeof( TYPESTR );
			if ( !strncasecmp( val, "refreshOnly", STRLENOF("refreshOnly") )) {
				si->si_type = LDAP_SYNC_REFRESH_ONLY;
			} else if ( !strncasecmp( val, "refreshAndPersist",
				STRLENOF("refreshAndPersist") ))
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
			RETRYSTR, sizeof( RETRYSTR ) - 1 ) )
		{
			char *str;
			char **retry_list;
			int j, k, n;

			val = cargv[ i ] + sizeof( RETRYSTR );
			retry_list = (char **) ch_calloc( 1, sizeof( char * ));
			retry_list[0] = NULL;

			str2clist( &retry_list, val, " ,\t" );

			for ( k = 0; retry_list && retry_list[k]; k++ ) ;
			n = k / 2;
			if ( k % 2 ) {
				fprintf( stderr,
						"Error: incomplete syncrepl retry list\n" );
				for ( k = 0; retry_list && retry_list[k]; k++ ) {
					ch_free( retry_list[k] );
				}
				ch_free( retry_list );
				exit( EXIT_FAILURE );
			}
			si->si_retryinterval = (time_t *) ch_calloc( n + 1, sizeof( time_t ));
			si->si_retrynum = (int *) ch_calloc( n + 1, sizeof( int ));
			si->si_retrynum_init = (int *) ch_calloc( n + 1, sizeof( int ));
			for ( j = 0; j < n; j++ ) {
				si->si_retryinterval[j] = atoi( retry_list[j*2] );
				if ( *retry_list[j*2+1] == '+' ) {
					si->si_retrynum_init[j] = -1;
					si->si_retrynum[j] = -1;
					j++;
					break;
				} else {
					si->si_retrynum_init[j] = atoi( retry_list[j*2+1] );
					si->si_retrynum[j] = atoi( retry_list[j*2+1] );
				}
			}
			si->si_retrynum_init[j] = -2;
			si->si_retrynum[j] = -2;
			si->si_retryinterval[j] = 0;
			
			for ( k = 0; retry_list && retry_list[k]; k++ ) {
				ch_free( retry_list[k] );
			}
			ch_free( retry_list );
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
