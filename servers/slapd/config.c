/* config.c - configuration file handling routines */

#include "portable.h"

#include <stdio.h>

#include <ac/string.h>
#include <ac/ctype.h>
#include <ac/socket.h>

#include "ldapconfig.h"
#include "slap.h"

#define MAXARGS	100

/*
 * defaults for various global variables
 */
int		defsize = SLAPD_DEFAULT_SIZELIMIT;
int		deftime = SLAPD_DEFAULT_TIMELIMIT;
struct acl	*global_acl = NULL;
int		global_default_access = ACL_READ;
char		*replogfile;
int		global_lastmod;
char		*ldap_srvtab = "";

static char	*fp_getline(FILE *fp, int *lineno);
static void	fp_getline_init(int *lineno);
static void	fp_parse_line(char *line, int *argcp, char **argv);

static char	*strtok_quote(char *line, char *sep);

void
read_config( char *fname, Backend **bep, FILE *pfp )
{
	FILE	*fp;
	char	*line, *savefname;
	int	cargc, savelineno;
	char	*cargv[MAXARGS];
	int	lineno, i;
	Backend	*be;

	if ( (fp = pfp) == NULL && (fp = fopen( fname, "r" )) == NULL ) {
		ldap_syslog = 1;
		Debug( LDAP_DEBUG_ANY,
		    "could not open config file \"%s\" - absolute path?\n",
		    fname, 0, 0 );
		perror( fname );
		exit( 1 );
	}

	Debug( LDAP_DEBUG_CONFIG, "reading config file %s\n", fname, 0, 0 );
	be = *bep;
	fp_getline_init( &lineno );
	while ( (line = fp_getline( fp, &lineno )) != NULL ) {
		/* skip comments and blank lines */
		if ( line[0] == '#' || line[0] == '\0' ) {
			continue;
		}

		Debug( LDAP_DEBUG_CONFIG, "line %d (%s)\n", lineno, line, 0 );

		fp_parse_line( line, &cargc, cargv );

		if ( cargc < 1 ) {
			Debug( LDAP_DEBUG_ANY,
			    "%s: line %d: bad config line (ignored)\n",
			    fname, lineno, 0 );
			continue;
		}

		/* start of a new database definition */
		if ( strcasecmp( cargv[0], "database" ) == 0 ) {
			if ( cargc < 2 ) {
				Debug( LDAP_DEBUG_ANY,
		"%s: line %d: missing type in \"database <type>\" line\n",
				    fname, lineno, 0 );
				exit( 1 );
			}
			*bep = new_backend( cargv[1] );
			be = *bep;

 		/* assign a default depth limit for alias deref */
		be->be_maxDerefDepth = SLAPD_DEFAULT_MAXDEREFDEPTH; 

		/* set size limit */
		} else if ( strcasecmp( cargv[0], "sizelimit" ) == 0 ) {
			if ( cargc < 2 ) {
				Debug( LDAP_DEBUG_ANY,
	    "%s: line %d: missing limit in \"sizelimit <limit>\" line\n",
				    fname, lineno, 0 );
				exit( 1 );
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
				exit( 1 );
			}
			if ( be == NULL ) {
				deftime = atoi( cargv[1] );
			} else {
				be->be_timelimit = atoi( cargv[1] );
			}

		/* set database suffix */
		} else if ( strcasecmp( cargv[0], "suffix" ) == 0 ) {
			if ( cargc < 2 ) {
				Debug( LDAP_DEBUG_ANY,
		    "%s: line %d: missing dn in \"suffix <dn>\" line\n",
				    fname, lineno, 0 );
				exit( 1 );
			} else if ( cargc > 2 ) {
				Debug( LDAP_DEBUG_ANY,
    "%s: line %d: extra cruft after <dn> in \"suffix %s\" line (ignored)\n",
				    fname, lineno, cargv[1] );
			}
			if ( be == NULL ) {
				Debug( LDAP_DEBUG_ANY,
"%s: line %d: suffix line must appear inside a database definition (ignored)\n",
				    fname, lineno, 0 );
			} else {
				char *dn = ch_strdup( cargv[1] );
				(void) dn_normalize( dn );
				charray_add( &be->be_suffix, dn );
			}

                /* set database suffixAlias */
                } else if ( strcasecmp( cargv[0], "suffixAlias" ) == 0 ) {
                        if ( cargc < 2 ) {
                                Debug( LDAP_DEBUG_ANY,
                    "%s: line %d: missing alias and aliased_dn in \"suffixAlias <alias> <aliased_dn>\" line\n",
                                    fname, lineno, 0 );
                                exit( 1 );
                        } else if ( cargc < 3 ) {
                                Debug( LDAP_DEBUG_ANY,
                    "%s: line %d: missing aliased_dn in \"suffixAlias <alias> <aliased_dn>\" line\n",
                                    fname, lineno, 0 );
                                exit( 1 );
                        } else if ( cargc > 3 ) {
                                Debug( LDAP_DEBUG_ANY,
    "%s: line %d: extra cruft in suffixAlias line (ignored)\n",
                                    fname, lineno, 0 );
                        }
                        if ( be == NULL ) {
                                Debug( LDAP_DEBUG_ANY,
"%s: line %d: suffixAlias line must appear inside a database definition (ignored)\n",
                                    fname, lineno, 0 );
                        } else {
                                char *alias, *aliased_dn;

								alias = ch_strdup( cargv[1] );
                                (void) dn_normalize( alias );

                                aliased_dn = ch_strdup( cargv[2] );
                                (void) dn_normalize( aliased_dn );


								if ( strcasecmp( alias, aliased_dn) ) {
                                	Debug( LDAP_DEBUG_ANY,
"%s: line %d: suffixAlias %s is not different from aliased dn (ignored)\n",
                                    fname, lineno, alias );
								} else {
                                	(void) dn_normalize_case( alias );
                                	(void) dn_normalize_case( aliased_dn );
                                	charray_add( &be->be_suffixAlias, alias );
                                	charray_add( &be->be_suffixAlias, aliased_dn );
								}

								free(alias);
								free(aliased_dn);
                        }

               /* set max deref depth */
               } else if ( strcasecmp( cargv[0], "maxDerefDepth" ) == 0 ) {
                       if ( cargc < 2 ) {
                               Debug( LDAP_DEBUG_ANY,
                   "%s: line %d: missing depth in \"maxDerefDepth <depth>\" line\n",
                                   fname, lineno, 0 );
                               exit( 1 );
                       }
                       if ( be == NULL ) {
                               Debug( LDAP_DEBUG_ANY,
"%s: line %d: depth line must appear inside a database definition (ignored)\n",
                                   fname, lineno, 0 );
                       } else {
                           be->be_maxDerefDepth = atoi (cargv[1]);
                       }


		/* set magic "root" dn for this database */
		} else if ( strcasecmp( cargv[0], "rootdn" ) == 0 ) {
			if ( cargc < 2 ) {
				Debug( LDAP_DEBUG_ANY,
		    "%s: line %d: missing dn in \"rootdn <dn>\" line\n",
				    fname, lineno, 0 );
				exit( 1 );
			}
			if ( be == NULL ) {
				Debug( LDAP_DEBUG_ANY,
"%s: line %d: rootdn line must appear inside a database definition (ignored)\n",
				    fname, lineno, 0 );
			} else {
				be->be_root_dn = ch_strdup( cargv[1] );
				be->be_root_ndn = dn_normalize_case( ch_strdup( cargv[1] ) );
			}

		/* set super-secret magic database password */
		} else if ( strcasecmp( cargv[0], "rootpw" ) == 0 ) {
			if ( cargc < 2 ) {
				Debug( LDAP_DEBUG_ANY,
	    "%s: line %d: missing passwd in \"rootpw <passwd>\" line\n",
				    fname, lineno, 0 );
				exit( 1 );
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
				exit( 1 );
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
				exit( 1 );
			}
			default_referral = (char *) malloc( strlen( cargv[1] )
			    + sizeof("Referral:\n") + 1 );
			strcpy( default_referral, "Referral:\n" );
			strcat( default_referral, cargv[1] );

		/* specify an objectclass */
		} else if ( strcasecmp( cargv[0], "objectclass" ) == 0 ) {
			parse_oc( be, fname, lineno, cargc, cargv );

		/* specify an attribute */
		} else if ( strcasecmp( cargv[0], "attribute" ) == 0 ) {
			attr_syntax_config( fname, lineno, cargc - 1,
			    &cargv[1] );

		/* turn on/off schema checking */
		} else if ( strcasecmp( cargv[0], "schemacheck" ) == 0 ) {
			if ( cargc < 2 ) {
				Debug( LDAP_DEBUG_ANY,
    "%s: line %d: missing on|off in \"schemacheck <on|off>\" line\n",
				    fname, lineno, 0 );
				exit( 1 );
			}
			if ( strcasecmp( cargv[1], "on" ) == 0 ) {
				global_schemacheck = 1;
			} else {
				global_schemacheck = 0;
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
				exit( 1 );
			}
			if ( be == NULL ) {
				if ( (global_default_access =
				    str2access( cargv[1] )) == -1 ) {
					Debug( LDAP_DEBUG_ANY,
"%s: line %d: bad access \"%s\" expecting [self]{none|compare|read|write}\n",
					    fname, lineno, cargv[1] );
					exit( 1 );
				}
			} else {
				if ( (be->be_dfltaccess =
				    str2access( cargv[1] )) == -1 ) {
					Debug( LDAP_DEBUG_ANY,
"%s: line %d: bad access \"%s\" expecting [self]{none|compare|read|write}\n",
					    fname, lineno, cargv[1] );
					exit( 1 );
				}
			}

		/* debug level to log things to syslog */
		} else if ( strcasecmp( cargv[0], "loglevel" ) == 0 ) {
			if ( cargc < 2 ) {
				Debug( LDAP_DEBUG_ANY,
		    "%s: line %d: missing level in \"loglevel <level>\" line\n",
				    fname, lineno, 0 );
				exit( 1 );
			}
			ldap_syslog = atoi( cargv[1] );

		/* list of replicas of the data in this backend (master only) */
		} else if ( strcasecmp( cargv[0], "replica" ) == 0 ) {
			if ( cargc < 2 ) {
				Debug( LDAP_DEBUG_ANY,
	    "%s: line %d: missing host in \"replica <host[:port]>\" line\n",
				    fname, lineno, 0 );
				exit( 1 );
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
						    ch_strdup( cargv[i] + 5 ) );
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
				exit( 1 );
			}
			if ( be == NULL ) {
				Debug( LDAP_DEBUG_ANY,
"%s: line %d: updatedn line must appear inside a database definition (ignored)\n",
				    fname, lineno, 0 );
			} else {
				be->be_update_ndn = ch_strdup( cargv[1] );
				(void) dn_normalize_case( be->be_update_ndn );
			}

		/* replication log file to which changes are appended */
		} else if ( strcasecmp( cargv[0], "replogfile" ) == 0 ) {
			if ( cargc < 2 ) {
				Debug( LDAP_DEBUG_ANY,
	    "%s: line %d: missing dn in \"replogfile <filename>\" line\n",
				    fname, lineno, 0 );
				exit( 1 );
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
				exit( 1 );
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

		/* include another config file */
		} else if ( strcasecmp( cargv[0], "include" ) == 0 ) {
			if ( cargc < 2 ) {
				Debug( LDAP_DEBUG_ANY,
    "%s: line %d: missing filename in \"include <filename>\" line\n",
				    fname, lineno, 0 );
				exit( 1 );
			}
			savefname = ch_strdup( cargv[1] );
			savelineno = lineno;
			read_config( savefname, bep, NULL );
			be = *bep;
			free( savefname );
			lineno = savelineno - 1;

		/* location of kerberos srvtab file */
		} else if ( strcasecmp( cargv[0], "srvtab" ) == 0 ) {
			if ( cargc < 2 ) {
				Debug( LDAP_DEBUG_ANY,
	    "%s: line %d: missing filename in \"srvtab <filename>\" line\n",
				    fname, lineno, 0 );
				exit( 1 );
			}
			ldap_srvtab = ch_strdup( cargv[1] );

		/* pass anything else to the current backend config routine */
		} else {
			if ( be == NULL ) {
				Debug( LDAP_DEBUG_ANY,
"%s: line %d: unknown directive \"%s\" outside database definition (ignored)\n",
				    fname, lineno, cargv[0] );
			} else if ( be->be_config == NULL ) {
				Debug( LDAP_DEBUG_ANY,
"%s: line %d: unknown directive \"%s\" inside database definition (ignored)\n",
				    fname, lineno, cargv[0] );
			} else {
				(*be->be_config)( be, fname, lineno, cargc,
				    cargv );
			}
		}
	}
	fclose( fp );
}

static void
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
			exit( 1 );
		}
		argv[(*argcp)++] = token;
	}
	argv[*argcp] = NULL;
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
			SAFEMEMCPY( next, next + 1, strlen( next + 1 ) + 1 );
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
		if ( ! isspace( buf[0] ) ) {
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
