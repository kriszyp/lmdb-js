/* $OpenLDAP$ */
/*
 * Copyright 1998-2000 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */
/* ldapmodify.c - generic program to modify or add entries using LDAP */

#include "portable.h"

#include <stdio.h>

#include <ac/stdlib.h>

#include <ac/ctype.h>
#include <ac/signal.h>
#include <ac/string.h>
#include <ac/unistd.h>

#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

#ifdef HAVE_SYS_FILE_H
#include <sys/file.h>
#endif
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#include <ldap.h>

#include "lutil_ldap.h"
#include "ldif.h"
#include "ldap_defaults.h"

static char	*prog;
static char	*binddn = NULL;
static struct berval passwd = { 0, NULL };
static char	*ldaphost = NULL;
static int	ldapport = 0;
#ifdef HAVE_CYRUS_SASL
static char	*sasl_authc_id = NULL;
static char	*sasl_authz_id = NULL;
static char	*sasl_mech = NULL;
static char	*sasl_secprops = NULL;
#endif
static int	use_tls = 0;
static int	ldapadd, replace, not, verbose, contoper, force;
static LDAP	*ld;

#define LDAPMOD_MAXLINE		4096

/* strings found in replog/LDIF entries (mostly lifted from slurpd/slurp.h) */
#define T_VERSION_STR		"version"
#define T_REPLICA_STR		"replica"
#define T_DN_STR		"dn"
#define T_CHANGETYPESTR         "changetype"
#define T_ADDCTSTR		"add"
#define T_MODIFYCTSTR		"modify"
#define T_DELETECTSTR		"delete"
#define T_MODRDNCTSTR		"modrdn"
#define T_MODDNCTSTR		"moddn"
#define T_RENAMECTSTR		"rename"
#define T_MODOPADDSTR		"add"
#define T_MODOPREPLACESTR	"replace"
#define T_MODOPDELETESTR	"delete"
#define T_MODSEPSTR		"-"
#define T_NEWRDNSTR		"newrdn"
#define T_DELETEOLDRDNSTR	"deleteoldrdn"
#define T_NEWSUPSTR		"newsuperior"


static void usage LDAP_P(( const char *prog )) LDAP_GCCATTR((noreturn));
static int process_ldif_rec LDAP_P(( char *rbuf, int count ));
static void addmodifyop LDAP_P((
	LDAPMod ***pmodsp, int modop,
	const char *attr,
	struct berval *value ));
static int domodify LDAP_P((
	const char *dn,
	LDAPMod **pmods,
	int newentry ));
static int dodelete LDAP_P((
	const char *dn ));
static int dorename LDAP_P((
	const char *dn,
	const char *newrdn,
	const char *newsup,
	int deleteoldrdn ));
static char *read_one_record LDAP_P(( FILE *fp ));

static void
usage( const char *prog )
{
    fprintf( stderr,
"Add or modify entries from an LDAP server\n\n"
"usage: %s [options]\n"
"	The list of desired operations are read from stdin or from the file\n"
"	specified by \"-f file\".\n"
"options:\n"
"	-a\t\tadd values (default%s)\n"
"	-b\t\tread values from files (for binary attributes)\n"
"	-c\t\tcontinuous operation\n"
"	-C\t\tchase referrals\n"
"	-d level\tset LDAP debugging level to `level'\n"
"	-D dn\t\tbind DN\n"
"	-f file\t\tperform sequence of operations listed in file\n"
"	-F\t\tforce all changes records to be used\n"
"	-h host\t\tLDAP server\n"
"	-k\t\tuse Kerberos authentication\n"
"	-K\t\tlike -k, but do only step 1 of the Kerberos bind\n"
"	-M\t\tenable Manage DSA IT control (-MM to make it critical)\n"
"	-n\t\tprint changes, don't actually do them\n"
"	-O secprops\tSASL security properties\n"
"	-p port\t\tport on LDAP server\n"
"	-r\t\treplace values\n"
"	-U user\t\tSASL authentication identity (username)\n"
"	-v\t\tverbose mode\n"
"	-w passwd\tbind password (for Simple authentication)\n"
"	-X id\t\tSASL authorization identity (\"dn:<dn>\" or \"u:<user>\")\n"
"	-Y mech\t\tSASL mechanism\n"
"	-Z\t\tissue Start TLS request (-ZZ to require successful response)\n"
	     , prog, (strcmp( prog, "ldapadd" ) ? " is to replace" : "") );
    exit( EXIT_FAILURE );
}


int
main( int argc, char **argv )
{
    char		*infile, *rbuf, *start;
    FILE		*fp;
	int		rc, i, authmethod, version, want_bindpw, debug, manageDSAit, referrals;
	int count;

    if (( prog = strrchr( argv[ 0 ], *LDAP_DIRSEP )) == NULL ) {
	prog = argv[ 0 ];
    } else {
	++prog;
    }

    /* Print usage when no parameters */
    if( argc < 2 ) usage( prog );

    ldapadd = ( strcmp( prog, "ldapadd" ) == 0 );

    infile = NULL;
    not = verbose = want_bindpw = debug = manageDSAit = referrals = 0;
    authmethod = LDAP_AUTH_SIMPLE;
	version = -1;

    while (( i = getopt( argc, argv, "acCD:d:Ff:h:KkMnO:P:p:rtU:vWw:X:Y:Z" )) != EOF ) {
	switch( i ) {
	case 'a':	/* add */
	    ldapadd = 1;
	    break;
	case 'c':	/* continuous operation */
	    contoper = 1;
	    break;
	case 'C':
		referrals++;
		break;
	case 'r':	/* default is to replace rather than add values */
	    replace = 1;
	    break;
	case 'k':	/* kerberos bind */
#ifdef LDAP_API_FEATURE_X_OPENLDAP_V2_KBIND
		authmethod = LDAP_AUTH_KRBV4;
#else
		fprintf( stderr, "%s was not compiled with Kerberos support\n", argv[0] );
		return( EXIT_FAILURE );
#endif
	    break;
	case 'K':	/* kerberos bind, part 1 only */
#ifdef LDAP_API_FEATURE_X_OPENLDAP_V2_KBIND
		authmethod = LDAP_AUTH_KRBV41;
#else
		fprintf( stderr, "%s was not compiled with Kerberos support\n", argv[0] );
		return( EXIT_FAILURE );
#endif
	    break;
	case 'F':	/* force all changes records to be used */
	    force = 1;
	    break;
	case 'h':	/* ldap host */
	    ldaphost = strdup( optarg );
	    break;
	case 'D':	/* bind DN */
	    binddn = strdup( optarg );
	    break;
	case 'w':	/* password */
	    passwd.bv_val = strdup( optarg );
		{
			char* p;

			for( p = optarg; *p == '\0'; p++ ) {
				*p = '*';
			}
		}
		passwd.bv_len = strlen( passwd.bv_val );
	    break;
	case 'd':
	    debug |= atoi( optarg );
	    break;
	case 'f':	/* read from file */
	    infile = strdup( optarg );
	    break;
	case 'p':
	    ldapport = atoi( optarg );
	    break;
	case 'n':	/* print adds, don't actually do them */
	    ++not;
	    break;
	case 'v':	/* verbose mode */
	    verbose++;
	    break;
	case 'M':
		/* enable Manage DSA IT */
		manageDSAit++;
		break;
	case 'W':
		want_bindpw++;
		break;
	case 'P':
		switch( atoi(optarg) )
		{
		case 2:
			version = LDAP_VERSION2;
			break;
		case 3:
			version = LDAP_VERSION3;
			break;
		default:
			fprintf( stderr, "protocol version should be 2 or 3\n" );
			usage( argv[0] );
		}
		break;
	case 'O':
#ifdef HAVE_CYRUS_SASL
		sasl_secprops = strdup( optarg );
		authmethod = LDAP_AUTH_SASL;
#else
		fprintf( stderr, "%s was not compiled with SASL support\n",
			argv[0] );
		return( EXIT_FAILURE );
#endif
		break;
	case 'Y':
#ifdef HAVE_CYRUS_SASL
		if ( strcasecmp( optarg, "any" ) && strcmp( optarg, "*" ) ) {
			sasl_mech = strdup( optarg );
		}
		authmethod = LDAP_AUTH_SASL;
#else
		fprintf( stderr, "%s was not compiled with SASL support\n",
			argv[0] );
		return( EXIT_FAILURE );
#endif
		break;
	case 'U':
#ifdef HAVE_CYRUS_SASL
		sasl_authc_id = strdup( optarg );
		authmethod = LDAP_AUTH_SASL;
#else
		fprintf( stderr, "%s was not compiled with SASL support\n",
			argv[0] );
		return( EXIT_FAILURE );
#endif
		break;
	case 'X':
#ifdef HAVE_CYRUS_SASL
		sasl_authz_id = strdup( optarg );
		authmethod = LDAP_AUTH_SASL;
#else
		fprintf( stderr, "%s was not compiled with SASL support\n",
			argv[0] );
		return( EXIT_FAILURE );
#endif
		break;
	case 'Z':
#ifdef HAVE_TLS
		use_tls++;
#else
		fprintf( stderr, "%s was not compiled with TLS support\n",
			argv[0] );
		return( EXIT_FAILURE );
#endif
		break;
	default:
	    usage( prog );
	}
    }

    if ( argc != optind )
	usage( prog );

	if ( ( authmethod == LDAP_AUTH_KRBV4 ) || ( authmethod ==
			LDAP_AUTH_KRBV41 ) ) {
		if( version > LDAP_VERSION2 ) {
			fprintf( stderr, "Kerberos requires LDAPv2\n" );
			return( EXIT_FAILURE );
		}
		version = LDAP_VERSION2;
	}
	else if ( authmethod == LDAP_AUTH_SASL ) {
		if( version != -1 && version != LDAP_VERSION3 ) {
			fprintf( stderr, "SASL requires LDAPv3\n" );
			return( EXIT_FAILURE );
		}
		version = LDAP_VERSION3;
	}

	if( manageDSAit ) {
		if( version != -1 && version != LDAP_VERSION3 ) {
			fprintf(stderr, "manage DSA control requires LDAPv3\n");
			return EXIT_FAILURE;
		}
		version = LDAP_VERSION3;
	}

	if( use_tls ) {
		if( version != -1 && version != LDAP_VERSION3 ) {
			fprintf(stderr, "Start TLS requires LDAPv3\n");
			return EXIT_FAILURE;
		}
		version = LDAP_VERSION3;
	}

    if ( infile != NULL ) {
	if (( fp = fopen( infile, "r" )) == NULL ) {
	    perror( infile );
	    return( EXIT_FAILURE );
	}
    } else {
	fp = stdin;
    }

	if ( debug ) {
		if( ber_set_option( NULL, LBER_OPT_DEBUG_LEVEL, &debug ) != LBER_OPT_SUCCESS ) {
			fprintf( stderr, "Could not set LBER_OPT_DEBUG_LEVEL %d\n", debug );
		}
		if( ldap_set_option( NULL, LDAP_OPT_DEBUG_LEVEL, &debug ) != LDAP_OPT_SUCCESS ) {
			fprintf( stderr, "Could not set LDAP_OPT_DEBUG_LEVEL %d\n", debug );
		}
		ldif_debug = debug;
	}

#ifdef SIGPIPE
	(void) SIGNAL( SIGPIPE, SIG_IGN );
#endif

    if ( !not ) {
	if (( ld = ldap_init( ldaphost, ldapport )) == NULL ) {
	    perror( "ldap_init" );
	    return( EXIT_FAILURE );
	}

	/* referrals */
	if( ldap_set_option( ld, LDAP_OPT_REFERRALS,
		referrals ? LDAP_OPT_ON : LDAP_OPT_OFF ) != LDAP_OPT_SUCCESS )
	{
		fprintf( stderr, "Could not set LDAP_OPT_REFERRALS %s\n",
			referrals ? "on" : "off" );
		return EXIT_FAILURE;
	}


	if (version == -1 ) {
		version = 3;
	}

	if( ldap_set_option( ld, LDAP_OPT_PROTOCOL_VERSION, &version )
		!= LDAP_OPT_SUCCESS )
	{
		fprintf( stderr, "Could not set LDAP_OPT_PROTOCOL_VERSION %d\n",
			version );
		return EXIT_FAILURE;
	}

	if ( use_tls && ldap_start_tls_s( ld, NULL, NULL ) != LDAP_SUCCESS ) {
		if ( use_tls > 1 ) {
			ldap_perror( ld, "ldap_start_tls" );
			return( EXIT_FAILURE );
		}
		fprintf( stderr, "WARNING: could not start TLS\n" );
	}

	if (want_bindpw) {
		passwd.bv_val = getpassphrase("Enter LDAP Password: ");
		passwd.bv_len = passwd.bv_val ? strlen( passwd.bv_val ) : 0;
	}

	if ( authmethod == LDAP_AUTH_SASL ) {
#ifdef HAVE_CYRUS_SASL
		ldap_set_sasl_interact_proc( ld, lutil_sasl_interact );

		if( sasl_secprops != NULL ) {
			rc = ldap_set_option( ld, LDAP_OPT_X_SASL_SECPROPS,
				(void *) sasl_secprops );
			
			if( rc != LDAP_OPT_SUCCESS ) {
				fprintf( stderr,
					"Could not set LDAP_OPT_X_SASL_SECPROPS: %s\n",
					sasl_secprops );
				return( EXIT_FAILURE );
			}
		}
		
		rc = ldap_sasl_interactive_bind_s( ld, binddn,
				sasl_mech, NULL, NULL );

		if( rc != LDAP_SUCCESS ) {
			ldap_perror( ld, "ldap_sasl_interactive_bind_s" );
			return( EXIT_FAILURE );
		}
#else
		fprintf( stderr, "%s was not compiled with SASL support\n",
			argv[0] );
		return( EXIT_FAILURE );
#endif
	}
	else {
		if ( ldap_bind_s( ld, binddn, passwd.bv_val, authmethod )
				!= LDAP_SUCCESS ) {
			ldap_perror( ld, "ldap_bind" );
			return( EXIT_FAILURE );
		}
	}

    }

    rc = 0;

	if ( manageDSAit ) {
		int err;
		LDAPControl c;
		LDAPControl *ctrls[2];
		ctrls[0] = &c;
		ctrls[1] = NULL;

		c.ldctl_oid = LDAP_CONTROL_MANAGEDSAIT;
		c.ldctl_value.bv_val = NULL;
		c.ldctl_value.bv_len = 0;
		c.ldctl_iscritical = manageDSAit > 1;

		err = ldap_set_option( ld, LDAP_OPT_SERVER_CONTROLS, &ctrls );

		if( err != LDAP_OPT_SUCCESS ) {
			fprintf( stderr, "Could not set ManageDSAit %scontrol\n",
				c.ldctl_iscritical ? "critical " : "" );
			if( c.ldctl_iscritical ) {
				exit( EXIT_FAILURE );
			}
		}
	}

	count = 0;
    while (( rc == 0 || contoper ) &&
		( rbuf = read_one_record( fp )) != NULL ) {
	count++;

	start = rbuf;

    rc = process_ldif_rec( start, count );

	if( rc )
		fprintf( stderr, "ldif_record() = %d\n", rc );
		free( rbuf );
    }

    if ( !not ) {
		ldap_unbind( ld );
    }

	return( rc );
}


static int
process_ldif_rec( char *rbuf, int count )
{
    char	*line, *dn, *type, *newrdn, *newsup, *p;
    int		rc, linenum, modop, replicaport;
    int		expect_modop, expect_sep, expect_ct, expect_newrdn, expect_newsup;
    int		expect_deleteoldrdn, deleteoldrdn;
    int		saw_replica, use_record, new_entry, delete_entry, got_all;
    LDAPMod	**pmods;
	int version;
	struct berval val;

    new_entry = ldapadd;

    rc = got_all = saw_replica = delete_entry = modop = expect_modop = 0;
    expect_deleteoldrdn = expect_newrdn = expect_newsup = 0;
	expect_sep = expect_ct = 0;
    linenum = 0;
	version = 0;
    deleteoldrdn = 1;
    use_record = force;
    pmods = NULL;
    dn = newrdn = newsup = NULL;

    while ( rc == 0 && ( line = ldif_getline( &rbuf )) != NULL ) {
	++linenum;

	if ( expect_sep && strcasecmp( line, T_MODSEPSTR ) == 0 ) {
	    expect_sep = 0;
	    expect_ct = 1;
	    continue;
	}
	
	if ( ldif_parse_line( line, &type, &val.bv_val, &val.bv_len ) < 0 ) {
	    fprintf( stderr, "%s: invalid format (line %d) entry: \"%s\"\n",
		    prog, linenum, dn == NULL ? "" : dn );
	    rc = LDAP_PARAM_ERROR;
	    break;
	}

	if ( dn == NULL ) {
	    if ( !use_record && strcasecmp( type, T_REPLICA_STR ) == 0 ) {
		++saw_replica;
		if (( p = strchr( val.bv_val, ':' )) == NULL ) {
		    replicaport = 0;
		} else {
		    *p++ = '\0';
		    replicaport = atoi( p );
		}
		if ( ldaphost != NULL && strcasecmp( val.bv_val, ldaphost ) == 0 &&
			replicaport == ldapport ) {
		    use_record = 1;
		}
	    } else if ( count == 1 && linenum == 1 && 
			strcasecmp( type, T_VERSION_STR ) == 0 )
		{
			if( val.bv_len == 0 || atoi(val.bv_val) != 1 ) {
		    	fprintf( stderr, "%s: invalid version %s, line %d (ignored)\n",
			   	prog, val.bv_val == NULL ? "(null)" : val.bv_val, linenum );
			}
			version++;

	    } else if ( strcasecmp( type, T_DN_STR ) == 0 ) {
		if (( dn = strdup( val.bv_val ? val.bv_val : "" )) == NULL ) {
		    perror( "strdup" );
		    exit( EXIT_FAILURE );
		}
		expect_ct = 1;
	    }
	    goto end_line;	/* skip all lines until we see "dn:" */
	}

	if ( expect_ct ) {
	    expect_ct = 0;
	    if ( !use_record && saw_replica ) {
		printf( "%s: skipping change record for entry: %s\n"
			"\t(LDAP host/port does not match replica: lines)\n",
			prog, dn );
		free( dn );
		ber_memfree( type );
		ber_memfree( val.bv_val );
		return( 0 );
	    }

	    if ( strcasecmp( type, T_CHANGETYPESTR ) == 0 ) {
		if ( strcasecmp( val.bv_val, T_MODIFYCTSTR ) == 0 ) {
			new_entry = 0;
			expect_modop = 1;
		} else if ( strcasecmp( val.bv_val, T_ADDCTSTR ) == 0 ) {
			new_entry = 1;
		} else if ( strcasecmp( val.bv_val, T_MODRDNCTSTR ) == 0
			|| strcasecmp( val.bv_val, T_MODDNCTSTR ) == 0
			|| strcasecmp( val.bv_val, T_RENAMECTSTR ) == 0)
		{
		    expect_newrdn = 1;
		} else if ( strcasecmp( val.bv_val, T_DELETECTSTR ) == 0 ) {
		    got_all = delete_entry = 1;
		} else {
		    fprintf( stderr,
			    "%s:  unknown %s \"%s\" (line %d of entry \"%s\")\n",
			    prog, T_CHANGETYPESTR, val.bv_val, linenum, dn );
		    rc = LDAP_PARAM_ERROR;
		}
		goto end_line;
	    } else if ( ldapadd ) {		/*  missing changetype => add */
		new_entry = 1;
		modop = LDAP_MOD_ADD;
	    } else {
		expect_modop = 1;	/* missing changetype => modify */
	    }
	}

	if ( expect_modop ) {
	    expect_modop = 0;
	    expect_sep = 1;
	    if ( strcasecmp( type, T_MODOPADDSTR ) == 0 ) {
		modop = LDAP_MOD_ADD;
		goto end_line;
	    } else if ( strcasecmp( type, T_MODOPREPLACESTR ) == 0 ) {
		modop = LDAP_MOD_REPLACE;
		addmodifyop( &pmods, modop, val.bv_val, NULL );
		goto end_line;
	    } else if ( strcasecmp( type, T_MODOPDELETESTR ) == 0 ) {
		modop = LDAP_MOD_DELETE;
		addmodifyop( &pmods, modop, val.bv_val, NULL );
		goto end_line;
	    } else {	/* no modify op:  use default */
		modop = replace ? LDAP_MOD_REPLACE : LDAP_MOD_ADD;
	    }
	}

	if ( expect_newrdn ) {
	    if ( strcasecmp( type, T_NEWRDNSTR ) == 0 ) {
			if (( newrdn = strdup( val.bv_val ? val.bv_val : "" )) == NULL ) {
		    perror( "strdup" );
		    exit( EXIT_FAILURE );
		}
		expect_deleteoldrdn = 1;
		expect_newrdn = 0;
	    } else {
		fprintf( stderr, "%s: expecting \"%s:\" but saw \"%s:\" (line %d of entry \"%s\")\n",
			prog, T_NEWRDNSTR, type, linenum, dn );
		rc = LDAP_PARAM_ERROR;
	    }
	} else if ( expect_deleteoldrdn ) {
	    if ( strcasecmp( type, T_DELETEOLDRDNSTR ) == 0 ) {
		deleteoldrdn = ( *val.bv_val == '0' ) ? 0 : 1;
		expect_deleteoldrdn = 0;
		expect_newsup = 1;
		got_all = 1;
	    } else {
		fprintf( stderr, "%s: expecting \"%s:\" but saw \"%s:\" (line %d of entry \"%s\")\n",
			prog, T_DELETEOLDRDNSTR, type, linenum, dn );
		rc = LDAP_PARAM_ERROR;
	    }
	} else if ( expect_newsup ) {
	    if ( strcasecmp( type, T_NEWSUPSTR ) == 0 ) {
		if (( newsup = strdup( val.bv_val ? val.bv_val : "" )) == NULL ) {
		    perror( "strdup" );
		    exit( EXIT_FAILURE );
		}
		expect_newsup = 0;
	    } else {
		fprintf( stderr, "%s: expecting \"%s:\" but saw \"%s:\" (line %d of entry \"%s\")\n",
			prog, T_NEWSUPSTR, type, linenum, dn );
		rc = LDAP_PARAM_ERROR;
	    }
	} else if ( got_all ) {
	    fprintf( stderr,
		    "%s: extra lines at end (line %d of entry \"%s\")\n",
		    prog, linenum, dn );
	    rc = LDAP_PARAM_ERROR;
	} else {
		addmodifyop( &pmods, modop, type, val.bv_val == NULL ? NULL : &val );
	}

end_line:
	ber_memfree( type );
	ber_memfree( val.bv_val );
    }

	if( linenum == 0 ) {
		return 0;
	}

	if( version && linenum == 1 ) {
		return 0;
	}

    if ( rc == 0 ) {
	if ( delete_entry ) {
	    rc = dodelete( dn );
	} else if ( newrdn != NULL ) {
	    rc = dorename( dn, newrdn, newsup, deleteoldrdn );
	} else {
	    rc = domodify( dn, pmods, new_entry );
	}

	if ( rc == LDAP_SUCCESS ) {
	    rc = 0;
	}
    }

    if ( dn != NULL ) {
	free( dn );
    }
    if ( newrdn != NULL ) {
	free( newrdn );
    }
    if ( pmods != NULL ) {
	ldap_mods_free( pmods, 1 );
    }

    return( rc );
}


static void
addmodifyop(
	LDAPMod ***pmodsp,
	int modop,
	const char *attr,
	struct berval *val )
{
	LDAPMod		**pmods;
	int			i, j;

	pmods = *pmodsp;
	modop |= LDAP_MOD_BVALUES;

	i = 0;
	if ( pmods != NULL ) {
		for ( ; pmods[ i ] != NULL; ++i ) {
			if ( strcasecmp( pmods[ i ]->mod_type, attr ) == 0 &&
				pmods[ i ]->mod_op == modop )
			{
				break;
			}
		}
	}

	if ( pmods == NULL || pmods[ i ] == NULL ) {
		if (( pmods = (LDAPMod **)ber_memrealloc( pmods, (i + 2) *
			sizeof( LDAPMod * ))) == NULL )
		{
			perror( "realloc" );
			exit( EXIT_FAILURE );
		}

		*pmodsp = pmods;
		pmods[ i + 1 ] = NULL;

		pmods[ i ] = (LDAPMod *)ber_memcalloc( 1, sizeof( LDAPMod ));
		if ( pmods[ i ] == NULL ) {
			perror( "calloc" );
			exit( EXIT_FAILURE );
		}

		pmods[ i ]->mod_op = modop;
		pmods[ i ]->mod_type = ber_strdup( attr );
		if ( pmods[ i ]->mod_type == NULL ) {
			perror( "strdup" );
			exit( EXIT_FAILURE );
		}
	}

	if ( val != NULL ) {
		j = 0;
		if ( pmods[ i ]->mod_bvalues != NULL ) {
			for ( ; pmods[ i ]->mod_bvalues[ j ] != NULL; ++j ) {
				/* Empty */;
			}
		}

		pmods[ i ]->mod_bvalues = (struct berval **) ber_memrealloc(
			pmods[ i ]->mod_bvalues, (j + 2) * sizeof( struct berval * ));
		if ( pmods[ i ]->mod_bvalues == NULL ) {
			perror( "ber_realloc" );
			exit( EXIT_FAILURE );
		}

		pmods[ i ]->mod_bvalues[ j + 1 ] = NULL;
		pmods[ i ]->mod_bvalues[ j ] = ber_bvdup( val );
		if ( pmods[ i ]->mod_bvalues[ j ] == NULL ) {
			perror( "ber_bvdup" );
			exit( EXIT_FAILURE );
		}
	}
}


static int
domodify(
	const char *dn,
	LDAPMod **pmods,
	int newentry )
{
    int			i, j, k, notascii, op;
    struct berval	*bvp;

    if ( pmods == NULL ) {
	fprintf( stderr, "%s: no attributes to change or add (entry=\"%s\")\n",
		prog, dn );
	return( LDAP_PARAM_ERROR );
    }

    if ( verbose ) {
	for ( i = 0; pmods[ i ] != NULL; ++i ) {
	    op = pmods[ i ]->mod_op & ~LDAP_MOD_BVALUES;
	    printf( "%s %s:\n", op == LDAP_MOD_REPLACE ?
		    "replace" : op == LDAP_MOD_ADD ?
		    "add" : "delete", pmods[ i ]->mod_type );
	    if ( pmods[ i ]->mod_bvalues != NULL ) {
		for ( j = 0; pmods[ i ]->mod_bvalues[ j ] != NULL; ++j ) {
		    bvp = pmods[ i ]->mod_bvalues[ j ];
		    notascii = 0;
		    for ( k = 0; (unsigned long) k < bvp->bv_len; ++k ) {
			if ( !isascii( bvp->bv_val[ k ] )) {
			    notascii = 1;
			    break;
			}
		    }
		    if ( notascii ) {
			printf( "\tNOT ASCII (%ld bytes)\n", bvp->bv_len );
		    } else {
			printf( "\t%s\n", bvp->bv_val );
		    }
		}
	    }
	}
    }

    if ( newentry ) {
	printf( "%sadding new entry \"%s\"\n", not ? "!" : "", dn );
    } else {
	printf( "%smodifying entry \"%s\"\n", not ? "!" : "", dn );
    }

    if ( !not ) {
	if ( newentry ) {
	    i = ldap_add_s( ld, dn, pmods );
	} else {
	    i = ldap_modify_s( ld, dn, pmods );
	}
	if ( i != LDAP_SUCCESS ) {
	    ldap_perror( ld, newentry ? "ldap_add" : "ldap_modify" );
	} else if ( verbose ) {
	    printf( "modify complete\n" );
	}
    } else {
	i = LDAP_SUCCESS;
    }

    putchar( '\n' );

    return( i );
}


static int
dodelete(
	const char *dn )
{
    int	rc;

    printf( "%sdeleting entry \"%s\"\n", not ? "!" : "", dn );
    if ( !not ) {
	if (( rc = ldap_delete_s( ld, dn )) != LDAP_SUCCESS ) {
	    ldap_perror( ld, "ldap_delete" );
	} else if ( verbose ) {
	    printf( "delete complete" );
	}
    } else {
	rc = LDAP_SUCCESS;
    }

    putchar( '\n' );

    return( rc );
}


static int
dorename(
	const char *dn,
	const char *newrdn,
	const char* newsup,
	int deleteoldrdn )
{
    int	rc;


    printf( "%smodifying rdn of entry \"%s\"\n", not ? "!" : "", dn );
    if ( verbose ) {
	printf( "\tnew RDN: \"%s\" (%skeep existing values)\n",
		newrdn, deleteoldrdn ? "do not " : "" );
    }
    if ( !not ) {
	if (( rc = ldap_rename2_s( ld, dn, newrdn, newsup, deleteoldrdn ))
		!= LDAP_SUCCESS ) {
	    ldap_perror( ld, "ldap_modrdn" );
	} else {
	    printf( "modrdn completed\n" );
	}
    } else {
	rc = LDAP_SUCCESS;
    }

    putchar( '\n' );

    return( rc );
}


static char *
read_one_record( FILE *fp )
{
    char        *buf, line[ LDAPMOD_MAXLINE ];
    int		lcur, lmax;

    lcur = lmax = 0;
    buf = NULL;

    while ( fgets( line, sizeof(line), fp ) != NULL ) {
    	int len = strlen( line );

		if( len < 2 ) {
			if( buf == NULL ) {
				continue;
			} else {
				break;
			}
		}

		if ( lcur + len + 1 > lmax ) {
			lmax = LDAPMOD_MAXLINE
				* (( lcur + len + 1 ) / LDAPMOD_MAXLINE + 1 );

			if (( buf = (char *)realloc( buf, lmax )) == NULL ) {
				perror( "realloc" );
				exit( EXIT_FAILURE );
			}
		}

		strcpy( buf + lcur, line );
		lcur += len;
    }

    return( buf );
}
