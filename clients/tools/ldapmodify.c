/* $OpenLDAP$ */
/*
 * Copyright 1998-1999 The OpenLDAP Foundation, All Rights Reserved.
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

#include <sys/stat.h>

#ifdef HAVE_SYS_FILE_H
#include <sys/file.h>
#endif
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#include <lber.h>
#include <ldap.h>

#include "ldif.h"
#include "ldap_defaults.h"

static char	*prog;
static char	*binddn = NULL;
static char	*passwd = NULL;
static char	*ldaphost = NULL;
static int	ldapport = 0;
static int	new, replace, not, verbose, contoper, force, valsfromfiles;
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
static int process_ldapmod_rec LDAP_P(( char *rbuf ));
static int process_ldif_rec LDAP_P(( char *rbuf, int count ));
static void addmodifyop LDAP_P(( LDAPMod ***pmodsp, int modop, char *attr,
	char *value, int vlen ));
static int domodify LDAP_P(( char *dn, LDAPMod **pmods, int newentry ));
static int dodelete LDAP_P(( char *dn ));
static int domodrdn LDAP_P(( char *dn, char *newrdn, int deleteoldrdn ));
static int fromfile LDAP_P(( char *path, struct berval *bv ));
static char *read_one_record LDAP_P(( FILE *fp ));

static void
usage( const char *prog )
{
    fprintf( stderr,
		 "Add or modify entries from an LDAP server\n\n"
	     "usage: %s [-abcknrvF] [-M[M]] [-d debug-level] [-P version] [-h ldaphost]\n"
	     "            [-p ldapport] [-D binddn] [-w passwd] [ -f file | < entryfile ]\n"
	     "       a    - add values (default%s)\n"
	     "       b    - read values from files (for binary attributes)\n"
	     "       c    - continuous operation\n"
	     "       D    - bind DN\n"
		 "       M    - enable Manage DSA IT control (-MM for critical)\n"
	     "       d    - debug level\n"
	     "       f    - read from file\n"
	     "       F    - force all changes records to be used\n"
	     "       h    - ldap host\n"
	     "       n    - print adds, don't actually do them\n"
	     "       p    - LDAP port\n"
	     "       r    - replace values\n"
	     "       v    - verbose mode\n"
	     "       w    - password\n"
	     , prog, (strcmp( prog, "ldapadd" ) ? " is to replace" : "") );
    exit( EXIT_FAILURE );
}


int
main( int argc, char **argv )
{
    char		*infile, *rbuf, *start, *p, *q;
    FILE		*fp;
	int		rc, i, use_ldif, authmethod, version, want_bindpw, debug, manageDSAit;
	int count;

    if (( prog = strrchr( argv[ 0 ], *LDAP_DIRSEP )) == NULL ) {
	prog = argv[ 0 ];
    } else {
	++prog;
    }

    /* Print usage when no parameters */
    if( argc < 2 )
	usage( prog );

    new = ( strcmp( prog, "ldapadd" ) == 0 );

    infile = NULL;
    not = verbose = valsfromfiles = want_bindpw = debug = manageDSAit = 0;
    authmethod = LDAP_AUTH_SIMPLE;
	version = -1;

    while (( i = getopt( argc, argv, "WFMabckKnrtvh:p:D:w:d:f:P:" )) != EOF ) {
	switch( i ) {
	case 'a':	/* add */
	    new = 1;
	    break;
	case 'b':	/* read values from files (for binary attributes) */
	    valsfromfiles = 1;
	    break;
	case 'c':	/* continuous operation */
	    contoper = 1;
	    break;
	case 'r':	/* default is to replace rather than add values */
	    replace = 1;
	    break;
	case 'k':	/* kerberos bind */
#ifdef LDAP_API_FEATURE_X_OPENLDAP_V2_KBIND
		authmethod = LDAP_AUTH_KRBV4;
#else
		fprintf (stderr, "%s was not compiled with Kerberos support\n", argv[0]);
		usage( argv[0] );
		return( EXIT_FAILURE );
#endif
	    break;
	case 'K':	/* kerberos bind, part 1 only */
#ifdef LDAP_API_FEATURE_X_OPENLDAP_V2_KBIND
		authmethod = LDAP_AUTH_KRBV41;
#else
		fprintf (stderr, "%s was not compiled with Kerberos support\n", argv[0]);
		usage( argv[0] );
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
	    passwd = strdup( optarg );
		{
			char* p;

			for( p = optarg; *p == '\0'; p++ ) {
				*p = '*';
			}
		}
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
	default:
	    usage( prog );
	}
    }

    if ( argc != optind )
	usage( prog );

	if( authmethod != LDAP_AUTH_SIMPLE ) {
		if( version == LDAP_VERSION3 ) {
			fprintf(stderr, "Kerberos requires LDAPv2\n");
			return EXIT_FAILURE;
		}
		version = LDAP_VERSION2;
	}

	if( manageDSAit ) {
		if( version == LDAP_VERSION2 ) {
			fprintf(stderr, "manage DSA control requires LDAPv3\n");
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

	/* this seems prudent */
	{
		int deref = LDAP_DEREF_NEVER;
		ldap_set_option( ld, LDAP_OPT_DEREF, &deref);
	}
	/* don't chase referrals */
	ldap_set_option( ld, LDAP_OPT_REFERRALS, LDAP_OPT_OFF );

	if (version != -1 &&
		ldap_set_option( ld, LDAP_OPT_PROTOCOL_VERSION, &version ) != LDAP_OPT_SUCCESS)
	{
		fprintf( stderr, "Could not set LDAP_OPT_PROTOCOL_VERSION to %d\n", version );
	}

	if (want_bindpw)
		passwd = getpass("Enter LDAP Password: ");

	if ( ldap_bind_s( ld, binddn, passwd, authmethod ) != LDAP_SUCCESS ) {
	    ldap_perror( ld, "ldap_bind" );
	    return( EXIT_FAILURE );
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
			fprintf( stderr, "Could not set Manage DSA IT Control\n" );
			if( c.ldctl_iscritical ) {
				exit( EXIT_FAILURE );
			}
		}
	}

	count = 0;
    while (( rc == 0 || contoper ) &&
		( rbuf = read_one_record( fp )) != NULL ) {
	count++;
	/*
	 * we assume record is ldif/slapd.replog if the first line
	 * has a colon that appears to the left of any equal signs, OR
	 * if the first line consists entirely of digits (an entry id)
	 */
	use_ldif = ( *rbuf == '#' ) ||
		(( p = strchr( rbuf, ':' )) != NULL &&
		(  q = strchr( rbuf, '\n' )) != NULL && p < q &&
		(( q = strchr( rbuf, '=' )) == NULL || p < q ));

	start = rbuf;

	if ( !use_ldif && ( q = strchr( rbuf, '\n' )) != NULL ) {
	    for ( p = rbuf; p < q; ++p ) {
		if ( !isdigit( (unsigned char) *p )) {
		    break;
		}
	    }
	    if ( p >= q ) {
		use_ldif = 1;
		start = q + 1;
	    }
	}

	if ( use_ldif ) {
	    rc = process_ldif_rec( start, count );
	} else {
	    rc = process_ldapmod_rec( start );
	}

	if( rc )
	    fprintf( stderr, "%s() = %d\n",
		     use_ldif ? "ldif_rec" : "ldapmod_rec" , rc );

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
    char	*line, *dn, *type, *value, *newrdn, *newsup, *p;
    int		rc, linenum, modop, replicaport;
	ber_len_t vlen;
    int		expect_modop, expect_sep, expect_ct, expect_newrdn, expect_newsup;
    int		expect_deleteoldrdn, deleteoldrdn;
    int		saw_replica, use_record, new_entry, delete_entry, got_all;
    LDAPMod	**pmods;
	int version;

    new_entry = new;

    rc = got_all = saw_replica = delete_entry = expect_modop = 0;
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
	
	if ( ldif_parse_line( line, &type, &value, &vlen ) < 0 ) {
	    fprintf( stderr, "%s: invalid format (line %d) entry: \"%s\"\n",
		    prog, linenum, dn == NULL ? "" : dn );
	    rc = LDAP_PARAM_ERROR;
	    break;
	}

	if ( dn == NULL ) {
	    if ( !use_record && strcasecmp( type, T_REPLICA_STR ) == 0 ) {
		++saw_replica;
		if (( p = strchr( value, ':' )) == NULL ) {
		    replicaport = 0;
		} else {
		    *p++ = '\0';
		    replicaport = atoi( p );
		}
		if ( strcasecmp( value, ldaphost ) == 0 &&
			replicaport == ldapport ) {
		    use_record = 1;
		}
	    } else if ( count == 1 && linenum == 1 && 
			strcasecmp( type, T_VERSION_STR ) == 0 )
		{
			if( vlen == 0 || atoi(value) != 1 ) {
		    	fprintf( stderr, "%s: invalid version %s, line %d (ignored)\n",
			   	prog, value == NULL ? "(null)" : value, linenum );
			}
			version++;

	    } else if ( strcasecmp( type, T_DN_STR ) == 0 ) {
		if (( dn = strdup( value ? value : "" )) == NULL ) {
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
		ber_memfree( value );
		return( 0 );
	    }

	    if ( strcasecmp( type, T_CHANGETYPESTR ) == 0 ) {
		if ( strcasecmp( value, T_MODIFYCTSTR ) == 0 ) {
			new_entry = 0;
			expect_modop = 1;
		} else if ( strcasecmp( value, T_ADDCTSTR ) == 0 ) {
			new_entry = 1;
		} else if ( strcasecmp( value, T_MODRDNCTSTR ) == 0
			|| strcasecmp( value, T_MODDNCTSTR ) == 0
			|| strcasecmp( value, T_RENAMECTSTR ) == 0)
		{
		    expect_newrdn = 1;
		} else if ( strcasecmp( value, T_DELETECTSTR ) == 0 ) {
		    got_all = delete_entry = 1;
		} else {
		    fprintf( stderr,
			    "%s:  unknown %s \"%s\" (line %d of entry \"%s\")\n",
			    prog, T_CHANGETYPESTR, value, linenum, dn );
		    rc = LDAP_PARAM_ERROR;
		}
		goto end_line;
	    } else if ( new ) {		/*  missing changetype => add */
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
		addmodifyop( &pmods, modop, value, NULL, 0 );
		goto end_line;
	    } else if ( strcasecmp( type, T_MODOPDELETESTR ) == 0 ) {
		modop = LDAP_MOD_DELETE;
		addmodifyop( &pmods, modop, value, NULL, 0 );
		goto end_line;
	    } else {	/* no modify op:  use default */
		modop = replace ? LDAP_MOD_REPLACE : LDAP_MOD_ADD;
	    }
	}

	if ( expect_newrdn ) {
	    if ( strcasecmp( type, T_NEWRDNSTR ) == 0 ) {
		if (( newrdn = strdup( value )) == NULL ) {
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
		deleteoldrdn = ( *value == '0' ) ? 0 : 1;
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
		if (( newsup = strdup( value )) == NULL ) {
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
	    addmodifyop( &pmods, modop, type, value, vlen );
	}

end_line:
	ber_memfree( type );
	ber_memfree( value );
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
	    rc = domodrdn( dn, newrdn, deleteoldrdn );
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


static int
process_ldapmod_rec( char *rbuf )
{
    char	*line, *dn, *p, *q, *attr, *value;
    int		rc, linenum, modop;
    LDAPMod	**pmods;

    pmods = NULL;
    dn = NULL;
    linenum = 0;
    line = rbuf;
    rc = 0;

    while ( rc == 0 && rbuf != NULL && *rbuf != '\0' ) {
	++linenum;
	if (( p = strchr( rbuf, '\n' )) == NULL ) {
	    rbuf = NULL;
	} else {
	    if ( *(p-1) == '\\' ) {	/* lines ending in '\' are continued */
		SAFEMEMCPY( p - 1, p, strlen( p ) + 1 );
		rbuf = p;
		continue;
	    }
	    *p++ = '\0';
	    rbuf = p;
	}

	if ( dn == NULL ) {	/* first line contains DN */
	    if (( dn = strdup( line )) == NULL ) {
		perror( "strdup" );
		exit( EXIT_FAILURE );
	    }
	} else {
	    if (( p = strchr( line, '=' )) == NULL ) {
		value = NULL;
		p = line + strlen( line );
	    } else {
		*p++ = '\0';
		value = p;
	    }

	    for ( attr = line;
		  *attr != '\0' && isspace( (unsigned char) *attr ); ++attr ) {
		;	/* skip attribute leading white space */
	    }

	    for ( q = p - 1; q > attr && isspace( (unsigned char) *q ); --q ) {
		*q = '\0';	/* remove attribute trailing white space */
	    }

	    if ( value != NULL ) {
		while ( isspace( (unsigned char) *value )) {
		    ++value;		/* skip value leading white space */
		}
		for ( q = value + strlen( value ) - 1; q > value &&
			isspace( (unsigned char) *q ); --q ) {
		    *q = '\0';	/* remove value trailing white space */
		}
		if ( *value == '\0' ) {
		    value = NULL;
		}

	    }

	    if ( value == NULL && new ) {
		fprintf( stderr, "%s: missing value on line %d (attr=\"%s\")\n",
			prog, linenum, attr );
		rc = LDAP_PARAM_ERROR;
	    } else {
		 switch ( *attr ) {
		case '-':
		    modop = LDAP_MOD_DELETE;
		    ++attr;
		    break;
		case '+':
		    modop = LDAP_MOD_ADD;
		    ++attr;
		    break;
		default:
		    modop = replace ? LDAP_MOD_REPLACE : LDAP_MOD_ADD;
		}

		addmodifyop( &pmods, modop, attr, value,
			( value == NULL ) ? 0 : strlen( value ));
	    }
	}

	line = rbuf;
    }

    if ( rc == 0 ) {
	if ( dn == NULL ) {
	    rc = LDAP_PARAM_ERROR;
	} else if (( rc = domodify( dn, pmods, new )) == LDAP_SUCCESS ) {
	    rc = 0;
	}
    }

    if ( pmods != NULL ) {
	ldap_mods_free( pmods, 1 );
    }
    if ( dn != NULL ) {
	free( dn );
    }

    return( rc );
}


static void
addmodifyop( LDAPMod ***pmodsp, int modop, char *attr, char *value, int vlen )
{
    LDAPMod		**pmods;
    int			i, j;
    struct berval	*bvp;

    pmods = *pmodsp;
    modop |= LDAP_MOD_BVALUES;

    i = 0;
    if ( pmods != NULL ) {
	for ( ; pmods[ i ] != NULL; ++i ) {
	    if ( strcasecmp( pmods[ i ]->mod_type, attr ) == 0 &&
		    pmods[ i ]->mod_op == modop ) {
		break;
	    }
	}
    }

    if ( pmods == NULL || pmods[ i ] == NULL ) {
	if (( pmods = (LDAPMod **)ber_memrealloc( pmods, (i + 2) *
		sizeof( LDAPMod * ))) == NULL ) {
	    perror( "realloc" );
	    exit( EXIT_FAILURE );
	}
	*pmodsp = pmods;
	pmods[ i + 1 ] = NULL;
	if (( pmods[ i ] = (LDAPMod *)ber_memcalloc( 1, sizeof( LDAPMod )))
		== NULL ) {
	    perror( "calloc" );
	    exit( EXIT_FAILURE );
	}
	pmods[ i ]->mod_op = modop;
	if (( pmods[ i ]->mod_type = ber_strdup( attr )) == NULL ) {
	    perror( "strdup" );
	    exit( EXIT_FAILURE );
	}
    }

    if ( value != NULL ) {
	j = 0;
	if ( pmods[ i ]->mod_bvalues != NULL ) {
	    for ( ; pmods[ i ]->mod_bvalues[ j ] != NULL; ++j ) {
		;
	    }
	}
	if (( pmods[ i ]->mod_bvalues =
		(struct berval **)ber_memrealloc( pmods[ i ]->mod_bvalues,
		(j + 2) * sizeof( struct berval * ))) == NULL ) {
	    perror( "ber_realloc" );
	    exit( EXIT_FAILURE );
	}
	pmods[ i ]->mod_bvalues[ j + 1 ] = NULL;
	if (( bvp = (struct berval *)ber_memalloc( sizeof( struct berval )))
		== NULL ) {
	    perror( "ber_memalloc" );
	    exit( EXIT_FAILURE );
	}
	pmods[ i ]->mod_bvalues[ j ] = bvp;

	if ( valsfromfiles && *value == '/' ) {	/* get value from file */
	    if ( fromfile( value, bvp ) < 0 ) {
		exit( EXIT_FAILURE );
	    }
	} else {
	    bvp->bv_len = vlen;
	    if (( bvp->bv_val = (char *)ber_memalloc( vlen + 1 )) == NULL ) {
		perror( "malloc" );
		exit( EXIT_FAILURE );
	    }
	    SAFEMEMCPY( bvp->bv_val, value, vlen );
	    bvp->bv_val[ vlen ] = '\0';
	}
    }
}


static int
domodify( char *dn, LDAPMod **pmods, int newentry )
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
dodelete( char *dn )
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
domodrdn( char *dn, char *newrdn, int deleteoldrdn )
{
    int	rc;


    printf( "%smodifying rdn of entry \"%s\"\n", not ? "!" : "", dn );
    if ( verbose ) {
	printf( "\tnew RDN: \"%s\" (%skeep existing values)\n",
		newrdn, deleteoldrdn ? "do not " : "" );
    }
    if ( !not ) {
	if (( rc = ldap_modrdn2_s( ld, dn, newrdn, deleteoldrdn ))
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


static int
fromfile( char *path, struct berval *bv )
{
	FILE		*fp;
	long		rlen;
	int		eof;

	if (( fp = fopen( path, "r" )) == NULL ) {
	    	perror( path );
		return( -1 );
	}

	if ( fseek( fp, 0L, SEEK_END ) != 0 ) {
		perror( path );
		fclose( fp );
		return( -1 );
	}

	bv->bv_len = ftell( fp );

	if (( bv->bv_val = (char *)ber_memalloc( bv->bv_len )) == NULL ) {
		perror( "malloc" );
		fclose( fp );
		return( -1 );
	}

	if ( fseek( fp, 0L, SEEK_SET ) != 0 ) {
		perror( path );
		fclose( fp );
		ber_memfree( bv->bv_val );
		bv->bv_val = NULL;
		return( -1 );
	}

	rlen = fread( bv->bv_val, 1, bv->bv_len, fp );
	eof = feof( fp );
	fclose( fp );

	if ( (unsigned long) rlen != bv->bv_len ) {
		perror( path );
		ber_memfree( bv->bv_val );
		bv->bv_val = NULL;
		return( -1 );
	}

	return( bv->bv_len );
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
