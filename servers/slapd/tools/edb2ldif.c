/* $OpenLDAP$ */
/*
 * Copyright (c) 1995 Regents of the University of Michigan.
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

#include <ac/stdlib.h>

#include <ac/ctype.h>
#include <ac/errno.h>
#include <ac/dirent.h>
#include <ac/string.h>
#include <ac/unistd.h>

#include <sys/stat.h>

#include <quipu/config.h>
#include <quipu/entry.h>
#include <quipu/commonarg.h>
#include <quipu/attrvalue.h>

#if ICRELEASE > 1
#define HAVE_FILE_ATTR_DIR
#endif

#ifdef TURBO_DISK
#define HAVE_PARSE_ENTRY
#endif

#define DEF_EDBFILENAME		"EDB"
#define EDB_ROOT_FILENAME	"EDB.root"
#define DEF_BASEDN		""
#define EDBMAP_FILENAME		"EDB.map"
#define ADDVALS_FILENAME	".add"

#define MAX_LINE_SIZE	2048

#define VERBOSE_ENTRY_REPORT_THRESHOLD	250


/* data structures */
struct edbmap {
    char		*edbm_filename;
    char		*edbm_rdn;
    struct edbmap	*edbm_next;
};

/* prototypes */
static int edb2ldif( FILE *outfp, char *edbfile, char *basedn, int recurse );
static int convert_entry( FILE *fp, char *edbname, FILE *outfp,
	char *basedn, char *loc_addvals, int loc_addlen, char *linebuf );
static int add_rdn_values (Attr_Sequence entryas, RDN rdn);
static int read_edbmap( char *mapfile, struct edbmap **edbmapp );
static char *file2rdn( struct edbmap *edbmap, char *filename );
static void free_edbmap( struct edbmap *edbmap );
static char *read_file( char *filename, int *lenp );
static void print_err( char *msg );


/* globals */
#ifdef LDAP_DEBUG
static int	debugflg;
#endif
static int	verboseflg;
static int	override_add = 0;
static int	entrycount;
static char	**ignore_attr = NULL;
static char	*always_addvals = NULL;
static int	always_addlen;
static char	*last_dn;
static char	*edb_home = ".";
char		*progname;
int		ldap_syslog = 0;
int		ldap_syslog_level = 0;


int
main( int argc, char **argv )
{
    char	*usage = "usage: %s [-d] [-o] [-r] [-v] [-b basedn] [-a addvalsfile] [-f fileattrdir] [-i ignoreattr...] [edbfile...]\n";
    char	edbfile[ MAXNAMLEN ], *basedn;
    int		c, rc, errflg, ignore_count, recurse;
    extern char	dsa_mode;
#ifdef HAVE_FILE_ATTR_DIR
    extern char	*file_attr_directory;
#endif

    if (( progname = strrchr( argv[ 0 ], '/' )) == NULL ) {
	progname = argv[ 0 ];
    } else {
	++progname;
    }

    errflg = recurse = 0;
#ifdef LDAP_DEBUG
    debugflg = 0;
#endif
    ignore_count = 0;
    always_addvals = NULL;
    basedn = NULL;

    while (( c = getopt( argc, argv, "dorva:b:f:h:i:" )) != EOF ) {
	switch( c ) {
	case 'd':
#ifdef LDAP_DEBUG
	    ++debugflg;
#else
	    fprintf( stderr, "Ignoring -d:  compile with -DLDAP_DEBUG to enable this option.\n" );
#endif
	    break;

	case 'o':
	    ++override_add;	
	    break;

	case 'r':
	    ++recurse;	
	    break;

	case 'v':
	    ++verboseflg;
	    break;

	case 'a':
	    if ( always_addvals != NULL ) {
		++errflg;
	    } else if (( always_addvals = read_file( optarg, &always_addlen ))
		    == NULL ) {
		print_err( optarg );
		exit( EXIT_FAILURE );
	    }
	    break;

	case 'b':
	    if ( basedn != NULL ) {
		++errflg;
	    } else {
		basedn = optarg;
	    }
	    break;

	case 'f':
#ifdef HAVE_FILE_ATTR_DIR
	    /* add trailing slash to directory name if missing */
	    if ( *( optarg + strlen( optarg ) - 1 ) == '/' ) {
		file_attr_directory = strdup( optarg );
	    } else if (( file_attr_directory = (char *)malloc( strlen( optarg )
		    + 2 )) != NULL ) {
		sprintf( file_attr_directory, "%s/", optarg );
	
	    }
	    if ( file_attr_directory == NULL ) {
		print_err( "malloc" );
		exit( EXIT_FAILURE );
	    }
#else /* HAVE_FILE_ATTR_DIR */
	    fprintf( stderr, "Ignoring -f:  this option requires a newer version of ISODE.\n" );
#endif /* HAVE_FILE_ATTR_DIR */
	    break;

	case 'h':
	    edb_home = optarg;
	    break;

	case 'i':
	    if ( ignore_count == 0 ) {
		ignore_attr = (char **)malloc( 2 * sizeof( char * ));
	    } else {
		ignore_attr = (char **)realloc( ignore_attr,
		    ( ignore_count + 2 ) * sizeof( char * ));
	    }
	    if ( ignore_attr == NULL ) {
		print_err( "malloc/realloc" );
		exit( EXIT_FAILURE );
	    }
	    ignore_attr[ ignore_count ] = optarg;
	    ignore_attr[ ++ignore_count ] = NULL;
	    break;

	default:
	    ++errflg;
	}
    }

    if ( errflg ) {
	fprintf( stderr, usage, progname );
	exit( EXIT_FAILURE );
    }

    if ( basedn == NULL ) {
	basedn = DEF_BASEDN;
    }

    /* load & initialize quipu syntax handlers */
    quipu_syntaxes();
#ifdef LDAP_USE_PP
    pp_quipu_init( progname );
#endif
    dsap_init( NULL, NULL );

    dsa_mode = 1;	/* so {CRYPT} is accepted by EDB parse routines */

    if ( init_syntaxes() < 0 ) {
	fprintf( stderr, "%s: init_syntaxes failed -- check your oid tables \n",
	    progname );
	exit( EXIT_FAILURE );
    }


    entrycount = 0;

    /* process EDB file(s) */
    if ( optind >= argc ) {
	*edbfile = '\0';
	rc = edb2ldif( stdout, edbfile, basedn, recurse );
    } else {
	for ( rc = 0; rc >= 0 && optind < argc; ++optind ) {
	    if ( argv[ optind ][ 0 ] == '/' ) {
		strcpy( edbfile, argv[ optind ] );
	    } else {
		sprintf( edbfile, "%s/%s", edb_home, argv[ optind ] );
	    }
	    rc = edb2ldif( stdout, edbfile, basedn, recurse );
	}
    }

    if ( last_dn != NULL ) {
	free( last_dn );
    }

#ifdef LDAP_DEBUG
    fprintf( stderr, "edb2ldif: exit( %d )\n", ( rc < 0 ) ? 1 : 0 );
#endif

    exit( ( rc < 0 ) ? EXIT_FAILURE : EXIT_SUCCESS );
}


static int
edb2ldif( FILE *outfp, char *edbfile, char *basedn, int recurse )
{
    FILE	*fp;
    char	*addvals, *p, *rdn, line[ MAX_LINE_SIZE + 1 ];
    char	dirname[ MAXNAMLEN ], filename[ MAXNAMLEN ];
    int		err, startcount, addvals_len;
    struct stat	st;

#ifdef LDAP_DEBUG
    if ( debugflg ) {
	fprintf( stderr, "edb2ldif( 0x%X, \"%s\", \"%s\", %d)\n",
		outfp, edbfile, basedn, recurse );
    }
#endif

    if ( *edbfile == '\0' ) {
	sprintf( filename, "%s/%s", edb_home, EDB_ROOT_FILENAME );
	if ( stat( filename, &st ) == 0 ) {
	    if (( err = edb2ldif( outfp, filename, basedn, 0 )) < 0 ) {
#ifdef LDAP_DEBUG
		if ( debugflg ) {
		    fprintf( stderr, "edb2ldif: 0 return( %d )\n", err );
		}
#endif
		return( err );
	    }
	    if (( basedn = strdup( last_dn )) == NULL ) {
		print_err( "strdup" );
#ifdef LDAP_DEBUG
		if ( debugflg ) {
		    fprintf( stderr, "edb2ldif: 1 return( -1 )\n" );
		}
#endif
		return( -1 );
	    }
	}
	sprintf( edbfile, "%s/%s", edb_home, DEF_EDBFILENAME );
    }

    if ( verboseflg ) {
	fprintf( stderr, "%s: converting EDB file: \"%s\"\n\tbasedn: \"%s\"\n",
		progname, edbfile, basedn );
    }

    startcount = entrycount;
    err = 0;


    /* construct name of directory we are working in */
    if (( p = strrchr( edbfile, '/' )) == NULL ) {
	dirname[ 0 ] = '.';
	dirname[ 1 ] = '\0';
    } else {
	strncpy( dirname, edbfile, p - edbfile );
	dirname[ p - edbfile ] = '\0';
    }

    /* load local ".add" file (if any) */
    sprintf( filename, "%s/%s", dirname, ADDVALS_FILENAME );
    addvals_len = 0;
    addvals = read_file( filename, &addvals_len );

    /* read and convert this EDB file */
    if (( fp = fopen( edbfile, "r" )) == NULL ) {
	print_err( edbfile );
	if ( addvals != NULL ) {
	    free( addvals );
	}
#ifdef LDAP_DEBUG
	if ( debugflg ) {
	    fprintf( stderr, "edb2ldif: 2 return( -1 )\n" );
	}
#endif
	return( -1 );
    }

    /* skip first two lines (type and timestamp) if they are present */
    if ( fgets( line, MAX_LINE_SIZE, fp ) == NULL ) {
	err = -1;
    } else {
	line[ strlen( line ) - 1 ] = '\0';
	if ( strcmp( line, "MASTER" ) == 0 || strcmp( line, "SLAVE" ) == 0 ||
	    	strcmp( line, "CACHE" ) == 0 ) {
	    if ( fgets( line, MAX_LINE_SIZE, fp ) == NULL ) {
		err = -1;
	    }
	} else {
	    rewind( fp );
	}
    }

    if ( err != 0 ) {
	fprintf( stderr, "%s: skipping empty EDB file %s\n", progname,
		edbfile );
	err = 0;	/* treat as a non-fatal error */
    } else {
	while ( !feof( fp ) && ( err = convert_entry( fp, edbfile, outfp,
		basedn, addvals, addvals_len, line )) > 0 ) {
	    if ( verboseflg && (( entrycount - startcount ) %
		    VERBOSE_ENTRY_REPORT_THRESHOLD ) == 0 ) {
		fprintf( stderr, "\tworking... %d entries done...\n", 
			entrycount - startcount );
	    }
	}
    }

    fclose( fp );
    if ( addvals != NULL ) {
	free( addvals );
    }

    if ( err < 0 ) {
#ifdef LDAP_DEBUG
	if ( debugflg ) {
	    fprintf( stderr, "edb2ldif: 3 return( %d )\n", err );
	}
#endif
	return( err );
    }

    if ( verboseflg ) {
	fprintf( stderr, "\t%d entries converted\n\n", 
		entrycount - startcount );
    }

    /* optionally convert EDB file within sub-directories */
    if ( recurse ) {
	char		*newbase;
	DIR		*dp;
	struct dirent	*dep;
	struct edbmap	*edbmap;

	/* open this directory */
	if (( dp = opendir( dirname )) == NULL ) {
	    print_err( dirname );
#ifdef LDAP_DEBUG
	    if ( debugflg ) {
		fprintf( stderr, "edb2ldif: 4 return( -1 )\n" );
	    }
#endif
	    return( -1 );
	}

	/* check for EDB.map file and record contents for future reference */
	sprintf( filename, "%s/%s", dirname, EDBMAP_FILENAME );
	if ( read_edbmap( filename, &edbmap ) < 0 ) {
	    print_err( "read_edbmap" );
	    closedir( dp );
#ifdef LDAP_DEBUG
	    if ( debugflg ) {
		fprintf( stderr, "edb2ldif: 5 return( -1 )\n" );
	    }
#endif
	    return( -1 );
	}

	p = dirname + strlen( dirname );
	*p++ = '/';
	*p = '\0';

	/* scan looking for sub-directories w/EDB files in them */
	err = 0;
	while ( err >= 0 && ( dep = readdir( dp )) != NULL ) {
	    if ( dep->d_name[ 0 ] == '.' && ( dep->d_name[ 1 ] == '\0' ||
		    ( dep->d_name[ 1 ] == '.' && dep->d_name[ 2 ] == '\0' ))) {
		continue;	/* skip "." and ".." */
	    }

	    strcpy( p, dep->d_name );
#ifdef LDAP_DEBUG
	    if ( debugflg ) {
		fprintf( stderr, "edb2ldif: checking directory \"%s\"\n",
			dirname );
	    }
#endif

	    if ( stat( dirname, &st ) != 0 ) {
		print_err( dirname );
	    } else if ( S_ISDIR( st.st_mode )) {
		sprintf( filename, "%s/%s", dirname, DEF_EDBFILENAME );

		if ( stat( filename, &st ) == 0 && S_ISREG( st.st_mode )) {
		    if (( newbase = malloc( strlen( basedn ) +
			    strlen( dep->d_name ) + 3 )) == NULL ) {
			print_err( "malloc" );
			err = -1;
			continue;
		    }

		    sprintf( newbase, "%s@%s", basedn,
			    file2rdn( edbmap, dep->d_name ));

		    /* recurse */
		    err = edb2ldif( outfp, filename, newbase, recurse );

		    free( newbase );
		}
	    }
	}

	free_edbmap( edbmap );
	closedir( dp );

	if ( verboseflg ) {
	    fprintf( stderr, "%s: %d total entries converted under \"%s\"\n\n",
		    progname, entrycount - startcount, basedn );
	}
    }

#ifdef LDAP_DEBUG
    if ( debugflg ) {
	fprintf( stderr, "edb2ldif: 6 return( %d )\n", err );
    }
#endif
    return( err );
}


/*
 * read one entry from fp and write to outfp.
 * return > 0 if entry converted, 0 if end of file, < 0 if error occurs
 */
static int
convert_entry(
    FILE	*fp,
    char	*edbname,
    FILE	*outfp,
    char	*basedn,
    char	*loc_addvals,
    int		loc_addlen,
    char	*linebuf
)
{
    Attr_Sequence	as, tmpas;
    AV_Sequence		av;
    PS			attrtype_ps, val_ps;
    char		*dnstr;
    DN			dn;
    RDN			rdn;
    int			valcnt;
    extern int		parse_status;
    extern char		*parse_file;
    extern RDN		parse_rdn;
#ifdef HAVE_PARSE_ENTRY
    extern char		*parse_entry;
    extern Attr_Sequence	fget_attributes();
#else /* HAVE_PARSE_ENTRY */
    extern Attr_Sequence	get_attributes();
#endif /* HAVE_PARSE_ENTRY */

#ifdef LDAP_DEBUG
    if ( debugflg ) {
	fprintf( stderr, "convert_entry( 0x%X, \"%s\", 0x%X, \"%s\", ...)\n",
		fp, edbname, outfp, basedn );
    }
#endif

    while (( dnstr = fgets( linebuf, MAX_LINE_SIZE, fp )) != NULL &&
	    *linebuf == '\n' ) {
	;
    }

    if ( dnstr == NULL ) {
	return( feof( fp ) ? 0 : -1 );	/* end of file or error */
    }

    linebuf[ strlen( linebuf ) - 1 ] = '\0';

    if (( dnstr = malloc( strlen( basedn ) + strlen( linebuf ) + 2 ))
	    == NULL ) {
	print_err( "convert_entry" );
	return( -1 );
    }
    sprintf( dnstr, "%s@%s", basedn, linebuf );
    if ( last_dn != NULL ) {
	free( last_dn );
    }
    last_dn = dnstr;

    if ( entrycount > 0 ) {
	fputc( '\n', outfp );
    }

    /*
     * parse_entry, parse_file and parse_rdn are needed inside the
     * libisode decoding routines, so we set it here.
     */
    parse_file = edbname;
#ifdef HAVE_PARSE_ENTRY
    parse_entry = dnstr;
#endif
    parse_rdn = rdn = str2rdn( linebuf );

    if (( val_ps = ps_alloc( str_open )) == NULLPS ||
	    str_setup( val_ps, NULLCP, 0, 0 ) == NOTOK ) {
	fprintf( stderr, "%s: ps_alloc/setup failed (EDB file %s)\n", progname,
		edbname );
	if ( rdn != NULLRDN ) {
	    rdn_free( rdn );
	}
	return( -1 );
    }

    if (( dn = str2dn( dnstr )) == NULLDN || av2ldif( outfp, NULL, dn,
	    0, "dn", val_ps ) < 0 ) {
	sprintf( linebuf,
		"str2dn or av2ldif of DN failed (EDB file %s, entry %s)\n", 
		edbname, dnstr );
	print_err( linebuf );
	if ( dn != NULLDN ) {
	    dn_free( dn );
	}
	ps_free( val_ps );
	if ( rdn != NULLRDN ) {
	    rdn_free( rdn );
	}
	return( -1 );
    }
    dn_free( dn );

    ++entrycount;

    if ( always_addvals != NULL && ( loc_addvals == NULL || !override_add )
	    && fwrite( always_addvals, always_addlen, 1, outfp ) != 1 ) {
	sprintf( linebuf,
		"write of additional values failed (EDB file %s, entry %s)\n", 
		edbname, dnstr );
	print_err( linebuf );
	ps_free( val_ps );
	if ( rdn != NULLRDN ) {
	    rdn_free( rdn );
	}
	return( -1 );
    }

    if ( loc_addvals != NULL && fwrite( loc_addvals, loc_addlen, 1,
	    outfp ) != 1 ) {
	sprintf( linebuf,
		"write of additional values failed (EDB file %s, entry %s)\n", 
		edbname, dnstr );
	print_err( linebuf );
	ps_free( val_ps );
	if ( rdn != NULLRDN ) {
	    rdn_free( rdn );
	}
	return( -1 );
    }


#ifdef HAVE_PARSE_ENTRY
    as = fget_attributes( fp );
#else /* HAVE_PARSE_ENTRY */
    as = get_attributes( fp );
#endif /* HAVE_PARSE_ENTRY */

    if ( parse_status != 0 ) {
	fprintf( stderr, "%s: problem parsing entry (EDB file %s)\n", progname,
		edbname );
	ps_free( val_ps );
	if ( as != NULLATTR ) {
	    as_free( as );
	}
	if ( rdn != NULLRDN ) {
	    rdn_free( rdn );
	}
	return( -1 );
    }

    if ( add_rdn_values( as, rdn ) != 0 ) {
	sprintf( linebuf,
	    "adding RDN values(s) failed (EDB file %s, entry %s)\n", 
	    edbname, dnstr );
	print_err( linebuf );
	if ( as != NULLATTR ) {
	    as_free( as );
	}
	if ( rdn != NULLRDN ) {
	    rdn_free( rdn );
	}
	return( -1 );
    }

    if (( attrtype_ps = ps_alloc( str_open )) == NULLPS ||
	    str_setup( attrtype_ps, NULLCP, 0, 0 ) == NOTOK ) {
	fprintf( stderr, "%s: ps_alloc/setup failed (EDB file %s)\n", progname,
		edbname );
	if ( as != NULLATTR ) {
	    as_free( as );
	}
	if ( rdn != NULLRDN ) {
	    rdn_free( rdn );
	}
	return( -1 );
    }

    for ( tmpas = as; tmpas != NULLATTR; tmpas = tmpas->attr_link ) {
	attrtype_ps->ps_ptr = attrtype_ps->ps_base;
	AttrT_print( attrtype_ps, tmpas->attr_type, EDBOUT );
	*attrtype_ps->ps_ptr = '\0';

	if ( ignore_attr != NULL ) {
	    int	i;

	    for ( i = 0; ignore_attr[ i ] != NULL; ++i ) {
		if ( strcasecmp( attrtype_ps->ps_base, ignore_attr[ i ] )
			== 0 ) {
		    break;
		}
	    }
	    if ( ignore_attr[ i ] != NULL ) {
		continue;	/* skip this attribute */
	    }
	}

	valcnt = 0;
	for ( av = tmpas->attr_value; av != NULLAV; av = av->avseq_next ) {
	    ++valcnt;
	    if ( av2ldif( outfp, av, NULL, tmpas->attr_type->oa_syntax,
		    attrtype_ps->ps_base, val_ps ) < 0 ) {
		sprintf( linebuf,
			"av2ldif failed (EDB file %s, entry %s, attribute %s, value no. %d)\n", 
			edbname, dnstr, attrtype_ps->ps_base, valcnt );
		print_err( linebuf );
		ps_free( attrtype_ps );
		ps_free( val_ps );
		as_free( as );
		if ( rdn != NULLRDN ) {
		    rdn_free( rdn );
		}
		return( -1 );
	    }
	}
    }

    ps_free( attrtype_ps );
    ps_free( val_ps );
    as_free( as );
    if ( rdn != NULLRDN ) {
	rdn_free( rdn );
    }

    return( 1 );
}


static int
add_rdn_values( Attr_Sequence entryas, RDN rdn )
{
/*
 * this routine is based on code from the real_unravel_attribute() routine
 * found in isode-8.0/.dsap/common/attribute.c
 */
    AttributeType	at;
    AV_Sequence   	avs;
    Attr_Sequence	as;

    for (; rdn != NULLRDN; rdn = rdn->rdn_next ) {
	if (( as = as_find_type( entryas, rdn->rdn_at )) == NULLATTR ) {
	    at = AttrT_cpy( rdn->rdn_at );
	    avs = avs_comp_new( AttrV_cpy(&rdn->rdn_av ));
	    as  = as_comp_new( at, avs, NULLACL_INFO );
	    entryas = as_merge( entryas, as );
	} else {
	    for ( avs = as->attr_value; avs != NULLAV; avs = avs->avseq_next ) {
		if ( AttrV_cmp( &rdn->rdn_av, &avs->avseq_av ) == 0 ) {
		    break;
		}
	    }

	    if ( avs == NULLAV ) {
		avs = avs_comp_new( AttrV_cpy( &rdn->rdn_av ));
		as->attr_value = avs_merge( as->attr_value, avs );
	    }
	}
    }

    return( 0 );
}


/* read the EDB.map file and return a linked list of translations */
static int
read_edbmap( char *mapfile, struct edbmap **edbmapp )
{
    FILE		*fp;
    char		*p, *filename, *rdn, line[ MAX_LINE_SIZE + 1 ];
    int			err;
    struct edbmap	*emp, *tmpemp;

#ifdef LDAP_DEBUG
    if ( debugflg ) {
	fprintf( stderr, "read_edbmap( \"%s\", ...)\n", mapfile );
    }
#endif

    if (( fp = fopen( mapfile, "r" )) == NULL ) {
	*edbmapp = NULL;
	return( 0 );	/* soft error -- no EDB.map file */
    }

    emp = NULL;

    /*
     * read all the lines in the file, looking for lines of the form:
     *	RDN # filename
     */
    err = 0;
    while ( err == 0 && fgets( line, MAX_LINE_SIZE, fp ) != NULL ) {
	line[ strlen( line ) - 1 ] = '\0';	/* remove trailing newline */
	if (( filename = strchr( line, '#' )) == NULL ) {
	    continue;
	}

	*filename++ = '\0';
	while ( isspace((unsigned char) *filename) ) { /* strip leading whitespace */
	    ++filename;
	}

	if ( *filename == '\0' ) {
	    continue;
	}

	p = filename + strlen( filename ) - 1;
	while ( isspace((unsigned char) *p) ) { /* strip trailing whitespace */
	    *p-- = '\0';
	}

	rdn = line;
	while ( isspace((unsigned char) *rdn)) { /* strip leading whitespace */
	    ++rdn;
	}

	if ( *rdn == '\0' ) {
	    continue;
	}

	p = rdn + strlen( rdn ) - 1;
	while ( isspace((unsigned char) *p)) { /* strip trailing whitespace */
	    *p-- = '\0';
	}

	if (( tmpemp = (struct edbmap *)calloc( 1, sizeof( struct edbmap )))
		== NULL ||
		( tmpemp->edbm_filename = strdup( filename )) == NULL ||
		( tmpemp->edbm_rdn = strdup( rdn )) == NULL ) {
	    err = -1;
	} else {
	    tmpemp->edbm_next = emp;
	    emp = tmpemp;
	}
    }

    fclose( fp );

    if ( err == 0 ) {
	*edbmapp = emp;
    } else {
	free_edbmap( emp );
    }

    return( err );
}


static char *
file2rdn( struct edbmap *edbmap, char *filename )
{
#ifdef LDAP_DEBUG
    if ( debugflg ) {
	fprintf( stderr, "file2rdn( 0x%X, \"%s\" )\n", edbmap, filename );
    }
#endif

    while ( edbmap != NULL ) {
	if ( strcmp( filename, edbmap->edbm_filename ) == 0 ) {
	    break;
	}
	edbmap = edbmap->edbm_next;
    }

    return(( edbmap == NULL ) ? filename : edbmap->edbm_rdn );
}


/* free the edbmap list */
static void
free_edbmap( struct edbmap *edbmap )
{
    struct edbmap	*tmp;

#ifdef LDAP_DEBUG
    if ( debugflg ) {
	fprintf( stderr, "free_edbmap( 0x%X )\n", edbmap );
    }
#endif

    while ( edbmap != NULL ) {
	if ( edbmap->edbm_filename != NULL ) free( edbmap->edbm_filename );
	if ( edbmap->edbm_rdn != NULL ) free( edbmap->edbm_rdn );
	tmp = edbmap;
	edbmap = edbmap->edbm_next;
	free( tmp );
    }
}


static void
print_err( char *msg )
{
#ifdef LDAP_DEBUG
    if ( debugflg ) {
	fprintf( stderr, "print_err( \"%s\" )\n", msg );
    }
#endif

    if ( errno > sys_nerr ) {
	fprintf( stderr, "%s: %s: errno=%d\n", progname, msg, errno );
    } else {
	fprintf( stderr, "%s: %s: %s\n", progname, msg, sys_errlist[ errno ] );
    }
}


static char *
read_file( char *filename, int *lenp )
{
    FILE	*fp;
    struct stat	st;
    char	*buf;

#ifdef LDAP_DEBUG
    if ( debugflg ) {
	fprintf( stderr, "read_file( \"%s\", 0x%X )\n", filename, lenp );
    }
#endif

    if ( stat( filename, &st ) != 0 || !S_ISREG( st.st_mode ) ||
	    ( fp = fopen( filename, "r" )) == NULL ) {
	return( NULL );
    }

    if (( buf = (char *)malloc( st.st_size )) == NULL ) {
	fclose( fp );
	return( NULL );
    }

    if ( fread( buf, st.st_size, 1, fp ) != 1 ) {
	fclose( fp );
	free( buf );
	return( NULL );
    }

    fclose( fp );
    *lenp = st.st_size;
    return( buf );
}
