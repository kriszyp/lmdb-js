/* centipede.c - generate and install indexing information (view w/tabstop=4) */
/* $OpenLDAP$ */

#include "portable.h"

#include <stdio.h>
#include <ac/stdlib.h>

#include <ac/ctype.h>
#include <ac/string.h>
#include <ac/time.h>
#include <ac/unistd.h>		/* get link(), unlink() */

#include <ldap.h>
#include <ldbm.h>

int	slap_debug;

#define DEFAULT_LDAPFILTER	"(objectclass=*)"

#define CENTROID_VALUE	1
#define CENTROID_WORD	2

#define CENTROID_RELATIVE	1
#define CENTROID_FULL		2

#define WORD_BREAKS	" -',.()!;:&$%*\"/\\+_<>=?[]|^~"

char	*centdir;
int		ldbmcachesize;
int		centroidvalues;
int		centroidtype;
int		doweights;
char	*ldaphost;
char	*srcldapbinddn;
char	*srcldappasswd;
char	*destldapbinddn;
char	*destldappasswd;
char	*ldapbase;
int		srcldapauthmethod;
int		destldapauthmethod;
int		verbose;
int		not;

static LDAP		*start_ldap_search(char *ldapsrcurl, char *ldapfilter, char **attrs);
static LDAP		*bind_to_destination_ldap(char *ldapsrcurl, char *ldapdesturl);
static int		create_tmp_files(char **attrs, char ***tmpfile, LDBM **ldbm);
static int		generate_new_centroids(LDAP *ld, char **attrs, LDBM *ldbm);
static LDAPMod	**diff_centroids(char *attr, LDBM oldbm, LDBM nldbm, int nentries);
static LDAPMod	**full_centroid(char *attr, LDBM ldbm, int nentries);
static char		**charray_add_dup(char ***a, int *cur, int *max, char *s);

static void usage( char *name )
{
	fprintf( stderr, "usage: %s [options] -s url -d url attributes\n", name );
	fprintf( stderr, "where:\n" );
	fprintf( stderr, "\t-s url\t\t[[ldap://][host[:port]]/]searchbasedn\n");
	fprintf( stderr, "\t-d url\t\t[[ldap://][host[:port]]/]centroidentrydn\n");
	fprintf( stderr, "options:\n" );
	fprintf( stderr, "\t-v \t\tturn on verbose mode\n" );
	fprintf( stderr, "\t-n \t\tgenerate, but do not install index info\n" );
	fprintf( stderr, "\t-f filter\tentry selection filter\n" );
	fprintf( stderr, "\t-F \t\tgenerate a full centroid\n" );
	fprintf( stderr, "\t-R \t\tgenerate a relative centroid\n" );
	fprintf( stderr, "\t-w \t\tgenerate a word-based centroid\n" );
	fprintf( stderr, "\t-t directory\tcentroid directory\n" );
	fprintf( stderr, "\t-b binddn\tsource bind dn\n" );
	fprintf( stderr, "\t-p passwd\tsource bind passwd (for simple auth)\n" );
	fprintf( stderr, "\t-m authmethod\tsource authmethod \"simple\" or \"kerberos\"\n" );
	fprintf( stderr, "\t-B binddn\tdestination bind dn\n" );
	fprintf( stderr, "\t-P passwd\tdestination bind passwd (for simple auth)\n" );
	fprintf( stderr, "\t-M authmethod\tdestination authmethod \"simple\" or \"kerberos\"\n" );
	fprintf( stderr, "\t-c size\t\tldbm cache size\n" );
}

int
main( int argc, char **argv )
{
	char		*ldapfilter;
	char		*ldapsrcurl, *ldapdesturl;
	LDAP		*ld;
	LDAPMod		**mods;
	char		**attrs;
	char		**tmpfile;
	LDBM		*ldbm;
	LDBM		oldbm;
	char		buf[BUFSIZ];
	int			i, j, k, count;
	char		*s;

	ldapsrcurl = NULL;
	ldapdesturl = NULL;
	ldaphost = NULL;
	ldapbase = NULL;
	srcldapauthmethod = LDAP_AUTH_SIMPLE;
	destldapauthmethod = LDAP_AUTH_SIMPLE;
	srcldapbinddn = NULL;
	srcldappasswd = NULL;
	destldapbinddn = NULL;
	destldappasswd = NULL;
	ldapfilter = DEFAULT_LDAPFILTER;
	centroidvalues = CENTROID_VALUE;
	centroidtype = CENTROID_RELATIVE;
	centdir = NULL;
	tmpfile = NULL;
	ldbmcachesize = 0;

	while ( (i = getopt( argc, argv, "s:d:c:b:B:f:FRWp:P:m:M:t:vwn" ))
	    != EOF ) {
		switch ( i ) {
		case 's':	/* source url [[ldap://][host[:port]]/]basedn */
			ldapsrcurl = strdup( optarg );
			break;

		case 'd':	/* destination url [[ldap://][host[:port]]/]entrydn */
			ldapdesturl = strdup( optarg );
			break;

		case 'f':	/* specify a filter */
			ldapfilter = strdup( optarg );
			break;

		case 'F':	/* generate full centroid */
			centroidtype = CENTROID_FULL;
			break;

		case 'R':	/* generate relative centroid */
			centroidtype = CENTROID_RELATIVE;
			break;

		case 'w':	/* generate word centroid */
			centroidvalues = CENTROID_WORD;
			break;

		case 'W':	/* generate weights */
			doweights = 1;
			break;

		case 't':	/* temp file directory */
			centdir = strdup( optarg );
			break;

		case 'b':	/* src bind dn */
			srcldapbinddn = strdup( optarg );
			break;

		case 'p':	/* src bind password */
			srcldappasswd = strdup( optarg );
			while ( *optarg )
				*optarg++ = 'x';
			break;

		case 'B':	/* dest bind dn */
			destldapbinddn = strdup( optarg );
			break;

		case 'P':	/* dest bind password */
			destldappasswd = strdup( optarg );
			while ( *optarg )
				*optarg++ = 'x';
			break;

		case 'm':	/* src bind method */
			if ( strcasecmp( optarg, "simple" ) == 0 ) {
				srcldapauthmethod = LDAP_AUTH_SIMPLE;
			} else if ( strcasecmp( optarg, "kerberos" ) == 0 ) {
				srcldapauthmethod = LDAP_AUTH_KRBV4;
			} else {
				fprintf( stderr, "%s: unknown auth method\n", optarg );
				fputs( "expecting \"simple\" or \"kerberos\"\n", stderr );
				exit( EXIT_FAILURE );
			}
			break;

		case 'M':	/* dest bind method */
			if ( strcasecmp( optarg, "simple" ) == 0 ) {
				destldapauthmethod = LDAP_AUTH_SIMPLE;
			} else if ( strcasecmp( optarg, "kerberos" ) == 0 ) {
				destldapauthmethod = LDAP_AUTH_KRBV4;
			} else {
				fprintf( stderr, "%s: unknown auth method\n", optarg );
				fputs( "expecting \"simple\" or \"kerberos\"\n", stderr );
				exit( EXIT_FAILURE );
			}
			break;

		case 'c':	/* ldbm cache size */
			ldbmcachesize = atoi( optarg );
			break;

		case 'v':	/* turn on verbose mode */
			verbose++;
			break;

		case 'n':	/* don't actually install index info */
			not++;
			break;

		default:
			usage( argv[0] );
			exit( EXIT_FAILURE );
		}
	}
	if ( optind == argc || ldapsrcurl == NULL || ldapdesturl == NULL ) {
		usage( argv[0] );
		exit( EXIT_FAILURE );
	}
	attrs = &argv[optind];

	/*
	 * open the ldap connection and start searching for the entries
	 * we will use to generate the centroids.
	 */

	if ( (ld = start_ldap_search( ldapsrcurl, ldapfilter, attrs )) == NULL ) {
		fprintf( stderr, "could not initiate ldap search\n" );
		exit( EXIT_FAILURE );
	}

	if ( create_tmp_files( attrs, &tmpfile, &ldbm ) != 0 ) {
		fprintf( stderr, "could not create temp files\n" );
		exit( EXIT_FAILURE );
	}

	/*
	 * go through the entries returned, building a centroid for each
	 * attribute as we go.
	 */

	if ( (count = generate_new_centroids( ld, attrs, ldbm )) < 1 ) {
		if ( count == 0 ) {
		    fprintf( stderr, "no entries matched\n" );
		    exit( EXIT_SUCCESS );
		} else {
		    fprintf( stderr, "could not generate new centroid\n" );
		    exit( EXIT_FAILURE );
		}
	}

	/*
	 * for each centroid we generated above, compare to the existing
	 * centroid, if any, and produce adds and deletes, or produce
	 * an entirely new centroid. in either case, update the "current"
	 * centroid version with the new one we just generated.
	 */

	if ( (ld = bind_to_destination_ldap( ldapsrcurl, ldapdesturl )) == NULL ) {
		fprintf( stderr,
		  "could not bind to index server, or could not create index entry\n" );
		exit( EXIT_FAILURE );
	}

	for ( i = 0; ldbm[i] != NULL; i++ ) {
		/* generate the name of the existing centroid, if any */
		s = strrchr( tmpfile[i], '/' );
		*s = '\0';
		sprintf( buf, "%s/cent.%s", tmpfile[i], attrs[i] );
		*s = '/';

		/* generate the full centroid changes */
		if ( centroidtype == CENTROID_FULL || (oldbm = ldbm_open( buf,
		  LDBM_WRITER, 0, ldbmcachesize )) == NULL ) {
			if ( (mods = full_centroid( attrs[i], ldbm[i], count )) == NULL ) {
				fprintf( stderr, "could not produce full centroid for %s\n",
				  attrs[i] );
				continue;
			}

		/* generate the differential centroid changes */
		} else {
			if ( (mods = diff_centroids( attrs[i], oldbm, ldbm[i], count ))
			  == NULL ) {
				fprintf( stderr, "could not diff centroids\n" );
				ldbm_close( oldbm );
				continue;
			}
			ldbm_close( oldbm );
		}

		if ( verbose > 1 ) {
			printf("changes:\n");
			for ( j = 0; mods[j] != NULL; j++ ) {
				switch( mods[j]->mod_op ) {
				case LDAP_MOD_ADD:
					printf( "\tadd: %s\n",mods[j]->mod_type );
					break;
				case LDAP_MOD_DELETE:
					printf( "\tdelete: %s\n",mods[j]->mod_type );
					break;
				case LDAP_MOD_REPLACE:
					printf( "\treplace: %s\n",mods[j]->mod_type );
					break;
				}
				if ( mods[j]->mod_values != NULL ) {
					for ( k = 0; mods[j]->mod_values[k] != NULL; k++ ) {
						printf( "\t\t%s\n", mods[j]->mod_values[k] );
					}
				}
			}
			printf("end changes:\n");
		}

		if ( verbose ) {
			printf( "%sModifying centroid...", not ? "Not " : "" );
			fflush( stdout );
		}

		/* attempt to make the changes to the index server entry */
		if ( !not && ldap_modify_s( ld, ldapbase, mods ) != LDAP_SUCCESS ) {
			fprintf( stderr, "could not apply centroid modification for %s\n",
			  attrs[i] );
			ldap_perror( ld, ldapbase );
		}
		ldap_mods_free( mods, 1 );

		if ( verbose ) {
			printf( "\n" );
			fflush( stdout );
		}

		/* move the new centroid into the old one's place */
		if ( ! not ) {
			(void) unlink( buf );
			if ( link( tmpfile[i], buf ) != 0 ) {
				perror( "link" );
				fprintf( stderr, "could not rename %s to %s\n", buf,
				  tmpfile[i] );
				continue;
			}
		}
		(void) unlink( tmpfile[i] );
	}

	/* clean up */
	for ( i = 0; attrs[i] != NULL; i++ ) {
		ldbm_close( ldbm[i] );
		free( tmpfile[i] );
	}
	free( ldbm );
	free( tmpfile );

	exit( EXIT_SUCCESS );
}

/*
 * open an ldap connection, bind, and initiate the search
 */

static LDAP *
start_ldap_search(
	char	*ldapsrcurl,
	char	*ldapfilter,
	char	**attrs
)
{
	LDAP	*ld;
	char	*s, *s2;
	int		i;

	if ( strncmp( ldapsrcurl, "ldap://", 7 ) != 0 ) {
		fputs( "Not an LDAP URL", stderr ); /* Should be smarter? */
		return( NULL );
	}
	s = ldapsrcurl + 7;
	if ( (s2 = strchr( s, '/' )) == NULL ) {
		ldapbase = strdup( s );
	} else {
		if ( *s != '/' ) {
			*s2 = '\0';
			ldaphost = strdup( s );
			*s2 = '/';
		}
		ldapbase = strdup( s2 + 1 );
	}

	if ( verbose ) {
		printf( "Base: %s\n", ldapbase );
		printf( "Attributes:" );
		for ( i = 0; attrs[i] != NULL; i++ ) {
			printf( " %s", attrs[i] );
		}
		printf( "\n" );
		printf( "Binding to source LDAP server..." );
		fflush( stdout );
	}

	if ( (ld = ldap_init( ldaphost, 0 )) == NULL ) {
		perror( "ldap_init" );
		return( NULL );
	}

	if ( ldap_bind_s( ld, srcldapbinddn, srcldappasswd, srcldapauthmethod )
	  != LDAP_SUCCESS) {
		ldap_perror( ld, "ldap_bind_s" );
		ldap_unbind( ld );
		return( NULL );
	}

	printf( "\nInitiating search..." );
	if ( ldap_search( ld, ldapbase, LDAP_SCOPE_SUBTREE, ldapfilter, attrs, 0 )
	  == -1 ) {
		ldap_perror( ld, "ldap_search" );
		ldap_unbind( ld );
		return( NULL );
	}

	if ( verbose ) {
		printf( "\n" );
	}

	return( ld );
}

/*
 * create the temporary ldbm files we will use to hold the new centroids
 */

static int
create_tmp_files(
	char	**attrs,
	char	***tmpfile,
	LDBM	**ldbm
)
{
	int	i;

	for ( i = 0; attrs[i] != NULL; i++ )
		;	/* NULL */
	i++;

	if ( (*tmpfile = (char **) malloc( i * sizeof(char *) )) == NULL ) {
		perror( "malloc" );
		return( -1 );
	}
	if ( (*ldbm = (LDBM *) malloc( i * sizeof(LDBM) )) == NULL ) {
		perror( "malloc" );
		return( -1 );
	}
	for ( i = 0; attrs[i] != NULL; i++ ) {
		if ( ((*tmpfile)[i] = tempnam( centdir, NULL )) == NULL ) {
			perror( "tmpnam" );
			return( -1 );
		}

		if ( ((*ldbm)[i] = ldbm_open( (*tmpfile)[i], LDBM_WRCREAT, 0600,
		  ldbmcachesize )) == NULL ) {
			fprintf( stderr, "ldbm_open of \"%s\" failed\n", (*tmpfile)[i] );
			perror( "ldbm_open" );
			return( -1 );
		}
	}
	(*tmpfile)[i] = NULL;
	(*ldbm)[i] = NULL;

	return( 0 );
}

/*
 * step through each entry returned from the search and generate
 * the appropriate centroid values.
 */

static int
generate_new_centroids(
	LDAP	*ld,
	char	**attrs,
	LDBM	*ldbm
)
{
	Datum		key, data;
	int			rc, i, j, count;
	LDAPMessage	*res, *e;
	char		*dn, *s, *w;
	char		**val;
	char		last;

	ldbm_datum_init( data );

	if ( verbose ) {
		printf( "Generating new centroids for..." );
		fflush( stdout );
	}

	data.dptr = "";
	data.dsize = 1;
	count = 0;
	while ( (rc = ldap_result( ld, LDAP_RES_ANY, 0, NULL, &res ))
	  == LDAP_RES_SEARCH_ENTRY ) {
		count++;
		e = ldap_first_entry( ld, res );
		dn = ldap_get_dn( ld, e );

		/* for each attr we want to generate a centroid for */
		for ( i = 0; attrs[i] != NULL; i++ ) {
			if ( (val = ldap_get_values( ld, e, attrs[i] )) == NULL ) {
				continue;
			}

			/* for each value */
			for ( j = 0; val[j] != NULL; j++ ) {

				ldbm_datum_init( key );

				/* normalize the value */
				for ( s = val[j]; *s; s++ ) {
					*s = TOLOWER( (unsigned char) *s );
					last = *s;
				}
				if ( isascii( last ) && isdigit( last ) ) {
					continue;
				}

				/* generate a value-based centroid */
				if ( centroidvalues == CENTROID_VALUE ) {
					key.dptr = val[j];
					key.dsize = strlen( key.dptr ) + 1;
					(void) ldbm_store( ldbm[i], key, data, LDBM_INSERT );

				/* generate a word-based centroid */
				} else {
					char *lasts;
					for ( w = ldap_pvt_strtok( val[j], WORD_BREAKS, &lasts );
					  w != NULL;
					  w = ldap_pvt_strtok( NULL, WORD_BREAKS, &lasts ) ) {
						key.dptr = w;
						key.dsize = strlen( key.dptr ) + 1;
						(void) ldbm_store( ldbm[i], key, data, LDBM_INSERT );
					}
				}
			}
			ldap_value_free( val );
		}
		free( dn );
		ldap_msgfree( res );
	}
	ldap_msgfree( res );
	ldap_unbind( ld );

	if ( verbose ) {
		printf( "%d entries\n", count );
	}

	return( count );
}

/*
 * compare the old and new centroids, generating the appropriate add
 * and delete operations. if the underlying database is ordered, we
 * can do this more efficiently.
 */

static LDAPMod **
diff_centroids(
	char	*attr,
	LDBM	oldbm,
	LDBM	nldbm,
    int		nentries
)
{
#ifdef LDBM_ORDERED
	Datum	okey, nkey;
	Datum	olast, nlast;
#endif
	Datum	lastkey, key;
	Datum	data;
	LDAPMod	**mods;
	char	**avals, **dvals;
	int		amax, acur, dmax, dcur;
	char	**vals;

	LDBMCursor	*ocursorp;
	LDBMCursor	*ncursorp;

	if ( verbose ) {
		printf( "Generating mods for differential %s centroid...", attr );
		fflush( stdout );
	}

	ldbm_datum_init( lastkey );
	ldbm_datum_init( key );
	ldbm_datum_init( data );

	if ( (mods = (LDAPMod **) malloc( sizeof(LDAPMod *) * 4 )) == NULL ||
	     (mods[0] = (LDAPMod *) malloc( sizeof(LDAPMod) )) == NULL ||
	     (mods[1] = (LDAPMod *) malloc( sizeof(LDAPMod) )) == NULL ||
	     (mods[2] = (LDAPMod *) malloc( sizeof(LDAPMod) )) == NULL ||
	     (vals = (char **) malloc( 2 * sizeof(char *) )) == NULL ||
		 (vals[0] = (char *) malloc( 20 )) == NULL )
	{
		perror( "malloc" );
		exit( EXIT_FAILURE );
	}
	/* add values in mods[0] */
	mods[0]->mod_op = LDAP_MOD_ADD;
	mods[0]->mod_type = attr;
	mods[0]->mod_values = NULL;
	avals = NULL;
	acur = amax = 0;
	/* delete values in mods[1] */
	mods[1]->mod_op = LDAP_MOD_DELETE;
	mods[1]->mod_type = attr;
	mods[1]->mod_values = NULL;
	dvals = NULL;
	dcur = dmax = 0;
	/* number of entries in mods[2] */
	sprintf( vals[0], "%d", nentries );
	vals[1] = NULL;
	mods[2]->mod_op = LDAP_MOD_REPLACE;
	mods[2]->mod_type = "nentries";
	mods[2]->mod_values = vals;
	/* null terminate list of mods */
	mods[3] = NULL;

#ifdef LDBM_ORDERED
	/*
	 * if the underlying database is ordered, we can do a more efficient
	 * dual traversal, yielding O(N) performance.
	 */

	ldbm_datum_init( okey );
	ldbm_datum_init( nkey );
	ldbm_datum_init( olast );
	ldbm_datum_init( nlast );

	olast.dptr = NULL;
	nlast.dptr = NULL;

	for ( okey = ldbm_firstkey( oldbm, &ocursorp ),
			nkey = ldbm_firstkey( nldbm, &ncursorp );
	      okey.dptr != NULL && nkey.dptr != NULL; )
	{
		int	rc = strcmp( okey.dptr, nkey.dptr );

		if ( rc == 0 ) {
			/* value is in both places - leave it */
			if ( olast.dptr != NULL ) {
				ldbm_datum_free( oldbm, olast );
			}
			olast = okey;
			if ( nlast.dptr != NULL ) {
				ldbm_datum_free( nldbm, nlast );
			}
			nlast = nkey;

			okey = ldbm_nextkey( oldbm, olast, ocursorp );
			nkey = ldbm_nextkey( nldbm, nlast, ncursorp );

		} else if ( rc > 0 ) {
			/* new value is not in old centroid - add it */
			if ( charray_add_dup( &avals, &acur, &amax, nkey.dptr ) == NULL ) {
				ldap_mods_free( mods, 1 );
				return( NULL );
			}

			if ( nlast.dptr != NULL ) {
				ldbm_datum_free( nldbm, nlast );
			}
			nlast = nkey;

			nkey = ldbm_nextkey( nldbm, nlast, ncursorp );

		} else {
			/* old value is not in new centroid - delete it */
			if ( charray_add_dup( &dvals, &dcur, &dmax, okey.dptr ) == NULL ) {
				ldap_mods_free( mods, 1 );
				return( NULL );
			}

			if ( olast.dptr != NULL ) {
				ldbm_datum_free( oldbm, olast );
			}
			olast = okey;

			okey = ldbm_nextkey( oldbm, olast, ocursorp );
		}
	}

	while ( okey.dptr != NULL ) {
		if ( charray_add_dup( &dvals, &dcur, &dmax, okey.dptr ) == NULL ) {
			ldap_mods_free( mods, 1 );
			return( NULL );
		}

		okey = ldbm_nextkey( oldbm, olast, ocursorp );
		if ( olast.dptr != NULL ) {
			ldbm_datum_free( oldbm, olast );
		}
		olast = okey;
	}
	if ( olast.dptr != NULL ) {
		ldbm_datum_free( oldbm, olast );
	}
	while ( nkey.dptr != NULL ) {
		if ( charray_add_dup( &avals, &acur, &amax, nkey.dptr ) == NULL ) {
			ldap_mods_free( mods, 1 );
			return( NULL );
		}

		nkey = ldbm_nextkey( nldbm, nlast, ncursorp );
		if ( nlast.dptr != NULL ) {
			ldbm_datum_free( nldbm, nlast );
		}
		nlast = nkey;
	}
	if ( nlast.dptr != NULL ) {
		ldbm_datum_free( nldbm, nlast );
	}
#else
	/*
	 * if the underlying database is not ordered, we have to
	 * generate list of values to add by stepping through all new
	 * values and looking them up in the old centroid (not there => add),
	 * then stepping through all old values and looking them up in the
	 * new centroid (not there => delete). this yields O(Nf(N)) performance,
	 * where f(N) is the order to retrieve a single item.
	 */

	/* generate list of values to add */
	lastkey.dptr = NULL;
	for ( key = ldbm_firstkey( nldbm, &ncursorp ); key.dptr != NULL;
	  key = ldbm_nextkey( nldbm, lastkey, ncursorp ) )
	{
		/* see if it's in the old one */
		data = ldbm_fetch( oldbm, key );

		/* not there - add it */
		if ( data.dptr == NULL ) {
			if ( charray_add_dup( &avals, &acur, &amax, key.dptr ) == NULL ) {
				ldap_mods_free( mods, 1 );
				return( NULL );
			}
		} else {
			ldbm_datum_free( oldbm, data );
		}
		if ( lastkey.dptr != NULL ) {
			ldbm_datum_free( nldbm, lastkey );
		}
		lastkey = key;
	}
	if ( lastkey.dptr != NULL ) {
		ldbm_datum_free( nldbm, lastkey );
	}

	/* generate list of values to delete */
	lastkey.dptr = NULL;
	for ( key = ldbm_firstkey( oldbm, &ocursorp ); key.dptr != NULL;
	  key = ldbm_nextkey( oldbm, lastkey, ocursorp ) )
	{
		/* see if it's in the new one */
		data = ldbm_fetch( nldbm, key );

		/* not there - delete it */
		if ( data.dptr == NULL ) {
			if ( charray_add_dup( &dvals, &dcur, &dmax, key.dptr ) == NULL ) {
				ldap_mods_free( mods, 1 );
				return( NULL );
			}
		} else {
			ldbm_datum_free( nldbm, data );
		}
		if ( lastkey.dptr != NULL ) {
			ldbm_datum_free( oldbm, lastkey );
		}
		lastkey = key;
	}
	if ( lastkey.dptr != NULL ) {
		ldbm_datum_free( oldbm, lastkey );
	}
#endif

	mods[0]->mod_values = avals;
	mods[1]->mod_values = dvals;

	if ( verbose ) {
		printf( "\n" );
		fflush( stdout );
	}

	if ( mods[1]->mod_values == NULL ) {
		free( (char *) mods[1] );
		mods[1] = NULL;
	}
	if ( mods[0]->mod_values == NULL ) {
		free( (char *) mods[0] );
		mods[0] = mods[1];
		mods[1] = NULL;
	}
	if ( mods[0] == NULL ) {
		free( (char *) mods );
		return( NULL );
	} else {
		return( mods );
	}
}

static LDAPMod **
full_centroid(
	char	*attr,
	LDBM	ldbm,
    int		nentries
)
{
	Datum	key, lastkey;
	LDAPMod	**mods;
	char	**vals;
	int		vcur, vmax;

	LDBMCursor *cursorp;

	if ( verbose ) {
		printf( "Generating mods for full %s centroid...", attr );
		fflush( stdout );
	}

	ldbm_datum_init( key );
	ldbm_datum_init( lastkey );

	if ( (mods = (LDAPMod **) malloc( sizeof(LDAPMod *) * 3 )) == NULL ||
	     (mods[0] = (LDAPMod *) malloc( sizeof(LDAPMod) )) == NULL ||
	     (mods[1] = (LDAPMod *) malloc( sizeof(LDAPMod) )) == NULL ||
	     (vals = (char **) malloc( 2 * sizeof(char *) )) == NULL ||
	     (vals[0] = (char *) malloc( 20 )) == NULL )
	{
		perror( "malloc" );
		exit( EXIT_FAILURE );
	}
	mods[0]->mod_op = LDAP_MOD_REPLACE;
	mods[0]->mod_type = attr;
	mods[0]->mod_values = NULL;
	sprintf( vals[0], "%d", nentries );
	vals[1] = NULL;
	mods[1]->mod_op = LDAP_MOD_REPLACE;
	mods[1]->mod_type = "nentries";
	mods[1]->mod_values = vals;
	mods[2] = NULL;

	lastkey.dptr = NULL;
	vals = NULL;
	vcur = vmax = 0;

	for ( key = ldbm_firstkey( ldbm, &cursorp ); key.dptr != NULL;
	  key = ldbm_nextkey( ldbm, lastkey, cursorp ) )
	{
		if ( charray_add_dup( &vals, &vcur, &vmax, key.dptr ) == NULL ) {
			ldap_mods_free( mods, 1 );
			return( NULL );
		}

		if ( lastkey.dptr != NULL ) {
			ldbm_datum_free( ldbm, lastkey );
		}
		lastkey = key;
	}
	if ( lastkey.dptr != NULL ) {
		ldbm_datum_free( ldbm, lastkey );
	}
	mods[0]->mod_values = vals;

	if ( verbose ) {
		printf( "\n" );
		fflush( stdout );
	}

	if ( mods[0]->mod_values == NULL ) {
		free( (char *) mods[0] );
		free( (char *) mods );
		return( NULL );
	} else {
		return( mods );
	}
}

/*
 * extract the destination ldap host, port, and base object for the
 * server to receive the index information. then, open a connection,
 * bind, and see if the entry exists. if not, create it and set things
 * up so the centroid full and diff routines can modify it to contain
 * the new centroid information.
 */

static LDAP *
bind_to_destination_ldap(
	char	*ldapsrcurl,
	char	*ldapdesturl
)
{
	LDAP		*ld;
	LDAPMessage	*res;
	int			rc;
	char		*s, *s2, *d;
	char		*attrs[2], *refvalues[2], *ocvalues[2];
	LDAPMod		*mp[3];
	LDAPMod		m[2];
	char		buf[BUFSIZ];

	if ( verbose ) {
		printf( "Binding to destination LDAP server..." );
		fflush( stdout );
	}

	/* first, pick out the destination ldap server info */
	if ( ldapbase != NULL ) {
		free( ldapbase );
		ldapbase = NULL;
	}
	if ( strncmp( ldapdesturl, "ldap://", 7 ) != 0 ) {
		fputs( "Not an LDAP URL", stderr ); /* Should be smarter? */
		return( NULL );
	}
	s = ldapdesturl + 7;
	if ( (s2 = strchr( s, '/' )) == NULL ) {
		ldapbase = strdup( s );
	} else {
		if ( *s != '/' ) {
			*s2 = '\0';
			if ( ldaphost != NULL )
				free( ldaphost );
			ldaphost = strdup( s );
			*s2 = '/';
		}
		ldapbase = strdup( s2 + 1 );
	}
	strcpy( buf, "ref=" );
	if ( strpbrk( ldapsrcurl, " ,;" ) != NULL ) {
		strcat( buf, "\"" );
	}
	for ( s = d = ldapsrcurl; *s; s++ ) {
		if ( *s != '"' ) {
			*d++ = *s;
		}
	}
	*d = '\0';
	strcat( buf, ldapsrcurl );
	if ( strpbrk( ldapsrcurl, " ,;" ) != NULL ) {
		strcat( buf, "\"" );
	}
	strcat( buf, ", " );
	strcat( buf, ldapbase );
	free( ldapbase );
	ldapbase = strdup( buf );

	if ( (ld = ldap_init( ldaphost, 0 )) == NULL ) {
		perror( "ldap_init" );
		return( NULL );
	}

	if ( ldap_bind_s( ld, destldapbinddn, destldappasswd, destldapauthmethod )
	  != LDAP_SUCCESS) {
		ldap_perror( ld, "ldap_bind_s" );
		ldap_unbind( ld );
		return( NULL );
	}
	if ( verbose ) {
		printf( "\n" );
	}

	attrs[0] = "c";
	attrs[1] = NULL;
	rc = ldap_search_s( ld, ldapbase, LDAP_SCOPE_BASE, "(objectclass=*)",
	  attrs, 0, &res );
	ldap_msgfree( res );

	if ( rc == LDAP_NO_SUCH_OBJECT ) {
		if ( verbose ) {
			printf( "%sCreating centroid entry...", not ? "Not " : "" );
			fflush( stdout );
		}

		/* create the centroid index entry */
		m[0].mod_op = 0;
		m[0].mod_type = "ref";
		refvalues[0] = ldapsrcurl;
		refvalues[1] = NULL;
		m[0].mod_values = refvalues;
		m[1].mod_op = 0;
		m[1].mod_type = "objectclass";
		ocvalues[0] = "indexentry";
		ocvalues[1] = NULL;
		m[1].mod_values = ocvalues;
		mp[0] = &m[0];
		mp[1] = &m[1];
		mp[2] = NULL;

		if ( !not && ldap_add_s( ld, ldapbase, mp ) != LDAP_SUCCESS ) {
			ldap_perror( ld, ldapbase );
			ldap_unbind( ld );
			return( NULL );
		}

		if ( verbose ) {
			printf( "\n" );
			fflush( stdout );
		}
	} else if ( rc != LDAP_SUCCESS ) {
		ldap_perror( ld, "ldap_search_s" );
		ldap_unbind( ld );
		return( NULL );
	}

	return( ld );
}

static char **
charray_add_dup(
	char    ***a,
    int		*cur,
    int		*max,
	char    *s
)
{
	if ( *a == NULL ) {
		*a = (char **) malloc( (BUFSIZ + 1) * sizeof(char *) );
		*cur = 0;
		*max = BUFSIZ;
	} else if ( *cur >= *max ) {
		*max += BUFSIZ;
		*a = (char **) realloc( *a, (*max + 1) * sizeof(char *) );
	}
	if ( *a == NULL ) {
		return( NULL );
	}

	(*a)[(*cur)++] = strdup( s );
	(*a)[*cur] = NULL;
	return( *a );
}
