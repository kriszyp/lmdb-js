/* $OpenLDAP$ */
/*
 * Copyright 1998-2003 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "portable.h"

#include <stdio.h>

#include <ac/stdlib.h>

#include <ac/ctype.h>
#include <ac/string.h>
#include <ac/unistd.h>
#include <ac/errno.h>
#include <sys/stat.h>

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_IO_H
#include <io.h>
#endif

#include <ldap.h>

#include "ldif.h"
#include "lutil.h"
#include "lutil_ldap.h"
#include "ldap_defaults.h"
#include "ldap_log.h"
#include "ldap_pvt.h"

#include "common.h"


static int scope = LDAP_SCOPE_SUBTREE;
static int deref = -1;
static int attrsonly;
static int timelimit = -1;
static int sizelimit = -1;

static char *def_tmpdir;
static char *def_urlpre;


void
usage( void )
{
	fprintf( stderr, _("usage: %s [options] [filter [attributes...]]\nwhere:\n"), prog);
	fprintf( stderr, _("  filter\tRFC-2254 compliant LDAP search filter\n"));
	fprintf( stderr, _("  attributes\twhitespace-separated list of attribute descriptions\n"));
	fprintf( stderr, _("    which may include:\n"));
	fprintf( stderr, _("      1.1   no attributes\n"));
	fprintf( stderr, _("      *     all user attributes\n"));
	fprintf( stderr, _("      +     all operational attributes\n"));


	fprintf( stderr, _("Search options:\n"));
	fprintf( stderr, _("  -a deref   one of never (default), always, search, or find\n"));
	fprintf( stderr, _("  -A         retrieve attribute names only (no values)\n"));
	fprintf( stderr, _("  -b basedn  base dn for search\n"));
	fprintf( stderr, _("  -E [!]<ctrl>[=<ctrlparam>] search controls (! indicates criticality)\n"));
#ifdef LDAP_CONTROL_X_DOMAIN_SCOPE
	fprintf( stderr, _("             [!]domainScope              (domain scope)\n"));
#endif
	fprintf( stderr, _("             [!]mv=<filter>              (matched values filter)\n"));
#ifdef LDAP_CONTROL_PAGEDRESULTS
	fprintf( stderr, _("             [!]pr=<size>                (paged results)\n"));
#endif
#ifdef LDAP_CONTROL_SUBENTRIES
	fprintf( stderr, _("             [!]subentries[=true|false]  (subentries)\n"));
#endif
	fprintf( stderr, _("             [!]sync=ro[/<cookie>]            (LDAP Sync refreshOnly)\n"));
	fprintf( stderr, _("                     rp[/<cookie>][/<slimit>] (LDAP Sync refreshAndPersist)\n"));
	fprintf( stderr, _("  -F prefix  URL prefix for files (default: %s)\n"), def_urlpre);
	fprintf( stderr, _("  -l limit   time limit (in seconds) for search\n"));
	fprintf( stderr, _("  -L         print responses in LDIFv1 format\n"));
	fprintf( stderr, _("  -LL        print responses in LDIF format without comments\n"));
	fprintf( stderr, _("  -LLL       print responses in LDIF format without comments\n"));
	fprintf( stderr, _("             and version\n"));
	fprintf( stderr, _("  -s scope   one of base, one, or sub (search scope)\n"));
	fprintf( stderr, _("  -S attr    sort the results by attribute `attr'\n"));
	fprintf( stderr, _("  -t         write binary values to files in temporary directory\n"));
	fprintf( stderr, _("  -tt        write all values to files in temporary directory\n"));
	fprintf( stderr, _("  -T path    write files to directory specified by path (default: %s)\n"), def_tmpdir);
	fprintf( stderr, _("  -u         include User Friendly entry names in the output\n"));
	fprintf( stderr, _("  -z limit   size limit (in entries) for search\n"));
	tool_common_usage();
	exit( EXIT_FAILURE );
}

static void print_entry LDAP_P((
	LDAP	*ld,
	LDAPMessage	*entry,
	int		attrsonly));

static void print_reference(
	LDAP *ld,
	LDAPMessage *reference );

static void print_extended(
	LDAP *ld,
	LDAPMessage *extended );

static void print_partial(
	LDAP *ld,
	LDAPMessage *partial );

static int print_result(
	LDAP *ld,
	LDAPMessage *result,
	int search );

static void print_ctrls(
	LDAPControl **ctrls );

static int write_ldif LDAP_P((
	int type,
	char *name,
	char *value,
	ber_len_t vallen ));

static int dosearch LDAP_P((
	LDAP	*ld,
	char	*base,
	int		scope,
	char	*filtpatt,
	char	*value,
	char	**attrs,
	int		attrsonly,
	LDAPControl **sctrls,
	LDAPControl **cctrls,
	struct timeval *timeout,
	int	sizelimit ));

static char *tmpdir = NULL;
static char *urlpre = NULL;
static char	*base = NULL;
static char	*sortattr = NULL;
static int  includeufn, vals2tmp = 0, ldif = 0;

static int subentries = 0, valuesReturnFilter = 0;
static char	*vrFilter = NULL;

#ifdef LDAP_CONTROL_X_DOMAIN_SCOPE
static int domainScope = 0;
#endif

static int ldapsync = 0;
static struct berval sync_cookie = { 0, NULL };
static int sync_slimit = -1;

#ifdef LDAP_CONTROL_PAGEDRESULTS
static int pagedResults = 0;
static ber_int_t pageSize = 0;
static ber_int_t entriesLeft = 0;
static ber_int_t morePagedResults = 1;
static struct berval cookie = { 0, NULL };
static int npagedresponses;
static int npagedentries;
static int npagedreferences;
static int npagedextended;
static int npagedpartial;

static int parse_page_control(
	LDAP *ld,
	LDAPMessage *result,
	struct berval *cookie );
#endif

static void
urlize(char *url)
{
	char *p;

	if (*LDAP_DIRSEP != '/') {
		for (p = url; *p; p++) {
			if (*p == *LDAP_DIRSEP)
				*p = '/';
		}
	}
}


const char options[] = "a:Ab:E:F:l:Ls:S:tT:uz:"
	"Cd:D:e:f:h:H:IkKMnO:p:P:QR:U:vVw:WxX:y:Y:Z";

int
handle_private_option( int i )
{
	int crit;
	char *control, *cvalue;
	switch ( i ) {
	case 'a':	/* set alias deref option */
		if ( strcasecmp( optarg, "never" ) == 0 ) {
		deref = LDAP_DEREF_NEVER;
		} else if ( strncasecmp( optarg, "search", sizeof("search")-1 ) == 0 ) {
		deref = LDAP_DEREF_SEARCHING;
		} else if ( strncasecmp( optarg, "find", sizeof("find")-1 ) == 0 ) {
		deref = LDAP_DEREF_FINDING;
		} else if ( strcasecmp( optarg, "always" ) == 0 ) {
		deref = LDAP_DEREF_ALWAYS;
		} else {
		fprintf( stderr, _("alias deref should be never, search, find, or always\n") );
		usage();
		}
		break;
	case 'A':	/* retrieve attribute names only -- no values */
		++attrsonly;
		break;
	case 'b': /* search base */
		base = strdup( optarg );
		break;
	case 'E': /* search controls */
		if( protocol == LDAP_VERSION2 ) {
			fprintf( stderr, _("%s: -E incompatible with LDAPv%d\n"),
				prog, protocol );
			exit( EXIT_FAILURE );
		}

		/* should be extended to support comma separated list of
		 *	[!]key[=value] parameters, e.g.  -E !foo,bar=567
		 */

		crit = 0;
		cvalue = NULL;
		if( optarg[0] == '!' ) {
			crit = 1;
			optarg++;
		}

		control = strdup( optarg );
		if ( (cvalue = strchr( control, '=' )) != NULL ) {
			*cvalue++ = '\0';
		}

		if ( strcasecmp( control, "mv" ) == 0 ) {
			/* ValuesReturnFilter control */
			if( valuesReturnFilter ) {
				fprintf( stderr, _("ValuesReturnFilter previously specified\n"));
				exit( EXIT_FAILURE );
			}
			valuesReturnFilter= 1 + crit;

			if ( cvalue == NULL ) {
				fprintf( stderr,
					_("missing filter in ValuesReturnFilter control\n"));
				exit( EXIT_FAILURE );
			}

			vrFilter = cvalue;
			protocol = LDAP_VERSION3;

#ifdef LDAP_CONTROL_PAGEDRESULTS
		} else if ( strcasecmp( control, "pr" ) == 0 ) {
			int num, tmp;
			/* PagedResults control */
			if ( pagedResults != 0 ) {
				fprintf( stderr, _("PagedResultsControl previously specified\n") );
				exit( EXIT_FAILURE );
			}
			
			num = sscanf( cvalue, "%d", &tmp );
			if ( num != 1 ) {
				fprintf( stderr, _("Invalid value for PagedResultsControl, %s.\n"), cvalue);
				exit( EXIT_FAILURE );

			}
			pageSize = (ber_int_t) tmp;
			pagedResults = 1 + crit;

#endif
#ifdef LDAP_CONTROL_X_DOMAIN_SCOPE
		} else if ( strcasecmp( control, "domainScope" ) == 0 ) {
			if( domainScope ) {
				fprintf( stderr,
					_("domainScope control previously specified\n"));
				exit( EXIT_FAILURE );
			}
			if( cvalue != NULL ) {
				fprintf( stderr,
			         _("domainScope: no control value expected\n") );
				usage();
			}

			domainScope = 1 + crit;
#endif
#ifdef LDAP_CONTROL_SUBENTRIES
		} else if ( strcasecmp( control, "subentries" ) == 0 ) {
			if( subentries ) {
				fprintf( stderr, _("subentries control previously specified\n"));
				exit( EXIT_FAILURE );
			}
			if( cvalue == NULL || strcasecmp( cvalue, "true") == 0 ) {
				subentries = 2;
			} else if ( strcasecmp( cvalue, "false") == 0 ) {
				subentries = 1;
			} else {
				fprintf( stderr,
					_("subentries control value \"%s\" invalid\n"),
					cvalue );
				exit( EXIT_FAILURE );
			}
			if( crit ) subentries *= -1;
#endif

	} else if ( strcasecmp( control, "sync" ) == 0 ) {
			char *cookiep;
			char *slimitp;
			if ( ldapsync ) {
				fprintf( stderr, _("ldap sync control previously specified\n") );
				exit( EXIT_FAILURE );
			}
			if ( cvalue == NULL ) {
				fprintf( stderr,
					_("missing specification of ldap sync control\n"));
				exit( EXIT_FAILURE );
			}
			if ( strncasecmp( cvalue, "ro", 2 ) == 0 ) {
				ldapsync = LDAP_SYNC_REFRESH_ONLY;
				cookiep = strchr( cvalue, '/' );
				if ( cookiep != NULL ) {
					cookiep++;
					if ( *cookiep != '\0' ) {
						ber_str2bv( cookiep, 0, 0, &sync_cookie );
					}
				}
			} else if ( strncasecmp( cvalue, "rp", 2 ) == 0 ) {
				ldapsync = LDAP_SYNC_REFRESH_AND_PERSIST;
				cookiep = strchr( cvalue, '/' );
				if ( cookiep != NULL ) {
					*cookiep++ = '\0';	
					cvalue = cookiep;
				}
				slimitp = strchr( cvalue, '/' );
				if ( slimitp != NULL ) {
					*slimitp++ = '\0';
				}
				if ( cookiep != NULL && *cookiep != '\0' )
					ber_str2bv( cookiep, 0, 0, &sync_cookie );
				if ( slimitp != NULL && *slimitp != '\0' )
					sync_slimit = atoi( slimitp );
			} else {
				fprintf( stderr,
					_("ldap sync control value \"%s\" invalid\n"),
					cvalue );
				exit( EXIT_FAILURE );
			}
			if ( crit ) ldapsync *= -1;

		} else {
			fprintf( stderr, _("Invalid control name: %s\n"), control );
			usage();
		}
		break;
	case 'F':	/* uri prefix */
		if( urlpre ) free( urlpre );
		urlpre = strdup( optarg );
		break;
	case 'l':	/* time limit */
		timelimit = atoi( optarg );
		if( timelimit < 0 ) {
			fprintf( stderr, _("%s: invalid timelimit (%d) specified\n"),
				prog, timelimit );
			exit( EXIT_FAILURE );
		}
		break;
	case 'L':	/* print entries in LDIF format */
		++ldif;
		break;
	case 's':	/* search scope */
		if ( strcasecmp( optarg, "base" ) == 0 ) {
		scope = LDAP_SCOPE_BASE;
		} else if ( strncasecmp( optarg, "one", sizeof("one")-1 ) == 0 ) {
		scope = LDAP_SCOPE_ONELEVEL;
		} else if ( strncasecmp( optarg, "sub", sizeof("sub")-1 ) == 0 ) {
		scope = LDAP_SCOPE_SUBTREE;
		} else {
		fprintf( stderr, _("scope should be base, one, or sub\n") );
		usage();
		}
		break;
	case 'S':	/* sort attribute */
		sortattr = strdup( optarg );
		break;
	case 't':	/* write attribute values to TMPDIR files */
		++vals2tmp;
		break;
	case 'T':	/* tmpdir */
		if( tmpdir ) free( tmpdir );
		tmpdir = strdup( optarg );
		break;
	case 'u':	/* include UFN */
		++includeufn;
		break;
	case 'z':	/* size limit */
		sizelimit = atoi( optarg );
		break;
	default:
		return 0;
	}
	return 1;
}


static void
private_conn_setup( LDAP *ld )
{
	if (deref != -1 &&
		ldap_set_option( ld, LDAP_OPT_DEREF, (void *) &deref ) != LDAP_OPT_SUCCESS )
	{
		fprintf( stderr, _("Could not set LDAP_OPT_DEREF %d\n"), deref );
		exit( EXIT_FAILURE );
	}
	if (timelimit != -1 &&
		ldap_set_option( ld, LDAP_OPT_TIMELIMIT, (void *) &timelimit ) != LDAP_OPT_SUCCESS )
	{
		fprintf( stderr, _("Could not set LDAP_OPT_TIMELIMIT %d\n"), timelimit );
		exit( EXIT_FAILURE );
	}
	if (sizelimit != -1 &&
		ldap_set_option( ld, LDAP_OPT_SIZELIMIT, (void *) &sizelimit ) != LDAP_OPT_SUCCESS )
	{
		fprintf( stderr, _("Could not set LDAP_OPT_SIZELIMIT %d\n"), sizelimit );
		exit( EXIT_FAILURE );
	}
}


int
main( int argc, char **argv )
{
	char		*filtpattern, **attrs = NULL, line[BUFSIZ];
	FILE		*fp = NULL;
	int			rc, i, first;
	LDAP		*ld = NULL;
	BerElement	*seber = NULL, *vrber = NULL, *prber = NULL;

	BerElement      *syncber = NULL;
	struct berval   *syncbvalp = NULL;

	tool_init();

#ifdef LDAP_CONTROL_PAGEDRESULTS
	npagedresponses = npagedentries = npagedreferences =
		npagedextended = npagedpartial = 0;
#endif

	prog = lutil_progname( "ldapsearch", argc, argv );

	lutil_log_initialize(argc, argv);

	if((def_tmpdir = getenv("TMPDIR")) == NULL &&
	   (def_tmpdir = getenv("TMP")) == NULL &&
	   (def_tmpdir = getenv("TEMP")) == NULL )
	{
		def_tmpdir = LDAP_TMPDIR;
	}

	if ( !*def_tmpdir )
		def_tmpdir = LDAP_TMPDIR;

	def_urlpre = malloc( sizeof("file:////") + strlen(def_tmpdir) );

	if( def_urlpre == NULL ) {
		perror( "malloc" );
		return EXIT_FAILURE;
	}

	sprintf( def_urlpre, "file:///%s/",
		def_tmpdir[0] == *LDAP_DIRSEP ? &def_tmpdir[1] : def_tmpdir );

	urlize( def_urlpre );

	tool_args( argc, argv );

	if (( argc - optind < 1 ) ||
		( *argv[optind] != '(' /*')'*/ &&
		( strchr( argv[optind], '=' ) == NULL ) ) )
	{
		filtpattern = "(objectclass=*)";
	} else {
		filtpattern = strdup( argv[optind++] );
	}

	if ( argv[optind] != NULL ) {
		attrs = &argv[optind];
	}

	if ( infile != NULL ) {
		if ( infile[0] == '-' && infile[1] == '\0' ) {
			fp = stdin;
		} else if (( fp = fopen( infile, "r" )) == NULL ) {
			perror( infile );
			return EXIT_FAILURE;
		}
	}

	if ( tmpdir == NULL ) {
		tmpdir = def_tmpdir;

		if ( urlpre == NULL )
			urlpre = def_urlpre;
	}

	if( urlpre == NULL ) {
		urlpre = malloc( sizeof("file:////") + strlen(tmpdir) );

		if( urlpre == NULL ) {
			perror( "malloc" );
			return EXIT_FAILURE;
		}

		sprintf( urlpre, "file:///%s/",
			tmpdir[0] == *LDAP_DIRSEP ? &tmpdir[1] : tmpdir );

		urlize( urlpre );
	}

	if ( debug )
		ldif_debug = debug;

	ld = tool_conn_setup( 0, &private_conn_setup );

	if ( pw_file || want_bindpw ) {
		if ( pw_file ) {
			rc = lutil_get_filed_password( pw_file, &passwd );
			if( rc ) return EXIT_FAILURE;
		} else {
			passwd.bv_val = getpassphrase( _("Enter LDAP Password: ") );
			passwd.bv_len = passwd.bv_val ? strlen( passwd.bv_val ) : 0;
		}
	}

	tool_bind( ld );

getNextPage:
	if ( assertion || authzid || manageDSAit || noop
#ifdef LDAP_CONTROL_X_DOMAIN_SCOPE
		|| domainScope
#endif
#ifdef LDAP_CONTROL_PAGEDRESULTS
		|| pageSize
#endif
		|| ldapsync
		|| subentries || valuesReturnFilter )
	{
		int err;
		int i=0;
		LDAPControl c[6];

#ifdef LDAP_CONTROL_X_DOMAIN_SCOPE
	if ( domainScope ) {
		c[i].ldctl_oid = LDAP_CONTROL_X_DOMAIN_SCOPE;
		c[i].ldctl_value.bv_val = NULL;
		c[i].ldctl_value.bv_len = 0;
		c[i].ldctl_iscritical = domainScope > 1;
		i++;
	}
#endif

#ifdef LDAP_CONTROL_SUBENTRIES
		if ( subentries ) {
	        if (( seber = ber_alloc_t(LBER_USE_DER)) == NULL ) {
				return EXIT_FAILURE;
			}

			err = ber_printf( seber, "{b}", abs(subentries) == 1 ? 0 : 1 );
	    	if ( err == -1 ) {
				ber_free( seber, 1 );
				fprintf( stderr, _("Subentries control encoding error!\n") );
				return EXIT_FAILURE;
			}

			if ( ber_flatten2( seber, &c[i].ldctl_value, 0 ) == -1 ) {
				return EXIT_FAILURE;
			}

			c[i].ldctl_oid = LDAP_CONTROL_SUBENTRIES;
			c[i].ldctl_iscritical = subentries < 1;
			i++;
		}
#endif

		if ( ldapsync ) {
			if (( syncber = ber_alloc_t(LBER_USE_DER)) == NULL ) {
				return EXIT_FAILURE;
			}

			if ( sync_cookie.bv_len == 0 ) {
				err = ber_printf( syncber, "{e}", abs(ldapsync) );
			} else {
				err = ber_printf( syncber, "{eO}", abs(ldapsync),
							&sync_cookie );
			}

			if ( err == LBER_ERROR ) {
				ber_free( syncber, 1 );
				fprintf( stderr, _("ldap sync control encoding error!\n") );
				return EXIT_FAILURE;
			}

			if ( ber_flatten( syncber, &syncbvalp ) == LBER_ERROR ) {
				return EXIT_FAILURE;
			}

			c[i].ldctl_oid = LDAP_CONTROL_SYNC;
			c[i].ldctl_value = (*syncbvalp);
			c[i].ldctl_iscritical = ldapsync < 0;
			i++;
		}

		if ( valuesReturnFilter ) {
	        if (( vrber = ber_alloc_t(LBER_USE_DER)) == NULL ) {
				return EXIT_FAILURE;
			}

	    	if ( ( err = ldap_put_vrFilter( vrber, vrFilter ) ) == -1 ) {
				ber_free( vrber, 1 );
				fprintf( stderr, _("Bad ValuesReturnFilter: %s\n"), vrFilter );
				return EXIT_FAILURE;
			}

			if ( ber_flatten2( vrber, &c[i].ldctl_value, 0 ) == -1 ) {
				return EXIT_FAILURE;
			}

			c[i].ldctl_oid = LDAP_CONTROL_VALUESRETURNFILTER;
			c[i].ldctl_iscritical = valuesReturnFilter > 1;
			i++;
		}

#ifdef LDAP_CONTROL_PAGEDRESULTS
		if ( pagedResults ) {
			if (( prber = ber_alloc_t(LBER_USE_DER)) == NULL ) {
				return EXIT_FAILURE;
			}

			ber_printf( prber, "{iO}", pageSize, &cookie );
			if ( ber_flatten2( prber, &c[i].ldctl_value, 0 ) == -1 ) {
				return EXIT_FAILURE;
			}
			
			c[i].ldctl_oid = LDAP_CONTROL_PAGEDRESULTS;
			c[i].ldctl_iscritical = pagedResults > 1;
			i++;
		}
#endif

		tool_server_controls( ld, c, i );

		ber_free( seber, 1 );
		ber_free( vrber, 1 );
		ber_free( prber, 1 );
	}
	
	if ( verbose ) {
		fprintf( stderr, _("filter%s: %s\nrequesting: "),
			infile != NULL ? _(" pattern") : "",
			filtpattern );

		if ( attrs == NULL ) {
			fprintf( stderr, _("ALL") );
		} else {
			for ( i = 0; attrs[ i ] != NULL; ++i ) {
				fprintf( stderr, "%s ", attrs[ i ] );
			}
		}
		fprintf( stderr, "\n" );
	}

	if ( ldif == 0 ) {
		printf( _("# extended LDIF\n") );
	} else if ( ldif < 3 ) {
		printf( _("version: %d\n\n"), 1 );
	}

	if (ldif < 2 ) {
		printf( "#\n" );
		printf(_("# LDAPv%d\n"), protocol);
		printf(_("# base <%s> with scope %s\n"),
			base ? base : "", (scope == LDAP_SCOPE_BASE) ? "base"
		       : ((scope == LDAP_SCOPE_ONELEVEL) ? "one" : "sub"));
		printf(_("# filter%s: %s\n"), infile != NULL ? _(" pattern") : "",
		       filtpattern);
		printf(_("# requesting: "));

		if ( attrs == NULL ) {
			printf( _("ALL") );
		} else {
			for ( i = 0; attrs[ i ] != NULL; ++i ) {
				printf( "%s ", attrs[ i ] );
			}
		}

		if ( manageDSAit ) {
			printf(_("\n# with manageDSAit %scontrol"),
				manageDSAit > 1 ? _("critical ") : "" );
		}
		if ( noop ) {
			printf(_("\n# with noop %scontrol"),
				noop > 1 ? _("critical ") : "" );
		}
		if ( subentries ) {
			printf(_("\n# with subentries %scontrol: %s"),
				subentries < 0 ? _("critical ") : "",
				abs(subentries) == 1 ? "false" : "true" );
		}
		if ( valuesReturnFilter ) {
			printf(_("\n# with valuesReturnFilter %scontrol: %s"),
				valuesReturnFilter > 1 ? _("critical ") : "", vrFilter );
		}
#ifdef LDAP_CONTROL_PAGEDRESULTS
		if ( pageSize ) {
			printf(_("\n# with pagedResults %scontrol: size=%d"),
				(pagedResults > 1) ? _("critical ") : "", 
				pageSize );
		}
#endif

		printf( _("\n#\n\n") );
	}

	if ( infile == NULL ) {
		rc = dosearch( ld, base, scope, NULL, filtpattern,
			attrs, attrsonly, NULL, NULL, NULL, -1 );

	} else {
		rc = 0;
		first = 1;
		while ( rc == 0 && fgets( line, sizeof( line ), fp ) != NULL ) { 
			line[ strlen( line ) - 1 ] = '\0';
			if ( !first ) {
				putchar( '\n' );
			} else {
				first = 0;
			}
			rc = dosearch( ld, base, scope, filtpattern, line,
				attrs, attrsonly, NULL, NULL, NULL, -1 );
		}
		if ( fp != stdin ) {
			fclose( fp );
		}
	}

#ifdef LDAP_CONTROL_PAGEDRESULTS
	if ( ( pageSize != 0 ) && ( morePagedResults != 0 ) ) {
		char	buf[6];
		int	i, moreEntries, tmpSize;

		/* Loop to get the next pages when 
		 * enter is pressed on the terminal.
		 */
		if ( entriesLeft > 0 ) {
			printf( _("Estimate entries: %d\n"), entriesLeft );
		}
		printf( _("Press [size] Enter for the next {%d|size} entries.\n"),
			(int)pageSize ); 
		i = 0;
		moreEntries = getchar();
		while ( moreEntries != EOF && moreEntries != '\n' ) { 
			if ( i < (int)sizeof(buf) - 1 ) {
				buf[i] = moreEntries;
				i++;
			}
			moreEntries = getchar();
		}
		buf[i] = '\0';

		if ( i > 0 && isdigit( (unsigned char)buf[0] ) ) {
			int num = sscanf( buf, "%d", &tmpSize );
			if ( num != 1 ) {
				fprintf( stderr, _("Invalid value for PagedResultsControl, %s.\n"), buf);
				return EXIT_FAILURE;

			}
			pageSize = (ber_int_t)tmpSize;
		}

		goto getNextPage;	
	}
#endif

	ldap_unbind( ld );
#ifdef HAVE_CYRUS_SASL
	sasl_done();
#endif
#ifdef HAVE_TLS
	ldap_pvt_tls_destroy();
#endif
	return( rc );
}


static int dosearch(
	LDAP	*ld,
	char	*base,
	int		scope,
	char	*filtpatt,
	char	*value,
	char	**attrs,
	int		attrsonly,
	LDAPControl **sctrls,
	LDAPControl **cctrls,
	struct timeval *timeout,
	int sizelimit )
{
	char			*filter;
	int			rc;
	int			nresponses;
	int			nentries;
	int			nreferences;
	int			nextended;
	int			npartial;
	LDAPMessage		*res, *msg;
	ber_int_t		msgid;
	char			*retoid = NULL;
	struct berval		*retdata = NULL;
	int			nresponses_psearch = -1;
	int			cancel_msgid = -1;

	if( filtpatt != NULL ) {
		filter = malloc( strlen( filtpatt ) + strlen( value ) );
		if( filter == NULL ) {
			perror( "malloc" );
			return EXIT_FAILURE;
		}

		sprintf( filter, filtpatt, value );

		if ( verbose ) {
			fprintf( stderr, _("filter: %s\n"), filter );
		}

		if( ldif < 2 ) {
			printf( _("#\n# filter: %s\n#\n"), filter );
		}

	} else {
		filter = value;
	}

	if ( not ) {
		return LDAP_SUCCESS;
	}

	rc = ldap_search_ext( ld, base, scope, filter, attrs, attrsonly,
		sctrls, cctrls, timeout, sizelimit, &msgid );

	if ( filtpatt != NULL ) {
		free( filter );
	}

	if( rc != LDAP_SUCCESS ) {
		fprintf( stderr, _("%s: ldap_search_ext: %s (%d)\n"),
			prog, ldap_err2string( rc ), rc );
		return( rc );
	}

	nresponses = nentries = nreferences = nextended = npartial = 0;

	res = NULL;

	while ((rc = ldap_result( ld, LDAP_RES_ANY,
		sortattr ? LDAP_MSG_ALL : LDAP_MSG_ONE,
		NULL, &res )) > 0 )
	{
		if( sortattr ) {
			(void) ldap_sort_entries( ld, &res,
				( *sortattr == '\0' ) ? NULL : sortattr, strcasecmp );
		}

		for ( msg = ldap_first_message( ld, res );
			msg != NULL;
			msg = ldap_next_message( ld, msg ) )
		{
			if ( nresponses++ ) putchar('\n');
			if ( nresponses_psearch >= 0 ) 
				nresponses_psearch++;

			switch( ldap_msgtype( msg ) ) {
			case LDAP_RES_SEARCH_ENTRY:
				nentries++;
				print_entry( ld, msg, attrsonly );
				break;

			case LDAP_RES_SEARCH_REFERENCE:
				nreferences++;
				print_reference( ld, msg );
				break;

			case LDAP_RES_EXTENDED:
				nextended++;
				print_extended( ld, msg );

				if( ldap_msgid( msg ) == 0 ) {
					/* unsolicited extended operation */
					goto done;
				}

				if ( cancel_msgid != -1 &&
						cancel_msgid == ldap_msgid( msg ) ) {
					printf(_("Cancelled \n"));
					printf(_("cancel_msgid = %d\n"), cancel_msgid);
					goto done;
				}
				break;

			case LDAP_RES_SEARCH_RESULT:
				rc = print_result( ld, msg, 1 );
#ifdef LDAP_CONTROL_PAGEDRESULTS
				if ( pageSize != 0 ) { 
					rc = parse_page_control( ld, msg, &cookie );
				}
#endif

				if ( ldapsync == LDAP_SYNC_REFRESH_AND_PERSIST ) {
					break;
				}

				goto done;

			case LDAP_RES_INTERMEDIATE:
				npartial++;
				ldap_parse_intermediate( ld, msg,
					&retoid, &retdata, NULL, 0 );

				nresponses_psearch = 0;

				if ( strcmp( retoid, LDAP_SYNC_INFO ) == 0 ) {
					printf(_("SyncInfo Received\n"));
					ldap_memfree( retoid );
					ber_bvfree( retdata );
					break;
				}

				print_partial( ld, msg );
				ldap_memfree( retoid );
				ber_bvfree( retdata );
				goto done;
			}

			if ( ldapsync && sync_slimit != -1 &&
					nresponses_psearch >= sync_slimit ) {
				BerElement *msgidber = NULL;
				struct berval *msgidvalp = NULL;
				msgidber = ber_alloc_t(LBER_USE_DER);
				ber_printf(msgidber, "{i}", msgid);
				ber_flatten(msgidber, &msgidvalp);
				ldap_extended_operation(ld, LDAP_EXOP_X_CANCEL,
						msgidvalp, NULL, NULL, &cancel_msgid);
				nresponses_psearch = -1;
			}
		}

		ldap_msgfree( res );
	}

	if ( rc == -1 ) {
		ldap_perror( ld, "ldap_result" );
		return( rc );
	}

done:
	ldap_msgfree( res );
#ifdef LDAP_CONTROL_PAGEDRESULTS
	if ( pageSize != 0 ) { 
		npagedresponses = npagedresponses + nresponses;
		npagedentries = npagedentries + nentries;
		npagedreferences = npagedreferences + nreferences;
		npagedextended = npagedextended + nextended;
		npagedpartial = npagedpartial + npartial;
		if ( ( morePagedResults == 0 ) && ( ldif < 2 ) ) {
			printf( _("\n# numResponses: %d\n"), npagedresponses );
			if( nentries ) printf( _("# numEntries: %d\n"), npagedentries );
			if( nextended ) printf( _("# numExtended: %d\n"), npagedextended );
			if( npartial ) printf( _("# numPartial: %d\n"), npagedpartial );
			if( nreferences ) printf( _("# numReferences: %d\n"), npagedreferences );
		}
	} else
#endif
	if ( ldif < 2 ) {
		printf( _("\n# numResponses: %d\n"), nresponses );
		if( nentries ) printf( _("# numEntries: %d\n"), nentries );
		if( nextended ) printf( _("# numExtended: %d\n"), nextended );
		if( npartial ) printf( _("# numPartial: %d\n"), npartial );
		if( nreferences ) printf( _("# numReferences: %d\n"), nreferences );
	}

	return( rc );
}

#ifdef OLD_WAY
/* This is the original version, the old way of doing things. */
static void
print_entry(
	LDAP	*ld,
	LDAPMessage	*entry,
	int		attrsonly)
{
	char		*a, *dn, *ufn;
	char	tmpfname[ 256 ];
	char	url[ 256 ];
	int			i, rc;
	BerElement		*ber = NULL;
	struct berval	**bvals;
	LDAPControl **ctrls = NULL;
	FILE		*tmpfp;

	dn = ldap_get_dn( ld, entry );
	ufn = NULL;

	if ( ldif < 2 ) {
		ufn = ldap_dn2ufn( dn );
		write_ldif( LDIF_PUT_COMMENT, NULL, ufn, ufn ? strlen( ufn ) : 0 );
	}
	write_ldif( LDIF_PUT_VALUE, "dn", dn, dn ? strlen( dn ) : 0);

	rc = ldap_get_entry_controls( ld, entry, &ctrls );

	if( rc != LDAP_SUCCESS ) {
		fprintf(stderr, _("print_entry: %d\n"), rc );
		ldap_perror( ld, "ldap_get_entry_controls" );
		exit( EXIT_FAILURE );
	}

	if( ctrls ) {
		print_ctrls( ctrls );
		ldap_controls_free( ctrls );
	}

	if ( includeufn ) {
		if( ufn == NULL ) {
			ufn = ldap_dn2ufn( dn );
		}
		write_ldif( LDIF_PUT_VALUE, "ufn", ufn, ufn ? strlen( ufn ) : 0 );
	}

	if( ufn != NULL ) ldap_memfree( ufn );
	ldap_memfree( dn );

	for ( a = ldap_first_attribute( ld, entry, &ber ); a != NULL;
		a = ldap_next_attribute( ld, entry, ber ) )
	{
		if ( attrsonly ) {
			write_ldif( LDIF_PUT_NOVALUE, a, NULL, 0 );

		} else if (( bvals = ldap_get_values_len( ld, entry, a )) != NULL ) {
			for ( i = 0; bvals[i] != NULL; i++ ) {
				if ( vals2tmp > 1 || ( vals2tmp
					&& ldif_is_not_printable( bvals[i]->bv_val, bvals[i]->bv_len ) ))
				{
					int tmpfd;
					/* write value to file */
					snprintf( tmpfname, sizeof tmpfname,
						"%s" LDAP_DIRSEP "ldapsearch-%s-XXXXXX",
						tmpdir, a );
					tmpfp = NULL;

					tmpfd = mkstemp( tmpfname );

					if ( tmpfd < 0  ) {
						perror( tmpfname );
						continue;
					}

					if (( tmpfp = fdopen( tmpfd, "w")) == NULL ) {
						perror( tmpfname );
						continue;
					}

					if ( fwrite( bvals[ i ]->bv_val,
						bvals[ i ]->bv_len, 1, tmpfp ) == 0 )
					{
						perror( tmpfname );
						fclose( tmpfp );
						continue;
					}

					fclose( tmpfp );

					snprintf( url, sizeof url, "%s%s", urlpre,
						&tmpfname[strlen(tmpdir) + sizeof(LDAP_DIRSEP) - 1] );

					urlize( url );
					write_ldif( LDIF_PUT_URL, a, url, strlen( url ));

				} else {
					write_ldif( LDIF_PUT_VALUE, a,
						bvals[ i ]->bv_val, bvals[ i ]->bv_len );
				}
			}
			ber_bvecfree( bvals );
		}
		ldap_memfree( a );
	}

	if( ber != NULL ) {
		ber_free( ber, 0 );
	}
}
#else
/* This is the proposed new way of doing things.
 * It is more efficient, but the API is non-standard.
 */
static void
print_entry(
	LDAP	*ld,
	LDAPMessage	*entry,
	int		attrsonly)
{
	char		*ufn = NULL;
	char	tmpfname[ 256 ];
	char	url[ 256 ];
	int			i, rc;
	BerElement		*ber = NULL;
	struct berval		bv, *bvals, **bvp = &bvals;
	LDAPControl **ctrls = NULL;
	FILE		*tmpfp;

	rc = ldap_get_dn_ber( ld, entry, &ber, &bv );

	if ( ldif < 2 ) {
		ufn = ldap_dn2ufn( bv.bv_val );
		write_ldif( LDIF_PUT_COMMENT, NULL, ufn, ufn ? strlen( ufn ) : 0 );
	}
	write_ldif( LDIF_PUT_VALUE, "dn", bv.bv_val, bv.bv_len );

	if ( includeufn ) {
		if( ufn == NULL ) {
			ufn = ldap_dn2ufn( bv.bv_val );
		}
		write_ldif( LDIF_PUT_VALUE, "ufn", ufn, ufn ? strlen( ufn ) : 0 );
	}

	if( ufn != NULL ) ldap_memfree( ufn );

	if ( attrsonly ) bvp = NULL;

	for ( rc = ldap_get_attribute_ber( ld, entry, ber, &bv, bvp );
		rc == LDAP_SUCCESS;
		rc = ldap_get_attribute_ber( ld, entry, ber, &bv, bvp ) )
	{
		if (bv.bv_val == NULL) break;

		if ( attrsonly ) {
			write_ldif( LDIF_PUT_NOVALUE, bv.bv_val, NULL, 0 );

		} else if ( bvals ) {
			for ( i = 0; bvals[i].bv_val != NULL; i++ ) {
				if ( vals2tmp > 1 || ( vals2tmp
					&& ldif_is_not_printable( bvals[i].bv_val, bvals[i].bv_len ) ))
				{
					int tmpfd;
					/* write value to file */
					snprintf( tmpfname, sizeof tmpfname,
						"%s" LDAP_DIRSEP "ldapsearch-%s-XXXXXX",
						tmpdir, bv.bv_val );
					tmpfp = NULL;

					tmpfd = mkstemp( tmpfname );

					if ( tmpfd < 0  ) {
						perror( tmpfname );
						continue;
					}

					if (( tmpfp = fdopen( tmpfd, "w")) == NULL ) {
						perror( tmpfname );
						continue;
					}

					if ( fwrite( bvals[ i ].bv_val,
						bvals[ i ].bv_len, 1, tmpfp ) == 0 )
					{
						perror( tmpfname );
						fclose( tmpfp );
						continue;
					}

					fclose( tmpfp );

					snprintf( url, sizeof url, "%s%s", urlpre,
						&tmpfname[strlen(tmpdir) + sizeof(LDAP_DIRSEP) - 1] );

					urlize( url );
					write_ldif( LDIF_PUT_URL, bv.bv_val, url, strlen( url ));

				} else {
					write_ldif( LDIF_PUT_VALUE, bv.bv_val,
						bvals[ i ].bv_val, bvals[ i ].bv_len );
				}
			}
			ber_memfree( bvals );
		}
	}
	rc = ldap_pvt_get_controls( ber, &ctrls );
	if( rc != LDAP_SUCCESS ) {
		fprintf(stderr, _("print_entry: %d\n"), rc );
		ldap_perror( ld, "ldap_pvt_get_controls" );
		exit( EXIT_FAILURE );
	}

	if( ctrls ) {
		print_ctrls( ctrls );
		ldap_controls_free( ctrls );
	}

	if( ber != NULL ) {
		ber_free( ber, 0 );
	}
}
#endif

static void print_reference(
	LDAP *ld,
	LDAPMessage *reference )
{
	int rc;
	char **refs = NULL;
	LDAPControl **ctrls;

	if( ldif < 2 ) {
		printf(_("# search reference\n"));
	}

	rc = ldap_parse_reference( ld, reference, &refs, &ctrls, 0 );

	if( rc != LDAP_SUCCESS ) {
		ldap_perror(ld, "ldap_parse_reference");
		exit( EXIT_FAILURE );
	}

	if( refs ) {
		int i;
		for( i=0; refs[i] != NULL; i++ ) {
			write_ldif( ldif ? LDIF_PUT_COMMENT : LDIF_PUT_VALUE,
				"ref", refs[i], strlen(refs[i]) );
		}
		ber_memvfree( (void **) refs );
	}

	if( ctrls ) {
		print_ctrls( ctrls );
		ldap_controls_free( ctrls );
	}
}

static void print_extended(
	LDAP *ld,
	LDAPMessage *extended )
{
	int rc;
	char *retoid = NULL;
	struct berval *retdata = NULL;

	if( ldif < 2 ) {
		printf(_("# extended result response\n"));
	}

	rc = ldap_parse_extended_result( ld, extended,
		&retoid, &retdata, 0 );

	if( rc != LDAP_SUCCESS ) {
		ldap_perror(ld, "ldap_parse_extended_result");
		exit( EXIT_FAILURE );
	}

	if ( ldif < 2 ) {
		write_ldif( ldif ? LDIF_PUT_COMMENT : LDIF_PUT_VALUE,
			"extended", retoid, retoid ? strlen(retoid) : 0 );
	}
	ber_memfree( retoid );

	if(retdata) {
		if ( ldif < 2 ) {
			write_ldif( ldif ? LDIF_PUT_COMMENT : LDIF_PUT_BINARY,
				"data", retdata->bv_val, retdata->bv_len );
		}
		ber_bvfree( retdata );
	}

	print_result( ld, extended, 0 );
}

static void print_partial(
	LDAP *ld,
	LDAPMessage *partial )
{
	int rc;
	char *retoid = NULL;
	struct berval *retdata = NULL;
	LDAPControl **ctrls = NULL;

	if( ldif < 2 ) {
		printf(_("# extended partial response\n"));
	}

	rc = ldap_parse_intermediate( ld, partial,
		&retoid, &retdata, &ctrls, 0 );

	if( rc != LDAP_SUCCESS ) {
		ldap_perror(ld, "ldap_parse_intermediate");
		exit( EXIT_FAILURE );
	}

	if ( ldif < 2 ) {
		write_ldif( ldif ? LDIF_PUT_COMMENT : LDIF_PUT_VALUE,
			"partial", retoid, retoid ? strlen(retoid) : 0 );
	}

	ber_memfree( retoid );

	if( retdata ) {
		if ( ldif < 2 ) {
			write_ldif( ldif ? LDIF_PUT_COMMENT : LDIF_PUT_BINARY,
				"data", retdata->bv_val, retdata->bv_len );
		}

		ber_bvfree( retdata );
	}

	if( ctrls ) {
		print_ctrls( ctrls );
		ldap_controls_free( ctrls );
	}
}

static int print_result(
	LDAP *ld,
	LDAPMessage *result, int search )
{
	int rc;
	int err;
	char *matcheddn = NULL;
	char *text = NULL;
	char **refs = NULL;
	LDAPControl **ctrls = NULL;

	if( search ) {
		if ( ldif < 2 ) {
			printf(_("# search result\n"));
		}
		if ( ldif < 1 ) {
			printf("%s: %d\n", _("search"), ldap_msgid(result) );
		}
	}

	rc = ldap_parse_result( ld, result,
		&err, &matcheddn, &text, &refs, &ctrls, 0 );

	if( rc != LDAP_SUCCESS ) {
		ldap_perror(ld, "ldap_parse_result");
		exit( EXIT_FAILURE );
	}


	if( !ldif ) {
		printf( _("result: %d %s\n"), err, ldap_err2string(err) );

	} else if ( err != LDAP_SUCCESS ) {
		fprintf( stderr, "%s (%d)\n", ldap_err2string(err), err );
	}

	if( matcheddn ) {
		if( *matcheddn ) {
		if( !ldif ) {
			write_ldif( LDIF_PUT_VALUE,
				"matchedDN", matcheddn, strlen(matcheddn) );
		} else {
			fprintf( stderr, _("Matched DN: %s\n"), matcheddn );
		}
		}

		ber_memfree( matcheddn );
	}

	if( text ) {
		if( *text ) {
		if( !ldif ) {
			write_ldif( LDIF_PUT_TEXT, "text",
				text, strlen(text) );
		} else {
			fprintf( stderr, _("Additional information: %s\n"), text );
		}
		}

		ber_memfree( text );
	}

	if( refs ) {
		int i;
		for( i=0; refs[i] != NULL; i++ ) {
			if( !ldif ) {
				write_ldif( LDIF_PUT_VALUE, "ref", refs[i], strlen(refs[i]) );
			} else {
				fprintf( stderr, _("Referral: %s\n"), refs[i] );
			}
		}

		ber_memvfree( (void **) refs );
	}

	if( ctrls ) {
		print_ctrls( ctrls );
		ldap_controls_free( ctrls );
	}

	return err;
}

static void print_ctrls(
	LDAPControl **ctrls )
{
	int i;
	for(i=0; ctrls[i] != NULL; i++ ) {
		/* control: OID criticality base64value */
		struct berval *b64 = NULL;
		ber_len_t len;
		char *str;

		len = ldif ? 2 : 0;
		len += strlen( ctrls[i]->ldctl_oid );

		/* add enough for space after OID and the critical value itself */
		len += ctrls[i]->ldctl_iscritical
			? sizeof("true") : sizeof("false");

		/* convert to base64 */
		if( ctrls[i]->ldctl_value.bv_len ) {
			b64 = ber_memalloc( sizeof(struct berval) );
			
			b64->bv_len = LUTIL_BASE64_ENCODE_LEN(
				ctrls[i]->ldctl_value.bv_len ) + 1;
			b64->bv_val = ber_memalloc( b64->bv_len + 1 );

			b64->bv_len = lutil_b64_ntop(
				(unsigned char *) ctrls[i]->ldctl_value.bv_val,
				ctrls[i]->ldctl_value.bv_len,
				b64->bv_val, b64->bv_len );
		}

		if( b64 ) {
			len += 1 + b64->bv_len;
		}

		str = malloc( len + 1 );
		if ( ldif ) {
			strcpy( str, ": " );
		} else {
			str[0] = '\0';
		}
		strcat( str, ctrls[i]->ldctl_oid );
		strcat( str, ctrls[i]->ldctl_iscritical
			? " true" : " false" );

		if( b64 ) {
			strcat(str, " ");
			strcat(str, b64->bv_val );
		}

		if ( ldif < 2 ) {
			write_ldif( ldif ? LDIF_PUT_COMMENT : LDIF_PUT_VALUE,
				"control", str, len );
		}

		free( str );
		ber_bvfree( b64 );
	}
}

static int
write_ldif( int type, char *name, char *value, ber_len_t vallen )
{
	char	*ldif;

	if (( ldif = ldif_put( type, name, value, vallen )) == NULL ) {
		return( -1 );
	}

	fputs( ldif, stdout );
	ber_memfree( ldif );

	return( 0 );
}


#ifdef LDAP_CONTROL_PAGEDRESULTS
static int 
parse_page_control(
	LDAP *ld,
	LDAPMessage *result,
	struct berval *cookie )
{
	int rc;
	int err;
	LDAPControl **ctrl = NULL;
	LDAPControl *ctrlp = NULL;
	BerElement *ber;
	ber_tag_t tag;
	struct berval servercookie = { 0, NULL };

	rc = ldap_parse_result( ld, result,
		&err, NULL, NULL, NULL, &ctrl, 0 );

	if( rc != LDAP_SUCCESS ) {
		ldap_perror(ld, "ldap_parse_result");
		exit( EXIT_FAILURE );
	}

	if ( err != LDAP_SUCCESS ) {
		fprintf( stderr, "%s (%d)\n", ldap_err2string(err), err );
	}

	if( ctrl ) {
		/* Parse the control value
		 * searchResult ::= SEQUENCE {
		 *		size	INTEGER (0..maxInt),
		 *				-- result set size estimate from server - unused
		 *		cookie	OCTET STRING
		 * }
		 */
		ctrlp = *ctrl;
		ber = ber_init( &ctrlp->ldctl_value );
		if ( ber == NULL ) {
			fprintf( stderr, _("Internal error.\n") );
			return EXIT_FAILURE;
		}

		tag = ber_scanf( ber, "{im}", &entriesLeft, &servercookie );
		ber_dupbv( cookie, &servercookie );
		(void) ber_free( ber, 1 );

		if( tag == LBER_ERROR ) {
			fprintf( stderr,
				_("Paged results response control could not be decoded.\n") );
			return EXIT_FAILURE;
		}

		if( entriesLeft < 0 ) {
			fprintf( stderr,
				_("Invalid entries estimate in paged results response.\n") );
			return EXIT_FAILURE;
		}

		ldap_controls_free( ctrl );

	} else {
		morePagedResults = 0;
	}

	return err;
}
#endif
