/* ldapmodrdn.c - generic program to modify an entry's RDN using LDAP */

#include "portable.h"

#include <stdio.h>
#include <stdlib.h>

#include <ac/ctype.h>
#include <ac/string.h>
#include <ac/unistd.h>

#include <lber.h>
#include <ldap.h>

static int	not, verbose, contoper;

#define safe_realloc( ptr, size )	( ptr == NULL ? malloc( size ) : \
					 realloc( ptr, size ))

static void
usage(char *s)
{
    fprintf(stderr, "Usage: %s [options] [dn]...\n", s);
    fprintf(stderr, "  -c\t\tcontinuous operation mode\n");
    fprintf(stderr, "  -D bindnd\tbind dn\n");
    fprintf(stderr, "  -d level\tdebugging level\n");
    fprintf(stderr, "  -f file\tread from file\n");
    fprintf(stderr, "  -h host\tldap sever\n");
#ifdef HAVE_KERBEROS
    fprintf(stderr, "  -K\t\tuse Kerberos step 1\n");
    fprintf(stderr, "  -k\t\tuse Kerberos instead of Simple Password authentication\n");
#endif
    fprintf(stderr, "  -n\t\tmake no modifications\n");
    fprintf(stderr, "  -p port\tldap port\n");
    fprintf(stderr, "  -r\t\tremove old RDN\n");
    fprintf(stderr, "  -v\t\tverbose\n");
    fprintf(stderr, "  -W\t\tprompt for bind password\n");
    fprintf(stderr, "  -w passwd\tbind password (for simple authentication)\n");
    exit(1);
}

static int domodrdn LDAP_P((
    LDAP	*ld,
    char	*dn,
    char	*rdn,
    int		remove));	/* flag: remove old RDN */

int
main(int argc, char **argv)
{
    FILE	*fp = NULL;
    LDAP	*ld = NULL;
    char	*myname, *infile, *entrydn, *rdn, buf[ 4096 ];
    char	*binddn = NULL;
    char	*passwd = NULL;
    char	*ldaphost = NULL;
    int		rc, i, remove, havedn, want_passwd;
    int         authmethod = LDAP_AUTH_SIMPLE;
    int	        ldapport = LDAP_PORT;

    infile = entrydn = rdn = NULL;
    not = contoper = verbose = remove = want_passwd = 0;
    myname = (myname = strrchr(argv[0], '/')) == NULL ? argv[0] : ++myname;

    while ((i = getopt(argc, argv, "cD:d:f:h:Kknp:rvWw:")) != EOF)
    {
        switch(i)
        {
	case 'c':	/* continuous operation mode */
	    contoper++;
	    break;

        case 'D':	/* bind DN */
	    binddn = strdup( optarg );
	    break;

        case 'd':
#ifdef LDAP_DEBUG
	    ldap_debug = lber_debug = atoi( optarg );
#else /* LDAP_DEBUG */
	    fprintf( stderr, "compile with -DLDAP_DEBUG for debugging\n" );
#endif /* LDAP_DEBUG */
	    break;

	case 'f':	/* read from file */
	    infile = strdup( optarg );
	    break;

        case 'h':	/* ldap host */
	    ldaphost = strdup( optarg );
	    break;

        case 'K':	/* kerberos bind, part one only */
#ifdef HAVE_KERBEROS
            authmethod = LDAP_AUTH_KRBV41;
#else
            fprintf(stderr, "%s was not compiled with Kerberos support\n", argv[0]);
#endif
            break;

        case 'k':	/* kerberos bind */
#ifdef HAVE_KERBEROS
            authmethod = LDAP_AUTH_KRBV4;
#else
            fprintf(stderr, "%s was not compiled with Kerberos support\n", argv[0]);
#endif
	    break;

	case 'n':	/* print adds, don't actually do them */
	    not++;
	    break;

        case 'p':
	    ldapport = atoi( optarg );
	    break;

        case 'r':	/* remove old RDN */
	    remove++;
	    break;

        case 'v':	/* verbose mode */
	    verbose++;
	    break;

        case 'W':
            want_passwd++;
            break;

        case 'w':	/* password */
	    passwd = strdup(optarg);
	    break;

        default:
            usage(argv[0]);
	}
    }

    havedn = 0;
    if (argc - optind == 2)
    {
        if (( rdn = strdup( argv[argc - 1] )) == NULL )
        {
	    perror( "strdup" );
	    return(1);
	}
        if (( entrydn = strdup( argv[argc - 2] )) == NULL )
        {
	    perror( "strdup" );
	    return( 1 );
        }
	havedn++;
    } else if (argc - optind != 0) {
        fprintf(stderr, "%s: invalid number of arguments, only two allowed\n", myname);
        usage(argv[0]);
    }

    if (want_passwd && !passwd)
        passwd = strdup(getpass("Enter LDAP password: "));

    if (infile != NULL)
    {
        if ((fp = fopen( infile, "r" )) == NULL)
        {
	    perror(infile);
	    return(1);
	}
    } else
	fp = stdin;

    if ((ld = ldap_open(ldaphost, ldapport)) == NULL)
    {
	perror("ldap_open");
	return(1);
    }

    /* this seems prudent */
    ldap_set_option(ld, LDAP_OPT_DEREF, LDAP_DEREF_NEVER);

    if (ldap_bind_s(ld, binddn, passwd, authmethod) != LDAP_SUCCESS)
    {
	ldap_perror(ld, "ldap_bind");
	return(1);
    }

    rc = 0;
    if (havedn)
	rc = domodrdn(ld, entrydn, rdn, remove);
    else while ((rc == 0 || contoper) && fgets(buf, sizeof(buf), fp) != NULL) {
	if (*buf != '\0') {	/* blank lines optional, skip */
	    buf[strlen(buf) - 1] = '\0';	/* remove nl */

            if (havedn)
            {
                /* have DN, get RDN */
                if (( rdn = strdup( buf )) == NULL)
                {
                    perror( "strdup" );
                    exit( 1 );
		}
		rc = domodrdn(ld, entrydn, rdn, remove);
		havedn = 0;
            } else if (!havedn) {
                /* don't have DN yet */
                if (( entrydn = strdup( buf )) == NULL )
                {
		    perror( "strdup" );
		    exit( 1 );
	        }
		havedn++;
	    }
	}
    }

    ldap_unbind(ld);

    return(rc);
}

static int domodrdn(
    LDAP	*ld,
    char	*dn,
    char	*rdn,
    int		remove)	/* flag: remove old RDN */
{
    int	rc = LDAP_SUCCESS;

    if (verbose)
    {
	printf("modrdn %s:\n\t%s\n", dn, rdn);
	if (remove)
	    printf("removing old RDN\n");
	else
	    printf("keeping old RDN\n");
    }

    if (!not)
    {
	rc = ldap_modrdn2_s(ld, dn, rdn, remove);
	if (rc != LDAP_SUCCESS)
	    ldap_perror(ld, "ldap_modrdn2_s");
	else if (verbose)
	    printf("modrdn complete\n");
    }

    return(rc);
}
