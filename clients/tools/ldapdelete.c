/* ldapdelete.c - simple program to delete an entry using LDAP */

#include "portable.h"

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

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
    fprintf(stderr, "Usage: %s [options] [dn]...", s);
    fprintf(stderr, "  -c\t\tcontinuous operation mode\n");
    fprintf(stderr, "  -D bindnd\tbind dn\n");
    fprintf(stderr, "  -d level\tdebugging level\n");
    fprintf(stderr, "  -f file\t\t\n");
    fprintf(stderr, "  -h host\tldap sever\n");
#ifdef HAVE_KERBEROS
    fprintf(stderr, "  -K\t\tuse Kerberos step 1\n");
    fprintf(stderr, "  -k\t\tuse Kerberos instead of Simple Password authentication\n");
#endif
    fprintf(stderr, "  -n\t\t make no modifications\n");
    fprintf(stderr, "  -p port\tldap port\n");
    fprintf(stderr, "  -v\t\tverbose\n");
    fprintf(stderr, "  -W\t\tprompt for bind password\n");
    fprintf(stderr, "  -w passwd\tbind password (for simple authentication)\n");
    exit(1);
}

static int dodelete LDAP_P((
    LDAP	*ld,
    char	*dn));

int
main( int argc, char **argv )
{
    FILE	*fp = NULL;
    LDAP	*ld = NULL;
    char	buf[4096];
    char	*binddn = NULL;
    char	*passwd = NULL;
    char	*ldaphost = NULL;
    int         authmethod = LDAP_AUTH_SIMPLE;
    int         deref = LDAP_DEREF_NEVER;
    int		i, rc, want_passwd;
    int         ldapport = LDAP_PORT;

    rc = not = verbose = contoper = want_passwd = 0;

    while ((i = getopt( argc, argv, "cD:d:f:h:Kknp:vWw:")) != EOF )
    {
        switch(i)
        {
	case 'c':	/* continuous operation mode */
	    contoper++;
	    break;

        case 'D':	/* bind DN */
	    binddn = strdup(optarg);
	    break;

        case 'd':
#ifdef LDAP_DEBUG
	    ldap_debug = lber_debug = atoi(optarg);
#else
	    fprintf( stderr, "compile with -DLDAP_DEBUG for debugging\n" );
#endif
	    break;

        case 'f':	/* read DNs from a file */
            if ((fp = fopen(optarg, "r")) == NULL)
            {
		perror(optarg);
		return(1);
	    }
	    break;

        case 'h':	/* ldap host */
	    ldaphost = strdup(optarg);
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

        case 'n':	/* print deletes, don't actually do them */
	    not++;
	    break;

        case 'p':
	    ldapport = atoi( optarg );
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

    if (want_passwd && !passwd)
        passwd = strdup(getpass("Enter LDAP Password: "));

    if (fp == NULL && optind >= argc)
        fp = stdin;

    if ((ld = ldap_open(ldaphost, ldapport)) == NULL) {
	perror("ldap_open");
	return(1);
    }

    /* this seems prudent */
    ldap_set_option(ld, LDAP_OPT_DEREF, &deref);

    if (ldap_bind_s(ld, binddn, passwd, authmethod) != LDAP_SUCCESS) {
	ldap_perror(ld, "ldap_bind");
	return(1);
    }

    if (fp == NULL) {
	for (; optind < argc; ++optind)
	    rc = dodelete(ld, argv[optind]);
    } else {
	rc = 0;
	while ((rc == 0 || contoper) && fgets(buf, sizeof(buf), fp) != NULL) {
	    buf[strlen(buf) - 1] = '\0';	/* remove trailing newline */
	    if ( *buf != '\0' )
                rc = dodelete( ld, buf );
	}
    }

    ldap_unbind(ld);

    return(rc);
}

static int
dodelete(
    LDAP	*ld,
    char	*dn)
{
    int	rc;

    if (verbose)
	printf( "%sdeleting entry %s\n", not ? "!" : "", dn );

    if (not)
	rc = LDAP_SUCCESS;
    else {
        if ((rc = ldap_delete_s(ld, dn)) != LDAP_SUCCESS)
            ldap_perror(ld, "ldap_delete");
        else if (verbose)
            printf("entry removed\n");
    }

    return(rc);
}
