/* schemaparse.c - routines to parse config file objectclass definitions */

#include "portable.h"

#include <stdio.h>

#include <ac/string.h>
#include <ac/socket.h>

#include "slap.h"
#include "ldap_schema.h"

ObjectClass 		*global_oc;
static Avlnode		*object_classes = NULL;

AttributeType		*global_at;
int	global_schemacheck = 1; /* schemacheck on is default */

static void		oc_usage_old(void);
static void		oc_usage(void);

static char *err2text[] = {
	"",
	"Out of memory",
	"Objectclass not found",
	"Attribute type not found",
	"Duplicate objectclass",
	"Duplicate attributetype"
};

char *
scherr2str(int code)
{
	if ( code < 1 || code >= (sizeof(err2text)/sizeof(char *)) ) {
		return "Unknown error";
	} else {
		return err2text[code];
	}
}

void
parse_oc_old(
    Backend	*be,
    char	*fname,
    int		lineno,
    int		argc,
    char	**argv
)
{
	int		i;
	char		last;
	LDAP_OBJECT_CLASS	*oc;
	int		code;
	char		*err;
	char		**namep;

	oc = (LDAP_OBJECT_CLASS *) ch_calloc( 1, sizeof(LDAP_OBJECT_CLASS) );
	oc->oc_names = ch_calloc( 2, sizeof(char *) );
	oc->oc_names[0] = ch_strdup( argv[1] );
	oc->oc_names[1] = NULL;
	for ( i = 2; i < argc; i++ ) {
		/* required attributes */
		if ( strcasecmp( argv[i], "requires" ) == 0 ) {
			do {
				i++;
				if ( i < argc ) {
					char **s = str2charray( argv[i], "," );
					last = argv[i][strlen( argv[i] ) - 1];
					charray_merge( &oc->oc_at_oids_must, s );
					charray_free( s );
				}
			} while ( i < argc && last == ',' );

		/* optional attributes */
		} else if ( strcasecmp( argv[i], "allows" ) == 0 ) {
			do {
				i++;
				if ( i < argc ) {
					char **s = str2charray( argv[i], "," );
					last = argv[i][strlen( argv[i] ) - 1];
					
					charray_merge( &oc->oc_at_oids_may, s );
					charray_free( s );
				}
			} while ( i < argc && last == ',' );

		} else {
			fprintf( stderr,
	    "%s: line %d: expecting \"requires\" or \"allows\" got \"%s\"\n",
			    fname, lineno, argv[i] );
			oc_usage_old();
		}
	}

	/*
	 * There was no requirement in the old schema that all attributes
	 * types were defined before use and they would just default to
	 * SYNTAX_CIS.  To support this, we need to make attribute types
	 * out of thin air.
	 */
	if ( oc->oc_at_oids_must ) {
		namep = oc->oc_at_oids_must;
		while ( *namep ) {
			code = at_fake_if_needed( *namep );
			if ( code ) {
				fprintf( stderr, "%s: line %d: %s %s\n",
					 fname, lineno, scherr2str(code), *namep);
				exit( 1 );
			}
			namep++;
		}
	}
	if ( oc->oc_at_oids_may ) {
		namep = oc->oc_at_oids_may;
		while ( *namep ) {
			code = at_fake_if_needed( *namep );
			if ( code ) {
				fprintf( stderr, "%s: line %d: %s %s\n",
					 fname, lineno, scherr2str(code), *namep);
				exit( 1 );
			}
			namep++;
		}
	}
	
	code = oc_add(oc,&err);
	if ( code ) {
		fprintf( stderr, "%s: line %d: %s %s\n",
			 fname, lineno, scherr2str(code), err);
		exit( 1 );
	}
	ldap_memfree(oc);
}

void
parse_oc(
    char	*fname,
    int		lineno,
    char	*line
)
{
	LDAP_OBJECT_CLASS *oc;
	int		code;
	char		*err;

	oc = ldap_str2objectclass(line,&code,&err);
	if ( !oc ) {
		fprintf( stderr, "%s: line %d: %s before %s\n",
			 fname, lineno, ldap_scherr2str(code), err );
		oc_usage();
	}
	code = oc_add(oc,&err);
	if ( code ) {
		fprintf( stderr, "%s: line %d: %s %s\n",
			 fname, lineno, scherr2str(code), err);
		exit( 1 );
	}
	ldap_memfree(oc);
}

static void
oc_usage( void )
{
	fprintf( stderr, "ObjectClassDescription = \"(\" whsp\n");
	fprintf( stderr, "  numericoid whsp      ; ObjectClass identifier\n");
	fprintf( stderr, "  [ \"NAME\" qdescrs ]\n");
	fprintf( stderr, "  [ \"DESC\" qdstring ]\n");
	fprintf( stderr, "  [ \"OBSOLETE\" whsp ]\n");
	fprintf( stderr, "  [ \"SUP\" oids ]       ; Superior ObjectClasses\n");
	fprintf( stderr, "  [ ( \"ABSTRACT\" / \"STRUCTURAL\" / \"AUXILIARY\" ) whsp ]\n");
	fprintf( stderr, "                       ; default structural\n");
	fprintf( stderr, "  [ \"MUST\" oids ]      ; AttributeTypes\n");
	fprintf( stderr, "  [ \"MAY\" oids ]       ; AttributeTypes\n");
	fprintf( stderr, "whsp \")\"\n");
	exit( 1 );
}

static void
oc_usage_old( void )
{
	fprintf( stderr, "<oc clause> ::= objectclass <ocname>\n" );
	fprintf( stderr, "                [ requires <attrlist> ]\n" );
	fprintf( stderr, "                [ allows <attrlist> ]\n" );
	exit( 1 );
}

static void
at_usage( void )
{
	fprintf( stderr, "AttributeTypeDescription = \"(\" whsp\n");
	fprintf( stderr, "  numericoid whsp      ; AttributeType identifier\n");
	fprintf( stderr, "  [ \"NAME\" qdescrs ]             ; name used in AttributeType\n");
	fprintf( stderr, "  [ \"DESC\" qdstring ]            ; description\n");
	fprintf( stderr, "  [ \"OBSOLETE\" whsp ]\n");
	fprintf( stderr, "  [ \"SUP\" woid ]                 ; derived from this other\n");
	fprintf( stderr, "                                 ; AttributeType\n");
	fprintf( stderr, "  [ \"EQUALITY\" woid ]            ; Matching Rule name\n");
        fprintf( stderr, "  [ \"ORDERING\" woid ]            ; Matching Rule name\n");
	fprintf( stderr, "  [ \"SUBSTR\" woid ]              ; Matching Rule name\n");
	fprintf( stderr, "  [ \"SYNTAX\" whsp noidlen whsp ] ; see section 4.3\n");
	fprintf( stderr, "  [ \"SINGLE-VALUE\" whsp ]        ; default multi-valued\n");
	fprintf( stderr, "  [ \"COLLECTIVE\" whsp ]          ; default not collective\n");
	fprintf( stderr, "  [ \"NO-USER-MODIFICATION\" whsp ]; default user modifiable\n");
	fprintf( stderr, "  [ \"USAGE\" whsp AttributeUsage ]; default userApplications\n");
	fprintf( stderr, "                                 ; userApplications\n");
	fprintf( stderr, "                                 ; directoryOperation\n");
	fprintf( stderr, "                                 ; distributedOperation\n");
	fprintf( stderr, "                                 ; dSAOperation\n");
	fprintf( stderr, "whsp \")\"\n");
	exit( 1 );
}

void
parse_at(
    char	*fname,
    int		lineno,
    char	*line
)
{
	LDAP_ATTRIBUTE_TYPE *at;
	int		code;
	char		*err;

	at = ldap_str2attributetype(line,&code,&err);
	if ( !at ) {
		fprintf( stderr, "%s: line %d: %s before %s\n",
			 fname, lineno, ldap_scherr2str(code), err );
		at_usage();
	}
	code = at_add(at,&err);
	if ( code ) {
		fprintf( stderr, "%s: line %d: %s %s\n",
			 fname, lineno, scherr2str(code), err);
		exit( 1 );
	}
	ldap_memfree(at);
}
