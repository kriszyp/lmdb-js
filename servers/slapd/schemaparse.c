/* schemaparse.c - routines to parse config file objectclass definitions */
/* $OpenLDAP$ */
/*
 * Copyright 1998-2000 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "portable.h"

#include <stdio.h>

#include <ac/ctype.h>
#include <ac/string.h>
#include <ac/socket.h>

#include "slap.h"
#include "ldap_schema.h"

int	global_schemacheck = 1; /* schemacheck on is default */

#ifndef SLAPD_SCHEMA_NOT_COMPAT
static void		oc_usage_old(void) LDAP_GCCATTR((noreturn));
#endif
static void		oc_usage(void)     LDAP_GCCATTR((noreturn));
static void		at_usage(void)     LDAP_GCCATTR((noreturn));

static char *const err2text[] = {
	"",
	"Out of memory",
	"Objectclass not found",
	"Attribute type not found",
	"Duplicate objectclass",
	"Duplicate attributetype",
	"Duplicate syntax",
	"Duplicate matchingrule",
	"OID or name required",
	"Syntax or superior required",
	"Matchingrule not found",
	"Syntax not found",
	"Syntax required"
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

#ifndef SLAPD_SCHEMA_NOT_COMPAT
void
parse_oc_old(
    Backend	*be,
    const char	*fname,
    int		lineno,
    int		argc,
    char	**argv
)
{
	int		i;
	char		last;
	LDAP_OBJECT_CLASS	*oc;
	int		code;
	const char	*err;
	char		**namep;

	oc = (LDAP_OBJECT_CLASS *) ch_calloc( 1, sizeof(LDAP_OBJECT_CLASS) );
	oc->oc_names = ch_calloc( 2, sizeof(char *) );
	oc->oc_names[0] = ch_strdup( argv[1] );
	oc->oc_names[1] = NULL;

	if ( strcasecmp( oc->oc_names[0], "top" ) ) {
		/*
		 * no way to distinguish "auxiliary" from "structural"
		 * This may lead to future problems.
		 */
		oc->oc_kind = LDAP_SCHEMA_STRUCTURAL;
	}
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
		for( namep = oc->oc_at_oids_must; *namep ; namep++ ) {
			code = at_fake_if_needed( *namep );
			if ( code ) {
				fprintf( stderr, "%s: line %d: %s %s\n",
					 fname, lineno, scherr2str(code), *namep);
				exit( EXIT_FAILURE );
			}
		}
	}
	if ( oc->oc_at_oids_may ) {
		for( namep = oc->oc_at_oids_may; *namep; namep++ ) {
			code = at_fake_if_needed( *namep );
			if ( code ) {
				fprintf( stderr, "%s: line %d: %s %s\n",
					 fname, lineno, scherr2str(code), *namep);
				exit( EXIT_FAILURE );
			}
		}
	}
	
	code = oc_add(oc,&err);
	if ( code ) {
		fprintf( stderr, "%s: line %d: %s %s\n",
			 fname, lineno, scherr2str(code), err);
		exit( EXIT_FAILURE );
	}
	ldap_memfree(oc);
}
#endif

/* OID Macros */

/* String compare with delimiter check. Return 0 if not
 * matched, otherwise return length matched.
 */
int
dscompare(const char *s1, const char *s2, char delim)
{
	const char *orig = s1;
	while (*s1++ == *s2++)
		if (!s1[-1]) break;
	--s1;
	--s2;
	if (!*s1 && (!*s2 || *s2 == delim))
		return s1 - orig;
	return 0;
}

static OidMacro *om_list = NULL;

/* Replace an OID Macro invocation with its full numeric OID.
 * If the macro is used with "macroname:suffix" append ".suffix"
 * to the expansion.
 */
static char *
find_oidm(char *oid)
{
	OidMacro *om;

	/* OID macros must start alpha */
	if ( isdigit( *oid ) )	{
		return oid;
	}

    for (om = om_list; om; om=om->som_next) {
		char **names = om->som_names;

		if( names == NULL ) {
			continue;
		}

		for( ; *names != NULL ; names++ ) {
			int pos = dscompare(*names, oid, ':');

			if( pos ) {
				int suflen = strlen(oid + pos);
				char *new = ch_calloc(1,
					om->som_oid.bv_len + suflen + 1);
				strcpy(new, om->som_oid.bv_val);

				if( suflen ) {
					suflen = om->som_oid.bv_len;
					new[suflen++] = '.';
					strcpy(new+suflen, oid+pos+1);
				}
				return new;
			}
		}
	}
	return NULL;
}

void
parse_oidm(
    const char	*fname,
    int		lineno,
    int		argc,
    char 	**argv
)
{
	char *oid;
	OidMacro *om;

	if (argc != 3) {
		fprintf( stderr, "%s: line %d: too many arguments\n",
			fname, lineno );
usage:	fprintf( stderr, "\tObjectIdentifier <name> <oid>\n");
		exit( EXIT_FAILURE );
	}

	oid = find_oidm( argv[1] );
	if( oid != NULL ) {
		fprintf( stderr,
			"%s: line %d: "
			"ObjectIdentifier \"%s\" previously defined \"%s\"",
			fname, lineno, argv[1], oid );
		exit( EXIT_FAILURE );
	}

	om = (OidMacro *) ch_malloc( sizeof(OidMacro) );

	om->som_names = NULL;
	charray_add( &om->som_names, argv[1] );
	om->som_oid.bv_val = find_oidm( argv[2] );

	if (!om->som_oid.bv_val) {
		fprintf( stderr, "%s: line %d: OID %s not recognized\n",
			fname, lineno, argv[2] );
		goto usage;
	}

	if (om->som_oid.bv_val == argv[2]) {
		om->som_oid.bv_val = ch_strdup( argv[2] );
	}

	om->som_oid.bv_len = strlen( om->som_oid.bv_val );
	om->som_next = om_list;
	om_list = om;
}

void
parse_oc(
    const char	*fname,
    int		lineno,
    char	*line,
    char	**argv
)
{
	LDAP_OBJECT_CLASS *oc;
	int		code;
	const char	*err;
	char		*oid = NULL;

	oc = ldap_str2objectclass(line,&code,&err);
	if ( !oc ) {
		fprintf( stderr, "%s: line %d: %s before %s\n",
			 fname, lineno, ldap_scherr2str(code), err );
		oc_usage();
	}
	if ( oc->oc_oid ) {
		if ( !isdigit( oc->oc_oid[0] )) {
			/* Expand OID macros */
			oid = find_oidm( oc->oc_oid );
			if ( !oid ) {
				fprintf(stderr,
					"%s: line %d: OID %s not recognized\n",
					fname, lineno, oc->oc_oid);
				exit( EXIT_FAILURE );
			}
			if ( oid != oc->oc_oid ) {
				ldap_memfree( oc->oc_oid );
				oc->oc_oid = oid;
			}
		}
	}
	/* oc->oc_oid == NULL will be an error someday */
	code = oc_add(oc,&err);
	if ( code ) {
		fprintf( stderr, "%s: line %d: %s %s\n",
			 fname, lineno, scherr2str(code), err);
		exit( EXIT_FAILURE );
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
	exit( EXIT_FAILURE );
}

#ifndef SLAPD_SCHEMA_NOT_COMPAT
static void
oc_usage_old( void )
{
	fprintf( stderr, "<oc clause> ::= objectclass <ocname>\n" );
	fprintf( stderr, "                [ requires <attrlist> ]\n" );
	fprintf( stderr, "                [ allows <attrlist> ]\n" );
	exit( EXIT_FAILURE );
}
#endif

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
	exit( EXIT_FAILURE );
}

void
parse_at(
    const char	*fname,
    int		lineno,
    char	*line,
    char	**argv
)
{
	LDAP_ATTRIBUTE_TYPE *at;
	int		code;
	const char	*err;
	char		*oid = NULL;
	char		*soid = NULL;

 	/* Kludge for OIDmacros for syntaxes. If the syntax field starts
	 * nonnumeric, look for and expand a macro. The macro's place in
	 * the input line will be replaced with a field of '0's to keep
	 * ldap_str2attributetype happy. The actual oid will be swapped
	 * into place afterwards.
 	 */
	for (; argv[3]; argv++)
	{
		if (!strcasecmp(argv[3], "syntax") &&
		    !isdigit(*argv[4]))
		{
			int slen;
			Syntax *syn;
			syn = syn_find_desc(argv[4], &slen);
			if (!syn)
			{
			    fprintf(stderr, "%s: line %d: OID %s not found\n",
				fname, lineno, argv[4]);
			    exit( EXIT_FAILURE );
			}
			memset(strstr(line, argv[4]), '0', slen);
			soid = ch_strdup(syn->ssyn_syn.syn_oid );
			break;
		}
	}
	at = ldap_str2attributetype(line,&code,&err);
	if ( !at ) {
		fprintf( stderr, "%s: line %d: %s before %s\n",
			 fname, lineno, ldap_scherr2str(code), err );
		at_usage();
	}
	if ( at->at_oid ) {
		if ( !isdigit( at->at_oid[0] )) {
			/* Expand OID macros */
			oid = find_oidm( at->at_oid );
			if ( !oid ) {
				fprintf(stderr,
					"%s: line %d: OID %s not recognized\n",
					fname, lineno, at->at_oid);
				exit( EXIT_FAILURE );
			}
			if ( oid != at->at_oid ) {
				ldap_memfree( at->at_oid );
				at->at_oid = oid;
			}
		}
	}
	/* at->at_oid == NULL will be an error someday */
	if (soid)
	{
		ldap_memfree(at->at_syntax_oid);
		at->at_syntax_oid = soid;
	}
	code = at_add(at,&err);
	if ( code ) {
		fprintf( stderr, "%s: line %d: %s %s\n",
			 fname, lineno, scherr2str(code), err);
		exit( EXIT_FAILURE );
	}
	ldap_memfree(at);
}
