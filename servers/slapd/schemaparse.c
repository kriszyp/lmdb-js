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

static void		oc_usage(void)     LDAP_GCCATTR((noreturn));
static void		at_usage(void)     LDAP_GCCATTR((noreturn));

static char *const err2text[] = {
	"Success",
	"Out of memory",
	"ObjectClass not found",
	"ObjectClass inappropriate SUPerior",
	"AttributeType not found",
	"AttributeType inappropriate USAGE",
	"Duplicate objectClass",
	"Duplicate attributeType",
	"Duplicate ldapSyntax",
	"Duplicate matchingRule",
	"OID or name required",
	"SYNTAX or SUPerior required",
	"MatchingRule not found",
	"Syntax not found",
	"Syntax required"
};

char *
scherr2str(int code)
{
	if ( code < 0 || code >= (sizeof(err2text)/sizeof(char *)) ) {
		return "Unknown error";
	} else {
		return err2text[code];
	}
}


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
	if ( OID_LEADCHAR( *oid ) )	{
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
	LDAPObjectClass *oc;
	int		code;
	const char	*err;
	char		*oid = NULL;

	oc = ldap_str2objectclass(line,&code,&err,LDAP_SCHEMA_ALLOW_ALL);
	if ( !oc ) {
		fprintf( stderr, "%s: line %d: %s before %s\n",
			 fname, lineno, ldap_scherr2str(code), err );
		oc_usage();
	}
	if ( oc->oc_oid ) {
		if ( !OID_LEADCHAR( oc->oc_oid[0] )) {
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
		fprintf( stderr, "%s: line %d: %s: \"%s\"\n",
			 fname, lineno, scherr2str(code), err);
		exit( EXIT_FAILURE );
	}
	ldap_memfree(oc);
}

static void
oc_usage( void )
{
	fprintf( stderr,
		"ObjectClassDescription = \"(\" whsp\n"
		"  numericoid whsp                 ; ObjectClass identifier\n"
		"  [ \"NAME\" qdescrs ]\n"
		"  [ \"DESC\" qdstring ]\n"
		"  [ \"OBSOLETE\" whsp ]\n"
		"  [ \"SUP\" oids ]                ; Superior ObjectClasses\n"
		"  [ ( \"ABSTRACT\" / \"STRUCTURAL\" / \"AUXILIARY\" ) whsp ]\n"
		"                                  ; default structural\n"
		"  [ \"MUST\" oids ]               ; AttributeTypes\n"
		"  [ \"MAY\" oids ]                ; AttributeTypes\n"
		"  whsp \")\"\n" );
	exit( EXIT_FAILURE );
}


static void
at_usage( void )
{
	fprintf( stderr,
		"AttributeTypeDescription = \"(\" whsp\n"
		"  numericoid whsp      ; AttributeType identifier\n"
		"  [ \"NAME\" qdescrs ]             ; name used in AttributeType\n"
		"  [ \"DESC\" qdstring ]            ; description\n"
		"  [ \"OBSOLETE\" whsp ]\n"
		"  [ \"SUP\" woid ]                 ; derived from this other\n"
		"                                   ; AttributeType\n"
		"  [ \"EQUALITY\" woid ]            ; Matching Rule name\n"
		"  [ \"ORDERING\" woid ]            ; Matching Rule name\n"
		"  [ \"SUBSTR\" woid ]              ; Matching Rule name\n"
		"  [ \"SYNTAX\" whsp noidlen whsp ] ; see section 4.3\n"
		"  [ \"SINGLE-VALUE\" whsp ]        ; default multi-valued\n"
		"  [ \"COLLECTIVE\" whsp ]          ; default not collective\n"
		"  [ \"NO-USER-MODIFICATION\" whsp ]; default user modifiable\n"
		"  [ \"USAGE\" whsp AttributeUsage ]; default userApplications\n"
		"                                   ; userApplications\n"
		"                                   ; directoryOperation\n"
		"                                   ; distributedOperation\n"
		"                                   ; dSAOperation\n"
		"  whsp \")\"\n");
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
	LDAPAttributeType *at;
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
		    !OID_LEADCHAR(*argv[4]))
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
	at = ldap_str2attributetype(line,&code,&err,LDAP_SCHEMA_ALLOW_ALL);
	if ( !at ) {
		fprintf( stderr, "%s: line %d: %s before %s\n",
			 fname, lineno, ldap_scherr2str(code), err );
		at_usage();
	}
	if ( at->at_oid ) {
		if ( !OID_LEADCHAR( at->at_oid[0] )) {
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
	if (soid) {
		ldap_memfree(at->at_syntax_oid);
		at->at_syntax_oid = soid;
	}
	code = at_add(at,&err);
	if ( code ) {
		fprintf( stderr, "%s: line %d: %s: \"%s\"\n",
			 fname, lineno, scherr2str(code), err);
		exit( EXIT_FAILURE );
	}
	ldap_memfree(at);
}
