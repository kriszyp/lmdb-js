#include <stdio.h>
#include <string.h>
#ifdef MACOS
#include <stdlib.h>
#else /* MACOS */
#if defined( DOS ) || defined( _WIN32 )
#include <malloc.h>
#include "msdos.h"
#else /* DOS */
#include <sys/types.h>
#include <sys/socket.h>
#endif /* DOS */
#endif /* MACOS */
#include "lber.h"
#include "ldap.h"

struct ldaperror {
	int	e_code;
	char	*e_reason;
};

static struct ldaperror ldap_errlist[] = {
	LDAP_SUCCESS, 			"Success",
	LDAP_OPERATIONS_ERROR, 		"Operations error",
	LDAP_PROTOCOL_ERROR, 		"Protocol error",
	LDAP_TIMELIMIT_EXCEEDED,	"Timelimit exceeded",
	LDAP_SIZELIMIT_EXCEEDED, 	"Sizelimit exceeded",
	LDAP_COMPARE_FALSE, 		"Compare false",
	LDAP_COMPARE_TRUE, 		"Compare true",
	LDAP_STRONG_AUTH_NOT_SUPPORTED, "Strong authentication not supported",
	LDAP_STRONG_AUTH_REQUIRED, 	"Strong authentication required",
	LDAP_PARTIAL_RESULTS, 		"Partial results and referral received",
	LDAP_NO_SUCH_ATTRIBUTE, 	"No such attribute",
	LDAP_UNDEFINED_TYPE, 		"Undefined attribute type",
	LDAP_INAPPROPRIATE_MATCHING, 	"Inappropriate matching",
	LDAP_CONSTRAINT_VIOLATION, 	"Constraint violation",
	LDAP_TYPE_OR_VALUE_EXISTS, 	"Type or value exists",
	LDAP_INVALID_SYNTAX, 		"Invalid syntax",
	LDAP_NO_SUCH_OBJECT, 		"No such object",
	LDAP_ALIAS_PROBLEM, 		"Alias problem",
	LDAP_INVALID_DN_SYNTAX,		"Invalid DN syntax",
	LDAP_IS_LEAF, 			"Object is a leaf",
	LDAP_ALIAS_DEREF_PROBLEM, 	"Alias dereferencing problem",
	LDAP_INAPPROPRIATE_AUTH, 	"Inappropriate authentication",
	LDAP_INVALID_CREDENTIALS, 	"Invalid credentials",
	LDAP_INSUFFICIENT_ACCESS, 	"Insufficient access",
	LDAP_BUSY, 			"DSA is busy",
	LDAP_UNAVAILABLE, 		"DSA is unavailable",
	LDAP_UNWILLING_TO_PERFORM, 	"DSA is unwilling to perform",
	LDAP_LOOP_DETECT, 		"Loop detected",
	LDAP_NAMING_VIOLATION, 		"Naming violation",
	LDAP_OBJECT_CLASS_VIOLATION, 	"Object class violation",
	LDAP_NOT_ALLOWED_ON_NONLEAF, 	"Operation not allowed on nonleaf",
	LDAP_NOT_ALLOWED_ON_RDN, 	"Operation not allowed on RDN",
	LDAP_ALREADY_EXISTS, 		"Already exists",
	LDAP_NO_OBJECT_CLASS_MODS, 	"Cannot modify object class",
	LDAP_RESULTS_TOO_LARGE,		"Results too large",
	LDAP_OTHER, 			"Unknown error",
	LDAP_SERVER_DOWN,		"Can't contact LDAP server",
	LDAP_LOCAL_ERROR,		"Local error",
	LDAP_ENCODING_ERROR,		"Encoding error",
	LDAP_DECODING_ERROR,		"Decoding error",
	LDAP_TIMEOUT,			"Timed out",
	LDAP_AUTH_UNKNOWN,		"Unknown authentication method",
	LDAP_FILTER_ERROR,		"Bad search filter",
	LDAP_USER_CANCELLED,		"User cancelled operation",
	LDAP_PARAM_ERROR,		"Bad parameter to an ldap routine",
	LDAP_NO_MEMORY,			"Out of memory",
	-1, 0
};

char *
ldap_err2string( int err )
{
	int	i;

	Debug( LDAP_DEBUG_TRACE, "ldap_err2string\n", 0, 0, 0 );

	for ( i = 0; ldap_errlist[i].e_code != -1; i++ ) {
		if ( err == ldap_errlist[i].e_code )
			return( ldap_errlist[i].e_reason );
	}

	return( "Unknown error" );
}

#ifndef NO_USERINTERFACE
void
ldap_perror( LDAP *ld, char *s )
{
	int	i;

	Debug( LDAP_DEBUG_TRACE, "ldap_perror\n", 0, 0, 0 );

	if ( ld == NULL ) {
		perror( s );
		return;
	}

	for ( i = 0; ldap_errlist[i].e_code != -1; i++ ) {
		if ( ld->ld_errno == ldap_errlist[i].e_code ) {
			fprintf( stderr, "%s: %s\n", s,
			    ldap_errlist[i].e_reason );
			if ( ld->ld_matched != NULL && *ld->ld_matched != '\0' )
				fprintf( stderr, "%s: matched: %s\n", s,
				    ld->ld_matched );
			if ( ld->ld_error != NULL && *ld->ld_error != '\0' )
				fprintf( stderr, "%s: additional info: %s\n",
				    s, ld->ld_error );
			fflush( stderr );
			return;
		}
	}

	fprintf( stderr, "%s: Not an LDAP errno %d\n", s, ld->ld_errno );
	fflush( stderr );
}

#else

void
ldap_perror( LDAP *ld, char *s )
{
}

#endif /* NO_USERINTERFACE */


int
ldap_result2error( LDAP *ld, LDAPMessage *r, int freeit )
{
	LDAPMessage	*lm;
	BerElement	ber;
	long		along;
	int		rc;

	Debug( LDAP_DEBUG_TRACE, "ldap_result2error\n", 0, 0, 0 );

	if ( r == NULLMSG )
		return( LDAP_PARAM_ERROR );

	for ( lm = r; lm->lm_chain != NULL; lm = lm->lm_chain )
		;	/* NULL */

	if ( ld->ld_error ) {
		free( ld->ld_error );
		ld->ld_error = NULL;
	}
	if ( ld->ld_matched ) {
		free( ld->ld_matched );
		ld->ld_matched = NULL;
	}

	ber = *(lm->lm_ber);
	if ( ld->ld_version == LDAP_VERSION2 ) {
		rc = ber_scanf( &ber, "{iaa}", &along, &ld->ld_matched,
		    &ld->ld_error );
	} else {
		rc = ber_scanf( &ber, "{ia}", &along, &ld->ld_error );
	}
	if ( rc == LBER_ERROR ) {
		ld->ld_errno = LDAP_DECODING_ERROR;
	} else {
		ld->ld_errno = (int) along;
	}

	if ( freeit )
		ldap_msgfree( r );

	return( ld->ld_errno );
}
