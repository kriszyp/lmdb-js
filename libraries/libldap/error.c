/* $OpenLDAP$ */
/*
 * Copyright 1998-2000 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "portable.h"

#include <stdio.h>

#include <ac/stdlib.h>

#include <ac/socket.h>
#include <ac/string.h>
#include <ac/time.h>

#include "ldap-int.h"

struct ldaperror {
	int	e_code;
	char	*e_reason;
};

static const struct ldaperror ldap_errlist[] = {
	{LDAP_SUCCESS, 					"Success" },
	{LDAP_OPERATIONS_ERROR, 		"Operations error" },
	{LDAP_PROTOCOL_ERROR, 			"Protocol error" },
	{LDAP_TIMELIMIT_EXCEEDED,		"Time limit exceeded" },
	{LDAP_SIZELIMIT_EXCEEDED, 		"Size limit exceeded" },
	{LDAP_COMPARE_FALSE, 			"Compare false" },
	{LDAP_COMPARE_TRUE, 			"Compare true" },
	{LDAP_STRONG_AUTH_NOT_SUPPORTED, "Authentication method not supported" },
	{LDAP_STRONG_AUTH_REQUIRED, 	"Strong authentication required" },
	{LDAP_PARTIAL_RESULTS, 			"Partial results and referral received" },

	{LDAP_REFERRAL,					"Referral"},
	{LDAP_ADMINLIMIT_EXCEEDED,		"Administrative limit exceeded"},
	{LDAP_UNAVAILABLE_CRITICAL_EXTENSION,
									"Criticial extension is unavailable"},
	{LDAP_CONFIDENTIALITY_REQUIRED,	"Confidentiality required"},
	{LDAP_SASL_BIND_IN_PROGRESS,	"SASL bind in progress"},

	{LDAP_NO_SUCH_ATTRIBUTE, 		"No such attribute" },
	{LDAP_UNDEFINED_TYPE, 			"Undefined attribute type" },
	{LDAP_INAPPROPRIATE_MATCHING, 	"Inappropriate matching" },
	{LDAP_CONSTRAINT_VIOLATION, 	"Constraint violation" },
	{LDAP_TYPE_OR_VALUE_EXISTS, 	"Type or value exists" },
	{LDAP_INVALID_SYNTAX, 			"Invalid syntax" },

	{LDAP_NO_SUCH_OBJECT, 			"No such object" },
	{LDAP_ALIAS_PROBLEM, 			"Alias problem" },
	{LDAP_INVALID_DN_SYNTAX,		"Invalid DN syntax" },
	{LDAP_IS_LEAF, 					"Entry is a leaf" },
	{LDAP_ALIAS_DEREF_PROBLEM,	 	"Alias dereferencing problem" },

	{LDAP_INAPPROPRIATE_AUTH, 		"Inappropriate authentication" },
	{LDAP_INVALID_CREDENTIALS, 		"Invalid credentials" },
	{LDAP_INSUFFICIENT_ACCESS, 		"Insufficient access" },
	{LDAP_BUSY, 					"DSA is busy" },
	{LDAP_UNAVAILABLE, 				"DSA is unavailable" },
	{LDAP_UNWILLING_TO_PERFORM, 	"DSA is unwilling to perform" },
	{LDAP_LOOP_DETECT, 				"Loop detected" },

	{LDAP_NAMING_VIOLATION, 		"Naming violation" },
	{LDAP_OBJECT_CLASS_VIOLATION, 	"Object class violation" },
	{LDAP_NOT_ALLOWED_ON_NONLEAF, 	"Operation not allowed on nonleaf" },
	{LDAP_NOT_ALLOWED_ON_RDN,	 	"Operation not allowed on RDN" },
	{LDAP_ALREADY_EXISTS, 			"Already exists" },
	{LDAP_NO_OBJECT_CLASS_MODS, 	"Cannot modify object class" },
	{LDAP_RESULTS_TOO_LARGE,		"Results too large" },
	{LDAP_AFFECTS_MULTIPLE_DSAS,	"Operation affects multiple DSAs" },

	{LDAP_OTHER, 					"Unknown error" },

	/* API ResultCodes */
	{LDAP_SERVER_DOWN,				"Can't contact LDAP server" },
	{LDAP_LOCAL_ERROR,				"Local error" },
	{LDAP_ENCODING_ERROR,			"Encoding error" },
	{LDAP_DECODING_ERROR,			"Decoding error" },
	{LDAP_TIMEOUT,					"Timed out" },
	{LDAP_AUTH_UNKNOWN,				"Unknown authentication method" },
	{LDAP_FILTER_ERROR,				"Bad search filter" },
	{LDAP_USER_CANCELLED,			"User cancelled operation" },
	{LDAP_PARAM_ERROR,				"Bad parameter to an ldap routine" },
	{LDAP_NO_MEMORY,				"Out of memory" },

	{LDAP_CONNECT_ERROR,			"Connect error" },
	{LDAP_NOT_SUPPORTED,			"Not Supported" },
	{LDAP_CONTROL_NOT_FOUND,		"Control not found" },
	{LDAP_NO_RESULTS_RETURNED,		"No results returned" },
	{LDAP_MORE_RESULTS_TO_RETURN,	"More results to return" },
	{LDAP_CLIENT_LOOP,				"Client Loop" },
	{LDAP_REFERRAL_LIMIT_EXCEEDED,	"Referral Limit Exceeded" },

	{-1, NULL }
};

static const struct ldaperror *
ldap_int_error( int err )
{
	int	i;

	for ( i = 0; ldap_errlist[i].e_code != -1; i++ ) {
		if ( err == ldap_errlist[i].e_code )
			return &ldap_errlist[i];
	}

	return NULL;
}

char *
ldap_err2string( int err )
{
	const struct ldaperror *e;
	
	Debug( LDAP_DEBUG_TRACE, "ldap_err2string\n", 0, 0, 0 );

	e = ldap_int_error( err );

	return ( e != NULL ) ? e->e_reason : "Unknown error";
}

/* deprecated */
void
ldap_perror( LDAP *ld, LDAP_CONST char *str )
{
	const char *s;
	const struct ldaperror *e;
	Debug( LDAP_DEBUG_TRACE, "ldap_perror\n", 0, 0, 0 );

	assert( ld != NULL );
	assert( LDAP_VALID( ld ) );
	assert( str );

	s = ( str != NULL ) ? str : "ldap_perror";

	if ( ld == NULL ) {
		perror( s );
		return;
	}

	e = ldap_int_error( ld->ld_errno );

	if ( e != NULL ) {
		fprintf( stderr, "%s: %s\n",
			s, e->e_reason );
	} else {
		fprintf( stderr, "%s: unknown LDAP error number %d\n",
			s, ld->ld_errno );
	}

	if ( ld->ld_matched != NULL && ld->ld_matched[0] != '\0' ) {
		fprintf( stderr, "\tmatched DN: \"%s\"\n",
			ld->ld_matched );
	}

	if ( ld->ld_error != NULL && ld->ld_error[0] != '\0' ) {
		fprintf( stderr, "\tadditional info: %s\n",
		    ld->ld_error );
	}

	fflush( stderr );
}

/* deprecated */
int
ldap_result2error( LDAP *ld, LDAPMessage *r, int freeit )
{
	int rc, err;

	rc = ldap_parse_result( ld, r, &err,
		NULL, NULL, NULL, NULL, freeit );

	return err != LDAP_SUCCESS ? err : rc;
}

/*
 * Parse LDAPResult Messages:
 *
 *   LDAPResult ::= SEQUENCE {
 *     resultCode      ENUMERATED,
 *     matchedDN       LDAPDN,
 *     errorMessage    LDAPString,
 *     referral        [3] Referral OPTIONAL }
 *
 * including Bind results:
 *
 *   BindResponse ::= [APPLICATION 1] SEQUENCE {
 *     COMPONENTS OF LDAPResult,
 *     serverSaslCreds  [7] OCTET STRING OPTIONAL }
 * 
 * and ExtendedOp results:
 *
 *   ExtendedResponse ::= [APPLICATION 24] SEQUENCE {
 *     COMPONENTS OF LDAPResult,
 *     responseName     [10] LDAPOID OPTIONAL,
 *     response         [11] OCTET STRING OPTIONAL }
 *
 */
int
ldap_parse_result(
	LDAP			*ld,
	LDAPMessage		*r,
	int				*errcodep,
	char			**matcheddnp,
	char			**errmsgp,
	char			***referralsp,
	LDAPControl		***serverctrls,
	int				freeit )
{
	LDAPMessage	*lm;
	ber_int_t errcode = LDAP_SUCCESS;

	ber_tag_t tag;
	BerElement	*ber;

	Debug( LDAP_DEBUG_TRACE, "ldap_parse_result\n", 0, 0, 0 );

	assert( ld != NULL );
	assert( LDAP_VALID( ld ) );
	assert( r != NULL );

	if ( ld == NULL || r == NULL ) {
		return LDAP_PARAM_ERROR;
	}

	if(errcodep != NULL) *errcodep = LDAP_SUCCESS;
	if(matcheddnp != NULL) *matcheddnp = NULL;
	if(errmsgp != NULL) *errmsgp = NULL;
	if(referralsp != NULL) *referralsp = NULL;
	if(serverctrls != NULL) *serverctrls = NULL;

	/* Find the next result... */
	for ( lm = r; lm->lm_chain != NULL; lm = lm->lm_chain ) {
		/* skip over entries and references */
		if( lm->lm_msgtype != LDAP_RES_SEARCH_ENTRY &&
			lm->lm_msgtype != LDAP_RES_SEARCH_REFERENCE &&
			lm->lm_msgtype != LDAP_RES_EXTENDED_PARTIAL )
		{
			break;
		}
	}

	if( lm == NULL ) {
		ld->ld_errno = LDAP_NO_RESULTS_RETURNED;
		return ld->ld_errno;
	}

	if ( ld->ld_error ) {
		LDAP_FREE( ld->ld_error );
		ld->ld_error = NULL;
	}
	if ( ld->ld_matched ) {
		LDAP_FREE( ld->ld_matched );
		ld->ld_matched = NULL;
	}

	/* parse results */

	ber = ber_dup( lm->lm_ber );

	if ( ld->ld_version < LDAP_VERSION2 ) {
		tag = ber_scanf( ber, "{ia}",
			&ld->ld_errno, &ld->ld_error );
	} else {
		ber_len_t len;
		tag = ber_scanf( ber, "{iaa" /*}*/,
			&ld->ld_errno, &ld->ld_matched, &ld->ld_error );

		if( tag != LBER_ERROR ) {
			/* peek for referrals */
			if( ber_peek_tag(ber, &len) == LDAP_TAG_REFERRAL ) {
				if( referralsp != NULL ) {
					tag = ber_scanf( ber, "v", referralsp );

				} else {
					/* no place to put them so skip 'em */
					tag = ber_scanf( ber, "x" );
				}
			}
		}

		/* need to clean out misc items */
		if( tag != LBER_ERROR ) {
			if( lm->lm_msgtype == LDAP_RES_BIND ) {
				/* look for sasl result creditials */
				if ( ber_peek_tag( ber, &len ) == LDAP_TAG_SASL_RES_CREDS ) {
					/* skip 'em */
					tag = ber_scanf( ber, "x" );
				}

			} else if( lm->lm_msgtype == LDAP_RES_EXTENDED ) {
				/* look for exop result oid or value */
				if ( ber_peek_tag( ber, &len ) == LDAP_TAG_EXOP_RES_OID ) {
					/* skip 'em */
					tag = ber_scanf( ber, "x" );
				}

				if ( tag != LBER_ERROR &&
					ber_peek_tag( ber, &len ) == LDAP_TAG_EXOP_RES_VALUE )
				{
					/* skip 'em */
					tag = ber_scanf( ber, "x" );
				}
			}
		}

		if( tag != LBER_ERROR ) {
			int rc = ldap_int_get_controls( ber, serverctrls );

			if( rc != LDAP_SUCCESS ) {
				tag = LBER_ERROR;
			}
		}

		if( tag != LBER_ERROR ) {
			tag = ber_scanf( ber, /*{*/"}" );
		}
	}

	if ( tag == LBER_ERROR ) {
		ld->ld_errno = errcode = LDAP_DECODING_ERROR;
	}

	if( ber != NULL ) {
		ber_free( ber, 0 );
	}

	/* return */
	if( errcodep != NULL ) {
		*errcodep = ld->ld_errno;
	}
	if ( errcode == LDAP_SUCCESS ) {
		if( matcheddnp != NULL ) {
			*matcheddnp = LDAP_STRDUP( ld->ld_matched );
		}
		if( errmsgp != NULL ) {
			*errmsgp = LDAP_STRDUP( ld->ld_error );
		}

		/* Find the next result... */
		for ( lm = lm->lm_chain; lm != NULL; lm = lm->lm_chain ) {
			/* skip over entries and references */
			if( lm->lm_msgtype != LDAP_RES_SEARCH_ENTRY &&
				lm->lm_msgtype != LDAP_RES_SEARCH_REFERENCE &&
				lm->lm_msgtype != LDAP_RES_EXTENDED_PARTIAL )
			{
				/* more results to return */
				errcode = LDAP_MORE_RESULTS_TO_RETURN;
				break;
			}
		}
	}

	if ( freeit ) {
		ldap_msgfree( r );
	}

	return( errcode );
}
