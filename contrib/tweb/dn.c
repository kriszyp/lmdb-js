/*_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/
*                                                                          *
* dn.c.......                                                              *
*                                                                          *
* Function:..DN-Handling-Functions                                         *
*                                                                          *
*            from LDAP3.2 University of Michigan                           *
*                                                                          *
*                                                                          *
*                                                                          *
* Authors:...Dr. Kurt Spanier & Bernhard Winkler,                          *
*            Zentrum fuer Datenverarbeitung, Bereich Entwicklung           *
*            neuer Dienste, Universitaet Tuebingen, GERMANY                *
*                                                                          *
*                                       ZZZZZ  DDD    V   V                *
*            Creation date:                Z   D  D   V   V                *
*            April 24 1996                Z    D   D   V V                 *
*            Last modification:          Z     D  D    V V                 *
*            September 13 1999          ZZZZ   DDD      V                  *
*                                                                          *
_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_/_*/

/*
 * $Id: dn.c,v 1.8 1999/09/13 13:47:44 zrnsk01 Exp $
 *
 */

/* dn.c - routines for dealing with distinguished names */

#include "tgeneral.h"
#include "tglobal.h"
#include "strng_exp.h"
#include "dn.h"

#if OL_LDAPV == 2
#define LDAP_DEBUG_ANY  0xffff
#endif


/*
 * dn_normalize - put dn into a canonical format.  the dn is
 * normalized in place, as well as returned.
 */

PUBLIC char * dn_normalize( dn )
char *dn;
{
	char	*d, *s;
	int	state, gotesc;

	/* Debug( LDAP_DEBUG_TRACE, "=> dn_normalize \"%s\"\n", dn, 0, 0 ); */

	gotesc = 0;
	state = B4TYPE;
	for ( d = s = dn; *s; s++ ) {
		switch ( state ) {
		case B4TYPE:
			if ( ! SPACE( *s ) ) {
				state = INTYPE;
				*d++ = *s;
			}
			break;
		case INTYPE:
			if ( *s == '=' ) {
				state = B4VALUE;
				*d++ = *s;
			} else if ( SPACE( *s ) ) {
				state = B4EQUAL;
			} else {
				*d++ = *s;
			}
			break;
		case B4EQUAL:
			if ( *s == '=' ) {
				state = B4VALUE;
				*d++ = *s;
			} else if ( ! SPACE( *s ) ) {
				/* not a valid dn - but what can we do here? */
				*d++ = *s;
			}
			break;
		case B4VALUE:
			if ( *s == '"' ) {
				state = INQUOTEDVALUE;
				*d++ = *s;
			} else if ( ! SPACE( *s ) ) { 
				state = INVALUE;
				*d++ = *s;
			}
			break;
		case INVALUE:
			if ( !gotesc && SEPARATOR( *s ) ) {
				while ( SPACE( *(d - 1) ) )
					d--;
				state = B4TYPE;
				if ( *s == '+' ) {
					*d++ = *s;
				} else {
					*d++ = ',';
				}
			} else if ( gotesc && !NEEDSESCAPE( *s ) &&
			    !SEPARATOR( *s ) ) {
				*--d = *s;
				d++;
			} else {
				*d++ = *s;
			}
			break;
		case INQUOTEDVALUE:
			if ( !gotesc && *s == '"' ) {
				state = B4SEPARATOR;
				*d++ = *s;
			} else if ( gotesc && !NEEDSESCAPE( *s ) ) {
				*--d = *s;
				d++;
			} else {
				*d++ = *s;
			}
			break;
		case B4SEPARATOR:
			if ( SEPARATOR( *s ) ) {
				state = B4TYPE;
				*d++ = *s;
			}
			break;
		default:

#if OL_LDAPV >= 2

            if ( ldap_debug & LDAP_DEBUG_ANY )
                fprintf( stderr, "dn_normalize - unknown state %d\n", state );

            if ( ldap_syslog & LDAP_DEBUG_ANY )
                syslog( ldap_syslog_level,
                             "dn_normalize - unknown state %d\n", state );

#else
			Debug( LDAP_DEBUG_ANY,
			    "dn_normalize - unknown state %d\n", state, 0, 0 );
#endif

			break;
		}
		if ( *s == '\\' ) {
			gotesc = 1;
		} else {
			gotesc = 0;
		}
	}
	*d = '\0';

	/* Debug( LDAP_DEBUG_TRACE, "<= dn_normalize \"%s\"\n", dn, 0, 0 ); */
	return( dn );
}
/* end of function: dn_normalize */

/*
 * dn_normalize_case - put dn into a canonical form suitable for storing
 * in a hash database.  this involves normalizing the case as well as
 * the format.  the dn is normalized in place as well as returned.
 */

PUBLIC char * dn_normalize_case( dn )
char *dn;
{

	/* normalize format */
	dn_normalize( dn );

	/* normalize case */
        str_toupper( dn );

	return( dn );
}
/* end of function: dn_normalize_case */

/*
 * dn_issuffix - tells whether suffix is a suffix of dn.  both dn
 * and suffix must be normalized.
 */

PUBLIC int dn_issuffix( dn, suffix )
char	*dn;
char	*suffix;
{
	int	dnlen, suffixlen;

	if ( dn == NULL ) {
		return( 0 );
	}

	suffixlen = strlen( suffix );
	dnlen = strlen( dn );

	if ( suffixlen > dnlen ) {
		return( 0 );
	}

	return( strcasecmp( dn + dnlen - suffixlen, suffix ) == 0 );
}
/* end of function: dn_issuffix */

