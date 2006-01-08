/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1998-2006 The OpenLDAP Foundation.
 * Copyright 2006 Hans Leidekker
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted only as authorized by the OpenLDAP
 * Public License.
 *
 * A copy of this license is available in the file LICENSE in the
 * top-level directory of the distribution or, alternatively, at
 * <http://www.OpenLDAP.org/license.html>.
 */
/* Portions Copyright (C) 1999, 2000 Novell, Inc. All Rights Reserved.
 *
 * THIS WORK IS SUBJECT TO U.S. AND INTERNATIONAL COPYRIGHT LAWS AND
 * TREATIES. USE, MODIFICATION, AND REDISTRIBUTION OF THIS WORK IS SUBJECT
 * TO VERSION 2.0.1 OF THE OPENLDAP PUBLIC LICENSE, A COPY OF WHICH IS
 * AVAILABLE AT HTTP://WWW.OPENLDAP.ORG/LICENSE.HTML OR IN THE FILE "LICENSE"
 * IN THE TOP-LEVEL DIRECTORY OF THE DISTRIBUTION. ANY USE OR EXPLOITATION
 * OF THIS WORK OTHER THAN AS AUTHORIZED IN VERSION 2.0.1 OF THE OPENLDAP
 * PUBLIC LICENSE, OR OTHER PRIOR WRITTEN CONSENT FROM NOVELL, COULD SUBJECT
 * THE PERPETRATOR TO CRIMINAL AND CIVIL LIABILITY.
 */
/* Note: A verbatim copy of version 2.0.1 of the OpenLDAP Public License 
 * can be found in the file "build/LICENSE-2.0.1" in this distribution
 * of OpenLDAP Software.
 */
/* Portions Copyright (C) The Internet Society (1997)
 * ASN.1 fragments are from RFC 2251; see RFC for full legal notices.
 */

#include "portable.h"

#include <stdio.h>
#include <ac/stdlib.h>
#include <ac/string.h>
#include <ac/time.h>

#include "ldap-int.h"

/* ---------------------------------------------------------------------------
    ldap_create_page_control_value

    Create and encode the value of the paged results control (RFC 2696).

    ld          (IN) An LDAP session handle, as obtained from a call to
                     ldap_init().

    pagesize    (IN) The number of entries to return per page.

    cookie      (IN) Opaque structure used by the server to track its
                     location in the search results. Pass in NULL on the
                     first call.

    value      (OUT) the pointer to a struct berval; it is filled by this function
                     with the value that must be assigned to the ldctl_value member
                     of the LDAPControl structure.  The bv_val member of the berval
                     structure SHOULD be freed by calling ldap_memfree() when done.
 
    Ber encoding

    pagedResultsControl ::= SEQUENCE {
            controlType     1.2.840.113556.1.4.319,
            criticality     BOOLEAN DEFAULT FALSE,
            controlValue    searchControlValue }

    searchControlValue ::= SEQUENCE {
            size            INTEGER (0..maxInt),
                                    -- requested page size from client
                                    -- result set size estimate from server
            cookie          OCTET STRING }

   ---------------------------------------------------------------------------*/

int
ldap_create_page_control_value(
	LDAP		*ld,
	unsigned long	pagesize,
	struct berval	*cookie,
	struct berval	*value )
{
	BerElement	*ber = NULL;
	ber_tag_t	tag;
	struct berval	null_cookie = { 0, NULL };

	if ( ld == NULL || value == NULL || pagesize > LDAP_MAXINT ) {
		ld->ld_errno = LDAP_PARAM_ERROR;
		return ld->ld_errno;
	}

	assert( LDAP_VALID( ld ) );

	value->bv_val = NULL;
	value->bv_len = 0;

	if ( cookie == NULL ) {
		cookie = &null_cookie;
	}

	ber = ldap_alloc_ber_with_options( ld );
	if ( ber == NULL ) {
		ld->ld_errno = LDAP_NO_MEMORY;
		return ld->ld_errno;
	}

	tag = ber_printf( ber, "{iO}", (ber_int_t)pagesize, cookie );
	if ( tag == LBER_ERROR ) {
		goto error_return;
	}

	if ( ber_flatten2( ber, value, 1 ) == -1 ) {
		ld->ld_errno = LDAP_NO_MEMORY;
	}

	if ( 0 ) {
error_return:;
		ld->ld_errno = LDAP_ENCODING_ERROR;
	}

	if ( ber != NULL ) {
		ber_free( ber, 1 );
	}

	return ld->ld_errno;
}


/* ---------------------------------------------------------------------------
    ldap_create_page_control

    Create and encode a page control.

    ld          (IN) An LDAP session handle, as obtained from a call to
                     ldap_init().

    pagesize    (IN) The number of entries to return per page.

    cookie      (IN) Opaque structure used by the server to track its
                     location in the search results. Pass in NULL on the
                     first call.

    iscritical  (IN) 0 - The control is not critical to the operation.
                     non-zero - The control is critical to the operation.

    ctrlp      (OUT) Returns a pointer to the LDAPControl created. This
                     control SHOULD be freed by calling ldap_control_free()
                     when done.
 
    Ber encoding

    pagedResultsControl ::= SEQUENCE {
            controlType     1.2.840.113556.1.4.319,
            criticality     BOOLEAN DEFAULT FALSE,
            controlValue    searchControlValue }

    searchControlValue ::= SEQUENCE {
            size            INTEGER (0..maxInt),
                                    -- requested page size from client
                                    -- result set size estimate from server
            cookie          OCTET STRING }

   ---------------------------------------------------------------------------*/

int
ldap_create_page_control(
	LDAP		*ld,
	unsigned long	pagesize,
	struct berval	*cookie,
	int		iscritical,
	LDAPControl	**ctrlp )
{
	struct berval	value;

	if ( ctrlp == NULL ) {
		ld->ld_errno = LDAP_PARAM_ERROR;
		return ld->ld_errno;
	}

	ld->ld_errno = ldap_create_page_control_value( ld, pagesize, cookie, &value );
	if ( ld->ld_errno == LDAP_SUCCESS ) {
		ld->ld_errno = ldap_create_control( LDAP_CONTROL_PAGEDRESULTS,
			NULL, iscritical, ctrlp );
		if ( ld->ld_errno == LDAP_SUCCESS ) {
			(*ctrlp)->ldctl_value = value;
		} else {
			LDAP_FREE( value.bv_val );
		}
	}

	return ld->ld_errno;
}


/* ---------------------------------------------------------------------------
    ldap_parse_pageresponse_control

    Decode a page control.

    ld          (IN) An LDAP session handle, as obtained from a call to
                     ldap_init().

    ctrls       (IN) The address of a NULL-terminated array of
                     LDAPControl structures, typically obtained by a
                     call to ldap_parse_result(). The array SHOULD include
                     a page control.

    count      (OUT) The number of entries returned in the page.

    cookie     (OUT) Opaque structure used by the server to track its
                     location in the search results. Use ldap_memfree() to
                     free the bv_val member of this structure.

   ---------------------------------------------------------------------------*/

int
ldap_parse_pageresponse_control(
	LDAP		*ld,
	LDAPControl	*ctrl,
	unsigned long	*countp,
	struct berval	*cookie )
{
	BerElement *ber;
	ber_tag_t tag;
	ber_int_t count;

	if ( ld == NULL || ctrl == NULL || cookie == NULL ) {
		ld->ld_errno = LDAP_PARAM_ERROR;
		return ld->ld_errno;
	}

	/* Create a BerElement from the berval returned in the control. */
	ber = ber_init( &ctrl->ldctl_value );

	if ( ber == NULL ) {
		ld->ld_errno = LDAP_NO_MEMORY;
		return ld->ld_errno;
	}

	/* Extract the count and cookie from the control. */
	tag = ber_scanf( ber, "{io}", &count, cookie );
        ber_free( ber, 1 );

	if ( tag == LBER_ERROR ) {
		ld->ld_errno = LDAP_DECODING_ERROR;
	} else {
		ld->ld_errno = LDAP_SUCCESS;

		if ( countp != NULL ) {
			*countp = (unsigned long)count;
		}
	}

	return ld->ld_errno;
}

/* ---------------------------------------------------------------------------
    ldap_parse_page_control

    Decode a page control.

    ld          (IN) An LDAP session handle, as obtained from a call to
                     ldap_init().

    ctrls       (IN) The address of a NULL-terminated array of
                     LDAPControl structures, typically obtained by a
                     call to ldap_parse_result(). The array SHOULD include
                     a page control.

    count      (OUT) The number of entries returned in the page.

    cookie     (OUT) Opaque structure used by the server to track its
                     location in the search results. Use ber_bvfree() to
                     free it.

   ---------------------------------------------------------------------------*/

int
ldap_parse_page_control(
	LDAP		*ld,
	LDAPControl	**ctrls,
	unsigned long	*countp,
	struct berval	**cookiep )
{
	struct berval	cookie;
	int		i;

	if ( cookiep == NULL ) {
		ld->ld_errno = LDAP_PARAM_ERROR;
		return ld->ld_errno;
	}

	if ( ctrls == NULL ) {
		ld->ld_errno =  LDAP_CONTROL_NOT_FOUND;
		return ld->ld_errno;
	}

	/* Search the list of control responses for a page control. */
	for ( i = 0; ctrls[i]; i++ ) {
		if ( strcmp( LDAP_CONTROL_PAGEDRESULTS, ctrls[ i ]->ldctl_oid ) == 0 ) {
			break;
		}
	}

	/* No page control was found. */
	if ( ctrls[ i ] == NULL ) {
		ld->ld_errno = LDAP_CONTROL_NOT_FOUND;
		return ld->ld_errno;
	}

	ld->ld_errno = ldap_parse_pageresponse_control( ld, ctrls[ i ], countp, &cookie );
	if ( ld->ld_errno == LDAP_SUCCESS ) {
		*cookiep = LDAP_MALLOC( sizeof( struct berval * ) );
		if ( *cookiep == NULL ) {
			ld->ld_errno = LDAP_NO_MEMORY;
		} else {
			**cookiep = cookie;
		}
	}

	return ld->ld_errno;
}

