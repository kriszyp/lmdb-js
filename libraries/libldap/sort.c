/* $OpenLDAP$ */
/*
 * Copyright 1998-1999 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */
/* Portions
 * Copyright (c) 1994 Regents of the University of Michigan.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that this notice is preserved and that due credit is given
 * to the University of Michigan at Ann Arbor. The name of the University
 * may not be used to endorse or promote products derived from this
 * software without specific prior written permission. This software
 * is provided ``as is'' without express or implied warranty.
 *
 * sort.c:  LDAP library entry and value sort routines
 */

#include "portable.h"

#include <stdio.h>
#include <ac/stdlib.h>

#include <ac/ctype.h>
#include <ac/string.h>
#include <ac/time.h>


#include "ldap-int.h"

struct entrything {
	char		**et_vals;
	LDAPMessage	*et_msg;
	int 		(*et_cmp_fn) LDAP_P((const char *a, const char *b));
};

static int	et_cmp LDAP_P(( const void *aa, const void *bb));


int
ldap_sort_strcasecmp(
	const void	*a,
	const void	*b
)
{
	return( strcasecmp( *(char *const *)a, *(char *const *)b ) );
}

static int
et_cmp(
	const void	*aa,
	const void	*bb
)
{
	int			i, rc;
	const struct entrything	*a = (const struct entrything *)aa;
	const struct entrything	*b = (const struct entrything *)bb;

	if ( a->et_vals == NULL && b->et_vals == NULL )
		return( 0 );
	if ( a->et_vals == NULL )
		return( -1 );
	if ( b->et_vals == NULL )
		return( 1 );

	for ( i = 0; a->et_vals[i] && b->et_vals[i]; i++ ) {
		if ( (rc = a->et_cmp_fn( a->et_vals[i], b->et_vals[i] )) != 0 ) {
			return( rc );
		}
	}

	if ( a->et_vals[i] == NULL && b->et_vals[i] == NULL )
		return( 0 );
	if ( a->et_vals[i] == NULL )
		return( -1 );
	return( 1 );
}

int
ldap_sort_entries(
    LDAP	*ld,
    LDAPMessage	**chain,
    LDAP_CONST char	*attr,		/* NULL => sort by DN */
    int		(*cmp) (LDAP_CONST  char *, LDAP_CONST char *)
)
{
	int			i, count;
	struct entrything	*et;
	LDAPMessage		*e, *last;
	LDAPMessage		**ep;

	count = ldap_count_entries( ld, *chain );


	if ( count < 0 ) {
		if( ld != NULL ) {
			ld->ld_errno = LDAP_PARAM_ERROR;
		}
		return -1;

	} else if ( count < 2 ) {
		/* zero or one entries -- already sorted! */
		return 0;
	}

	if ( (et = (struct entrything *) LDAP_MALLOC( count *
	    sizeof(struct entrything) )) == NULL ) {
		ld->ld_errno = LDAP_NO_MEMORY;
		return( -1 );
	}

	e = *chain;
	for ( i = 0; i < count; i++ ) {
		et[i].et_cmp_fn = cmp;
		et[i].et_msg = e;
		if ( attr == NULL ) {
			char	*dn;

			dn = ldap_get_dn( ld, e );
			et[i].et_vals = ldap_explode_dn( dn, 1 );
			LDAP_FREE( dn );
		} else {
			et[i].et_vals = ldap_get_values( ld, e, attr );
		}

		e = e->lm_chain;
	}
	last = e;

	qsort( et, count, sizeof(struct entrything), et_cmp );

	ep = chain;
	for ( i = 0; i < count; i++ ) {
		*ep = et[i].et_msg;
		ep = &(*ep)->lm_chain;

		ldap_value_free( et[i].et_vals );
	}
	*ep = last;
	LDAP_FREE( (char *) et );

	return( 0 );
}

int
ldap_sort_values(
    LDAP	*ld,
    char	**vals,
    int		(*cmp) (const void *, const void *)
)
{
	int	nel;

	for ( nel = 0; vals[nel] != NULL; nel++ )
		;	/* NULL */

	qsort( vals, nel, sizeof(char *), cmp );

	return( 0 );
}
