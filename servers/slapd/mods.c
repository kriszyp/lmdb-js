/*
 * Copyright 1998-2002 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */
/*
 * Copyright (c) 1995 Regents of the University of Michigan.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that this notice is preserved and that due credit is given
 * to the University of Michigan at Ann Arbor. The name of the University
 * may not be used to endorse or promote products derived from this
 * software without specific prior written permission. This software
 * is provided ``as is'' without express or implied warranty.
 */

#include "portable.h"

#include <stdio.h>

#include "slap.h"

void
slap_mod_free(
	Modification	*mod,
	int				freeit
)
{
	ad_free( mod->sm_desc, 1 );

	if ( mod->sm_bvalues != NULL )
		ber_bvecfree( mod->sm_bvalues );

	if( freeit )
		free( mod );
}

void
slap_mods_free(
    Modifications	*ml
)
{
	Modifications *next;

	for ( ; ml != NULL; ml = next ) {
		next = ml->sml_next;

		slap_mod_free( &ml->sml_mod, 0 );
		free( ml );
	}
}

void
slap_modlist_free(
    LDAPModList	*ml
)
{
	LDAPModList *next;

	for ( ; ml != NULL; ml = next ) {
		next = ml->ml_next;

		if (ml->ml_type)
			free( ml->ml_type );

		if ( ml->ml_bvalues != NULL )
			ber_bvecfree( ml->ml_bvalues );

		free( ml );
	}
}
