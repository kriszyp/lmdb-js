/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1999-2005 The OpenLDAP Foundation.
 * Portions Copyright 2001-2003 Pierangelo Masarati.
 * Portions Copyright 1999-2003 Howard Chu.
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
/* ACKNOWLEDGEMENTS:
 * This work was initially developed by the Howard Chu for inclusion
 * in OpenLDAP Software and subsequently enhanced by Pierangelo
 * Masarati.
 */

#include "portable.h"

#include <stdio.h>

#include "slap.h"
#include "../back-ldap/back-ldap.h"
#include "back-meta.h"

/*
 * The meta-directory has one suffix, called <suffix>.
 * It handles a pool of target servers, each with a branch suffix
 * of the form <branch X>,<suffix>
 *
 * When the meta-directory receives a request with a dn that belongs
 * to a branch, the corresponding target is invoked. When the dn
 * does not belong to a specific branch, all the targets that
 * are compatible with the dn are selected as candidates, and
 * the request is spawned to all the candidate targets
 *
 * A request is characterized by a dn. The following cases are handled:
 * 	- the dn is the suffix: <dn> == <suffix>,
 * 		all the targets are candidates (search ...)
 * 	- the dn is a branch suffix: <dn> == <branch X>,<suffix>, or
 * 	- the dn is a subtree of a branch suffix:
 * 		<dn> == <rdn>,<branch X>,<suffix>,
 * 		the target is the only candidate.
 *
 * A possible extension will include the handling of multiple suffixes
 */

static int
meta_back_is_candidate_unique(
		struct metainfo		*li,
		struct berval		*ndn
);

/*
 * returns 1 if suffix is candidate for dn, otherwise 0
 *
 * Note: this function should never be called if dn is the <suffix>.
 */
int 
meta_back_is_candidate(
		struct berval	*nsuffix,
		struct berval	*ndn,
		int		scope
)
{
	if ( dnIsSuffix( ndn, nsuffix ) ) {
		return META_CANDIDATE;
	}

	if ( scope == LDAP_SCOPE_SUBTREE && dnIsSuffix( nsuffix, ndn ) ) {
		/*
		 * suffix longer than dn, but common part matches
		 */
		return META_CANDIDATE;
	}

	return META_NOT_CANDIDATE;
}

/*
 * meta_back_is_candidate_unique
 *
 * checks whether a candidate is unique
 * Note: dn MUST be normalized
 */
static int
meta_back_is_candidate_unique(
		struct metainfo		*li,
		struct berval		*ndn
)
{
	switch ( meta_back_select_unique_candidate( li, ndn ) ) {
	case META_TARGET_MULTIPLE:
	case META_TARGET_NONE:
		return 0;
	}

	return 1;
}

/*
 * meta_back_select_unique_candidate
 *
 * returns the index of the candidate in case it is unique, otherwise -1
 * Note: dn MUST be normalized.
 * Note: if defined, the default candidate is returned in case of no match.
 */
int
meta_back_select_unique_candidate(
		struct metainfo		*li,
		struct berval		*ndn
)
{
	int	i, candidate = META_TARGET_NONE;

	for ( i = 0; i < li->mi_ntargets; ++i ) {
		if ( meta_back_is_candidate( &li->mi_targets[ i ]->mt_nsuffix, ndn, LDAP_SCOPE_BASE ) )
		{
			if ( candidate == META_TARGET_NONE ) {
				candidate = i;

			} else {
				return META_TARGET_MULTIPLE;
			}
		}
	}

	return candidate;
}

/*
 * meta_clear_unused_candidates
 *
 * clears all candidates except candidate
 */
int
meta_clear_unused_candidates(
		Operation		*op,
		struct metaconn		*lc,
		int			candidate
)
{
	struct metainfo	*li = ( struct metainfo * )op->o_bd->be_private;
	int		i;
	SlapReply	*candidates = meta_back_candidates_get( op );
	
	for ( i = 0; i < li->mi_ntargets; ++i ) {
		if ( i == candidate ) {
			continue;
		}
		candidates[ i ].sr_tag = META_NOT_CANDIDATE;
	}

	return 0;
}

/*
 * meta_clear_one_candidate
 *
 * clears the selected candidate
 */
int
meta_clear_one_candidate(
		struct metasingleconn	*lsc
)
{
	if ( lsc->msc_ld ) {
		ldap_unbind_ext_s( lsc->msc_ld, NULL, NULL );
		lsc->msc_ld = NULL;
	}

	if ( !BER_BVISNULL( &lsc->msc_bound_ndn ) ) {
		ber_memfree( lsc->msc_bound_ndn.bv_val );
		BER_BVZERO( &lsc->msc_bound_ndn );
	}

	if ( !BER_BVISNULL( &lsc->msc_cred ) ) {
		ber_memfree( lsc->msc_cred.bv_val );
		BER_BVZERO( &lsc->msc_cred );
	}

	return 0;
}

