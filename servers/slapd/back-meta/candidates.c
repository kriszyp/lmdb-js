/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1999-2004 The OpenLDAP Foundation.
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

/*
 * returns 1 if suffix is candidate for dn, otherwise 0
 *
 * Note: this function should never be called if dn is the <suffix>.
 */
int 
meta_back_is_candidate(
		struct berval	*nsuffix,
		struct berval	*ndn
)
{
	if ( dnIsSuffix( nsuffix, ndn ) || dnIsSuffix( ndn, nsuffix ) ) {
		/*
		 * suffix longer than dn
		 */
		return META_CANDIDATE;
	}

	return META_NOT_CANDIDATE;
}

/*
 * meta_back_count_candidates
 *
 * returns a count of the possible candidate targets
 * Note: dn MUST be normalized
 */

int
meta_back_count_candidates(
		struct metainfo		*li,
		struct berval		*ndn
)
{
	int i, cnt = 0;

	/*
	 * I know assertions should not check run-time values;
	 * at present I didn't find a place for such checks
	 * after config.c
	 */
	assert( li->targets != NULL );
	assert( li->ntargets != 0 );

	for ( i = 0; i < li->ntargets; ++i ) {
		if ( meta_back_is_candidate( &li->targets[ i ]->suffix, ndn ) ) {
			++cnt;
		}
	}

	return cnt;
}

/*
 * meta_back_is_candidate_unique
 *
 * checks whether a candidate is unique
 * Note: dn MUST be normalized
 */
int
meta_back_is_candidate_unique(
		struct metainfo		*li,
		struct berval		*ndn
)
{
	return ( meta_back_count_candidates( li, ndn ) == 1 );
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
	int i;
	
	switch ( meta_back_count_candidates( li, ndn ) ) {
	case 1:
		break;
	case 0:
	default:
		return ( li->defaulttarget == META_DEFAULT_TARGET_NONE
			       	? -1 : li->defaulttarget );
	}

	for ( i = 0; i < li->ntargets; ++i ) {
		if ( meta_back_is_candidate( &li->targets[ i ]->suffix, ndn ) ) {
			return i;
		}
	}

	return -1;
}

/*
 * meta_clear_unused_candidates
 *
 * clears all candidates except candidate
 */
int
meta_clear_unused_candidates(
		struct metainfo		*li,
		struct metaconn		*lc,
		int			candidate,
		int			reallyclean
)
{
	int i;
	
	for ( i = 0; i < li->ntargets; ++i ) {
		if ( i == candidate ) {
			continue;
		}
		meta_clear_one_candidate( &lc->conns[ i ], reallyclean );
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
		struct metasingleconn	*lsc,
		int			reallyclean
)
{
	lsc->candidate = META_NOT_CANDIDATE;

	if ( !reallyclean ) {
		return 0;
	}

	if ( lsc->ld ) {
		ldap_unbind( lsc->ld );
		lsc->ld = NULL;
	}

	if ( lsc->bound_dn.bv_val != NULL ) {
		ber_memfree( lsc->bound_dn.bv_val );
		lsc->bound_dn.bv_val = NULL;
		lsc->bound_dn.bv_len = 0;
	}

	if ( lsc->cred.bv_val != NULL ) {
		ber_memfree( lsc->cred.bv_val );
		lsc->cred.bv_val = NULL;
		lsc->cred.bv_len = 0;
	}

	return 0;
}

