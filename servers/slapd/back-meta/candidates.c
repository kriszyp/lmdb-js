/*
 * Copyright 1998-2002 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 *
 * Copyright 2001, Pierangelo Masarati, All rights reserved. <ando@sys-net.it>
 *
 * This work has been developed to fulfill the requirements
 * of SysNet s.n.c. <http:www.sys-net.it> and it has been donated
 * to the OpenLDAP Foundation in the hope that it may be useful
 * to the Open Source community, but WITHOUT ANY WARRANTY.
 *
 * Permission is granted to anyone to use this software for any purpose
 * on any computer system, and to alter it and redistribute it, subject
 * to the following restrictions:
 *
 * 1. The author and SysNet s.n.c. are not responsible for the consequences
 *    of use of this software, no matter how awful, even if they arise from 
 *    flaws in it.
 *
 * 2. The origin of this software must not be misrepresented, either by
 *    explicit claim or by omission.  Since few users ever read sources,
 *    credits should appear in the documentation.
 *
 * 3. Altered versions must be plainly marked as such, and must not be
 *    misrepresented as being the original software.  Since few users
 *    ever read sources, credits should appear in the documentation.
 *    SysNet s.n.c. cannot be responsible for the consequences of the
 *    alterations.
 *
 * 4. This notice may not be removed or altered.
 *
 *
 * This software is based on the backend back-ldap, implemented
 * by Howard Chu <hyc@highlandsun.com>, and modified by Mark Valence
 * <kurash@sassafras.com>, Pierangelo Masarati <ando@sys-net.it> and other
 * contributors. The contribution of the original software to the present
 * implementation is acknowledged in this copyright statement.
 *
 * A special acknowledgement goes to Howard for the overall architecture
 * (and for borrowing large pieces of code), and to Mark, who implemented
 * from scratch the attribute/objectclass mapping.
 *
 * The original copyright statement follows.
 *
 * Copyright 1999, Howard Chu, All rights reserved. <hyc@highlandsun.com>
 *
 * Permission is granted to anyone to use this software for any purpose
 * on any computer system, and to alter it and redistribute it, subject
 * to the following restrictions:
 *
 * 1. The author is not responsible for the consequences of use of this
 *    software, no matter how awful, even if they arise from flaws in it.
 *
 * 2. The origin of this software must not be misrepresented, either by
 *    explicit claim or by omission.  Since few users ever read sources,
 *    credits should appear in the documentation.
 *
 * 3. Altered versions must be plainly marked as such, and must not be
 *    misrepresented as being the original software.  Since few users
 *    ever read sources, credits should appear in the
 *    documentation.
 *
 * 4. This notice may not be removed or altered.
 *                
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
		meta_clear_one_candidate( lc->conns[ i ], reallyclean );
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

	return 0;
}

