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

#include <ac/socket.h>
#include <ac/string.h>

#include "slap.h"
#include "../back-ldap/back-ldap.h"
#include "back-meta.h"


/* return 0 IFF op_dn is a value in group_at (member) attribute
 * of entry with gr_dn AND that entry has an objectClass
 * value of group_oc (groupOfNames)
 */
int
meta_back_group(
		Backend			*be,
		Connection 		*conn,
		Operation 		*op,
		Entry			*target,
		struct berval		*gr_ndn,
		struct berval		*op_ndn,
		ObjectClass		*group_oc,
		AttributeDescription	*group_at
)
{
	struct metainfo *li = ( struct metainfo * )be->be_private;    
	int rc = 1, candidate;
	Attribute   *attr;
	AttributeDescription *ad_objectClass = slap_schema.si_ad_objectClass;
	LDAPMessage	*result;
	char *gattr[ 2 ];
	char *filter = NULL, *ptr;
	LDAP *ld = NULL;
	struct berval mop_ndn = { 0, NULL }, mgr_ndn = { 0, NULL };

	struct berval group_oc_name = { 0, NULL };
	struct berval group_at_name = group_at->ad_cname;

	if ( group_oc->soc_names && group_oc->soc_names[ 0 ] ) {
		group_oc_name.bv_val = group_oc->soc_names[ 0 ];
	} else {
		group_oc_name.bv_val = group_oc->soc_oid;
	}

	if ( group_oc_name.bv_val ) {
		group_oc_name.bv_len = strlen( group_oc_name.bv_val );
	}

	if ( target != NULL && dn_match( &target->e_nname, gr_ndn ) ) {
		/* we already have a copy of the entry */
		/* attribute and objectclass mapping has already been done */

		/*
		 * first we need to check if the objectClass attribute
		 * has been retrieved; otherwise we need to repeat the search
		 */
		attr = attr_find( target->e_attrs, ad_objectClass );
		if ( attr != NULL ) {

			/*
			 * Now we can check for the group objectClass value
			 */
			if ( !is_entry_objectclass( target, group_oc, 0 ) ) {
				return 1;
			}

			/*
			 * This part has been reworked: the group attr compare
			 * fails only if the attribute is PRESENT but the value
			 * is NOT PRESENT; if the attribute is NOT PRESENT, the
			 * search must be repeated as well.
			 * This may happen if a search for an entry has already
			 * been performed (target is not null) but the group
			 * attribute has not been required
			 */
			attr = attr_find( target->e_attrs, group_at );
			if ( attr != NULL ) {
				rc = value_find( group_at, attr->a_vals, 
						op_ndn );
				if ( rc != LDAP_SUCCESS ) {
					return 1;
				}
				return 0;
			} /* else: repeat the search */
		} /* else: repeat the search */
	} /* else: do the search */

	candidate = meta_back_select_unique_candidate( li, gr_ndn );
	if ( candidate == -1 ) {
		goto cleanup;
	}

	/*
	 * Rewrite the op ndn if needed
	 */
	switch ( rewrite_session( li->targets[ candidate ]->rwinfo, "bindDn",
				op_ndn->bv_val, conn, &mop_ndn.bv_val ) ) {
	case REWRITE_REGEXEC_OK:
		if ( mop_ndn.bv_val != NULL && mop_ndn.bv_val[ 0 ] != '\0' ) {
			mop_ndn.bv_len = strlen( mop_ndn.bv_val );
		} else {
			mop_ndn = *op_ndn;
		}
#ifdef NEW_LOGGING
		LDAP_LOG(( "backend", LDAP_LEVEL_DETAIL1,
				"[rw] bindDn (op ndn in group):"
				 \"%s\" -> \"%s\"\n",
				 op_ndn->bv_val, mop_ndn.bv_val));
#else /* !NEW_LOGGING */
		Debug( LDAP_DEBUG_ARGS,
				"rw> bindDn (op ndn in group):"
				" \"%s\" -> \"%s\"\n%s",
				op_ndn->bv_val, mop_ndn.bv_val, "" );
#endif /* !NEW_LOGGING */
		break;
		
	case REWRITE_REGEXEC_UNWILLING:
		/* continues to next case */
		
	case REWRITE_REGEXEC_ERR:
		return 1;
	}

	/*
	 * Rewrite the gr ndn if needed
	 */
	switch ( rewrite_session( li->targets[ candidate ]->rwinfo,
				"searchBase",
				gr_ndn->bv_val, conn, &mgr_ndn.bv_val ) ) {
	case REWRITE_REGEXEC_OK:
		if ( mgr_ndn.bv_val != NULL && mgr_ndn.bv_val[ 0 ] != '\0' ) {
			mgr_ndn.bv_len = strlen( mgr_ndn.bv_val );
		} else {
			mgr_ndn = *gr_ndn;
		}
#ifdef NEW_LOGGING
		LDAP_LOG(( "backend", LDAP_LEVEL_DETAIL1,
				"[rw] searchBase (gr ndn in group):"
				" \"%s\" -> \"%s\"\n",
				gr_ndn->bv_val, mgr_ndn.bv_val ));
#else /* !NEW_LOGGING */
		Debug( LDAP_DEBUG_ARGS,
				"rw> searchBase (gr ndn in group):"
				" \"%s\" -> \"%s\"\n%s",
				gr_ndn->bv_val, mgr_ndn.bv_val, "" );
#endif /* !NEW_LOGGING */
		break;
		
	case REWRITE_REGEXEC_UNWILLING:
		/* continues to next case */
		
	case REWRITE_REGEXEC_ERR:
		goto cleanup;
	}
	
	ldap_back_map( &li->targets[ candidate ]->oc_map,
			&group_oc_name, &group_oc_name, 0 );
	if ( group_oc_name.bv_val == NULL ) {
		goto cleanup;
	}
	ldap_back_map( &li->targets[ candidate ]->at_map,
			&group_at_name, &group_at_name, 0 );
	if ( group_at_name.bv_val == NULL ) {
		goto cleanup;
	}

	filter = ch_malloc( sizeof( "(&(objectclass=)(=))" )
			+ group_oc_name.bv_len
			+ group_at_name.bv_len
			+ mop_ndn.bv_len + 1 );
	if ( filter == NULL ) {
		goto cleanup;
	}

	rc = ldap_initialize( &ld, li->targets[ candidate ]->uri );
	if ( rc != LDAP_SUCCESS ) {
		goto cleanup;
	}

	rc = ldap_bind_s( ld, li->targets[ candidate ]->binddn.bv_val,
			li->targets[ candidate ]->bindpw.bv_val, 
			LDAP_AUTH_SIMPLE );
	if ( rc != LDAP_SUCCESS ) {
		goto cleanup;
	}

	ptr = slap_strcopy( filter, "(&(objectclass=" );
	ptr = slap_strcopy( ptr , group_oc_name.bv_val );
	ptr = slap_strcopy( ptr , ")(" );
	ptr = slap_strcopy( ptr , group_at_name.bv_val );
	ptr = slap_strcopy( ptr , "=" );
	ptr = slap_strcopy( ptr , mop_ndn.bv_val );
	strcpy( ptr , "))" );

	gattr[ 0 ] = "objectclass";
	gattr[ 1 ] = NULL;
	rc = 1;
	if ( ldap_search_ext_s( ld, mgr_ndn.bv_val, LDAP_SCOPE_BASE, filter,
				gattr, 0, NULL, NULL, LDAP_NO_LIMIT,
				LDAP_NO_LIMIT, &result ) == LDAP_SUCCESS ) {
		if ( ldap_first_entry( ld, result ) != NULL ) {
			rc = 0;
		}
		ldap_msgfree( result );
	}

cleanup:;
	if ( ld != NULL ) {
		ldap_unbind( ld );
	}
	if ( filter != NULL ) {
		ch_free( filter );
	}
	if ( mop_ndn.bv_val != op_ndn->bv_val ) {
		free( mop_ndn.bv_val );
	}
	if ( mgr_ndn.bv_val != gr_ndn->bv_val ) {
		free( mgr_ndn.bv_val );
	}

	return rc;
}

