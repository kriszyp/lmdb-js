/* Copyright (c) 2003 by International Business Machines, Inc.
 *
 * International Business Machines, Inc. (hereinafter called IBM) grants
 * permission under its copyrights to use, copy, modify, and distribute this
 * Software with or without fee, provided that the above copyright notice and
 * all paragraphs of this notice appear in all copies, and that the name of IBM
 * not be used in connection with the marketing of any product incorporating
 * the Software or modifications thereof, without specific, written prior
 * permission.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", AND IBM DISCLAIMS ALL WARRANTIES,
 * INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE.  IN NO EVENT SHALL IBM BE LIABLE FOR ANY SPECIAL,
 * DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE, EVEN
 * IF IBM IS APPRISED OF THE POSSIBILITY OF SUCH DAMAGES.
 */

#include "portable.h"

#include <stdio.h>

#include <ac/socket.h>
#include <ac/string.h>
#include <ac/time.h>

#include "slap.h"
#include "ldif.h"
#include "../back-ldap/back-ldap.h"
#include "back-meta.h"
#include "ldap_pvt.h"
#undef ldap_debug	/* silence a warning in ldap-int.h */
#include "ldap_log.h"
#include "../../../libraries/libldap/ldap-int.h"
#include <sys/time.h>

static struct berval bv_queryid_any = BER_BVC( "(queryid=*)" );

static Attribute* 
add_attribute(AttributeDescription *ad,
	Entry* e,
	BerVarray value_array
); 

static int
null_response (
	Operation	*op,
	SlapReply	*rs
); 

static int 
normalize_values( Attribute* attr ); 	

struct entry_info {
	int			size_init; 
	int			size_final; 
	int			added; 
	Entry*			entry; 
	struct berval*		uuid; 
	struct timeval		tv;     /* time */ 
	enum type_of_result	err; 
	Backend*		glue_be; 
}; 


int 
get_entry_size(
	Entry* e, 
	int size_init, 
	struct exception* result )
{
	Attribute       *a;
        struct berval   bv;
	int             i; 
	int 		tmplen;
	int		size=0;

	if ( result )
		result->type = SUCCESS; 

	if ( e->e_dn != NULL ) {
		tmplen = strlen( e->e_dn );
		size = LDIF_SIZE_NEEDED( 2, tmplen );
	}

	for ( a = e->e_attrs; a != NULL; a = a->a_next ) {
		for ( i = 0; a->a_vals[i].bv_val != NULL; i++ ) {
			bv = a->a_vals[i];
			tmplen = a->a_desc->ad_cname.bv_len;
			size += LDIF_SIZE_NEEDED( tmplen, bv.bv_len);
		}
	}
	if ((size < size_init) && result) {
		result->type = SIZE_ERR; 
	}
	return size;
}

int
merge_entry(
	Operation		*op,
	SlapReply		*rs,
	struct berval*		query_uuid, 
	struct exception*	result )
{
	struct entry_info info;
	int		rc;
	Modifications* modlist = NULL;
	const char* 	text = NULL;
	BerVarray 		value_array; 
	Attribute		*uuid_attr, *attr;
	Entry			*e;

	SlapReply sreply = {REP_RESULT};

	Operation op_tmp = *op;
	slap_callback cb;

	sreply.sr_entry = NULL; 
	sreply.sr_nentries = 0; 

	e = ( Entry * ) ch_calloc( 1, sizeof( Entry )); 

	dnPrettyNormal(0, &rs->sr_entry->e_name, &op_tmp.o_req_dn, &op_tmp.o_req_ndn, op->o_tmpmemctx);
	ber_dupbv( &e->e_name, &op_tmp.o_req_dn );
	ber_dupbv( &e->e_nname, &op_tmp.o_req_ndn );
	sl_free( op_tmp.o_req_ndn.bv_val, op->o_tmpmemctx );
	sl_free( op_tmp.o_req_dn.bv_val, op->o_tmpmemctx );
	op_tmp.o_req_dn = e->e_name;
	op_tmp.o_req_ndn = e->e_nname;

	e->e_private = NULL;
	e->e_attrs = NULL; 
	e->e_bv.bv_val = NULL; 

	/* add queryid attribute */	
	value_array = (struct berval *)malloc(2 * sizeof( struct berval) );
	ber_dupbv(value_array, query_uuid);
	value_array[1].bv_val = NULL;
	value_array[1].bv_len = 0;

	uuid_attr = add_attribute(slap_schema.si_ad_queryid, e, value_array); 

	/* append the attribute list from the fetched entry */
	uuid_attr->a_next = rs->sr_entry->e_attrs;
	rs->sr_entry->e_attrs = NULL;

	for ( attr = e->e_attrs; attr; attr = attr->a_next ) {
		if ( normalize_values( attr ) ) {
			info.err = MERGE_ERR; 
			result->rc = info.err;
			return 0;
		}
	}

	info.entry = e;
	info.uuid = query_uuid;
	info.size_init = get_entry_size( rs->sr_entry, 0, 0 );
	info.size_final = 0;
	info.added = 0;
	info.glue_be = op->o_bd;
	info.err = SUCCESS;
	cb.sc_private = &info;
	cb.sc_response = null_response;

	op_tmp.o_tag = LDAP_REQ_ADD;
	op_tmp.o_protocol = LDAP_VERSION3;
	op_tmp.o_callback = &cb;
	op_tmp.o_time = slap_get_time();
	op_tmp.o_do_not_cache = 1;

	op_tmp.ora_e = e;
	rc = op->o_bd->be_add( &op_tmp, &sreply );

	if ( rc != LDAP_SUCCESS ) {
		if ( rc == LDAP_ALREADY_EXISTS ) {
			slap_entry2mods( e, &modlist, &text );
			op_tmp.o_tag = LDAP_REQ_MODIFY;
			op_tmp.orm_modlist = modlist;
			op_tmp.o_req_dn = e->e_name;
			op_tmp.o_req_ndn = e->e_nname;
			rc = op->o_bd->be_modify( &op_tmp, &sreply );
			result->rc = info.added;
		} else if ( rc == LDAP_REFERRAL ||
					rc == LDAP_NO_SUCH_OBJECT ) {
			slap_entry2mods( e, &modlist, &text );
			syncrepl_add_glue( NULL, NULL, &op_tmp, e, modlist, 0, NULL, NULL );
			result->rc = info.added;
		} else {
			result->rc = 0;
		}
		if ( modlist != NULL ) slap_mods_free( modlist );
	} else {
		info.size_init = 0;
		result->rc = info.added;
		be_entry_release_w( &op_tmp, e );
	}

	if ( result->rc )
		info.size_final = get_entry_size( e, info.size_init, result );
	else
		info.size_final = info.size_init;

	return ( info.size_final - info.size_init );
}

static Attribute* 
add_attribute(AttributeDescription *ad,
	Entry* e, 
	BerVarray value_array) 
{
	Attribute* new_attr, *last_attr; 
	const char* text; 

	if (e->e_attrs == NULL) 
		last_attr = NULL; 
	else 
		for (last_attr = e->e_attrs; last_attr->a_next;
				last_attr = last_attr->a_next)
			; 

	new_attr = (Attribute*)malloc(sizeof(Attribute));		
	if (last_attr) 
		last_attr->a_next = new_attr;
	else 
		e->e_attrs = new_attr; 

	new_attr->a_next = NULL; 
	new_attr->a_desc = NULL;
	new_attr->a_vals = value_array; 
	new_attr->a_desc = ad;

	return new_attr; 
}

static int
null_response (
	Operation	*op,
	SlapReply	*rs )
{
	return 0;
}

static int 
normalize_values( Attribute* attr ) 
{
	int nvals, rc, i; 
 
	if (attr->a_vals == NULL) {
		attr->a_nvals = NULL; 
		return 0; 
	} 

	for ( nvals = 0; attr->a_vals[nvals].bv_val; nvals++ ) 
		; 

	attr->a_nvals = (struct berval*)ch_malloc((nvals+1)*sizeof(struct berval));

	if ( attr->a_desc->ad_type->sat_equality &&
				attr->a_desc->ad_type->sat_equality->smr_normalize )
	{
		for ( i = 0; i < nvals; i++ ) {
			rc = attr->a_desc->ad_type->sat_equality->smr_normalize(
				SLAP_MR_VALUE_OF_ATTRIBUTE_SYNTAX,
				attr->a_desc->ad_type->sat_syntax,
				attr->a_desc->ad_type->sat_equality,
				&attr->a_vals[i], &attr->a_nvals[i], NULL );
			if ( rc ) {
#ifdef NEW_LOGGING
				LDAP_LOG( OPERATION, DETAIL1,
					"Error in normalizing attribute %s value %d (%d)\n",
					attr->a_desc->ad_cname.bv_val, i, rc );
#else
				Debug( LDAP_DEBUG_ANY,
					"Error in normalizing attribute %s value %d (%d)\n",
					attr->a_desc->ad_cname.bv_val, i, rc );
#endif
				return rc;
			}
		}
	} else {
		for ( i = 0; i < nvals; i++ ) {
			ber_dupbv( &attr->a_nvals[i], &attr->a_vals[i] ); 
		}
	}
			
	attr->a_nvals[i].bv_val = NULL;
	attr->a_nvals[i].bv_len = 0;

	return LDAP_SUCCESS;
}
