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

#ifdef LDAP_CACHING

static struct berval bv_queryid_any = BER_BVC( "(queryid=*)" );

static int
merge_func (
	Operation	*op,
	SlapReply	*rs
); 

static void
add_func (
	Operation	*op,
	SlapReply	*rs
); 

static Attribute* 
add_attribute(AttributeDescription *ad,
	Entry* e,
	BerVarray value_array
); 

static int
get_size_func (
	Operation	*op,
	SlapReply	*rs
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

/* quick hack: call the right callback */
static int
add_merge_func( Operation *op, SlapReply *rs )
{
	switch ( rs->sr_type ) {
	case REP_SEARCH:
		merge_func( op, rs );
		break;

	case REP_RESULT:
		add_func( op, rs );
		break;

	default:
		assert( 0 );
	}
	return 0;
}

int
merge_entry(
	Operation		*op,
	SlapReply		*rs,
	struct berval*		query_uuid, 
	struct exception*	result )
{
	struct entry_info info;
	struct berval normdn;
	struct berval prettydn;

	SlapReply sreply = {REP_RESULT};

	Operation op_tmp = *op;
	slap_callback cb = { add_merge_func, NULL };

	Filter* filter = str2filter( bv_queryid_any.bv_val );
	sreply.sr_entry = NULL; 
	sreply.sr_nentries = 0; 

	dnPrettyNormal(0, &rs->sr_entry->e_name, &prettydn, &normdn,
			op->o_tmpmemctx);

	free(rs->sr_entry->e_name.bv_val);
	rs->sr_entry->e_name = prettydn;
	if (rs->sr_entry->e_nname.bv_val) free(rs->sr_entry->e_nname.bv_val);
	rs->sr_entry->e_nname = normdn;

	info.entry = rs->sr_entry;
	info.uuid = query_uuid;
	info.size_init = 0;
	info.size_final = 0;
	info.added = 0;
	info.glue_be = op->o_bd;
	info.err = SUCCESS;
	cb.sc_private = &info;

	op_tmp.o_tag = LDAP_REQ_SEARCH;
	op_tmp.o_protocol = LDAP_VERSION3;
	op_tmp.o_callback = &cb;
	op_tmp.o_caching_on = 1;
	op_tmp.o_time = slap_get_time();
	op_tmp.o_do_not_cache = 1;

	op_tmp.o_req_dn = rs->sr_entry->e_name;
	op_tmp.o_req_ndn = rs->sr_entry->e_nname;
	op_tmp.ors_scope = LDAP_SCOPE_BASE;
	op_tmp.ors_deref = LDAP_DEREF_NEVER;
	op_tmp.ors_slimit = 1;
	op_tmp.ors_tlimit = 0;
	op_tmp.ors_filter = filter;
	op_tmp.ors_filterstr = bv_queryid_any;
	op_tmp.ors_attrs = NULL;
	op_tmp.ors_attrsonly = 0;

	op->o_bd->be_search( &op_tmp, &sreply );
	result->type = info.err; 
	if ( result->type == SUCCESS )
		result->rc = info.added; 
	else 
		result->rc = 0; 
	return ( info.size_final - info.size_init );
}

static int
merge_func (
	Operation	*op,
	SlapReply	*rs
)
{
	Backend			*be;
	char 			*new_attr_name;
	Attribute		*a_new, *a;
	int 			i = 0;
	int 			rc = 0;
    
	int 			count;
	struct timeval		time;	/* time */
	long 			timediff; /* time */
	struct entry_info	*info = op->o_callback->sc_private;
	Filter			*filter = str2filter( bv_queryid_any.bv_val );
	Entry			*entry = info->entry;
	struct berval		*uuid = info->uuid;
	Modifications		*modhead = NULL;
	Modifications		*mod;
	Modifications		**modtail = &modhead;
	AttributeDescription	*a_new_desc;
	const char		*text = NULL;
	Operation		op_tmp = *op;
	SlapReply		sreply = {REP_RESULT}; 
	SlapReply		sreply1 = {REP_RESULT}; 

	info->err = SUCCESS; 

	be = select_backend(&entry->e_nname, 0, 0); 
     
	info->size_init = get_entry_size(rs->sr_entry, 0, 0);  
	a_new = entry->e_attrs;

	while (a_new != NULL) {
		a_new_desc = a_new->a_desc; 
		mod = (Modifications *) malloc( sizeof(Modifications) );
		mod->sml_op = LDAP_MOD_REPLACE;
		ber_dupbv(&mod->sml_type, &a_new_desc->ad_cname); 

		for ( count = 0; a_new->a_vals[count].bv_val; count++ ) 
			;

		mod->sml_bvalues = (struct berval*) malloc(
				(count+1) * sizeof( struct berval) );

		mod->sml_nvalues = (struct berval*) malloc(
				(count+1) * sizeof( struct berval) );

		for ( i = 0; i < count; i++ ) {
			ber_dupbv(mod->sml_bvalues+i, a_new->a_vals+i); 
			if ( a_new->a_desc->ad_type->sat_equality &&
				a_new->a_desc->ad_type->sat_equality->smr_normalize ) {
				rc = a_new->a_desc->ad_type->sat_equality->smr_normalize(
					0,
					a_new->a_desc->ad_type->sat_syntax,
					a_new->a_desc->ad_type->sat_equality,
					a_new->a_vals+i, mod->sml_nvalues+i, NULL );
				if (rc) {
					info->err = MERGE_ERR; 
					return 0; 
			        } 
			}
			else {	
				ber_dupbv( mod->sml_nvalues+i, a_new->a_vals+i ); 
			} 
		}

		mod->sml_bvalues[count].bv_val = 0; 
		mod->sml_bvalues[count].bv_len = 0; 

		mod->sml_nvalues[count].bv_val = 0; 
		mod->sml_nvalues[count].bv_len = 0; 

		mod->sml_desc = NULL;
		slap_bv2ad(&mod->sml_type, &mod->sml_desc, &text); 
		mod->sml_next =NULL;
		*modtail = mod;
		modtail = &mod->sml_next;
		a_new = a_new->a_next; 
	} 

	/* add query UUID to queryid attribute */
	mod = (Modifications *) ch_malloc( sizeof(Modifications) );
	mod->sml_op = LDAP_MOD_ADD;
	mod->sml_desc = slap_schema.si_ad_queryid; 
	ber_dupbv(&mod->sml_type, &mod->sml_desc->ad_cname); 

	mod->sml_bvalues = (BerVarray) ch_malloc( 2 * sizeof( struct berval ) );
	ber_dupbv( mod->sml_bvalues, uuid );
	mod->sml_bvalues[1].bv_val = NULL;
	mod->sml_bvalues[1].bv_len = 0;

	mod->sml_nvalues = (BerVarray) ch_malloc( 2 * sizeof( struct berval ) );
	ber_dupbv( mod->sml_nvalues, uuid );
	mod->sml_nvalues[1].bv_val = NULL;
	mod->sml_nvalues[1].bv_len = 0;

	*modtail = mod;
	mod->sml_next = NULL; 

	/* Apply changes */
	op_tmp.o_req_dn = entry->e_name;
	op_tmp.o_req_ndn = entry->e_nname;
	op_tmp.orm_modlist = modhead;

	op_tmp.o_callback->sc_response = null_response; 
	/* FIXME: &op_tmp ??? */
	if (be->be_modify(&op_tmp, &sreply ) != 0 ) {
		/* FIXME: cleanup ? */
		info->err = MERGE_ERR;
		goto cleanup; 
	}

	/* compute the size of the entry */
	op_tmp.o_callback->sc_response = get_size_func; 

	op_tmp.ors_scope = LDAP_SCOPE_BASE;
	op_tmp.ors_deref = LDAP_DEREF_NEVER;
	op_tmp.ors_slimit = 1;
	op_tmp.ors_tlimit = 0;
	op_tmp.ors_filter = filter;
	op_tmp.ors_filterstr = bv_queryid_any;
	op_tmp.ors_attrs = NULL;
	op_tmp.ors_attrsonly = 0;
   
        sreply1.sr_entry = NULL; 
	sreply1.sr_nentries = 0; 

	if (be->be_search( &op_tmp, &sreply1 ) != 0) {
		info->err = GET_SIZE_ERR;
	}

cleanup:;
	if ( modhead != NULL) {
		slap_mods_free( modhead );
	}

	return 0; 
}

static void
add_func (
	Operation	*op,
	SlapReply	*rs
)
{
	struct entry_info	*info = op->o_callback->sc_private; 
	Entry			*entry = info->entry; 
	struct berval		*uuid = info->uuid; 
	Backend			*be; 
	BerVarray 		value_array; 
	Entry			*e; 
	Attribute		*a, *attr; 
	int 			i,j;
	SlapReply 		sreply = {REP_RESULT}; 

	struct timeval		time;	/* time */ 
	long			timediff; /* time */ 

	Operation		op_tmp = *op;

	/* 
	 * new entry, construct an entry with 
	 * the projected attributes 
	 */
	if (rs->sr_nentries) {
		return;
	}
	
	op_tmp.o_callback->sc_response = null_response; 
	be = select_backend(&entry->e_nname, 0, 0); 
	e = (Entry*)malloc(sizeof(Entry)); 

	ber_dupbv(&e->e_name,&entry->e_name); 
	ber_dupbv(&e->e_nname,&entry->e_nname); 

	e->e_private = 0;
	e->e_attrs = 0; 
	e->e_bv.bv_val = 0; 

	/* add queryid attribute */	
	value_array = (struct berval *)malloc(2 * sizeof( struct berval) );
	ber_dupbv(value_array, uuid);
	value_array[1].bv_val = NULL;
	value_array[1].bv_len = 0;

	a = add_attribute(slap_schema.si_ad_queryid, 
			e, value_array); 

	/* append the attribute list from the fetched entry */
	a->a_next = entry->e_attrs;
	entry->e_attrs = NULL;

	for ( attr = e->e_attrs; attr; attr = attr->a_next ) {
		if ( normalize_values( attr ) ) {
			info->err = MERGE_ERR; 
			return;
		}
	}

	info->size_final = get_entry_size( e, 0, NULL ); 

	op_tmp.o_bd = be;
	op_tmp.ora_e = e;
	
	if ( be->be_add( &op_tmp, &sreply ) == 0 ) {
		info->added = 1; 
		be_entry_release_w( &op_tmp, e );
	} else {
		info->err = MERGE_ERR; 
	}
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
get_size_func (
	Operation	*op,
	SlapReply	*rs
)
{
	struct entry_info	*info = op->o_callback->sc_private; 
	struct exception	result; 

	if ( rs->sr_type == REP_SEARCH ) {
		result.type = info->err;  
		info->size_final = get_entry_size(rs->sr_entry,
				info->size_init, &result); 
	}

	return 0; 
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
				0,
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

#endif /* LDAP_CACHING */
