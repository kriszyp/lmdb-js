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
static int
merge_func (
	Backend	*be,
	Connection	*conn,
	Operation	*op,
	Entry	*stored_entry,
	AttributeName	*attrs,
	int		attrsonly,
	LDAPControl **ctrls
); 

void
add_func (
	Connection	*conn,
	Operation	*op,
	ber_int_t	err,
	const char	*matched,
	const char	*text,
	BerVarray	refs,
	LDAPControl	**ctrls,
	int		nentries
); 

static Attribute* 
add_attribute(const char* attr_name, 
	Entry* e,
	BerVarray value_array
); 

static int
get_size_func (
	Backend		*be,
	Connection	*conn,
	Operation	*op,
	Entry		*entry,
	AttributeName	*attrs,
	int		attrsonly,
	LDAPControl	**ctrls
); 


/* Two empty callback functions to avoid sending results */
void callback_null_response(
	Connection	*conn,
	Operation	*o,
	ber_tag_t	tag,
	ber_int_t	msgid,
	ber_int_t	err,
	const char	*matched,
	const char	*text,
	BerVarray	ref,
	const char	*resoid,
	struct berval	*resdata,
	struct berval	*sasldata,
	LDAPControl	**c	)
{
}

void callback_null_sresult(
	Connection	*conn,
	Operation	*o,
	ber_int_t	err,
	const char	*matched,
	const char	*text,
	BerVarray	refs,
	LDAPControl	**c,
	int nentries	)
{
}

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
merge_entry (
	Backend*		be,
	Connection*		conn, 
	Entry*			e, 
	struct berval*		query_uuid, 
	struct exception*	result	)
{
	struct entry_info info; 
	struct berval normdn; 
	struct berval prettydn; 

	Operation op = {0};
	slap_callback cb = {callback_null_response, 
		add_func, merge_func, NULL}; 

	Filter* filter = str2filter("(queryid=*)"); 	      

	dnPrettyNormal(0, &(e->e_name), &prettydn, &normdn); 

	free(e->e_name.bv_val); 
	e->e_name = prettydn; 
	e->e_nname = normdn; 

	info.entry = e; 
	info.uuid = query_uuid; 
	info.size_init = 0; 
	info.size_final = 0; 
	info.added = 0; 
	info.glue_be = be; 
	info.err = SUCCESS; 
	cb.sc_private = &info;

	op.o_tag = LDAP_REQ_SEARCH;
	op.o_protocol = LDAP_VERSION3;
	op.o_ndn = conn->c_ndn;
	op.o_callback = &cb;
	op.o_caching_on = 1;
	op.o_time = slap_get_time();
	op.o_do_not_cache = 1;

	be->be_search( be, conn, &op, NULL, &(e->e_nname),
		LDAP_SCOPE_BASE, LDAP_DEREF_NEVER, 1, 0,
		filter, NULL, NULL, 0 );
	result->type = info.err; 
	if ( result->type == SUCCESS )
		result->rc = info.added; 
	else 
		result->rc = 0; 
	return ( info.size_final - info.size_init );
}

static int
merge_func (
	Backend		*be_glue,
	Connection	*conn,
	Operation	*op,
	Entry		*e,
	AttributeName	*attrs,
	int		attrsonly,
	LDAPControl	**ctrls
)
{ 
	Backend* be; 
	char 		*new_attr_name;
	Attribute		*a_new, *a;
	int 		i=0;
	int 		rc=0;
    
	int 		count; 
	struct timeval      time;	/* time */ 
	long 		timediff; /* time */ 
	slap_callback	*tmp = op->o_callback;  
	struct entry_info*   	info = tmp->sc_private; 
	Filter* filter = str2filter("(queryid=*)"); 	      
	Entry* entry = info->entry; 
	struct berval* uuid = info->uuid; 
	Modifications *modhead = NULL; 
	Modifications *mod; 
	Modifications **modtail = &modhead; 
	AttributeDescription* a_new_desc;
	const char	*text = NULL; 

	info->err = SUCCESS; 

	be = select_backend(&entry->e_nname, 0, 0); 
     
	info->size_init = get_entry_size(e, 0, 0);  
	a_new = entry->e_attrs;

	while (a_new != NULL) {
		a_new_desc = a_new->a_desc; 
		mod = (Modifications *) malloc( sizeof(Modifications) );
		mod->sml_op = LDAP_MOD_REPLACE;
		ber_dupbv(&(mod->sml_type), &(a_new_desc->ad_cname)); 

		for (count=0; a_new->a_vals[count].bv_val; count++) 
			;
		mod->sml_bvalues = (struct berval*) malloc(
				(count+1) * sizeof( struct berval) );

		for (i=0; i < count; i++) {
			ber_dupbv(mod->sml_bvalues+i, a_new->a_vals+i); 
		}

		mod->sml_bvalues[count].bv_val = 0; 
		mod->sml_bvalues[count].bv_len = 0; 

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
	ber_dupbv(&(mod->sml_type), &(mod->sml_desc->ad_cname)); 
	mod->sml_bvalues = (BerVarray) ch_malloc( 2 * sizeof( struct berval ) );
	ber_dupbv( mod->sml_bvalues, uuid );
	mod->sml_bvalues[1].bv_val = NULL;
	mod->sml_bvalues[1].bv_len = 0;
	*modtail = mod;
	mod->sml_next = NULL; 

	if (be->be_modify(be, conn, op, &(entry->e_name),
				&(entry->e_nname), modhead) != 0 ) {
		info->err = MERGE_ERR;
		return 0; 
	}
	op->o_callback->sc_sendentry = get_size_func; 
	op->o_callback->sc_sresult = NULL; 
    
	if (be->be_search( be, conn, op, NULL, &(entry->e_nname),
			LDAP_SCOPE_BASE, LDAP_DEREF_NEVER, 1, 0,
			filter, NULL, NULL, 0 ) != 0) {
		info->err = GET_SIZE_ERR;
	}
	return 0; 
}

void
add_func (
	Connection	*conn,
	Operation	*op,
	ber_int_t	err,
	const char	*matched,
	const char	*text,
	BerVarray	refs,
	LDAPControl **ctrls,
	int		nentries
)
{
	slap_callback	*tmp = op->o_callback;  
	struct entry_info   *info = tmp->sc_private; 
	Entry* entry = info->entry; 
	struct berval* uuid = info->uuid; 
	Backend* be; 
	BerVarray 		value_array; 
	Entry		*e; 
	Attribute		*a; 

	struct timeval      time;	/* time */ 
	long 		timediff; /* time */ 

	/* 
	 * new entry, construct an entry with 
	 * the projected attributes 
	 */
	if (nentries) 
		return; 
	
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

	a = add_attribute("queryid", e, value_array); 

	/* append the attribute list from the fetched entry */
	a->a_next = entry->e_attrs;
	entry->e_attrs = NULL;

	info->size_final = get_entry_size(e, 0, NULL); 
	if ( be->be_add( be, conn, op, e ) == 0 ) {
		info->added = 1; 
		be_entry_release_w( be, conn, op, e );
	} else {
		info->err = MERGE_ERR; 
	}
}
 

static Attribute* 
add_attribute(const char* attr_name, 
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
	slap_str2ad(attr_name, &(new_attr->a_desc), &text);   

	return new_attr; 
}

static int
get_size_func (
	Backend		*be,
	Connection	*conn,
	Operation	*op,
	Entry		*entry,
	AttributeName	*attrs,
	int		attrsonly,
	LDAPControl	**ctrls
)
{
	slap_callback		*tmp = op->o_callback;  
	struct entry_info	*info = tmp->sc_private; 
	struct exception	result; 

	result.type = info->err;  
	info->size_final = get_entry_size(entry, info->size_init, &result); 
	return 0; 
}  
#endif /* LDAP_CACHING */
