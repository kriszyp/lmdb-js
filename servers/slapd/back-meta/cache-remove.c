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
remove_func (
	Backend		*be,
	Connection	*conn,
	Operation	*op,
	Entry		*entry,
	AttributeName	*attrs,
	int		attrsonly,
	LDAPControl	**ctrls
);
 
struct query_info {
	int			freed; 
	int			deleted; 
	struct berval*		uuid; 
	struct timeval		tv; 
	enum type_of_result	err; 
}; 
   
int 
remove_query_data (
	Backend* be,
	Connection* conn, 
	struct berval* query_uuid, 
	struct exception* result)
{
	struct query_info info; 
	char filter_str[64]; 
	Operation op = {0};
	Filter* filter; 
	struct timeval time_in; 
	struct timeval time_out; 
	long timediff; 

	slap_callback cb = {callback_null_response, 
			callback_null_sresult, remove_func, NULL}; 
	sprintf(filter_str, "(queryid=%s)", query_uuid->bv_val);
	filter = str2filter(filter_str); 	      
	info.uuid = query_uuid; 
	info.freed = 0; 
	info.deleted = 0; 
	info.err = SUCCESS; 
	cb.sc_private = &info; 
 
	op.o_tag = LDAP_REQ_SEARCH;
	op.o_protocol = LDAP_VERSION3;
	op.o_ndn = conn->c_ndn;
	op.o_callback = &cb;
	op.o_time = slap_get_time();
	op.o_do_not_cache = 1;
	op.o_caching_on = 1; 
	be->be_search( be, conn, &op, NULL, &(be->be_nsuffix[0]),
			LDAP_SCOPE_SUBTREE, LDAP_DEREF_NEVER, 0, 0,
			filter, NULL, NULL, 0 );
	result->type = info.err;  
	result->rc = info.deleted; 
	return info.freed;  
}

static int
remove_func (
	Backend		*be,
	Connection	*conn,
	Operation	*op,
	Entry		*entry,
	AttributeName	*attrs,
	int		attrsonly,
	LDAPControl	**ctrls
)
{
	slap_callback	*tmp = op->o_callback;  
	struct query_info* info = tmp->sc_private; 
#if 0	/* ??? pdn is not used anywhere */
	struct berval pdn; 
#endif
	int count = 0; 
	int size; 
	struct timeval time_in; 
	struct timeval time_out; 
	long timediff; 
	Modifications* mod; 

	Attribute* attr; 
	size = get_entry_size(entry, 0, NULL);  

	for (attr = entry->e_attrs; attr!= NULL; attr = attr->a_next) {
		if (attr->a_desc == slap_schema.si_ad_queryid) {
			for (count=0; attr->a_vals[count].bv_val; count++) 
				;
			break; 
		}
	}	

	if (count == 0) {
		info->err = REMOVE_ERR; 
		return 0; 
	}
	if (count == 1) {
#if 0	/* ??? pdn is not used anywhere */
		dnPretty(NULL, &entry->e_nname, &pdn); 	
#endif
		info->freed += size; 
#ifdef NEW_LOGGING
		LDAP_LOG( BACK_META, DETAIL1,
				"DELETING ENTRY SIZE=%d TEMPLATE=%s\n",
				size, attr->a_vals[0].bv_val, 0 );
#else
		Debug( LDAP_DEBUG_ANY, "DELETING ENTRY SIZE=%d TEMPLATE=%s\n",
				size, attr->a_vals[0].bv_val, 0 );
#endif

		if (be->be_delete (be, conn, op, &entry->e_name, &entry->e_nname)) {
			info->err = REMOVE_ERR; 
		} else {
			info->deleted++; 
		}
		return 0; 
	}

	mod = (Modifications*)malloc(sizeof(Modifications)); 
	mod->sml_op = LDAP_MOD_DELETE; 
	mod->sml_type.bv_len = sizeof("queryid"); 
	mod->sml_type.bv_val = "queryid"; 
	mod->sml_desc = slap_schema.si_ad_queryid;   
	mod->sml_bvalues = (struct berval*) malloc( 2 * sizeof( struct berval) );
	ber_dupbv(mod->sml_bvalues, info->uuid); 
	mod->sml_bvalues[1].bv_val = NULL; 
	mod->sml_bvalues[1].bv_len = 0; 
	mod->sml_next = NULL; 
#ifdef NEW_LOGGING
	LDAP_LOG( BACK_META, DETAIL1,
			"REMOVING TEMP ATTR : TEMPLATE=%s\n",
			attr->a_vals[0].bv_val, 0, 0 );
#else
	Debug( LDAP_DEBUG_ANY, "REMOVING TEMP ATTR : TEMPLATE=%s\n",
			attr->a_vals[0].bv_val, 0, 0 );
#endif
	if (be->be_modify(be, conn, op, &(entry->e_name), &(entry->e_nname), mod)) {
		info->err = REMOVE_ERR;
	}
	info->freed += LDIF_SIZE_NEEDED(9, (strlen(info->uuid->bv_val))); 

	return 0;
}

#endif /* LDAP_CACHING */
