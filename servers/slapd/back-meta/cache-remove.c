/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1999-2003 The OpenLDAP Foundation.
 * Portions Copyright 2003 IBM Corporation.
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
 * This work was initially developed by the Apurva Kumar for inclusion
 * in OpenLDAP Software.
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

static int
remove_func (
	Operation	*op,
	SlapReply	*rs
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
	Operation	*op,
	SlapReply	*rs,
	struct berval* query_uuid, 
	struct exception* result)
{
	struct query_info	info; 
	char			filter_str[64]; 
	Operation		op_tmp = *op;
	Filter			*filter; 
	long timediff;
	SlapReply 		sreply = {REP_RESULT}; 
	slap_callback cb = { remove_func, NULL }; 

	sreply.sr_entry = NULL; 
	sreply.sr_nentries = 0; 
	snprintf(filter_str, sizeof(filter_str), "(queryid=%s)",
			query_uuid->bv_val);
	filter = str2filter(filter_str); 	      
	info.uuid = query_uuid; 
	info.freed = 0; 
	info.deleted = 0; 
	info.err = SUCCESS; 
	cb.sc_private = &info; 
 
	op_tmp.o_tag = LDAP_REQ_SEARCH;
	op_tmp.o_protocol = LDAP_VERSION3;
	op_tmp.o_callback = &cb;
	op_tmp.o_time = slap_get_time();
	op_tmp.o_do_not_cache = 1;

	op_tmp.o_req_dn = op->o_bd->be_suffix[0];
	op_tmp.o_req_ndn = op->o_bd->be_nsuffix[0];
	op_tmp.ors_scope = LDAP_SCOPE_SUBTREE;
	op_tmp.ors_deref = LDAP_DEREF_NEVER;
	op_tmp.ors_slimit = 0;
	op_tmp.ors_tlimit = 0;
	op_tmp.ors_filter = filter;
	op_tmp.ors_filterstr.bv_val = filter_str;
	op_tmp.ors_filterstr.bv_len = strlen(filter_str);
	op_tmp.ors_attrs = NULL;
	op_tmp.ors_attrsonly = 0;

	op->o_bd->be_search( &op_tmp, &sreply );

	result->type = info.err;  
	result->rc = info.deleted; 

	return info.freed;  
}

static int
remove_func (
	Operation	*op,
	SlapReply	*rs
)
{
	struct query_info	*info = op->o_callback->sc_private;
	int			count = 0;
	int			size;
	long			timediff;
	Modifications		*mod;

	Attribute		*attr;
	Operation		op_tmp = *op;

	SlapReply 		sreply = {REP_RESULT}; 

	if (rs->sr_type == REP_RESULT) 
		return 0; 

	size = get_entry_size(rs->sr_entry, 0, NULL);

	for (attr = rs->sr_entry->e_attrs; attr!= NULL; attr = attr->a_next) {
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
		info->freed += size; 
#ifdef NEW_LOGGING
		LDAP_LOG( BACK_META, DETAIL1,
				"DELETING ENTRY SIZE=%d TEMPLATE=%s\n",
				size, attr->a_vals[0].bv_val, 0 );
#else
		Debug( LDAP_DEBUG_ANY, "DELETING ENTRY SIZE=%d TEMPLATE=%s\n",
				size, attr->a_vals[0].bv_val, 0 );
#endif

		op_tmp.o_req_dn = rs->sr_entry->e_name;
		op_tmp.o_req_ndn = rs->sr_entry->e_nname;

		if (op->o_bd->be_delete(&op_tmp, rs)) {
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

	op_tmp.o_req_dn = rs->sr_entry->e_name;
	op_tmp.o_req_ndn = rs->sr_entry->e_nname;
	op_tmp.orm_modlist = mod;
	
	if (op->o_bd->be_modify( &op_tmp, &sreply )) {
		info->err = REMOVE_ERR;
	}

	info->freed += LDIF_SIZE_NEEDED(9, (strlen(info->uuid->bv_val))); 

	return 0;
}
