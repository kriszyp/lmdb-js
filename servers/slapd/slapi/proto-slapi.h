/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 2002-2005 The OpenLDAP Foundation.
 * Portions Copyright 1997,2002-2003 IBM Corporation.
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
 * This work was initially developed by IBM Corporation for use in
 * IBM products and subsequently ported to OpenLDAP Software by
 * Steve Omrani.  Additional significant contributors include:
 *   Luke Howard
 */

#ifndef _PROTO_SLAPI_H
#define _PROTO_SLAPI_H

LDAP_BEGIN_DECL

/* slapi_utils.c */
LDAP_SLAPI_F (int) slapi_int_pblock_set_operation LDAP_P(( Slapi_PBlock *pb, Operation *op ));

LDAP_SLAPI_F (LDAPMod **) slapi_int_modifications2ldapmods LDAP_P((Modifications **));
LDAP_SLAPI_F (Modifications *) slapi_int_ldapmods2modifications LDAP_P((LDAPMod **));
LDAP_SLAPI_F (void) slapi_int_free_ldapmods LDAP_P((LDAPMod **));

LDAP_SLAPI_F (int) slapi_int_access_allowed LDAP_P((Operation *op,
	Entry *entry,
	AttributeDescription *desc,
	struct berval *val,
	slap_access_t access,
	AccessControlState *state ));

LDAP_SLAPI_F (char **) slapi_get_supported_extended_ops LDAP_P((void));

/* slapi_ops.c */
LDAP_SLAPI_F (int) slapi_int_init_connection LDAP_P((Slapi_PBlock *pb, SlapReply *rs, int OpType, Connection **pConn));
LDAP_SLAPI_F (void) slapi_int_connection_destroy LDAP_P(( Connection **pConn ));

/* slapi_pblock.c */
LDAP_SLAPI_F (void) slapi_pblock_check_params LDAP_P(( Slapi_PBlock *pb, int flag ));
LDAP_SLAPI_F (int) slapi_pblock_delete_param LDAP_P(( Slapi_PBlock *p, int param ));
LDAP_SLAPI_F (void) slapi_pblock_clear LDAP_P(( Slapi_PBlock *pb ));

LDAP_SLAPI_F (int) slapi_int_pblock_get_first LDAP_P(( Backend *be, Slapi_PBlock **pb ));
LDAP_SLAPI_F (int) slapi_int_pblock_get_next LDAP_P(( Slapi_PBlock **pb ));

/* plugin.c */
LDAP_SLAPI_F (int) slapi_int_register_plugin LDAP_P((Backend *be, Slapi_PBlock *pPB));
LDAP_SLAPI_F (int) slapi_int_call_plugins LDAP_P((Backend *be, int funcType, Slapi_PBlock * pPB));
LDAP_SLAPI_F (int) slapi_int_get_plugins LDAP_P((Backend *be, int functype, SLAPI_FUNC **ppFuncPtrs));
LDAP_SLAPI_F (int) slapi_int_register_extop LDAP_P((Backend *pBE, ExtendedOp **opList, Slapi_PBlock *pPB));
LDAP_SLAPI_F (int) slapi_int_get_extop_plugin LDAP_P((struct berval  *reqoid, SLAPI_FUNC *pFuncAddr ));
LDAP_SLAPI_F (struct berval *) slapi_int_get_supported_extop LDAP_P(( int ));
LDAP_SLAPI_F (int) slapi_int_read_config LDAP_P((Backend *be, const char *fname, int lineno,
		int argc, char **argv ));
LDAP_SLAPI_F (void) slapi_int_plugin_unparse LDAP_P((Backend *be, BerVarray *out ));
LDAP_SLAPI_F (int) slapi_int_initialize LDAP_P((void));

/* slapi_ext.c */
LDAP_SLAPI_F (int) slapi_int_init_object_extensions LDAP_P((void));
LDAP_SLAPI_F (int) slapi_int_free_object_extensions LDAP_P((int objecttype, void *object));
LDAP_SLAPI_F (int) slapi_int_create_object_extensions LDAP_P((int objecttype, void *object));
LDAP_SLAPI_F (int) slapi_int_clear_object_extensions LDAP_P((int objecttype, void *object));

LDAP_END_DECL

#endif /* _PROTO_SLAPI_H */

