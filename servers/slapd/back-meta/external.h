/*
 * Copyright 1998-2001 The OpenLDAP Foundation, All Rights Reserved.
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

#ifndef META_EXTERNAL_H
#define META_EXTERNAL_H

LDAP_BEGIN_DECL

extern int
meta_back_initialize LDAP_P((
		BackendInfo *bi
));
extern int
meta_back_open LDAP_P((
		BackendInfo *bi
));
extern int
meta_back_close LDAP_P((
		BackendInfo *bi
));
extern int
meta_back_destroy LDAP_P((
		BackendInfo *bi
));
extern int
meta_back_db_init LDAP_P((
		BackendDB *bd
));
extern int
meta_back_db_destroy LDAP_P((
		BackendDB *bd
));
extern int
meta_back_db_config LDAP_P((
		BackendDB *bd,
		const char *fname,
		int lineno,
		int argc,
		char **argv
));
extern int
meta_back_bind LDAP_P((
		BackendDB *bd,
		Connection *conn,
		Operation *op,
		const char *dn,
		const char *ndn,
		int method,
		struct berval *cred,
		char** edn
));
extern int
meta_back_conn_destroy LDAP_P((
		BackendDB *bd,
		Connection *conn
));
extern int
meta_back_search LDAP_P((
		BackendDB *bd,
		Connection *conn,
		Operation *op,
		const char *base,
		const char *nbase,
		int scope,
		int deref,
		int sizelimit,
		int timelimit,
		Filter *filter,
		const char *filterstr,
		char **attrs,
		int attrsonly
));
extern int
meta_back_compare LDAP_P((
		BackendDB *bd,
		Connection *conn,
		Operation *op,
		const char *dn,
		const char *ndn,
		AttributeAssertion *ava
));
extern int
meta_back_modify LDAP_P((
		BackendDB *bd,
		Connection *conn,
		Operation *op,
		const char *dn,
		const char *ndn,
		Modifications *ml
));
extern int
meta_back_modrdn LDAP_P((
		BackendDB *bd,
		Connection *conn,
		Operation *op,
		const char *dn,
		const char *ndn,
		const char *newrdn,
		int deleteoldrdn,
		const char *newSuperior
));
extern int
meta_back_add LDAP_P((
		BackendDB *bd,
		Connection *conn,
		Operation *op,
		Entry *e
));
extern int
meta_back_delete LDAP_P((
		BackendDB *bd,
		Connection *conn,
		Operation *op,
		const char *dn,
		const char *ndn
));
extern int meta_back_abandon LDAP_P((
		BackendDB *bd,
		Connection *conn,
		Operation *op,
		int msgid
));
extern int meta_back_group LDAP_P((
		BackendDB *bd,
		Connection *conn,
		Operation *op,
		Entry *target,
		const char* gr_ndn,
		const char* op_ndn,
		ObjectClass* group_oc,
		AttributeDescription*
		group_at
));
extern int
meta_back_attribute LDAP_P((
		BackendDB *bd,
		Connection *conn,
		Operation *op,
		Entry *target,
		const char* ndn,
		AttributeDescription* entry_at,
		struct berval ***vals
));

LDAP_END_DECL

#endif /* META_EXTERNAL_H */

