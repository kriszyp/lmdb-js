/*
 * Copyright 1998-2000 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */
/*
 * Copyright 2001 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 * 
 * Copyright 2001, Pierangelo Masarati, All rights reserved. <ando@sys-net.it>
 * 
 * This work has beed deveolped for the OpenLDAP Foundation 
 * in the hope that it may be useful to the Open Source community, 
 * but WITHOUT ANY WARRANTY.
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
 */

#ifndef _MONITOR_EXTERNAL_H
#define _MONITOR_EXTERNAL_H

LDAP_BEGIN_DECL

extern int	monitor_back_initialize LDAP_P(( BackendInfo *bi ));
extern int	monitor_back_db_init LDAP_P(( BackendDB *be ));
extern int	monitor_back_open LDAP_P(( BackendInfo *bi ));
extern int	monitor_back_config LDAP_P(( BackendInfo *bi,
	const char *fname, int lineno, int argc, char **argv ));
extern int	monitor_back_db_config LDAP_P(( Backend *be,
	const char *fname, int lineno, int argc, char **argv ));

extern int	monitor_back_db_destroy LDAP_P(( BackendDB *be ));

extern int	monitor_back_search LDAP_P(( BackendDB *bd,
	Connection *conn, Operation *op,
	const char *base, const char *nbase,
	int scope, int deref, int sizelimit, int timelimit,
	Filter *filter, const char *filterstr,
	char **attrs, int attrsonly ));

extern int	monitor_back_compare LDAP_P(( BackendDB *bd,
	Connection *conn, Operation *op,
	const char *dn, const char *ndn,
	AttributeAssertion *ava ));

extern int	monitor_back_abandon LDAP_P(( BackendDB *bd,
	Connection *conn, Operation *op, ber_int_t msgid ));

extern int	monitor_back_modify LDAP_P(( BackendDB *bd,
	Connection *conn, Operation *op,
	const char *dn, const char *ndn, Modifications *ml ));

extern int	monitor_back_bind LDAP_P(( BackendDB *bd,
	Connection *conn, Operation *op,
	const char *dn, const char *ndn, int method,
	struct berval *cred, char** edn ));

extern int	monitor_back_operational LDAP_P((BackendDB *bd,
	Connection *conn, Operation *op,
	Entry *e, char **attrs, int opattrs, Attribute **a ));

LDAP_END_DECL

#endif /* _MONITOR_EXTERNAL_H */

