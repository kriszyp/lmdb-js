/* $OpenLDAP$ */
/*
 *	 Copyright 2000, OpenLDAP Foundation, All rights reserved.
 *
 *	 Redistribution and use in source and binary forms are permitted only
 *	 as authorized by the OpenLDAP Public License.	A copy of this
 *	 license is available at http://www.OpenLDAP.org/license.html or
 *	 in file LICENSE in the top-level directory of the distribution.
 */
#ifndef _DNSSRV_EXTERNAL_H
#define _DNSSRV_EXTERNAL_H

LDAP_BEGIN_DECL

extern BI_init	dnssrv_back_initialize;
extern BI_open	dnssrv_back_open;
extern BI_close	dnssrv_back_close;
extern BI_destroy	dnssrv_back_destroy;

extern BI_db_init	dnssrv_back_db_init;
extern BI_db_destroy	dnssrv_back_db_destroy;

extern BI_db_config	dnssrv_back_db_config;

extern BI_op_bind	dnssrv_back_bind;

extern BI_op_search	dnssrv_back_search;

extern BI_op_compare	dnssrv_back_compare;

extern BI_chk_referrals	dnssrv_back_referrals;

LDAP_END_DECL

#endif /* _DNSSRV_EXTERNAL_H */
