/* $OpenLDAP$ */
/*
 * Copyright 1998-2003 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */
#ifndef _PASSWD_EXTERNAL_H
#define _PASSWD_EXTERNAL_H

LDAP_BEGIN_DECL

extern BI_init	passwd_back_initialize;
extern BI_destroy	passwd_back_destroy;

extern BI_op_search	passwd_back_search;

extern BI_db_config	passwd_back_db_config;

LDAP_END_DECL

#endif /* _PASSWD_EXTERNAL_H */
