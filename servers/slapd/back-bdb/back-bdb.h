/* back-bdb.h - ldap ldbm back-end header file */
/* $OpenLDAP$ */
/*
 * Copyright 2000 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#ifndef _BACK_BDB_H_
#define _BACK_BDB_H_

#include <portable.h>
#include <db.h>

#include "slap.h"

LDAP_BEGIN_DECL

#define DBTzero(t)			(memset((t), 0, sizeof(DBT)))
#define DBT2bv(t,bv)		((bv)->bv_val = (t)->data, \
								(bv)->bv_len = (t)->size)
#define bv2DBT(bv,t)		((t)->data = (bv)->bv_val, \
								(t)->size = (bv)->bv_len )

#define DEFAULT_MODE		0600

#define BDB_DBENV_HOME	LDAP_RUNDIR LDAP_DIRSEP "openldap-bdb"

#define BDB_TMP_SUBDIR	LDAP_DIRSEP "tmp"
#define BDB_LG_SUBDIR	LDAP_DIRSEP "log"
#define BDB_DATA_SUBDIR	LDAP_DIRSEP "data"

#define BDB_NEXTID	0
#define BDB_ENTRIES	1
#define BDB_DN2ID	2

struct bdb_db_info {
	DB			*bdi_db;
};

struct bdb_info {
	DB_ENV		*bi_dbenv;

	/* DB_ENV parameters */
	/* The DB_ENV can be tuned via DB_CONFIG */
	char		*bi_dbenv_home;
	u_int32_t	bi_dbenv_xflags; /* extra flags */
	int			bi_dbenv_mode;

	int			bi_ndatabases;
	struct bdb_db_info **bdi_databases;
};
#define bi_nextid	bdi_databases[BDB_NEXTID]
#define bi_entries	bdi_databases[BDB_ENTRIES]
#define bi_dn2id	bdi_databases[BDB_DN2ID]

LDAP_END_DECL

#include "proto-bdb.h"

#endif /* _BACK_BDB_H_ */
