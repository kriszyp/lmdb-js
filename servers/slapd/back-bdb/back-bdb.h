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

LDAP_BEGIN_DECL

#define DEFAULT_MODE		0600
#define DEFAULT_CACHE_SIZE	1000

#define DEFAULT_DBCACHE_SIZE (100 * DEFAULT_DB_PAGE_SIZE)

#define DEFAULT_DB_DIRECTORY	LDAP_RUNDIR LDAP_DIRSEP "openldap-bdb"

#define DEFAULT_DBENV_HOME	LDAP_RUNDIR LDAP_DIRSEP "openldap-bdb-home"
#define DEFAULT_DBENV_MODE	DEFAULT_MODE

#define DEFAULT_BLOCKSIZE	8192

struct bdb_dbinfo {
	DB_ENV		*bdi_dbenv;

	/* DBenv parameters */
	char		*bdi_dbenv_home;
	u_int32_t	bdi_dbenv_xflags; /* extra flags */
	int			bdi_dbenv_mode;

	slap_mask_t	bdi_db_mode;
	char		*bdi_db_directory;
};

LDAP_END_DECL

#endif /* _BACK_BDB_H_ */
