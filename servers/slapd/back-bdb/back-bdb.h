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

#define SLAPD_BDB_PRIVATE

#define DEFAULT_MODE		0600

#define DEFAULT_DBENV_HOME	LDAP_RUNDIR LDAP_DIRSEP "openldap-bdb"

#define DEFAULT_DB_TMP_DIR	DEFAULT_DBENV_HOME LDAP_DIRSEP "tmp"
#define DEFAULT_DB_LG_DIR	DEFAULT_DBENV_HOME LDAP_DIRSEP "log"
#define DEFAULT_DB_DATA_DIR	DEFAULT_DBENV_HOME LDAP_DIRSEP "data"

struct bdb_dbinfo {
	DB_ENV		*bdi_dbenv;

	/* DBenv parameters */
	char		*bdi_dbenv_home;
	u_int32_t	bdi_dbenv_xflags; /* extra flags */
	int			bdi_dbenv_mode;

	char		*bdi_db_tmp_dir;
	char		*bdi_db_lg_dir;
	char		*bdi_db_data_dir;
};

LDAP_END_DECL

#endif /* _BACK_BDB_H_ */
