/* config.h - configuration abstraction structure */

/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1998-2005 The OpenLDAP Foundation.
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

typedef struct ConfigTable {
	char *name;
	char *what;
	int min_args;
	int max_args;
	int length;
	unsigned int arg_type;
	void *arg_item;
	char *attribute;
	AttributeDescription *ad;
	void *notify;
} ConfigTable;

#define ARGS_USERLAND	0x00000fff
#define ARGS_TYPES	0x000ff000
#define ARGS_POINTER	0x0001f000
#define ARGS_NUMERIC	0x0000f000
#define ARG_INT		0x00001000
#define ARG_LONG	0x00002000
#define ARG_BER_LEN_T	0x00004000
#define ARG_ON_OFF	0x00008000
#define ARG_STRING	0x00010000
#define ARG_DN		0x00020000
#define ARG_EXISTS	0x00040000	/* XXX not yet */
#define ARG_IGNORED	0x00080000

#define ARGS_SYNTAX	0xfff00000
#define ARG_PRE_BI	0x00100000
#define ARG_PRE_DB	0x00200000
#define ARG_DB		0x00400000	/* Only applies to DB */
#define ARG_MAY_DB	0x00800000	/* May apply to DB */
#define ARG_PAREN	0x01000000
#define ARG_NONZERO	0x02000000
#define ARG_UNIQUE	0x10000000
#define ARG_MUTEX	0x20000000	/* modify in single-thread mode */
#define ARG_OFFSET	0x40000000
#define ARG_MAGIC	0x80000000

#define ARG_BAD_CONF	0xdead0000	/* overload return values */
#define ARG_UNKNOWN	0xc0de0000

typedef struct config_args_s {
	int argc;
	char **argv;
	int argv_size;
	char *line;
	const char *fname;
	unsigned long lineno;
	char log[PATH_MAX + STRLENOF(": line 18446744073709551615") + 1];
	int depth;
	/* parsed first val for simple cases */
	union {
		int v_int;
		long v_long;
		ber_len_t v_ber_t;
		char *v_string;
		struct {
			struct berval vdn_dn;
			struct berval vdn_ndn;
		} v_dn;
	} values;
	/* return values for emit mode */
	BerVarray rvalue_vals;
	BerVarray rvalue_nvals;
	int emit;	/* emit instead of setting */
	int type;	/* ConfigTable.arg_type & ARGS_USERLAND */
	BackendDB *be;
	BackendInfo *bi;
} ConfigArgs;

#define value_int values.v_int
#define value_long values.v_long
#define value_ber_t values.v_ber_t
#define value_string values.v_string
#define value_dn values.v_dn.vdn_dn
#define value_ndn values.v_dn.vdn_ndn

typedef int (ConfigDriver)(ConfigArgs *c);

#ifdef SLAPD_MODULES
typedef struct modpath_s {
	struct modpath_s *mp_next;
	struct berval mp_path;
	BerVarray mp_loads;
} ModPaths;
#endif

typedef struct ConfigFile {
	struct ConfigFile *c_sibs;
	struct ConfigFile *c_kids;
	struct berval c_file;
#ifdef SLAPD_MODULES
	ModPaths c_modpaths;
	ModPaths *c_modlast;
#endif
	BerVarray c_dseFiles;
} ConfigFile;

int config_back_init( ConfigFile *cfp, ConfigTable *ct );
int config_get_vals(ConfigTable *ct, ConfigArgs *c);
