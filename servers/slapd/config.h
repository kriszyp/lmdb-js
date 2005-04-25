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

typedef enum {
	Cft_Abstract = 0,
	Cft_Global,
	Cft_Schema,
	Cft_Backend,
	Cft_Database,
	Cft_Overlay,
	Cft_Include,
	Cft_Module
} ConfigType;

#define ARGS_USERLAND	0x00000fff
#define ARGS_TYPES	0x000ff000
#define ARGS_POINTER	0x0003f000
#define ARGS_NUMERIC	0x0000f000
#define ARG_INT		0x00001000
#define ARG_LONG	0x00002000
#define ARG_BER_LEN_T	0x00004000
#define ARG_ON_OFF	0x00008000
#define ARG_STRING	0x00010000
#define ARG_BERVAL	0x00020000
#define ARG_DN		0x00040000
#define ARG_IGNORED	0x00080000

#define ARGS_SYNTAX	0xfff00000
#define ARG_PRE_BI	0x00100000
#define ARG_PRE_DB	0x00200000
#define ARG_DB		0x00400000	/* Only applies to DB */
#define ARG_MAY_DB	0x00800000	/* May apply to DB */
#define ARG_PAREN	0x01000000
#define ARG_NONZERO	0x02000000
#define	ARG_NO_INSERT	0x04000000	/* no arbitrary inserting */
#define	ARG_NO_DELETE	0x08000000	/* no runtime deletes */
#define ARG_UNIQUE	0x10000000
#define ARG_OFFSET	0x40000000
#define ARG_MAGIC	0x80000000

#define ARG_BAD_CONF	0xdead0000	/* overload return values */

extern ConfigTable config_back_cf_table[];

typedef struct ConfigOCs {
	char *def;
	ConfigType cft;
	ObjectClass **oc;
} ConfigOCs;

struct config_args_s;

typedef int (ConfigDriver)(struct config_args_s *c);

typedef struct config_args_s {
	int argc;
	char **argv;
	int argv_size;
	char *line;
	char *tline;
	const char *fname;
	unsigned long lineno;
	char log[MAXPATHLEN + STRLENOF(": line 18446744073709551615") + 1];
	char msg[SLAP_TEXT_BUFLEN];
	int depth;
	int valx;	/* multi-valued value index */
	/* parsed first val for simple cases */
	union {
		int v_int;
		long v_long;
		ber_len_t v_ber_t;
		char *v_string;
		struct berval v_bv;
		struct {
			struct berval vdn_dn;
			struct berval vdn_ndn;
		} v_dn;
	} values;
	/* return values for emit mode */
	BerVarray rvalue_vals;
	BerVarray rvalue_nvals;
#define	SLAP_CONFIG_EMIT	0x2000	/* emit instead of set */
#define SLAP_CONFIG_ADD		0x4000	/* config file add vs LDAP add */
	int op;
	int type;	/* ConfigTable.arg_type & ARGS_USERLAND */
	BackendDB *be;
	BackendInfo *bi;
	void *private;	/* anything */
	ConfigDriver *cleanup;
} ConfigArgs;

#define value_int values.v_int
#define value_long values.v_long
#define value_ber_t values.v_ber_t
#define value_string values.v_string
#define value_bv values.v_bv
#define value_dn values.v_dn.vdn_dn
#define value_ndn values.v_dn.vdn_ndn

int config_register_schema(ConfigTable *ct, ConfigOCs *co);
int config_get_vals(ConfigTable *ct, ConfigArgs *c);
int config_add_vals(ConfigTable *ct, ConfigArgs *c);
ConfigTable * config_find_keyword(ConfigTable *ct, ConfigArgs *c);
