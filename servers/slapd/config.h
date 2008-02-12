/* config.h - configuration abstraction structure */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1998-2008 The OpenLDAP Foundation.
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

#ifndef CONFIG_H
#define CONFIG_H

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
	Cft_Module,
	Cft_Misc	/* backend/overlay defined */
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
#define	ARG_QUOTE	0x20000000	/* wrap with quotes before parsing */
#define ARG_OFFSET	0x40000000
#define ARG_MAGIC	0x80000000

#define ARG_BAD_CONF	0xdead0000	/* overload return values */

/* This is a config entry's e_private data */
typedef struct CfEntryInfo {
	struct CfEntryInfo *ce_parent;
	struct CfEntryInfo *ce_sibs;
	struct CfEntryInfo *ce_kids;
	Entry *ce_entry;
	ConfigType ce_type;
	BackendInfo *ce_bi;
	BackendDB *ce_be;
	void *ce_private;
} CfEntryInfo;

struct config_args_s;

/* Check if the child is allowed to be LDAPAdd'd to the parent */
typedef int (ConfigLDAPadd)(
	CfEntryInfo *parent, Entry *child, struct config_args_s *ca);

/* Let the object create children out of slapd.conf */
typedef int (ConfigCfAdd)(
	Operation *op, SlapReply *rs, Entry *parent, struct config_args_s *ca );

typedef struct ConfigOCs {
	char *co_def;
	ConfigType co_type;
	ConfigTable *co_table;
	ConfigLDAPadd *co_ldadd;
	ConfigCfAdd *co_cfadd;
	ObjectClass *co_oc;
	struct berval *co_name;
} ConfigOCs;

typedef int (ConfigDriver)(struct config_args_s *c);

typedef struct config_args_s {
	int argc;
	char **argv;
	int argv_size;
	char *line;
	char *tline;
	const char *fname;
	int lineno;
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
	Entry *ca_entry;	/* entry being modified */
	void *private;	/* anything */
	ConfigDriver *cleanup;
	ConfigType table;	/* which config table did we come from */
} ConfigArgs;

/* If lineno is zero, we have an actual LDAP Add request from a client.
 * Otherwise, we're reading a config file or a config dir.
 */
#define CONFIG_ONLINE_ADD(ca)	(!((ca)->lineno))

#define value_int values.v_int
#define value_long values.v_long
#define value_ber_t values.v_ber_t
#define value_string values.v_string
#define value_bv values.v_bv
#define value_dn values.v_dn.vdn_dn
#define value_ndn values.v_dn.vdn_ndn

int config_register_schema(ConfigTable *ct, ConfigOCs *co);
int config_del_vals(ConfigTable *cf, ConfigArgs *c);
int config_get_vals(ConfigTable *ct, ConfigArgs *c);
int config_add_vals(ConfigTable *ct, ConfigArgs *c);

void init_config_argv( ConfigArgs *c );
int init_config_attrs(ConfigTable *ct);
int init_config_ocs( ConfigOCs *ocs );
int config_parse_vals(ConfigTable *ct, ConfigArgs *c, int valx);
int config_parse_add(ConfigTable *ct, ConfigArgs *c);
int read_config_file(const char *fname, int depth, ConfigArgs *cf,
	ConfigTable *cft );

ConfigTable * config_find_keyword(ConfigTable *ct, ConfigArgs *c);
Entry * config_build_entry( Operation *op, SlapReply *rs, CfEntryInfo *parent,
	ConfigArgs *c, struct berval *rdn, ConfigOCs *main, ConfigOCs *extra );

int config_shadow( ConfigArgs *c, int flag );
#define	config_slurp_shadow(c)	config_shadow((c), SLAP_DBFLAG_SLURP_SHADOW)
#define	config_sync_shadow(c)	config_shadow((c), SLAP_DBFLAG_SYNC_SHADOW)

	/* Make sure we don't exceed the bits reserved for userland */
#define	config_check_userland(last) \
	assert( ( ( (last) - 1 ) & ARGS_USERLAND ) == ( (last) - 1 ) );

#define	SLAP_X_ORDERED_FMT	"{%d}"

#endif /* CONFIG_H */
