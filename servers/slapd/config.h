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

typedef struct config_table_s {
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

#define ARGS_USERLAND	0x0000ffff
#define ARGS_TYPES	0x00ff0000
#define ARGS_POINTER	0x001f0000
#define ARGS_NUMERIC	0x000f0000
#define ARG_INT		0x00010000
#define ARG_LONG	0x00020000
#define ARG_BER_LEN_T	0x00040000
#define ARG_ON_OFF	0x00080000
#define ARG_STRING	0x00100000
#define ARG_DN		0x00200000
#define ARG_EXISTS	0x00400000	/* XXX not yet */
#define ARG_IGNORED	0x00800000

#define ARGS_SYNTAX	0xff000000
#define ARG_DB		0x01000000
#define ARG_PRE_DB	0x02000000
#define ARG_PAREN	0x04000000
#define ARG_NONZERO	0x08000000
#define ARG_UNIQUE	0x10000000
#define ARG_SPECIAL	0x20000000	/* one special case */
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
	int value_int;   /* parsed first val */
	long value_long; /* for simple cases */
	ber_len_t value_ber_t;
	char *value_string;
	struct berval value_dn;
	struct berval value_ndn;
	int emit;	/* emit instead of setting */
	int type;	/* ConfigTable.arg_type & ARGS_USERLAND */
	BackendDB *be;
	BackendInfo *bi;
} ConfigArgs;

typedef int (ConfigDriver)(ConfigArgs *c);
