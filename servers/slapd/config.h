/* config.h - configuration abstraction structure */

/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1998-2004 The OpenLDAP Foundation.
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
	int min_args;
	int max_args;
	int length;
	char *what;
	unsigned long arg_type;
	void *arg_item;
	char *attribute;
	AttributeDescription *ad;
	void *notify;
} ConfigTable;

#define ARGS_USERLAND	0x0000ffffL
#define ARGS_TYPES	0x00ff0000L
#define ARGS_POINTER	0x001f0000L
#define ARGS_NUMERIC	0x000f0000L
#define ARG_INT		0x00010000L
#define ARG_LONG	0x00020000L
#define ARG_BER_LEN_T	0x00040000L
#define ARG_ON_OFF	0x00080000L
#define ARG_STRING	0x00100000L
#define ARG_BERVAL	0x00200000L	/* XXX not yet */
#define ARG_EXISTS	0x00400000L	/* XXX not yet */
#define ARG_IGNORED	0x00800000L

#define ARGS_SYNTAX	0xff000000L
#define ARG_DB		0x01000000L
#define ARG_PRE_DB	0x02000000L
#define ARG_PAREN	0x04000000L
#define ARG_NONZERO	0x08000000L
#define ARG_UNIQUE	0x10000000L	/* XXX not yet */
#define ARG_SPECIAL	0x20000000L	/* one special case */
#define ARG_OFFSET	0x40000000L
#define ARG_MAGIC	0x80000000L

#define ARG_BAD_CONF	0xdead0000L	/* overload return values */
#define ARG_UNKNOWN	0xc0de0000L

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
	int emit;	/* emit instead of setting */
	int type;	/* ConfigTable.arg_type & ARGS_USERLAND */
	BackendDB *be;
	BackendInfo *bi;
} ConfigArgs;

typedef int (ConfigDriver)(ConfigArgs *c);
