/* $OpenLDAP$ */
/*
 * Copyright 1998-2000 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */
/* Portions
 * Copyright (c) 1990 Regents of the University of Michigan.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that this notice is preserved and that due credit is given
 * to the University of Michigan at Ann Arbor. The name of the University
 * may not be used to endorse or promote products derived from this
 * software without specific prior written permission. This software
 * is provided ``as is'' without express or implied warranty.
 */

#ifndef _LBER_INT_H
#define _LBER_INT_H

#include "lber.h"
#include "ldap_log.h"
#include "lber_pvt.h"

LDAP_BEGIN_DECL

LBER_F (BER_ERRNO_FN) ber_int_errno_fn;

struct lber_options {
	short lbo_valid;
	unsigned short		lbo_options;
	int			lbo_debug;
	long		lbo_meminuse;
};

#define LBER_UNINITIALIZED		0x0
#define LBER_INITIALIZED		0x1
#define LBER_VALID_BERELEMENT	0x2
#define LBER_VALID_SOCKBUF		0x3

LBER_F (struct lber_options) ber_int_options;
#define ber_int_debug ber_int_options.lbo_debug

struct berelement {
	struct		lber_options ber_opts;
#define ber_valid		ber_opts.lbo_valid
#define ber_options		ber_opts.lbo_options
#define ber_debug		ber_opts.lbo_debug

	ber_tag_t	ber_usertag;

	ber_tag_t	ber_tag;
	ber_len_t	ber_len;

	char		*ber_buf;
	char		*ber_ptr;
	char		*ber_end;

	struct seqorset	*ber_sos;
	char		*ber_rwptr;
};
#define BER_VALID(ber)	((ber)->ber_valid==LBER_VALID_BERELEMENT)

#define ber_pvt_ber_bytes(ber)		((ber)->ber_ptr - (ber)->ber_buf)
#define ber_pvt_ber_remaining(ber)	((ber)->ber_end - (ber)->ber_ptr)

struct sockbuf {
	struct lber_options sb_opts;
	Sockbuf_IO_Desc		*sb_iod;		/* I/O functions */
#define	sb_valid		sb_opts.lbo_valid
#define	sb_options		sb_opts.lbo_options
#define	sb_debug		sb_opts.lbo_debug
	ber_socket_t		sb_fd;
   	unsigned int		sb_trans_needs_read:1;
   	unsigned int		sb_trans_needs_write:1;
};

#define SOCKBUF_VALID( sb )	( (sb)->sb_valid == LBER_VALID_SOCKBUF )

#define READBUFSIZ	8192

struct seqorset {
	BerElement	*sos_ber;
	ber_len_t	sos_clen;
	ber_tag_t	sos_tag;
	char		*sos_first;
	char		*sos_ptr;
	struct seqorset	*sos_next;
};


/*
 * io.c
 */
int ber_realloc LDAP_P((
	BerElement *ber,
	ber_len_t len ));

/*
 * bprint.c
 */
#define ber_log_printf ber_pvt_log_printf

LBER_F( int )
ber_log_bprint LDAP_P((
	int errlvl,
	int loglvl,
	const char *data,
	ber_len_t len ));

LBER_F( int )
ber_log_dump LDAP_P((
	int errlvl,
	int loglvl,
	BerElement *ber,
	int inout ));

LBER_F( int )
ber_log_sos_dump LDAP_P((
	int errlvl,
	int loglvl,
	Seqorset *sos ));


/* memory.c */
	/* simple macros to realloc for now */
LBER_F (BerMemoryFunctions *)	ber_int_memory_fns;

#ifdef CSRIMALLOC
#define LBER_INT_MALLOC		malloc
#define LBER_INT_CALLOC		calloc
#define LBER_INT_REALLOC	realloc
#define LBER_INT_FREE		free
#define LBER_INT_VFREE		ber_memvfree
#define LBER_INT_STRDUP		strdup

#define LBER_MALLOC			malloc
#define LBER_CALLOC			calloc
#define LBER_REALLOC		realloc
#define LBER_FREE			free
#define LBER_VFREE			ber_memvfree
#define LBER_STRDUP			strdup

#else
#define LBER_INT_MALLOC(s)		ber_memalloc((s))
#define LBER_INT_CALLOC(n,s)	ber_memcalloc((n),(s))
#define LBER_INT_REALLOC(p,s)	ber_memrealloc((p),(s))
#define LBER_INT_FREE(p)		ber_memfree((p))
#define LBER_INT_VFREE(v)		ber_memvfree((void**)(v))
#define LBER_INT_STRDUP(s)		ber_strdup((s))

#define LBER_MALLOC(s)		ber_memalloc((s))
#define LBER_CALLOC(n,s)	ber_memcalloc((n),(s))
#define LBER_REALLOC(p,s)	ber_memrealloc((p),(s))
#define LBER_FREE(p)		ber_memfree((p))	
#define LBER_VFREE(v)		ber_memvfree((void**)(v))
#define LBER_STRDUP(s)		ber_strdup((s))
#endif

/* sockbuf.c */

LBER_F(	int )
ber_int_sb_init LDAP_P(( Sockbuf *sb ));

LBER_F( int )
ber_int_sb_close LDAP_P(( Sockbuf *sb ));

LBER_F(	int )
ber_int_sb_destroy LDAP_P(( Sockbuf *sb ));

LBER_F( ber_slen_t )
ber_int_sb_read LDAP_P(( Sockbuf *sb, void *buf, ber_len_t len ));

LBER_F( ber_slen_t )
ber_int_sb_write LDAP_P(( Sockbuf *sb, void *buf, ber_len_t len ));

LDAP_END_DECL

#endif /* _LBER_INT_H */
