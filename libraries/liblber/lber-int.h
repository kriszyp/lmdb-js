/*
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

LDAP_BEGIN_DECL

#define LBER_ITEM_BERELEMENT 1
#define LBER_ITEM_SOCKBUF 2

extern int lber_int_debug;

struct berelement {
	short		ber_item_type; 	/* always LBER_ITEM_BERELEMENT */
	short		ber_options;
	int			ber_debug;

	int			ber_usertag;

	unsigned long	ber_tag;
	unsigned long	ber_len;

	char		*ber_buf;
	char		*ber_ptr;
	char		*ber_end;

	struct seqorset	*ber_sos;
	char		*ber_rwptr;
	BERTranslateProc ber_encode_translate_proc;
	BERTranslateProc ber_decode_translate_proc;
};
#define NULLBER	((BerElement *) 0)

struct sockbuf {
	short		sb_item_type; 	/* always LBER_ITEM_SOCKBUF */
	short		sb_options;	/* to support copying ber elements */
	int			sb_debug;

	int			sb_fd;
#ifndef MACOS
	int		sb_sd;
#else /* MACOS */
	void		*sb_sd;
#endif /* MACOS */

	long		sb_max_incoming;

	BerElement	sb_ber;

	int			sb_naddr;	/* > 0 implies using CLDAP (UDP) */
	void		*sb_useaddr;	/* pointer to sockaddr to use next */
	void		*sb_fromaddr;	/* pointer to message source sockaddr */
	void		**sb_addrs;	/* actually an array of pointers to
						sockaddrs */
};
#define READBUFSIZ	8192

struct seqorset {
	BerElement	*sos_ber;
	unsigned long	sos_clen;
	unsigned long	sos_tag;
	char		*sos_first;
	char		*sos_ptr;
	struct seqorset	*sos_next;
};
#define NULLSEQORSET	((Seqorset *) 0)

/*
 * bprint.c
 */
LDAP_F int lber_log_printf LDAP_P((
	int errlvl,
	int loglvl,
	char *fmt,
	... ));

LDAP_F int lber_log_bprint LDAP_P((
	int errlvl,
	int loglvl,
	char *data,
	int len ));

LDAP_F int lber_log_dump LDAP_P((
	int errlvl,
	int loglvl,
	BerElement *ber,
	int inout ));

LDAP_F int lber_log_sos_dump LDAP_P((
	int errlvl,
	int loglvl,
	Seqorset *sos ));

#endif /* _LBER_INT_H */
