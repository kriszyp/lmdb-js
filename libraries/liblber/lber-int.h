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

LDAP_BEGIN_DECL

typedef struct berelement {
	char		*ber_buf;
	char		*ber_ptr;
	char		*ber_end;
	struct seqorset	*ber_sos;
	unsigned long	ber_tag;
	unsigned long	ber_len;
	int		ber_usertag;
	char		ber_options;
#define LBER_USE_DER		0x01
#define LBER_USE_INDEFINITE_LEN	0x02
#define LBER_TRANSLATE_STRINGS	0x04
	char		*ber_rwptr;
	BERTranslateProc ber_encode_translate_proc;
	BERTranslateProc ber_decode_translate_proc;
} BerElement;
#define NULLBER	((BerElement *) 0)

typedef struct sockbuf {
#ifndef MACOS
	int		sb_sd;
#else /* MACOS */
	void		*sb_sd;
#endif /* MACOS */
	BerElement	sb_ber;

	int		sb_naddr;	/* > 0 implies using CLDAP (UDP) */
	void		*sb_useaddr;	/* pointer to sockaddr to use next */
	void		*sb_fromaddr;	/* pointer to message source sockaddr */
	void		**sb_addrs;	/* actually an array of pointers to
						sockaddrs */

	int		sb_options;	/* to support copying ber elements */
#define LBER_TO_FILE		0x01	/* to a file referenced by sb_fd   */
#define LBER_TO_FILE_ONLY	0x02	/* only write to file, not network */
#define LBER_MAX_INCOMING_SIZE	0x04	/* impose limit on incoming stuff  */
#define LBER_NO_READ_AHEAD	0x08	/* read only as much as requested  */
	int		sb_fd;
	long		sb_max_incoming;
} Sockbuf;
#define READBUFSIZ	8192

typedef struct seqorset {
	BerElement	*sos_ber;
	unsigned long	sos_clen;
	unsigned long	sos_tag;
	char		*sos_first;
	char		*sos_ptr;
	struct seqorset	*sos_next;
} Seqorset;
#define NULLSEQORSET	((Seqorset *) 0)

#endif /* _LBER_INT_H */
