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

#ifndef _LBER_H
#define _LBER_H

#include <ldap_cdefs.h>

LDAP_BEGIN_DECL

/* BER classes and mask */
#define LBER_CLASS_UNIVERSAL	0x00
#define LBER_CLASS_APPLICATION	0x40
#define LBER_CLASS_CONTEXT	0x80
#define LBER_CLASS_PRIVATE	0xc0
#define LBER_CLASS_MASK		0xc0

/* BER encoding type and mask */
#define LBER_PRIMITIVE		0x00
#define LBER_CONSTRUCTED	0x20
#define LBER_ENCODING_MASK	0x20

#define LBER_BIG_TAG_MASK	0x1f
#define LBER_MORE_TAG_MASK	0x80

/*
 * Note that LBER_ERROR and LBER_DEFAULT are values that can never appear
 * as valid BER tags, and so it is safe to use them to report errors.  In
 * fact, any tag for which the following is true is invalid:
 *     (( tag & 0x00000080 ) != 0 ) && (( tag & 0xFFFFFF00 ) != 0 )
 */
#define LBER_ERROR		0xffffffffL
#define LBER_DEFAULT		0xffffffffL

/* general BER types we know about */
#define LBER_BOOLEAN		0x01L
#define LBER_INTEGER		0x02L
#define LBER_BITSTRING		0x03L
#define LBER_OCTETSTRING	0x04L
#define LBER_NULL		0x05L
#define LBER_ENUMERATED		0x0aL
#define LBER_SEQUENCE		0x30L	/* constructed */
#define LBER_SET		0x31L	/* constructed */

#define OLD_LBER_SEQUENCE	0x10L	/* w/o constructed bit - broken */
#define OLD_LBER_SET		0x11L	/* w/o constructed bit - broken */

typedef int (*BERTranslateProc) LDAP_P(( char **bufp,
	unsigned long *buflenp,
	int free_input ));

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

/* structure for returning a sequence of octet strings + length */
struct berval {
	unsigned long	bv_len;
	char		*bv_val;
};

#ifdef LDAP_DEBUG
extern int lber_debug;
#endif

/*
 * in bprint.c:
 */
LDAP_F void lber_bprint LDAP_P(( char *data, int len ));

/*
 * in decode.c:
 */
LDAP_F unsigned long ber_get_tag LDAP_P(( BerElement *ber ));
LDAP_F unsigned long ber_skip_tag LDAP_P(( BerElement *ber, unsigned long *len ));
LDAP_F unsigned long ber_peek_tag LDAP_P(( BerElement *ber, unsigned long *len ));
LDAP_F unsigned long ber_get_int LDAP_P(( BerElement *ber, long *num ));
LDAP_F unsigned long ber_get_stringb LDAP_P(( BerElement *ber, char *buf,
	unsigned long *len ));
LDAP_F unsigned long ber_get_stringa LDAP_P(( BerElement *ber, char **buf ));
LDAP_F unsigned long ber_get_stringal LDAP_P(( BerElement *ber, struct berval **bv ));
LDAP_F unsigned long ber_get_bitstringa LDAP_P(( BerElement *ber, char **buf,
	unsigned long *len ));
LDAP_F unsigned long ber_get_null LDAP_P(( BerElement *ber ));
LDAP_F unsigned long ber_get_boolean LDAP_P(( BerElement *ber, int *boolval ));
LDAP_F unsigned long ber_first_element LDAP_P(( BerElement *ber, unsigned long *len,
	char **last ));
LDAP_F unsigned long ber_next_element LDAP_P(( BerElement *ber, unsigned long *len,
	char *last ));
LDAP_F unsigned long ber_scanf LDAP_P(( BerElement *ber, char *fmt, ... ));
LDAP_F void ber_bvfree LDAP_P(( struct berval *bv ));
LDAP_F void ber_bvecfree LDAP_P(( struct berval **bv ));
LDAP_F struct berval *ber_bvdup LDAP_P(( struct berval *bv ));
LDAP_F void ber_set_string_translators LDAP_P(( BerElement *ber,
	BERTranslateProc encode_proc, BERTranslateProc decode_proc ));

/*
 * in encode.c
 */
LDAP_F int ber_put_enum LDAP_P(( BerElement *ber, long num, unsigned long tag ));
LDAP_F int ber_put_int LDAP_P(( BerElement *ber, long num, unsigned long tag ));
LDAP_F int ber_put_ostring LDAP_P(( BerElement *ber, char *str, unsigned long len,
	unsigned long tag ));
LDAP_F int ber_put_string LDAP_P(( BerElement *ber, char *str, unsigned long tag ));
LDAP_F int ber_put_bitstring LDAP_P(( BerElement *ber, char *str,
	unsigned long bitlen, unsigned long tag ));
LDAP_F int ber_put_null LDAP_P(( BerElement *ber, unsigned long tag ));
LDAP_F int ber_put_boolean LDAP_P(( BerElement *ber, int boolval,
	unsigned long tag ));
LDAP_F int ber_start_seq LDAP_P(( BerElement *ber, unsigned long tag ));
LDAP_F int ber_start_set LDAP_P(( BerElement *ber, unsigned long tag ));
LDAP_F int ber_put_seq LDAP_P(( BerElement *ber ));
LDAP_F int ber_put_set LDAP_P(( BerElement *ber ));
LDAP_F int ber_printf LDAP_P(( BerElement *ber, char *fmt, ... ));

/*
 * in io.c:
 */

LDAP_F long ber_read LDAP_P(( BerElement *ber, char *buf, unsigned long len ));
LDAP_F long ber_write LDAP_P(( BerElement *ber, char *buf, unsigned long len,
	int nosos ));
LDAP_F void ber_free LDAP_P(( BerElement *ber, int freebuf ));
LDAP_F int ber_flush LDAP_P(( Sockbuf *sb, BerElement *ber, int freeit ));
LDAP_F BerElement *ber_alloc LDAP_P(( void ));
LDAP_F BerElement *der_alloc LDAP_P(( void ));
LDAP_F BerElement *ber_alloc_t LDAP_P(( int options ));
LDAP_F BerElement *ber_dup LDAP_P(( BerElement *ber ));
LDAP_F void ber_dump LDAP_P(( BerElement *ber, int inout ));
LDAP_F void ber_sos_dump LDAP_P(( Seqorset *sos ));
LDAP_F unsigned long ber_get_next LDAP_P(( Sockbuf *sb, unsigned long *len,
	BerElement *ber ));
LDAP_F void ber_init LDAP_P(( BerElement *ber, int options ));
LDAP_F void ber_reset LDAP_P(( BerElement *ber, int was_writing ));

LDAP_END_DECL

#endif /* _LBER_H */
