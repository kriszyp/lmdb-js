/*
 * Copyright 1998 The OpenLDAP Foundation, All Rights Reserved.
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

#define LBER_ITEM_BERELEMENT 1
#define LBER_ITEM_SOCKBUF 2

extern int lber_int_debug;
#define lber_log_printf lber_pvt_log_printf

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

struct sockbuf;

struct sockbuf_io {
	int	(*sbi_setup)( struct sockbuf * sb, void *arg );
	int	(*sbi_remove)( struct sockbuf *sb );
	
	long	(*sbi_read)( struct sockbuf *sb, void *buf, long len );
	long	(*sbi_write)( struct sockbuf *sb, void *buf, long len );
	int	(*sbi_close)( struct sockbuf *sb );
};

struct sockbuf_sec
{
	int	(*sbs_setup)( struct sockbuf * sb, void *arg );
	int	(*sbs_remove)( struct sockbuf *sb );
   
	long	(*sbs_protect)( struct sockbuf *sb, char *in, long *ilen,
			        char *out, long olen );
	long	(*sbs_release)( struct sockbuf *sb, char *in, long ilen,
			       char *out0, long olen0, char *out1, long olen1 );
};

struct sockbuf_buf
{
	long	buf_size;
	long	buf_ptr;
	long	buf_end;
	char	*buf_base;
};

typedef struct sockbuf_io Sockbuf_IO;
typedef struct sockbuf_sec Sockbuf_Sec;
typedef struct sockbuf_buf Sockbuf_Buf;

#define	lber_pvt_sb_get_desc( sb ) ((sb)->sb_sd)
#define lber_pvt_sb_set_desc( sb, val ) ((sb)->sb_sd =(val))
#define lber_pvt_sb_in_use( sb ) ((sb)->sb_sd!=-1)

#ifdef USE_SASL
#define lber_pvt_sb_data_ready( sb ) \
(((sb)->sb_buf_ready) || ((sb)->sb_trans_ready) || ((sb)->sb_sec_ready))
#else
#define lber_pvt_sb_data_ready( sb ) \
(((sb)->sb_buf_ready) || ((sb)->sb_trans_ready))
#endif

struct sockbuf {
	short		sb_item_type; 	/* always LBER_ITEM_SOCKBUF */
	short		sb_options;	/* to support copying ber elements */

	int		sb_debug:1;
	int		sb_non_block:1;	
	int		sb_read_ahead:1;
   
	int		sb_buf_ready:1;
	int		sb_trans_ready:1;
   	int		sb_sec_ready:1;
      
   	int		sb_fd;
   
	void		*sb_iodata;	/* transport-layer data pointer */
	Sockbuf_IO	*sb_io;		/* I/O functions */
   
#ifdef LDAP_SASL
   	void		*sb_sdata;	/* security-layer data pointer */
	Sockbuf_Sec	*sb_sec;
#endif	
	
#ifndef MACOS
	int		sb_sd;
#else /* MACOS */
	void		*sb_sd;
#endif /* MACOS */
#ifdef DEADWOOD
	long		sb_max_incoming;
#endif
	Sockbuf_Buf	sb_buf;
#ifdef LDAP_SASL   
	Sockbuf_Buf	sb_sec_buf_in;
	Sockbuf_Buf	sb_sec_buf_out;
	long		sb_sec_prev_len;
#endif   
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

/* sockbuf.c */

LDAP_F	int lber_pvt_sb_init LDAP_P(( Sockbuf *sb ));
LDAP_F	int lber_pvt_sb_destroy LDAP_P(( Sockbuf *sb ));
#ifdef USE_SASL
LDAP_F  int lber_pvt_sb_set_sec LDAP_P(( Sockbuf *sb, Sockbuf_Sec *sec, void *arg ));
LDAP_F  int lber_pvt_sb_clear_sec LDAP_P(( Sockbuf *sb ));
#endif
LDAP_F	int lber_pvt_sb_set_io LDAP_P(( Sockbuf *sb, Sockbuf_IO *layer, void *arg ));
LDAP_F	int lber_pvt_sb_clear_io LDAP_P(( Sockbuf *sb ));
LDAP_F	int lber_pvt_sb_close LDAP_P((Sockbuf *sb ));
LDAP_F  int lber_pvt_sb_set_nonblock LDAP_P(( Sockbuf *sb, int nb ));
LDAP_F  int lber_pvt_sb_set_readahead LDAP_P(( Sockbuf *sb, int rh ));
LDAP_F  long lber_pvt_sb_read LDAP_P(( Sockbuf *sb, void *buf, long len ));
LDAP_F  long lber_pvt_sb_write LDAP_P(( Sockbuf *sb, void *buf, long len ));
LDAP_F	int lber_pvt_sb_udp_set_dst LDAP_P((Sockbuf *sb, void *addr ));
LDAP_F	void *lber_pvt_sb_udp_get_src LDAP_P((Sockbuf *sb ));

extern Sockbuf_IO lber_pvt_sb_io_tcp;
extern Sockbuf_IO lber_pvt_sb_io_udp;

#endif /* _LBER_INT_H */
