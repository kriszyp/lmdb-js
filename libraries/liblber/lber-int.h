/* $OpenLDAP$ */
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

/* these have to match lber types settings */
#define LBER_INT_HTON(i)	AC_HTONL(i)
#define LBER_INT_NTOH(i)	AC_NTOHL(i)
#define LBER_LEN_HTON(l)	AC_HTONL(l)
#define LBER_LEN_NTOH(l)	AC_NTOHL(l)
#define LBER_TAG_HTON(t)	AC_HTONL(t)
#define LBER_TAG_NTOH(t)	AC_NTOHL(t)


struct lber_options {
	short lbo_valid;
#define LBER_UNINITIALIZED		0x0
#define LBER_INITIALIZED		0x1
#define LBER_VALID_BERELEMENT	0x2
#define LBER_VALID_SOCKBUF		0x3

	unsigned short lbo_options;
	int lbo_debug;
};

extern struct lber_options ber_int_options;
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
	BERTranslateProc ber_encode_translate_proc;
	BERTranslateProc ber_decode_translate_proc;
};
#define BER_VALID(ber)	((ber)->ber_valid==LBER_VALID_BERELEMENT)


#define ber_pvt_ber_bytes(ber)		((ber)->ber_ptr - (ber)->ber_buf)
#define ber_pvt_ber_remaining(ber)	((ber)->ber_end - (ber)->ber_ptr)

struct sockbuf;

struct sockbuf_io {
	int	(*sbi_setup)( struct sockbuf * sb, void *arg );
	int	(*sbi_remove)( struct sockbuf *sb );
	
	ber_slen_t	(*sbi_read)( struct sockbuf *sb, void *buf, ber_len_t len );
	ber_slen_t	(*sbi_write)( struct sockbuf *sb, void *buf, ber_len_t len );
	int	(*sbi_close)( struct sockbuf *sb );
};

struct sockbuf_sec {
	int	(*sbs_setup)( struct sockbuf * sb, void *arg );
	int	(*sbs_remove)( struct sockbuf *sb );
   
	long	(*sbs_protect)( struct sockbuf *sb, char *in, long *ilen,
			        char *out, long olen );
	long	(*sbs_release)( struct sockbuf *sb, char *in, long ilen,
			       char *out0, long olen0, char *out1, long olen1 );
};

struct sockbuf_buf {
	ber_len_t	buf_size;
	ber_len_t	buf_ptr;
	ber_len_t	buf_end;
	char	*buf_base;
};

typedef struct sockbuf_io Sockbuf_IO;
typedef struct sockbuf_sec Sockbuf_Sec;
typedef struct sockbuf_buf Sockbuf_Buf;

extern Sockbuf_IO ber_pvt_sb_io_tcp;
extern Sockbuf_IO ber_pvt_sb_io_udp;


struct sockbuf {
	struct lber_options sb_opts;
#define	sb_valid		sb_opts.lbo_valid
#define	sb_options		sb_opts.lbo_options
#define	sb_debug		sb_opts.lbo_debug

	int		sb_non_block:1;	
	int		sb_read_ahead:1;
   
	int		sb_buf_ready:1;
	int		sb_trans_ready:1;
   	int		sb_sec_ready:1;
      
   	/* these bits indicate if the transport layer 
	 * needs to read or write 
	 */
   	int		sb_trans_needs_read:1;
   	int		sb_trans_needs_write:1;

   	int		sb_fd;
   
	void		*sb_iodata;	/* transport-layer data pointer */
	Sockbuf_IO	*sb_io;		/* I/O functions */
   
#ifdef LDAP_SASL
   	void		*sb_sdata;	/* security-layer data pointer */
	Sockbuf_Sec	*sb_sec;
#endif	

	ber_socket_t	sb_sd;

#ifdef DEADWOOD
	long		sb_max_incoming;
#endif
	Sockbuf_Buf	sb_buf;
#ifdef LDAP_SASL   
	Sockbuf_Buf	sb_sec_buf_in;
	Sockbuf_Buf	sb_sec_buf_out;
	ber_len_t	sb_sec_prev_len;
#endif   
};
#define SOCKBUF_VALID(ber)	((sb)->sb_valid==LBER_VALID_SOCKBUF)

/* these should be internal ie: ber_int_* */
#define	ber_pvt_sb_get_desc( sb ) ((sb)->sb_sd)
#define ber_pvt_sb_set_desc( sb, val ) ((sb)->sb_sd =(val))

#define ber_pvt_sb_in_use( sb ) ((sb)->sb_sd != AC_SOCKET_INVALID)

#ifdef USE_SASL
#define ber_pvt_sb_data_ready( sb ) \
(((sb)->sb_buf_ready) || ((sb)->sb_trans_ready) || ((sb)->sb_sec_ready))
#else
#define ber_pvt_sb_data_ready( sb ) \
(((sb)->sb_buf_ready) || ((sb)->sb_trans_ready))
#endif
#define ber_pvt_sb_needs_read( sb ) \
((sb)->sb_trans_needs_read)
#define ber_pvt_sb_needs_write( sb ) \
((sb)->sb_trans_needs_write)

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
 * bprint.c
 */
#define ber_log_printf ber_pvt_log_printf

LDAP_F( int )
ber_log_bprint LDAP_P((
	int errlvl,
	int loglvl,
	const char *data,
	ber_len_t len ));

LDAP_F( int )
ber_log_dump LDAP_P((
	int errlvl,
	int loglvl,
	const BerElement *ber,
	int inout ));

LDAP_F( int )
ber_log_sos_dump LDAP_P((
	int errlvl,
	int loglvl,
	const Seqorset *sos ));


/* memory.c */
	/* simple macros to realloc for now */
extern BerMemoryFunctions*		ber_int_memory_fns;

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

/* these should be ber_int*() functions */

LDAP_F( int )
ber_pvt_sb_init LDAP_P(( Sockbuf *sb ));

LDAP_F(	int )
ber_pvt_sb_destroy LDAP_P(( Sockbuf *sb ));

#ifdef USE_SASL
LDAP_F( int )
ber_pvt_sb_set_sec LDAP_P(( Sockbuf *sb, Sockbuf_Sec *sec, void *arg ));

LDAP_F( int )
ber_pvt_sb_clear_sec LDAP_P(( Sockbuf *sb ));
#endif

LDAP_F(	int )
ber_pvt_sb_set_io LDAP_P(( Sockbuf *sb, Sockbuf_IO *layer, void *arg ));

LDAP_F(	int )
ber_pvt_sb_clear_io LDAP_P(( Sockbuf *sb ));

LDAP_F(	int )
ber_pvt_sb_close LDAP_P((Sockbuf *sb ));

LDAP_F( int )
ber_pvt_sb_set_nonblock LDAP_P(( Sockbuf *sb, int nb ));

LDAP_F( int )
ber_pvt_sb_set_readahead LDAP_P(( Sockbuf *sb, int rh ));

LDAP_F( ber_slen_t )
ber_pvt_sb_read LDAP_P(( Sockbuf *sb, void *buf, ber_len_t len ));

LDAP_F( ber_slen_t )
ber_pvt_sb_write LDAP_P(( Sockbuf *sb, void *buf, ber_len_t len ));

LDAP_F(	int )
ber_pvt_sb_udp_set_dst LDAP_P((Sockbuf *sb, void *addr ));

LDAP_F(	void * )
ber_pvt_sb_udp_get_src LDAP_P((Sockbuf *sb ));

LDAP_F( int )
ber_pvt_socket_set_nonblock LDAP_P(( ber_socket_t sd, int nb ));

#endif /* _LBER_INT_H */
