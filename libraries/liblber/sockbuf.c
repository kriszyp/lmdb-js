/* sockbuf.c - i/o routines with support for adding i/o layers. */
/*
 * Copyright 1998-1999 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "portable.h"

#include <stdio.h>

#include <ac/stdlib.h>

#include <ac/ctype.h>
#include <ac/errno.h>
#include <ac/socket.h>
#include <ac/string.h>
#include <ac/unistd.h>

#ifdef HAVE_IO_H
#include <io.h>
#endif /* HAVE_IO_H */

#if defined( HAVE_SYS_FILIO_H )
#include <sys/filio.h>
#elif defined( HAVE_SYS_IOCTL_H )
#include <sys/ioctl.h>
#endif

#undef LDAP_F_PRE
#define LDAP_F_PRE LDAP_F_EXPORT

#include "lber-int.h"

#ifdef LDAP_TEST
#undef TEST_PARTIAL_READ
#undef TEST_PARTIAL_WRITE
#endif

#define MAX_BUF_SIZE	65535
#define MIN_BUF_SIZE	4096

#define sockbuf_io_write( sb, buf, len ) \
((sb)->sb_io->sbi_write( (sb), (buf), (len) ))

#define sockbuf_io_read( sb, buf, len ) \
((sb)->sb_io->sbi_read( (sb), (buf), (len) ))

static ber_slen_t have_no_read( Sockbuf *sb, void *buf, ber_len_t len );
static ber_slen_t have_no_write( Sockbuf *sb, void *buf, ber_len_t len );
static int have_no_close( Sockbuf *sb );

static Sockbuf_IO sb_IO_None=
{
	NULL,	/* sbi_setup */
	NULL,	/* sbi_release */
	have_no_read,	/* sbi_read */
	have_no_write,	/* sbi_write */
	have_no_close	/* sbi_close */
};

static void
update_status( Sockbuf *sb )
{
	assert( sb != NULL );
	assert( SOCKBUF_VALID( sb ) );

   sb->sb_buf_ready = (sb->sb_buf.buf_ptr < sb->sb_buf.buf_end);
#ifdef USE_SASL   
   sb->sb_sec_ready = ((sb->sb_sec_buf_in.buf_end!=0) &&
		       (sb->sb_sec_buf_in.buf_ptr >= 
			sb->sb_sec_buf_in.buf_end));
#endif   
}

#ifdef LDAP_DEBUG
static int 
status_is_ok( Sockbuf *sb )
{
	int obr;
#ifdef USE_SASL
	int osr;
#endif

	assert( sb != NULL );
	assert( SOCKBUF_VALID( sb ) );

	obr = sb->sb_buf_ready;
#ifdef USE_SASL
	osr = sb->sb_sec_ready;
#endif

   update_status(sb);
   if (obr!=sb->sb_buf_ready)
     return 0;

#ifdef USE_SASL
   if (osr!=sb->sb_sec_ready)
     return 0;
#endif

   return 1;
}
#endif

#ifdef USE_SASL
static ber_len_t
packet_length( Sockbuf *sb, const char *buf )
{
   ber_len_t size;

   assert( buf != NULL );

   size = (((ber_len_t)buf[0])<<24)|
     (((ber_len_t)buf[1])<<16)|
     (((ber_len_t)buf[2])<<8)|
     (((ber_len_t)buf[3]));
   
   if ( size > MAX_BUF_SIZE ) {
      /* somebody is trying to mess me up. */
      ber_log_printf( LDAP_DEBUG_SASL, sb->sb_debug,
		      "SASL: received packet length of %lu bytes\n",
		      (unsigned long) size );      
      size = 16; /* this should lead to an error. */
   }
   
   return size + 4; /* include the size !!! */
}
#endif

static int
grow_buffer( Sockbuf_Buf * buf, ber_len_t minsize )
{
   ber_len_t pw;;
   
   assert( buf != NULL );

   for( pw=MIN_BUF_SIZE; pw<minsize; pw<<=1 ) {
      if (pw > MAX_BUF_SIZE) {
	 /* this could mean that somebody is trying to crash us. */
	 return -1;
      }
   }
   minsize = pw;

   if (buf->buf_size<minsize) {
      if ((buf->buf_base==NULL) || ((buf->buf_end==0) && (buf->buf_ptr==0))) {
	 /* empty buffer */
	 if (buf->buf_base!=NULL)
	   LBER_FREE( buf->buf_base );
	 assert( buf->buf_ptr==0 );
	 assert( buf->buf_end==0 );
	 buf->buf_base = LBER_MALLOC( minsize );
	 if (buf->buf_base==NULL)
	   return -1;
      } else {
	 char *nb;
	 nb = LBER_REALLOC( buf->buf_base, minsize );
	 if (nb==NULL)
	   return -1;
	 buf->buf_base = nb;
      }
      buf->buf_size = minsize;
   }
   return 0;
}

#ifdef USE_SASL
static ber_slen_t
sockbuf_sec_release( Sockbuf *sb, char *buf, ber_len_t len )
{
   /* when this is called:
    *  sb->sb_sec_buf_in.buf_base  points to a packet.
    *  sb->sb_sec_buf_in.buf_ptr   contains the total bytes read.
    *  sb->sb_sec_end.buf_end   contains the packet length.
    * 
    *  sb->sb_buf.buf_ptr == sb->sb_buf.buf_end == 0;
    */
   long rlen;
   long total;
   char *ptr;
   char *end;
   long size;
   
    assert( buf != NULL );
	assert( sb != NULL );
	assert( SOCKBUF_VALID( sb ) );

   assert( sb->sb_sec );
   assert( sb->sb_sec->sbs_release );
   assert( sb->sb_sec_buf_in.sb_ptr >= sb->sb_sec_buf_in.sb_end );
   
   assert( sb->sb_buf.sb_ptr == 0 );
   assert( sb->sb_buf.sb_end == 0 );

   assert( status_is_ok(sb) );
   
   total = 0;
   
   ptr = sb->sb_sec_buf_in.buf_base;
   end = ptr+ sb->sb_sec_buf_in.buf_ptr;
   size = sb->sb_sec_buf_in.buf_end;
   
   sb->sb_sec_ready = 1;
   
   for(;(ptr+size<=end);) {
      for(;;) {
	 rlen = sb->sb_sec->sbs_release( sb, ptr, size,
					buf, len, 
					sb->sb_buf.buf_base,
					sb->sb_buf.buf_size );
	 if (rlen==0) {
	    /* this means a security violation. */
	    return total; /* total ? total : 0 */
	 }
	 if (rlen<0) {
	    /* this means that the buffer isn't big enough. */
	    if (grow_buffer( &(sb->sb_buf), -rlen )<0)
	      /* memory violation. */
	      return total; /* total ? total : 0 */
	    continue;
	 }
	 /* if (rlen>0) */
	 break;
      }
      total+=rlen;
      
      /* move to the next packet... */
      ptr+=size;
      
      if (ptr+4<=end)
	size = packet_length( sb, ptr ); 
      /* size is always at least 4, so the loop condition is always OK !!*/
      assert( size>=4 );
      
      if (rlen<len) {
	 len-=rlen;
	 buf+=rlen;
      } else {
	 sb->sb_buf_ready = (sb->sb_buf.buf_end = rlen - len) ? 1 : 0;
	 break;
      }
   }
   
   if (ptr+size>end)
     sb->sb_sec_ready = 0;
   /* clean up the mess. */
   if (ptr<end) {
      /* copy back to beginning of buffer. */
      SAFEMEMCPY( sb->sb_sec_buf_in.buf_base, ptr, end-ptr );
      sb->sb_sec_buf_in.buf_ptr = 0;
      sb->sb_sec_buf_in.buf_end -= (ptr - sb->sb_sec_buf_in.buf_base);
   }
   assert( status_is_ok(sb) );
   return total;
}

static long
sockbuf_sec_protect( Sockbuf *sb, char *buf, long len )
{
   long ret;
   long blen;
   long total;
   
   assert( buf != NULL );

   assert( sb != NULL );
	assert( SOCKBUF_VALID( sb ) );

   assert( sb->sb_sec_out.buf_end == 0 );
   assert( sb->sb_sec_out.buf_ptr == 0 );
   
   assert( sb->sb_sec );
   assert( sb->sb_sec->sbs_protect );
   
   assert( status_is_ok(sb) );
   
   total = 0;
   for(;(len);) {
      for(;;) {
	 blen = len;
	 ret = sb->sb_sec->sbs_protect( sb, buf, &blen, 
				       sb->sb_sec_out.buf_base+
				       sb->sb_sec_out.buf_end, 
				       sb->sb_sec_out.buf_size -
				       sb->sb_sec_out.buf_end );
	 if (ret==0)
	   /* protection error ? */
	   return total;
	 if (ret<0) {
	    if (grow_buffer( &(sb->sb_sec_out),-ret-sb->sb_sec_out.buf_end )<0)
	      /* memory error */
	      return total;
	    continue;
	 }
	 /* else if (ret>0) */
	 break;
      }
      sb->sb_sec_out.buf_end += ret;
      len -= blen;
      total += blen;
   }
   assert( status_is_ok(sb) );
   return total;
}
#endif

static ber_len_t 
sockbuf_copy_out( Sockbuf *sb, char **buf, ber_len_t len )
{
   ber_len_t blen = (sb->sb_buf.buf_end - sb->sb_buf.buf_ptr );

   assert( buf != NULL );

   assert( sb != NULL );
	assert( SOCKBUF_VALID( sb ) );
   assert( status_is_ok(sb) );

   if (blen) {
      ber_len_t rlen = (blen<len) ? blen : len;
      memcpy( *buf, sb->sb_buf.buf_base + sb->sb_buf.buf_ptr, rlen );
      sb->sb_buf.buf_ptr+=rlen;
      *buf+=rlen;
      len -= rlen;
      if (sb->sb_buf.buf_ptr >= sb->sb_buf.buf_end) {
	 sb->sb_buf.buf_ptr = sb->sb_buf.buf_end = 0;
	 sb->sb_buf_ready = 0;
      } else {
	 sb->sb_buf_ready = 1;
      }
   }
   assert( status_is_ok(sb) );
   return len;
}

Sockbuf *ber_sockbuf_alloc( void )
{
	Sockbuf *sb;

	ber_int_options.lbo_valid = LBER_INITIALIZED;

	sb = LBER_CALLOC(1, sizeof(Sockbuf));

	if( sb == NULL ) return NULL;

	ber_pvt_sb_init( sb );
	return sb;
}

Sockbuf *ber_sockbuf_alloc_fd( ber_socket_t fd )
{
	Sockbuf *sb = ber_sockbuf_alloc();

	if( sb == NULL ) return NULL;

	ber_pvt_sb_set_desc( sb, fd );
   	ber_pvt_sb_set_io( sb, &ber_pvt_sb_io_tcp, NULL );
	return sb;
}

void ber_sockbuf_free( Sockbuf *sb )
{
	assert(sb != NULL);
	assert( SOCKBUF_VALID( sb ) );
	ber_pvt_sb_destroy( sb );
	LBER_FREE(sb);
}

ber_slen_t 
ber_pvt_sb_read( Sockbuf *sb, void *buf_arg, ber_len_t len )
{
   char *buf;
   ber_slen_t ret;
   
   assert( buf_arg != NULL );
   assert( sb != NULL );
   assert( SOCKBUF_VALID( sb ) );
   assert( status_is_ok(sb) );

   /* slapd might have problems with this */
   assert( ber_pvt_sb_in_use( sb ) );

#ifdef TEST_PARTIAL_READ
   if ((rand() & 3)==1) { /* 1 out of 4 */
      errno = EWOULDBLOCK;
      return -1;
   }

   if( len > 0 )
	   len = (rand() % len)+1;
#endif   
   
   buf = (char *) buf_arg;

   if (sb->sb_buf.buf_ptr!=sb->sb_buf.buf_end) {
      len = sockbuf_copy_out( sb, &buf, len );
      if (len==0) {
	 return (buf - (char *) buf_arg);
      }
   }

#ifdef USE_SASL
   if (sb->sb_sec) {
      ber_slen_t max;
      assert( sb->sb_sec->sbs_release );
      assert( sb->sb_sec_buf_in.buf_base );
      if (sb->sb_read_ahead) {
	 max = sb->sb_sec_buf_in.buf_size - sb->sb_sec_buf_in.buf_ptr;
      } else {
	 max = sb->sb_sec_buf_in.buf_end - sb->sb_sec_buf_in.buf_ptr;
	 if (max<=0) {
	    /* special situation. This means that we need to read the first
	     * four bytes for the packet length.
	     */
	    max += 4;
	 }
      }
      for(;;) {
	 /* read from stream into sb_sec_buf_in */
	 for(;;) {
	    ret = sockbuf_io_read( sb, sb->sb_sec_buf_in.buf_base +
				  sb->sb_sec_buf_in.buf_ptr, max );
#ifdef EINTR
	    if ((ret<0) && (errno==EINTR))
	      continue;
#endif
	    break;
	 }
	 if (ret<=0) {
	    /* read error. return */
	    goto do_return;
	 }
	 sb->sb_sec_buf_in.buf_ptr += ret;
	 
	 if (sb->sb_sec_buf_in.buf_ptr < sb->sb_sec_buf_in.buf_end) {
	    /* did not finish a packet. give up. */
	    goto do_return;
	 }
	    
	 if (sb->sb_sec_buf_in.buf_end == 0) {
	    /* Were trying to read the first four bytes... */
	    if (sb->sb_sec_buf_in.buf_ptr < 4) {
	       /* did not read enough for packet length. give up. */
	       goto do_return;
	    }
	    /* calculate the packet length. */
	    sb->sb_sec_buf_in.buf_end = 
	       packet_length(sb, sb->sb_sec_buf_in.buf_base );
	    if ((sb->sb_sec_buf_in.buf_end > sb->sb_sec_buf_in.buf_size) &&
		(grow_buffer( &(sb->sb_sec_buf_in), sb->sb_sec_buf_in.buf_end)<0)) {
	       /* buffer has to be to big. exit with error. */
	       ret = -1;
	       goto do_return;
	    }
	    if (sb->sb_sec_buf_in.buf_ptr >= sb->sb_sec_buf_in.buf_end) {
	       /* finished packet. decode it. */
	       goto decode_packet;
	    }
	    /* did not finish packet yet. try again ? */
	    if (sb->sb_read_ahead) {
	       /* we were trying to read the max anyway. forget it */
	       goto do_return;
	    }
	 }
decode_packet:
	 /* we read enough for at least 1 packet */
	 ret = sockbuf_sec_release( sb, buf, len );
	 if (ret<=0) {
	    /* something went wrong... */
	    goto do_return;
	 }
	 buf+=ret;
	 len-=ret;
	 /* we are finished !!! */
	 if ((len==0) || (ret!=max))
	   goto do_return;
      }
   } else {
#endif
      if (sb->sb_read_ahead) {
	 ber_slen_t max;
	 max = sb->sb_buf.buf_size - sb->sb_buf.buf_end;
	 if (max> (ber_slen_t) len) {
	    for(;;) {
	       ret = sockbuf_io_read( sb, 
				     sb->sb_buf.buf_base +
				     sb->sb_buf.buf_end,
				     max );
#ifdef EINTR	       
	       if ((ret<0) && (errno==EINTR))
		 continue;
#endif
	       break;
	    }
	    if (ret<=0) {
	       /* some error occured */
	       goto do_return;
	    }
	    sb->sb_buf.buf_end += ret;
	    /* move out the data... */
	    len = sockbuf_copy_out( sb, &buf, len );
	    goto do_return;
	 }
      }
      /* no read_ahead, just try to put the data in the buf. */
      for(;;) {
	 ret = sockbuf_io_read( sb, buf, len );
#ifdef EINTR	 
	 if ((ret<0) && (errno==EINTR))
	   continue;
#endif
	 break;
      }
      if (ret>0) {
	 buf+=ret;
	 len-=ret;
      }
      /* we might as well return, since there is nothing to do... */
#ifdef USE_SASL	    
   }
#endif
do_return:
   assert( status_is_ok(sb) );
   if ((ret<=0) && (buf==buf_arg)) {
      /* there was an error. */
      return ret;
   }
   return (buf - ((char *) buf_arg));
}

#ifdef USE_SASL
long sockbuf_do_write( Sockbuf *sb )
{
   long to_go;
   ber_slen_t   ret;

   assert( sb != NULL );
	assert( SOCKBUF_VALID( sb ) );

   to_go = sb->sb_sec_out.buf_end - sb->sb_sec_out.buf_ptr;
   assert( to_go > 0 );
   /* there is something left of the last time... */
   for(;;) {
      ret = sockbuf_io_write( sb, sb->sb_sec_out.buf_base+
			     sb->sb_sec_out.buf_ptr, to_go );
#ifdef EINTR
      if ((ret<0) && (errno==EINTR))
	continue;
#endif
      break;
   }
   if (ret<=0) /* error */
     return ret;
   sb->sb_sec_out.buf_ptr += ret;
   if (ret<to_go) /* not enough data, so pretend no data was sent. */
     return -1;
   return ret;
}
#endif

ber_slen_t ber_pvt_sb_write( Sockbuf *sb, void *buf, ber_len_t len_arg )
{
   ber_slen_t ret;
   ber_len_t len = len_arg;

	assert( buf != NULL );
	assert( sb != NULL );
	assert( SOCKBUF_VALID( sb ) );
   assert( status_is_ok(sb) );

   /* slapd might have problems with this */
   assert( ber_pvt_sb_in_use( sb ) );

#ifdef TEST_PARTIAL_WRITE
   if ((rand() & 3)==1) { /* 1 out of 4 */
      errno = EWOULDBLOCK;
      return -1;
   }

   len_arg = (rand() % len_arg)+1;
   len = len_arg;
#endif   
   
#ifdef USE_SASL
   if (sb->sb_sec) {
      assert( sb->sb_sec_prev_len <= len );
      if (sb->sb_sec_prev_len) {
	 ret = sockbuf_do_write( sb );
	 if (ret<=0)
	   return ret;
	 /* finished. */
	 len -= sb->sb_sec_prev_len;
	 sb->sb_sec_prev_len = 0;
	 sb->sb_sec_out.buf_end = sb->sb_sec_out.buf_ptr = 0;
      }
      /* now protect the next packet. */
      ret = sockbuf_sec_protect( sb, buf, len );
      if (ret<=0)
	return ret;
      ret = sockbuf_do_write( sb );
      if (ret<=0) {
	 sb->sb_sec_prev_len = len;
	 return ret;
      }
      return len_arg;
   } else {
#endif
      for(;;) {
	 ret = sockbuf_io_write( sb, buf, len );
#ifdef EINTR
	 if ((ret<0) && (errno==EINTR))
	   continue;
#endif
	 break;
      }
#ifdef USE_SASL      
   }
#endif

   return ret;
}
     
int ber_pvt_sb_close( Sockbuf *sb )
{
   int ret;

   assert( sb != NULL );
   assert( SOCKBUF_VALID( sb ) );
   assert( sb->sb_io );
   assert( sb->sb_io->sbi_close );
   assert( status_is_ok(sb) );
   assert( ber_pvt_sb_in_use( sb ) );
   
   ret = sb->sb_io->sbi_close( sb );
   ber_pvt_sb_set_desc( sb, -1 );

   return ret;
}

int ber_pvt_sb_set_readahead( Sockbuf *sb, int rh )
{
   assert( sb != NULL );
   assert( SOCKBUF_VALID( sb ) );
   assert( status_is_ok(sb) );
   sb->sb_read_ahead = (rh!=0);
   return 0;
}

int ber_pvt_socket_set_nonblock( ber_socket_t sd, int nb )
{
#if HAVE_FCNTL
	int flags = fcntl(ber_pvt_sb_get_desc(sb), F_GETFL);
	if( nb ) {
		flags |= O_NONBLOCK;
	} else {
		flags &= ~O_NONBLOCK;
	}
	return fcntl( ber_pvt_sb_get_desc(sb), F_SETFL, flags );
		
#elif defined( FIONBIO )
	ioctl_t status = nb ? 1 : 0;
	return ioctl( sd, FIONBIO, &status );
#endif
}

#define USE_NONBLOCK
#ifdef USE_NONBLOCK
int ber_pvt_sb_set_nonblock( Sockbuf *sb, int nb )
{
   assert( sb != NULL );
   assert( SOCKBUF_VALID( sb ) );
   assert( status_is_ok(sb) );
   if (nb) {
      sb->sb_non_block = 1;
#if 0      
      sb->sb_read_ahead = 1;
#endif
   } else {
      sb->sb_non_block = 0;
#if 0
      sb->sb_read_ahead = 0;
#endif
   }
	if (ber_pvt_sb_in_use(sb)) {
		return ber_pvt_socket_set_nonblock(
			ber_pvt_sb_get_desc(sb), nb );
	}
	return 0;
}
#endif
	 
#define sockbuf_buf_init( bb ) do { \
		Sockbuf_Buf *sbb = (bb); \
		sbb->buf_base = NULL; \
		sbb->buf_ptr = 0; \
		sbb->buf_end = 0; \
		sbb->buf_size = 0; \
	} while(0)

static int 
sockbuf_buf_destroy( Sockbuf_Buf *buf )
{
	assert( buf != NULL);

   if (buf->buf_base)
     LBER_FREE( buf->buf_base );
   sockbuf_buf_init( buf );
   return 0;
}

int ber_pvt_sb_init( Sockbuf *sb )
{
	assert( sb != NULL);

	ber_int_options.lbo_valid = LBER_INITIALIZED;

   sb->sb_valid=LBER_VALID_SOCKBUF;
   sb->sb_options = 0;
   sb->sb_debug = 0;
   sb->sb_trans_ready = 0;
   sb->sb_buf_ready = 0;
#ifdef USE_SASL   
   sb->sb_sec_ready = 0;
#endif   
   sb->sb_read_ahead = 1; /* test */
   sb->sb_non_block = 0;
   sb->sb_trans_needs_read = 0;
   sb->sb_trans_needs_write = 0;
   sb->sb_fd = -1;
   sb->sb_iodata = NULL;
   sb->sb_io = &sb_IO_None;
   sb->sb_sd = -1;
#ifdef DEADWOOD   
   sb->sb_max_incoming = 0;
#endif   
   sockbuf_buf_init( &(sb->sb_buf) );
#ifdef USE_SASL
   sockbuf_buf_init( &(sb->sb_sec_buf_in) );
   sockbuf_buf_init( &(sb->sb_sec_buf_out) );
   sb->sb_sdata = NULL;
   sb->sb_sec = NULL;
   sb->sb_sec_prev_len = 0;
#endif 
   
   assert( SOCKBUF_VALID( sb ) );
   return 0;
}
   
int ber_pvt_sb_destroy( Sockbuf *sb )
{
	assert( sb != NULL);
	assert( SOCKBUF_VALID(sb) );
#ifdef USE_SASL
   ber_pvt_sb_clear_sec(sb);
   sockbuf_buf_destroy( &(sb->sb_sec_buf_in) );
   sockbuf_buf_destroy( &(sb->sb_sec_buf_out) );
#endif
   ber_pvt_sb_clear_io(sb);
   sockbuf_buf_destroy( &(sb->sb_buf) );
   return ber_pvt_sb_init( sb );
}

#ifdef USE_SASL
int ber_pvt_sb_set_sec( Sockbuf *sb, Sockbuf_Sec * sec, void *arg )
{
   int len;
	assert( sb != NULL);
	assert( SOCKBUF_VALID( *sb ) );
   if ((sb->sb_sec) || (sec==NULL))
     return -1;
   
   sb->sb_sec = sec;
   
   if ((sec->sbs_setup) && (sec->sbs_setup( sb, arg)<0)) {
      return -1;
   }
   
   len = sb->sb_buf.buf_end - sb->sb_buf.buf_ptr;
   
   if (len>0) {
      /* move this to the security layer. */
      if (grow_buffer( &(sb->sb_sec_buf_in), len )<0)
	return -1;
      memcpy( sb->sb_sec_buf_in.buf_base, 
	     sb->sb_buf.buf_base + sb->sb_buf.buf_ptr, len );
      sb->sb_sec_buf_in.buf_ptr = len;
      sb->sb_sec_buf_in.buf_end = (len>4) ? packet_length( sb, sb->sb_sec_buf_in ) : 0;
      sb->sb_buf.buf_ptr = sb->sb_buf.buf_end = 0;
   }
   update_status( sb );
   return 0;
}

int ber_pvt_sb_clear_sec( Sockbuf *sb )
{
	assert( sb != NULL);
	assert( SOCKBUF_VALID( sb ) );

   if (sb->sb_buf.buf_ptr!=0)
     return -1;
   if (sb->sb_sec==NULL)
     return -1;
   if ((sb->sb_sec->sbs_remove) && (sb->sb_sec->sbs_remove(sb)<0)) 
     return -1;
   
   sb->sb_sec = NULL;
   if (sb->sb_sec_buf_in.buf_ptr!=0) {
      if (grow_buffer( &(sb->sb_buf), 
		      sb->sb_buf.buf_end + sb->sb_sec_buf_in.buf_ptr)<0)
	return -1;
      memcpy( sb->sb_buf.buf_base + sb->sb_buf.buf_end,
	      sb->sb_sec_buf_in.buf_base, sb->sb_sec_buf_in.buf_ptr );
      sb->sb_buf.buf_end += sb->sb_sec_buf_in.buf_ptr;
      sb->sb_buf_ready = 1;
   }
   sockbuf_buf_destroy( &(sb->sb_sec_buf_in) );
   assert( sb->sb_sec_buf.buf_end==0 );
   sockbuf_buf_destroy( &(sb->sb_sec_buf_out) );
   
   sb->sb_sec_ready = 0;
   
   return 0;
}
#endif

int ber_pvt_sb_set_io( Sockbuf *sb, Sockbuf_IO *trans, void *arg )
{
	assert( sb != NULL);
	assert( SOCKBUF_VALID( sb ) );
   assert( sb->sb_io == &sb_IO_None );

   if (trans==NULL)
     return -1;
   
   sb->sb_io = trans;
   
   if ((trans->sbi_setup) && (trans->sbi_setup( sb, arg)<0))
     return -1;
   
   return 0;
}

int ber_pvt_sb_clear_io( Sockbuf *sb )
{
	assert( sb != NULL);
	assert( SOCKBUF_VALID( sb ) );

   if (sb->sb_io==&sb_IO_None)
     return -1;
   
   if ((sb->sb_io->sbi_remove) && (sb->sb_io->sbi_remove( sb )<0))
     return -1;

   sb->sb_io = &sb_IO_None;
   
   sb->sb_trans_ready = 0;
   sb->sb_trans_needs_read = 0;
   sb->sb_trans_needs_write = 0;

   return 0;
}

/*
 * Support for TCP
 */

static ber_slen_t
stream_read( Sockbuf *sb, void *buf, ber_len_t len )
{
	assert( sb != NULL);
	assert( SOCKBUF_VALID( sb ) );

#if defined(MACOS)
/*
 * MacTCP/OpenTransport
 */
   return tcpread( ber_pvt_sb_get_desc(sb), 0, (unsigned char *)buf, 
		   len, NULL );

#elif defined( HAVE_PCNFS ) || \
   defined( HAVE_WINSOCK ) || defined ( __BEOS__ )
/*
 * PCNFS (under DOS)
 */
/*
 * Windows Socket API (under DOS/Windows 3.x)
 */
/*
 * 32-bit Windows Socket API (under Windows NT or Windows 95)
 */
   {
   int rc;
   rc = recv( ber_pvt_sb_get_desc(sb), buf, len, 0 );
#ifdef HAVE_WINSOCK
   if ( rc < 0 ) errno = WSAGetLastError();
#endif
   return rc;
   }
#elif defined( HAVE_NCSA )
/*
 * NCSA Telnet TCP/IP stack (under DOS)
 */
   return nread( ber_pvt_sb_get_desc(sb), buf, len );

#else
   return read( ber_pvt_sb_get_desc(sb), buf, len );
#endif
}

static ber_slen_t
stream_write( Sockbuf *sb, void *buf, ber_len_t len )
{
	assert( sb != NULL);
	assert( SOCKBUF_VALID( sb ) );

#if defined(MACOS) 
/*
 * MacTCP/OpenTransport
 */
#define MAX_WRITE	65535
   return tcpwrite( ber_pvt_sb_get_desc(sb),
		    (unsigned char *)(buf), 
		    (len<MAX_WRITE)? len : MAX_WRITE );

#elif defined( HAVE_PCNFS) \
   || defined( HAVE_WINSOCK) || defined ( __BEOS__ )
/*
 * PCNFS (under DOS)
 */
/*
 * Windows Socket API (under DOS/Windows 3.x)
 */
/*
 * 32-bit Windows Socket API (under Windows NT or Windows 95)
 */

   {
   int rc;
   rc = send( ber_pvt_sb_get_desc(sb), buf, len, 0 );
#ifdef HAVE_WINSOCK
   if ( rc < 0 ) errno = WSAGetLastError();
#endif
   return rc;
   }

#elif defined(HAVE_NCSA)
   return netwrite( ber_pvt_sb_get_desc(sb), buf, len );

#elif defined(VMS)
/*
 * VMS -- each write must be 64K or smaller
 */
#define MAX_WRITE 65535
   return write( ber_pvt_sb_get_desc(sb), buf, 
		 (len<MAX_WRITE)? len : MAX_WRITE);
#else
   return write( ber_pvt_sb_get_desc(sb), buf, len );
#endif   
}   
   
static int 
stream_close( Sockbuf *sb )
{
	assert( sb != NULL);
	assert( SOCKBUF_VALID( sb ) );
   tcp_close( ber_pvt_sb_get_desc( sb ) );
   return 0;
}

Sockbuf_IO ber_pvt_sb_io_tcp=
{
	NULL,	/* sbi_setup */
	NULL,	/* sbi_release */
	stream_read,	/* sbi_read */
	stream_write,	/* sbi_write */
	stream_close,	/* sbi_close */
};

/*
 * Support for UDP (CLDAP)
 */

struct dgram_data
{
	struct sockaddr	dst;
	struct sockaddr	src;
};

static int 
dgram_setup( Sockbuf *sb, void *arg )
{
	assert( sb != NULL);
	assert( SOCKBUF_VALID( sb ) );

   sb->sb_iodata = LBER_MALLOC( sizeof( struct dgram_data ) );
   if (sb->sb_iodata==NULL)
     return -1;
   sb->sb_read_ahead = 1; /* important since udp is packet based. */
   return 0;
}

static int 
dgram_release( Sockbuf *sb )
{
	assert( sb != NULL);
	assert( SOCKBUF_VALID( sb ) );

   LBER_FREE( sb->sb_iodata );
   return 0;
}

static ber_slen_t
dgram_read( Sockbuf *sb, void *buf, ber_len_t len )
{
#ifdef LDAP_CONNECTIONLESS
   ber_slen_t rc;
   socklen_t  addrlen;
   struct dgram_data *dd;
   
	assert( sb != NULL );
	assert( SOCKBUF_VALID( sb ) );
	assert( buf != NULL );

   dd = (struct dgram_data *)(sb->sb_iodata);
   
   addrlen = sizeof( struct sockaddr );
   rc=recvfrom( ber_pvt_sb_get_desc(sb), buf, len, 0, &(dd->src), &addrlen );
   
   if ( sb->sb_debug ) {
      ber_log_printf( LDAP_DEBUG_ANY, sb->sb_debug,
		      "dgram_read udp_read %ld bytes\n",
		      (long) rc );
      if ( rc > 0 )
	ber_log_bprint( LDAP_DEBUG_PACKETS, sb->sb_debug,
			buf, rc );
   }
   return rc;
# else /* LDAP_CONNECTIONLESS */
   return -1;
# endif /* LDAP_CONNECTIONLESS */
}

static ber_slen_t 
dgram_write( Sockbuf *sb, void *buf, ber_len_t len )
{
#ifdef LDAP_CONNECTIONLESS
   ber_slen_t rc;
   struct dgram_data *dd;
   
	assert( sb != NULL );
	assert( SOCKBUF_VALID( sb ) );
	assert( buf != NULL );

   dd = (struct dgram_data *)(sb->sb_iodata);
   
   rc=sendto( ber_pvt_sb_get_desc(sb), buf, len, 0, &(dd->dst),
	     sizeof( struct sockaddr ) );

   if ( rc <= 0 )
       return( -1 );
   
   /* fake error if write was not atomic */
   if (rc < len) {
# ifdef EMSGSIZE
      errno = EMSGSIZE;
# endif
      return( -1 );
   }
   return rc;
#else
   return -1;
#endif	
}

static int 
dgram_close( Sockbuf *sb )
{
	assert( sb != NULL );
	assert( SOCKBUF_VALID( sb ) );

	tcp_close( ber_pvt_sb_get_desc(sb) );
	return 0;
}

Sockbuf_IO ber_pvt_sb_io_udp=
{
	dgram_setup,	/* sbi_setup */
	dgram_release,	/* sbi_release */
	dgram_read,	/* sbi_read */
	dgram_write,	/* sbi_write */
	dgram_close,	/* sbi_close */
};

int ber_pvt_sb_udp_set_dst(Sockbuf *sb, void *addr )
{
   struct dgram_data *dd;
	assert( sb != NULL );
	assert( SOCKBUF_VALID( sb ) );
   assert( sb->sb_io == &ber_pvt_sb_io_udp );
   dd = (struct dgram_data *) (sb->sb_iodata);
   memcpy( &(dd->dst), addr, sizeof( struct sockaddr ) );
   return 0;
}

void *ber_pvt_sb_udp_get_src( Sockbuf *sb )
{
   struct dgram_data *dd;

	assert( sb != NULL );
	assert( SOCKBUF_VALID( sb ) );
   assert( sb->sb_io == &ber_pvt_sb_io_udp );
   dd = (struct dgram_data *) (sb->sb_iodata);
   return &(dd->src);
}

/*
 * debug routines.
 * 
 * BUGS:
 * These routines should really call abort, but at the moment that would
 * break the servers.
 */

static ber_slen_t
have_no_read( Sockbuf *sb, void *buf, ber_len_t len )
{
	assert( sb != NULL );
	assert( SOCKBUF_VALID( sb ) );

   ber_log_printf( LDAP_DEBUG_ANY, ber_int_debug,
		   "warning: reading from uninitialized sockbuf\n");
   errno =  EBADF;
   return -1;
}

static ber_slen_t
have_no_write( Sockbuf *sb, void *buf, ber_len_t len )
{
	assert( sb != NULL );
	assert( SOCKBUF_VALID( sb ) );

   ber_log_printf( LDAP_DEBUG_ANY, ber_int_debug,
		   "warning: writing to uninitialized sockbuf\n");
   errno =  EBADF;
   return -1;
}

static int 
have_no_close( Sockbuf *sb )
{   
	assert( sb != NULL );
	assert( SOCKBUF_VALID( sb ) );

   assert( 0 );
   return -1;
}
