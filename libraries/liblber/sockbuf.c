/* sockbuf.c - i/o routines with support for adding i/o layers. */
/*
 * Copyright 1998-1999 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "portable.h"

#include <stdio.h>
#include <stdlib.h>

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

#include "lber-int.h"

#ifdef LDAP_DEBUG
#include <assert.h>
#undef TEST_PARTIAL_READ
#undef TEST_PARTIAL_WRITE
#else
#define assert( cond )
#endif

#define MAX_BUF_SIZE	65535
#define MIN_BUF_SIZE	4096

#define sockbuf_io_write( sb, buf, len ) \
((sb)->sb_io->sbi_write( (sb), (buf), (len) ))

#define sockbuf_io_read( sb, buf, len ) \
((sb)->sb_io->sbi_read( (sb), (buf), (len) ))

static long have_no_read( Sockbuf *sb, void *buf, long len );
static long have_no_write( Sockbuf *sb, void *buf, long len );
static int have_no_close( Sockbuf *sb );

static Sockbuf_IO lber_pvt_sb_IO_None=
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
   int obr = sb->sb_buf_ready;
#ifdef USE_SASL
   int osr = sb->sb_sec_ready;
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
static long
packet_length( char *buf )
{
   long size;
   size = (((unsigned long)buf[0])<<24)|
     (((unsigned long)buf[1])<<16)|
     (((unsigned long)buf[2])<<8)|
     (((unsigned long)buf[3]));
   
   if ((size<0) || (size>MAX_BUF_SIZE))	{
      /* somebody is trying to mess me up. */
      lber_log_printf( LDAP_DEBUG_SASL, sb->sb_debug,
		      "SASL: received packet length of %d bytes\n",
		      size );      
      size = 16; /* this should lead to an error. */
   }
   
   return size + 4; /* include the size !!! */
}
#endif

static int
grow_buffer( Sockbuf_Buf * buf, long minsize )
{
   long pw=MIN_BUF_SIZE;
   
   for(;(pw<minsize);pw<<=1) {
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
	   free( buf->buf_base );
	 assert( buf->buf_ptr==0 );
	 assert( buf->buf_end==0 );
	 buf->buf_base = malloc( minsize );
	 if (buf->buf_base==NULL)
	   return -1;
      } else {
	 char *nb;
	 nb = realloc( buf->buf_base, minsize );
	 if (nb==NULL)
	   return -1;
	 buf->buf_base = nb;
      }
      buf->buf_size = minsize;
   }
   return 0;
}

#ifdef USE_SASL
static long
sockbuf_sec_release( Sockbuf *sb, char *buf, long len )
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
	size = packet_length( ptr ); 
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

static long 
sockbuf_copy_out( Sockbuf *sb, char **buf, long len )
{
   long blen = (sb->sb_buf.buf_end - sb->sb_buf.buf_ptr );
   assert( status_is_ok(sb) );
   if (blen) {
      long rlen = (blen<len) ? blen : len;
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


long 
lber_pvt_sb_read( Sockbuf *sb, void *buf_arg, long len )
{
   char *buf;
   long ret;
   
   assert( status_is_ok(sb) );
#if 0
   /* breaks slapd :-) */
   assert( lber_pvt_sb_in_use( sb ) );
#endif 

#ifdef TEST_PARTIAL_READ
   if ((rand() & 3)==1) { /* 1 out of 4 */
      errno = EWOULDBLOCK;
      return -1;
   }

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
      int max;
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
	       packet_length(sb->sb_sec_buf_in.buf_base );
	    if ((sb->sb_sec_buf_in.buf_end > sb->sb_sec_buf_in.buf_size) &&
		(grow_buffer( &(sb->sb_sec_buf_in), sb->sb_sec_buf_in.buf_end)<0)) {
	       /* buffer has to be to big. exit with error. */
	       ret = -1;
	       goto do_return;
	    }
	    if (sb->sb_sec_buf_in.buf_ptr >= sb_sec_buf_in.buf_end) {
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
	 long max;
	 max = sb->sb_buf.buf_size - sb->sb_buf.buf_end;
	 if (max>len) {
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

long lber_pvt_sb_write( Sockbuf *sb, void *buf, long len_arg )
{
   long ret;
   long len = len_arg;
   assert( status_is_ok(sb) );
#if 0
   /* unfortunately breaks slapd */
   assert( lber_pvt_sb_in_use( sb ) );
#endif   
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
     
int lber_pvt_sb_close( Sockbuf *sb )
{
   int ret;
   assert( sb->sb_io );
   assert( sb->sb_io->sbi_close );
   assert( status_is_ok(sb) );
   assert( lber_pvt_sb_in_use( sb ) );
   
   ret = sb->sb_io->sbi_close( sb );
   lber_pvt_sb_set_desc( sb, -1 );

   return ret;
}

int lber_pvt_sb_set_readahead( Sockbuf *sb, int rh )
{
   assert( status_is_ok(sb) );
   sb->sb_read_ahead = (rh!=0);
   return 0;
}

#define USE_NONBLOCK
#ifdef USE_NONBLOCK
int lber_pvt_sb_set_nonblock( Sockbuf *sb, int nb )
{
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
   if (lber_pvt_sb_in_use(sb)) {
      int status = (nb!=0);
      if (ioctl( lber_pvt_sb_get_desc(sb), FIONBIO, (caddr_t)&status ) == -1 ) {
	 return -1;
      }
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
   if (buf->buf_base)
     free( buf->buf_base );
   sockbuf_buf_init( buf );
   return 0;
}

int lber_pvt_sb_init( Sockbuf *sb )
{
   sb->sb_item_type=LBER_ITEM_SOCKBUF;
   sb->sb_options = 0;
   sb->sb_debug = 0;
   sb->sb_trans_ready = 0;
   sb->sb_buf_ready = 0;
#ifdef USE_SASL   
   sb->sb_sec_ready = 0;
#endif   
   sb->sb_read_ahead = 0;
   sb->sb_non_block = 0;
   sb->sb_fd = -1;
   sb->sb_iodata = NULL;
   sb->sb_io = &lber_pvt_sb_IO_None;
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
   return 0;
}
   
int lber_pvt_sb_destroy( Sockbuf *sb )
{
#ifdef USE_SASL
   lber_pvt_sb_clear_sec(sb);
   sockbuf_buf_destroy( &(sb->sb_sec_buf_in) );
   sockbuf_buf_destroy( &(sb->sb_sec_buf_out) );
#endif
   lber_pvt_sb_clear_io(sb);
   sockbuf_buf_destroy( &(sb->sb_buf) );
   return lber_pvt_sb_init( sb );
}

#ifdef USE_SASL
int lber_pvt_sb_set_sec( Sockbuf *sb, Sockbuf_Sec * sec, void *arg )
{
   int len;
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
      sb->sb_sec_buf_in.buf_end = (len>4) ? packet_length( sb->sb_sec_buf_in ) : 0;
      sb->sb_buf.buf_ptr = sb->sb_buf.buf_end = 0;
   }
   update_status();
   return 0;
}

int lber_pvt_sb_clear_sec( Sockbuf *sb )
{
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

int lber_pvt_sb_set_io( Sockbuf *sb, Sockbuf_IO *trans, void *arg )
{
   assert( sb->sb_io == &lber_pvt_sb_IO_None );

   if (trans==NULL)
     return -1;
   
   sb->sb_io = trans;
   
   if ((trans->sbi_setup) && (trans->sbi_setup( sb, arg)<0))
     return -1;
   
   return 0;
}

int lber_pvt_sb_clear_io( Sockbuf *sb )
{
   if (sb->sb_io==&lber_pvt_sb_IO_None)
     return -1;
   
   if ((sb->sb_io->sbi_remove) && (sb->sb_io->sbi_remove( sb )<0))
     return -1;

   sb->sb_io = &lber_pvt_sb_IO_None;
   
   sb->sb_trans_ready = 0;
   
   return 0;
}

/*
 * Support for TCP
 */

static long
stream_read( Sockbuf *sb, void *buf, long len )
{
#if defined(MACOS)
/*
 * MacTCP/OpenTransport
 */
   return tcpread( lber_pvt_sb_get_desc(sb), 0, (unsigned char *)buf, 
		   len, NULL );
#elif (defined(DOS) && (defined(PCNFS) || defined( WINSOCK))) \
	|| defined( _WIN32)
/*
 * PCNFS (under DOS)
 */
/*
 * Windows Socket API (under DOS/Windows 3.x)
 */
/*
 * 32-bit Windows Socket API (under Windows NT or Windows 95)
 */
   return recv( lber_pvt_sb_get_desc(sb), buf, len, 0 );
#elif (defined(DOS) && defined( NCSA ))
/*
 * NCSA Telnet TCP/IP stack (under DOS)
 */
   return nread( lber_pvt_sb_get_desc(sb), buf, len );
#else
   return read( lber_pvt_sb_get_desc(sb), buf, len );
#endif
}

static long
stream_write( Sockbuf *sb, void *buf, long len )
{
#if defined(MACOS) 
/*
 * MacTCP/OpenTransport
 */
#define MAX_WRITE	65535
   return tcpwrite( lber_pvt_sb_get_desc(sb),
		    (unsigned char *)(buf), 
		    (len<MAX_WRITE)? len : MAX_WRITE );
#elif (defined(DOS) && (defined(PCNFS) || defined( WINSOCK))) \
	|| defined( _WIN32)
/*
 * PCNFS (under DOS)
 */
/*
 * Windows Socket API (under DOS/Windows 3.x)
 */
/*
 * 32-bit Windows Socket API (under Windows NT or Windows 95)
 */
   return send( lber_pvt_sb_get_desc(sb), buf, len, 0 );
#elif defined(NCSA)
   return netwrite( lber_pvt_sb_get_desc(sb), buf, len );
#elif defined(VMS)
/*
 * VMS -- each write must be 64K or smaller
 */
#define MAX_WRITE 65535
   return write( lber_pvt_sb_get_desc(sb), buf, 
		 (len<MAX_WRITE)? len : MAX_WRITE);
#else
   return write( lber_pvt_sb_get_desc(sb), buf, len );
#endif   
}   
   
static int 
stream_close( Sockbuf *sb )
{
   tcp_close( lber_pvt_sb_get_desc( sb ) );
   return 0;
}

Sockbuf_IO lber_pvt_sb_io_tcp=
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
   sb->sb_iodata = malloc( sizeof( struct dgram_data ) );
   if (sb->sb_iodata==NULL)
     return -1;
   sb->sb_read_ahead = 1; /* important since udp is packet based. */
   return 0;
}

static int 
dgram_release( Sockbuf *sb )
{
   free( sb->sb_iodata );
   return 0;
}

static long
dgram_read( Sockbuf *sb, void *buf, long len )
{
#ifdef LDAP_CONNECTIONLESS
   long rc;
   int addrlen;
   struct dgram_data *dd;
   
   dd = (struct dgram_data *)(sb->sb_iodata);
   
# if !defined( MACOS) && !defined(DOS) && !defined( _WIN32)
   addrlen = sizeof( struct sockaddr );
   rc=recvfrom( lber_pvt_sb_get_desc(sb), buf, len, 0, &(dd->src), &addrlen );
# else
   UDP not supported
# endif
   
   if ( sb->sb_debug ) {
      lber_log_printf( LDAP_DEBUG_ANY, sb->sb_debug,
		      "dgram_read udp_read %d bytes\n",
		      rc );
      if ( rc > 0 )
	lber_log_bprint( LDAP_DEBUG_PACKETS, sb->sb_debug,
			buf, rc );
   }
   return rc;
# else /* LDAP_CONNECTIONLESS */
   return -1;
# endif /* LDAP_CONNECTIONLESS */
}

static long 
dgram_write( Sockbuf *sb, void *buf, long len )
{
#ifdef LDAP_CONNECTIONLESS
   int rc;
   struct dgram_data *dd;
   
   dd = (struct dgram_data *)(sb->sb_iodata);
   
# if !defined( MACOS) && !defined(DOS) && !defined( _WIN32)
   rc=sendto( lber_pvt_sb_get_desc(sb), buf, len, 0, &(dd->dst),
	     sizeof( struct sockaddr ) );
# else
   UDP not supported
# endif
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
	tcp_close( lber_pvt_sb_get_desc(sb) );
	return 0;
}

Sockbuf_IO lber_pvt_sb_io_udp=
{
	dgram_setup,	/* sbi_setup */
	dgram_release,	/* sbi_release */
	dgram_read,	/* sbi_read */
	dgram_write,	/* sbi_write */
	dgram_close,	/* sbi_close */
};

int lber_pvt_sb_udp_set_dst(Sockbuf *sb, void *addr )
{
   struct dgram_data *dd;
   assert( sb->sb_io == &lber_pvt_sb_io_udp );
   dd = (struct dgram_data *) (sb->sb_iodata);
   memcpy( &(dd->dst), addr, sizeof( struct sockaddr ) );
   return 0;
}

void *lber_pvt_sb_udp_get_src( Sockbuf *sb )
{
   struct dgram_data *dd;
   assert( sb->sb_io == &lber_pvt_sb_io_udp );
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

static long
have_no_read( Sockbuf *sb, void *buf, long len )
{
   lber_log_printf( LDAP_DEBUG_ANY, lber_int_debug,
		   "warning: reading from uninitialized sockbuf\n");
   errno =  EBADF;
   return -1;
}

static long
have_no_write( Sockbuf *sb, void *buf, long len )
{
   lber_log_printf( LDAP_DEBUG_ANY, lber_int_debug,
		   "warning: writing to uninitialized sockbuf\n");
   errno =  EBADF;
   return -1;
}

static int 
have_no_close( Sockbuf *sb )
{   
   assert( 0 );
   return -1;
}
