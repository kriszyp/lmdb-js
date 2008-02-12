/* thr_debug.c - wrapper around the chosen thread wrapper, for debugging. */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 2005-2008 The OpenLDAP Foundation.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted only as authorized by the OpenLDAP
 * Public License.
 *
 * A copy of this license is available in file LICENSE in the
 * top-level directory of the distribution or, alternatively, at
 * <http://www.OpenLDAP.org/license.html>.
 */

/*
 * This package provides three types of thread operation debugging:
 *
 * - Print error messages and abort() when thread operations fail:
 *   Operations on threads, mutexes, condition variables, rdwr locks.
 *   Some thread pool operations are also checked, but not those for
 *   which failure can happen in normal slapd operation.
 *
 * - Wrap those types except threads and pools in structs that
 *   contain a state variable or a pointer to dummy allocated memory,
 *   and check that on all operations.  The dummy memory variant lets
 *   malloc debuggers see some incorrect use as memory leaks, access
 *   to freed memory, etc.
 *
 * - Print a count of leaked thread resources after cleanup.
 *
 * Compile-time (./configure) setup:  Macros defined in CPPFLAGS.
 *
 *   LDAP_THREAD_DEBUG or LDAP_THREAD_DEBUG=2
 *      Enables debugging, but value & 2 turns off type wrapping.
 *
 *   LDAP_UINTPTR_T=integer type to hold pointers, preferably unsigned.
 *      Used by dummy memory option "scramble". Default = unsigned long.
 *
 *   In addition, you may need to set up an implementation-specific way
 *      to enable whatever error checking your thread library provides.
 *      Currently only implemented for Posix threads (pthreads), where
 *      you may need to define LDAP_INT_THREAD_MUTEXATTR.  The default
 *      is PTHREAD_MUTEX_ERRORCHECK, or PTHREAD_MUTEX_ERRORCHECK_NP for
 *      Linux threads.  See pthread_mutexattr_settype(3).
 *
 * Run-time configuration:  Environment variable LDAP_THREAD_DEBUG.
 *
 *   The variable may contain a comma- or space-separated option list.
 *   Options:
 *      off      - Disable this package.
 *   Error checking:
 *      noabort  - Do not abort() on errors.
 *      noerror  - Do not report errors.  Implies noabort.
 *      nocount  - Do not report counts of unreleased resources.
 *   State variable/dummy memory, unless type wrapping is disabled:
 *      noalloc  - Default.  Use a state variable, not dummy memory.
 *      dupinit  - Implies noalloc.  Check if resources that have
 *                 not been destroyed are reinitialized.  Tools that
 *                 report uninitialized memory access should disable
 *                 such warnings about debug_already_initialized().
 *      alloc    - Allocate dummy memory and store pointers as-is.
 *                 Malloc debuggers might not notice unreleased
 *                 resources in global variables as memory leaks.
 *      scramble - Store bitwise complement of dummy memory pointer.
 *                 That never escapes memory leak detectors -
 *                 but detection while the program is running will
 *                 report active resources as leaks.  Do not
 *                 use this if a garbage collector is in use:-)
 *      adjptr   - Point to end of dummy memory.
 *                 Purify reports these as "potential leaks" (PLK).
 *                 I have not checked other malloc debuggers.
 *   Tracing:
 *      tracethreads - Report create/join/exit/kill of threads.
 */

#include "portable.h"

#if defined( LDAP_THREAD_DEBUG )

#include <stdio.h>
#include <ac/errno.h>
#include <ac/stdlib.h>
#include <ac/string.h>

#include "ldap_pvt_thread.h" /* Get the thread interface */
#define LDAP_THREAD_IMPLEMENTATION
#define LDAP_THREAD_DEBUG_IMPLEMENTATION
#define LDAP_THREAD_RDWR_IMPLEMENTATION
#define LDAP_THREAD_POOL_IMPLEMENTATION
#include "ldap_thr_debug.h"  /* Get the underlying implementation */


/* Options from environment variable $LDAP_THREAD_DEBUG */
enum { Count_no = 0, Count_yes, Count_reported, Count_reported_more };
static int nodebug, noabort, noerror, count = Count_yes, options_done;
#ifdef LDAP_THREAD_DEBUG_WRAP
enum { Wrap_noalloc, Wrap_alloc, Wrap_scramble, Wrap_adjptr };
static int dupinit, wraptype = Wrap_noalloc, wrap_offset, unwrap_offset;
#endif
static int tracethreads;

static int threading_enabled;

enum {
	Idx_unexited_thread, Idx_unjoined_thread, Idx_locked_mutex,
	Idx_mutex, Idx_cond, Idx_rdwr, Idx_tpool, Idx_max
};
static int resource_counts[Idx_max];
static const char *const resource_names[] = {
	"unexited threads", "unjoined threads", "locked mutexes",
	"mutexes", "conds", "rdwrs", "thread pools"
};
static ldap_int_thread_mutex_t resource_mutexes[Idx_max];


/*
 * Making ldap_pvt_thread_t a wrapper around ldap_int_thread_t would
 * slow down ldap_pvt_thread_self(), so keep a list of threads instead.
 */
typedef struct ldap_debug_thread_s {
	ldap_pvt_thread_t			wrapped;
	ldap_debug_usage_info_t		usage;
	int							detached;
	int							freeme, idx;
} ldap_debug_thread_t;

static ldap_debug_thread_t		**thread_info;
static unsigned int				thread_info_size, thread_info_used;
static ldap_int_thread_mutex_t	thread_info_mutex;


#define WARN(var, msg)   (warn (__FILE__, __LINE__, (msg), #var, (var)))
#define ERROR(var,msg)   (error(__FILE__, __LINE__, (msg), #var, (var)))
#define WARN_IF(rc, msg) {if (rc) warn (__FILE__, __LINE__, (msg), #rc, (rc));}
#define ERROR_IF(rc,msg) {if (rc) error(__FILE__, __LINE__, (msg), #rc, (rc));}

#if 0
static void
warn( const char *file, int line, const char *msg, const char *var, int val )
{
	fprintf( stderr, "%s:%d: %s warning: %s is %d\n",
		file, line, msg, var, val );
}
#endif

static void
error( const char *file, int line, const char *msg, const char *var, int val )
{
	if( !noerror ) {
		fprintf( stderr, "%s:%d: %s error: %s is %d\n",
			file, line, msg, var, val );
		if( !noabort )
			abort();
	}
}

static void
count_resource_leaks( void )
{
	int i, j;
	char errbuf[200], *delim = "Leaked";
	if( count == Count_yes ) {
		count = Count_reported;
#if 0 /* Could break if there are still threads after atexit */
		for( i = j = 0; i < Idx_max; i++ )
			j |= ldap_int_thread_mutex_destroy( &resource_mutexes[i] );
		WARN_IF( j, "ldap_debug_thread_destroy:mutexes" );
#endif
		for( i = j = 0; i < Idx_max; i++ ) {
			if( resource_counts[i] ) {
				j += sprintf( errbuf + j, "%s %d %s",
					delim, resource_counts[i], resource_names[i] );
				delim = ",";
			}
		}
		if( j )
			fprintf( stderr, "%s:%d: %s.\n", __FILE__, __LINE__, errbuf );
	}
}

static void
get_options( void )
{
	static const struct option_info_s {
		const char	*name;
		int       	*var, val;
	} option_info[] = {
		{ "off",        &nodebug,  1 },
		{ "noabort",    &noabort,  1 },
		{ "noerror",    &noerror,  1 },
		{ "nocount",    &count,    Count_no },
#ifdef LDAP_THREAD_DEBUG_WRAP
		{ "noalloc",    &wraptype, Wrap_noalloc },
		{ "dupinit",    &dupinit,  1 },
		{ "alloc",      &wraptype, Wrap_alloc },
		{ "adjptr",     &wraptype, Wrap_adjptr },
		{ "scramble",	&wraptype, Wrap_scramble },
#endif
		{ "tracethreads", &tracethreads, 1 },
		{ NULL, NULL, 0 }
	};
	const char *s = getenv( "LDAP_THREAD_DEBUG" );
	if( s != NULL ) {
		while( *(s += strspn( s, ", \t\r\n" )) != '\0' ) {
			size_t optlen = strcspn( s, ", \t\r\n" );
			const struct option_info_s *oi = option_info;
			while( oi->name &&
				   (strncasecmp( oi->name, s, optlen ) || oi->name[optlen]) )
				oi++;
			if( oi->name )
				*oi->var = oi->val;
			else
				fprintf( stderr, "Unknown $%s option '%.*s'\n",
					"LDAP_THREAD_DEBUG", (int) optlen, s );
			s += optlen;
		}
	}
	if( nodebug ) {
		noabort = noerror = 1;
		tracethreads = dupinit = 0;
		count = Count_no;
	}
#ifdef LDAP_THREAD_DEBUG_WRAP
	if( nodebug || dupinit ) {
		wraptype = Wrap_noalloc;
	} else if( wraptype == Wrap_scramble ) {
		const unsigned char *dummy = (const unsigned char *)&option_info;
		if( sizeof(LDAP_UINTPTR_T) < sizeof(void *)
			|| (unsigned char *)~~(LDAP_UINTPTR_T) dummy != dummy
			|| (unsigned char *)~~(LDAP_UINTPTR_T) (unsigned char *)0 )
		{
			fprintf( stderr, "Misconfigured for $%s %s.  Using %s.\n",
				"LDAP_THREAD_DEBUG", "scramble", "adjptr" );
			wraptype = Wrap_adjptr;
		}
	}
	unwrap_offset = -(wrap_offset = (wraptype == Wrap_adjptr));
#endif
	options_done = 1;
}


static char *
thread_name( char *buf, int bufsize, ldap_pvt_thread_t thread )
{
	int i;
	--bufsize;
	if( bufsize > 2*sizeof(thread) )
		bufsize = 2*sizeof(thread);
	for( i = 0; i < bufsize; i += 2 )
		snprintf( buf+i, 3, "%02x", ((unsigned char *)&thread)[i/2] );
	return buf;
}

static void
exit_thread_message( ldap_pvt_thread_t thread )
{
	if( tracethreads ) {
		char buf[40];
		fprintf( stderr, "== Exiting thread %s ==\n",
			thread_name( buf, sizeof(buf), thread ) );
	}
}


#ifndef LDAP_THREAD_DEBUG_WRAP

#define	WRAPPED(ptr)			(ptr)
#define alloc_usage(ptr, msg)	((void) 0)
#define check_usage(ptr, msg)	((void) 0)
#define free_usage(ptr, msg)	((void) 0)

#define with_threads_lock(statement)	{ statement; }
#define get_new_thread_info(msg)		NULL
#define update_thread_info(ti, th, det)	{}
#define remove_thread_info(ti, msg)		((void)0)
#define get_thread_info(thread, msg)	NULL
#define exiting_thread(msg)	exit_thread_message(ldap_pvt_thread_self())

#else /* LDAP_THREAD_DEBUG_WRAP */

#define	WRAPPED(ptr)			(&(ptr)->wrapped)

#define INITED_VALUE		0x12345678UL
#define INITED_BYTE_VALUE	0xd5

/* Valid programs will access uninitialized memory here if dupinit. */
static int
debug_already_initialized( const LDAP_UINTPTR_T *num )
{
	/*
	 * 'ret' keeps the Valgrind warning "Conditional jump or move
	 * depends on uninitialised value(s)" _inside_ this function.
	 */
	volatile int ret = 0;
	if( dupinit && *num == INITED_VALUE )
		ret = 1;
	return ret;
}

static void
alloc_usage( ldap_debug_usage_info_t *usage, const char *msg )
{
	if( !options_done )
		get_options();
	if( wraptype == Wrap_noalloc ) {
		ERROR_IF( debug_already_initialized( &usage->num ), msg );
		usage->num = INITED_VALUE;
	} else {
		unsigned char *dummy = malloc( 1 );
		assert( dummy != NULL );
		*dummy = INITED_BYTE_VALUE;
		if( wraptype == Wrap_scramble ) {
			usage->num = ~(LDAP_UINTPTR_T) dummy;
			/* Check that ptr<->integer casts work on this host */
			assert( (unsigned char *)~usage->num == dummy );
		} else {
			usage->ptr = dummy + wrap_offset;
		}
	}
}

static void
check_usage( ldap_debug_usage_info_t *usage, const char *msg )
{
	if( wraptype == Wrap_noalloc ) {
		ERROR_IF( usage->num != INITED_VALUE, msg );
	} else if( wraptype == Wrap_scramble ) {
		ERROR_IF( !usage->num, msg );
		ERROR_IF( *(unsigned char *)~usage->num != INITED_BYTE_VALUE, msg );
	} else {
		ERROR_IF( !usage->ptr, msg );
		ERROR_IF( usage->ptr[unwrap_offset] != INITED_BYTE_VALUE, msg );
	}
}

static void
free_usage( ldap_debug_usage_info_t *usage, const char *msg )
{
	if( wraptype == Wrap_noalloc ) {
		usage->num = ~(LDAP_UINTPTR_T)INITED_VALUE;
	} else {
		unsigned char *dummy = (wraptype == Wrap_scramble
		                        ? (unsigned char *)~usage->num
		                        : usage->ptr + unwrap_offset);
		*(volatile unsigned char *)dummy = (unsigned char)-1;
		free( dummy );
	}
}

#define with_threads_lock(statement) { \
	if( !nodebug ) { \
		int rc_wtl_ = ldap_int_thread_mutex_lock( &thread_info_mutex ); \
		assert( rc_wtl_ == 0 ); \
	} \
    statement; \
	if( !nodebug ) { \
		int rc_wtl_ = ldap_int_thread_mutex_unlock( &thread_info_mutex ); \
		assert( rc_wtl_ == 0 ); \
	} \
}

static ldap_debug_thread_t *
get_new_thread_info( const char *msg )
{
	if( nodebug )
		return NULL;
	if( thread_info_used >= thread_info_size ) {
		unsigned int more = thread_info_size + 1; /* debug value. increase. */
		unsigned int new_size = thread_info_size + more;
		ldap_debug_thread_t *t = calloc( more, sizeof(ldap_debug_thread_t) );
		assert( t != NULL );
		t->freeme = 1;
		thread_info = realloc( thread_info, new_size * sizeof(*thread_info) );
		assert( thread_info != NULL );
		while( thread_info_size < new_size ) {
			t->idx = thread_info_size;
			thread_info[thread_info_size++] = t++;
		}
	}
	alloc_usage( &thread_info[thread_info_used]->usage, msg );
	return thread_info[thread_info_used++];
}

static void
update_thread_info(
	ldap_debug_thread_t *t,
	const ldap_pvt_thread_t *thread,
	int detached )
{
	if( !nodebug ) {
		t->wrapped = *thread;
		t->detached = detached;
	}
}

static void
remove_thread_info( ldap_debug_thread_t *t, const char *msg )
{
	if( !nodebug ) {
		ldap_debug_thread_t *last;
		int idx;
		free_usage( &t->usage, msg );
		idx = t->idx;
		assert( thread_info[idx] == t );
		last = thread_info[--thread_info_used];
		assert( last->idx == thread_info_used );
		(thread_info[idx]              = last)->idx = idx;
		(thread_info[thread_info_used] = t   )->idx = thread_info_used;
	}
}

static ldap_debug_thread_t *
get_thread_info( ldap_pvt_thread_t thread, const char *msg )
{
	unsigned int i;
	ldap_debug_thread_t *t;
	if( nodebug )
		return NULL;
	for( i = 0; i < thread_info_used; i++ ) {
		if( ldap_pvt_thread_equal( thread, thread_info[i]->wrapped ) )
			break;
	}
	ERROR_IF( i == thread_info_used, msg );
	t = thread_info[i];
	check_usage( &t->usage, msg );
	return t;
}

static void
exiting_thread( const char *msg )
{
	if( !nodebug ) {
		ldap_pvt_thread_t thread;
		thread = ldap_pvt_thread_self();
		exit_thread_message( thread );
		with_threads_lock({
			ldap_debug_thread_t *t = get_thread_info( thread, msg );
			if( t->detached )
				remove_thread_info( t, msg );
		});
	}
}

#endif /* LDAP_THREAD_DEBUG_WRAP */


static void
adjust_count( int which, int adjust )
{
	int rc;
	switch( count ) {
	case Count_no:
		break;
	case Count_yes:
		rc = ldap_int_thread_mutex_lock( &resource_mutexes[which] );
		assert( rc == 0 );
		resource_counts[which] += adjust;
		rc = ldap_int_thread_mutex_unlock( &resource_mutexes[which] );
		assert( rc == 0 );
		break;
	case Count_reported:
		fputs( "...more ldap_debug_thread activity after exit...\n", stderr );
		count = Count_reported_more;
		/* FALL THROUGH */
	case Count_reported_more:
		/* Not used, but result might be inspected with debugger */
		/* (Hopefully threading is disabled by now...) */
		resource_counts[which] += adjust;
		break;
	}
}


/* Wrappers for LDAP_THREAD_IMPLEMENTATION: */

/* Used instead of ldap_int_thread_initialize by ldap_pvt_thread_initialize */
int
ldap_debug_thread_initialize( void )
{
	int i, rc, rc2;
	if( !options_done )
		get_options();
	ERROR_IF( threading_enabled, "ldap_debug_thread_initialize" );
	threading_enabled = 1;
	rc = ldap_int_thread_initialize();
	if( rc ) {
		ERROR( rc, "ldap_debug_thread_initialize:threads" );
		threading_enabled = 0;
	} else {
		rc2 = ldap_int_thread_mutex_init( &thread_info_mutex );
		assert( rc2 == 0 );
		if( count != Count_no ) {
			for( i = rc2 = 0; i < Idx_max; i++ )
				rc2 |= ldap_int_thread_mutex_init( &resource_mutexes[i] );
			assert( rc2 == 0 );
			/* FIXME: Only for static libldap_r as in init.c? If so, why? */
			atexit( count_resource_leaks );
		}
	}
	return rc;
}

/* Used instead of ldap_int_thread_destroy by ldap_pvt_thread_destroy */
int
ldap_debug_thread_destroy( void )
{
	int rc;
	ERROR_IF( !threading_enabled, "ldap_debug_thread_destroy" );
	/* sleep(1) -- need to wait for thread pool to finish? */
	rc = ldap_int_thread_destroy();
	if( rc ) {
		ERROR( rc, "ldap_debug_thread_destroy:threads" );
	} else {
		threading_enabled = 0;
	}
	return rc;
}

int
ldap_pvt_thread_set_concurrency( int n )
{
	int rc;
	ERROR_IF( !threading_enabled, "ldap_pvt_thread_set_concurrency" );
	rc = ldap_int_thread_set_concurrency( n );
	ERROR_IF( rc, "ldap_pvt_thread_set_concurrency" );
	return rc;
}

int
ldap_pvt_thread_get_concurrency( void )
{
	int rc;
	ERROR_IF( !threading_enabled, "ldap_pvt_thread_get_concurrency" );
	rc = ldap_int_thread_get_concurrency();
	ERROR_IF( rc, "ldap_pvt_thread_get_concurrency" );
	return rc;
}

unsigned int
ldap_pvt_thread_sleep( unsigned int interval )
{
	int rc;
	ERROR_IF( !threading_enabled, "ldap_pvt_thread_sleep" );
	rc = ldap_int_thread_sleep( interval );
	ERROR_IF( rc, "ldap_pvt_thread_sleep" );
	return 0;
}

int
ldap_pvt_thread_create(
	ldap_pvt_thread_t *thread,
	int detach,
	void *(*start_routine)( void * ),
	void *arg )
{
	int rc;
	ERROR_IF( !threading_enabled, "ldap_pvt_thread_create" );
	if( !options_done )
		get_options();
	with_threads_lock({
		ldap_debug_thread_t *t;
		t = get_new_thread_info( "ldap_pvt_thread_create" );
		rc = ldap_int_thread_create( thread, detach, start_routine, arg );
		if( rc ) {
			ERROR( rc, "ldap_pvt_thread_create" );
			remove_thread_info( t, "ldap_pvt_thread_init" );
		} else {
			update_thread_info( t, thread, detach );
		}
	});
	if( rc == 0 ) {
		if( tracethreads ) {
			char buf[40];
			fprintf( stderr, "== Created thread %s%s ==\n",
				thread_name( buf, sizeof(buf), *thread ),
				detach ? " (detached)" : "" );
		}
		adjust_count( Idx_unexited_thread, +1 );
		if( !detach )
			adjust_count( Idx_unjoined_thread, +1 );
	}
	return rc;
}

void
ldap_pvt_thread_exit( void *retval )
{
#if 0 /* Detached threads may exit after ldap_debug_thread_destroy(). */
	ERROR_IF( !threading_enabled, "ldap_pvt_thread_exit" );
#endif
	adjust_count( Idx_unexited_thread, -1 );
	exiting_thread( "ldap_pvt_thread_exit" );
	ldap_int_thread_exit( retval );
}

int
ldap_pvt_thread_join( ldap_pvt_thread_t thread, void **thread_return )
{
	int rc;
	ldap_debug_thread_t *t;
	ERROR_IF( !threading_enabled, "ldap_pvt_thread_join" );
	if( tracethreads ) {
		char buf[40];
		fprintf( stderr, "== Joining thread %s ==\n",
			thread_name( buf, sizeof(buf), thread ) );
	}
	with_threads_lock(
		t = get_thread_info( thread, "ldap_pvt_thread_join" ) );
	rc = ldap_int_thread_join( thread, thread_return );
	if( rc ) {
		ERROR( rc, "ldap_pvt_thread_join" );
	} else {
		with_threads_lock(
			remove_thread_info( t, "ldap_pvt_thread_join" ) );
		adjust_count( Idx_unjoined_thread, -1 );
	}
	return rc;
}

int
ldap_pvt_thread_kill( ldap_pvt_thread_t thread, int signo )
{
	int rc;
	ERROR_IF( !threading_enabled, "ldap_pvt_thread_kill" );
	if( tracethreads ) {
		char buf[40];
		fprintf( stderr, "== Killing thread %s (sig %i) ==\n",
			thread_name( buf, sizeof(buf), thread ), signo );
	}
	rc = ldap_int_thread_kill( thread, signo );
	ERROR_IF( rc, "ldap_pvt_thread_kill" );
	return rc;
}

int
ldap_pvt_thread_yield( void )
{
	int rc;
	ERROR_IF( !threading_enabled, "ldap_pvt_thread_yield" );
	rc = ldap_int_thread_yield();
	ERROR_IF( rc, "ldap_pvt_thread_yield" );
	return rc;
}

ldap_pvt_thread_t
ldap_pvt_thread_self( void )
{
#if 0 /* Function is used by ch_free() via slap_sl_contxt() in slapd */
	ERROR_IF( !threading_enabled, "ldap_pvt_thread_self" );
#endif
	return ldap_int_thread_self();
}

int
ldap_pvt_thread_cond_init( ldap_pvt_thread_cond_t *cond )
{
	int rc;
	alloc_usage( &cond->usage, "ldap_pvt_thread_cond_init" );
	rc = ldap_int_thread_cond_init( WRAPPED( cond ) );
	if( rc ) {
		ERROR( rc, "ldap_pvt_thread_cond_init" );
		free_usage( &cond->usage, "ldap_pvt_thread_cond_init" );
	} else {
		adjust_count( Idx_cond, +1 );
	}
	return rc;
}

int
ldap_pvt_thread_cond_destroy( ldap_pvt_thread_cond_t *cond )
{
	int rc;
	check_usage( &cond->usage, "ldap_pvt_thread_cond_destroy" );
	rc = ldap_int_thread_cond_destroy( WRAPPED( cond ) );
	if( rc ) {
		ERROR( rc, "ldap_pvt_thread_cond_destroy" );
	} else {
		free_usage( &cond->usage, "ldap_pvt_thread_cond_destroy" );
		adjust_count( Idx_cond, -1 );
	}
	return rc;
}

int
ldap_pvt_thread_cond_signal( ldap_pvt_thread_cond_t *cond )
{
	int rc;
	check_usage( &cond->usage, "ldap_pvt_thread_cond_signal" );
	rc = ldap_int_thread_cond_signal( WRAPPED( cond ) );
	ERROR_IF( rc, "ldap_pvt_thread_cond_signal" );
	return rc;
}

int
ldap_pvt_thread_cond_broadcast( ldap_pvt_thread_cond_t *cond )
{
	int rc;
	check_usage( &cond->usage, "ldap_pvt_thread_cond_broadcast" );
	rc = ldap_int_thread_cond_broadcast( WRAPPED( cond ) );
	ERROR_IF( rc, "ldap_pvt_thread_cond_broadcast" );
	return rc;
}

int
ldap_pvt_thread_cond_wait(
	ldap_pvt_thread_cond_t *cond,
	ldap_pvt_thread_mutex_t *mutex )
{
	int rc;
	check_usage( &cond->usage, "ldap_pvt_thread_cond_wait:cond" );
	check_usage( &mutex->usage, "ldap_pvt_thread_cond_wait:mutex" );
	adjust_count( Idx_locked_mutex, -1 );
	rc = ldap_int_thread_cond_wait( WRAPPED( cond ), WRAPPED( mutex ) );
	adjust_count( Idx_locked_mutex, +1 );
	ERROR_IF( rc, "ldap_pvt_thread_cond_wait" );
	return rc;
}

int
ldap_pvt_thread_mutex_init( ldap_pvt_thread_mutex_t *mutex )
{
	int rc;
	alloc_usage( &mutex->usage, "ldap_pvt_thread_mutex_init" );
	rc = ldap_int_thread_mutex_init( WRAPPED( mutex ) );
	if( rc ) {
		ERROR( rc, "ldap_pvt_thread_mutex_init" );
		free_usage( &mutex->usage, "ldap_pvt_thread_mutex_init" );
	} else {
		adjust_count( Idx_mutex, +1 );
	}
	return rc;
}

int
ldap_pvt_thread_mutex_destroy( ldap_pvt_thread_mutex_t *mutex )
{
	int rc;
	check_usage( &mutex->usage, "ldap_pvt_thread_mutex_destroy" );
	rc = ldap_int_thread_mutex_destroy( WRAPPED( mutex ) );
	if( rc ) {
		ERROR( rc, "ldap_pvt_thread_mutex_destroy" );
	} else {
		free_usage( &mutex->usage, "ldap_pvt_thread_mutex_destroy" );
		adjust_count( Idx_mutex, -1 );
	}
	return rc;
}

int
ldap_pvt_thread_mutex_lock( ldap_pvt_thread_mutex_t *mutex )
{
	int rc;
	check_usage( &mutex->usage, "ldap_pvt_thread_mutex_lock" );
	rc = ldap_int_thread_mutex_lock( WRAPPED( mutex ) );
	if( rc ) {
		ERROR_IF( rc, "ldap_pvt_thread_mutex_lock" );
	} else {
		adjust_count( Idx_locked_mutex, +1 );
	}
	return rc;
}

int
ldap_pvt_thread_mutex_trylock( ldap_pvt_thread_mutex_t *mutex )
{
	int rc;
	check_usage( &mutex->usage, "ldap_pvt_thread_mutex_trylock" );
	rc = ldap_int_thread_mutex_trylock( WRAPPED( mutex ) );
	if( rc == 0 )
		adjust_count( Idx_locked_mutex, +1 );
	return rc;
}

int
ldap_pvt_thread_mutex_unlock( ldap_pvt_thread_mutex_t *mutex )
{
	int rc;
	check_usage( &mutex->usage, "ldap_pvt_thread_mutex_unlock" );
	rc = ldap_int_thread_mutex_unlock( WRAPPED( mutex ) );
	if( rc ) {
		ERROR_IF( rc, "ldap_pvt_thread_mutex_unlock" );
	} else {
		adjust_count( Idx_locked_mutex, -1 );
	}
	return rc;
}


/* Wrappers for LDAP_THREAD_RDWR_IMPLEMENTATION: */

int
ldap_pvt_thread_rdwr_init( ldap_pvt_thread_rdwr_t *rwlock )
{
	int rc;
	alloc_usage( &rwlock->usage, "ldap_pvt_thread_rdwr_init" );
	rc = ldap_int_thread_rdwr_init( WRAPPED( rwlock ) );
	if( rc ) {
		ERROR( rc, "ldap_pvt_thread_rdwr_init" );
		free_usage( &rwlock->usage, "ldap_pvt_thread_rdwr_init" );
	} else {
		adjust_count( Idx_rdwr, +1 );
	}
	return rc;
}

int
ldap_pvt_thread_rdwr_destroy( ldap_pvt_thread_rdwr_t *rwlock )
{
	int rc;
	check_usage( &rwlock->usage, "ldap_pvt_thread_rdwr_destroy" );
	rc = ldap_int_thread_rdwr_destroy( WRAPPED( rwlock ) );
	if( rc ) {
		ERROR( rc, "ldap_pvt_thread_rdwr_destroy" );
	} else {
		free_usage( &rwlock->usage, "ldap_pvt_thread_rdwr_destroy" );
		adjust_count( Idx_rdwr, -1 );
	}
	return rc;
}

int
ldap_pvt_thread_rdwr_rlock( ldap_pvt_thread_rdwr_t *rwlock )
{
	int rc;
	check_usage( &rwlock->usage, "ldap_pvt_thread_rdwr_rlock" );
	rc = ldap_int_thread_rdwr_rlock( WRAPPED( rwlock ) );
	ERROR_IF( rc, "ldap_pvt_thread_rdwr_rlock" );
	return rc;
}

int
ldap_pvt_thread_rdwr_rtrylock( ldap_pvt_thread_rdwr_t *rwlock )
{
	check_usage( &rwlock->usage, "ldap_pvt_thread_rdwr_rtrylock" );
	return ldap_int_thread_rdwr_rtrylock( WRAPPED( rwlock ) );
}

int
ldap_pvt_thread_rdwr_runlock( ldap_pvt_thread_rdwr_t *rwlock )
{
	int rc;
	check_usage( &rwlock->usage, "ldap_pvt_thread_rdwr_runlock" );
	rc = ldap_int_thread_rdwr_runlock( WRAPPED( rwlock ) );
	ERROR_IF( rc, "ldap_pvt_thread_rdwr_runlock" );
	return rc;
}

int
ldap_pvt_thread_rdwr_wlock( ldap_pvt_thread_rdwr_t *rwlock )
{
	int rc;
	check_usage( &rwlock->usage, "ldap_pvt_thread_rdwr_wlock" );
	rc = ldap_int_thread_rdwr_wlock( WRAPPED( rwlock ) );
	ERROR_IF( rc, "ldap_pvt_thread_rdwr_wlock" );
	return rc;
}

int
ldap_pvt_thread_rdwr_wtrylock( ldap_pvt_thread_rdwr_t *rwlock )
{
	check_usage( &rwlock->usage, "ldap_pvt_thread_rdwr_wtrylock" );
	return ldap_int_thread_rdwr_wtrylock( WRAPPED( rwlock ) );
}

int
ldap_pvt_thread_rdwr_wunlock( ldap_pvt_thread_rdwr_t *rwlock )
{
	int rc;
	check_usage( &rwlock->usage, "ldap_pvt_thread_rdwr_wunlock" );
	rc = ldap_int_thread_rdwr_wunlock( WRAPPED( rwlock ) );
	ERROR_IF( rc, "ldap_pvt_thread_rdwr_wunlock" );
	return rc;
}

#ifdef LDAP_RDWR_DEBUG

int
ldap_pvt_thread_rdwr_readers( ldap_pvt_thread_rdwr_t *rwlock )
{
	check_usage( &rwlock->usage, "ldap_pvt_thread_rdwr_readers" );
	return ldap_int_thread_rdwr_readers( WRAPPED( rwlock ) );
}

int
ldap_pvt_thread_rdwr_writers( ldap_pvt_thread_rdwr_t *rwlock )
{
	check_usage( &rwlock->usage, "ldap_pvt_thread_rdwr_writers" );
	return ldap_int_thread_rdwr_writers( WRAPPED( rwlock ) );
}

int
ldap_pvt_thread_rdwr_active( ldap_pvt_thread_rdwr_t *rwlock )
{
	check_usage( &rwlock->usage, "ldap_pvt_thread_rdwr_active" );
	return ldap_int_thread_rdwr_active( WRAPPED( rwlock ) );
}

#endif /* LDAP_RDWR_DEBUG */


/* Some wrappers for LDAP_THREAD_POOL_IMPLEMENTATION: */
#ifdef LDAP_THREAD_POOL_IMPLEMENTATION

int
ldap_pvt_thread_pool_init(
	ldap_pvt_thread_pool_t *tpool,
	int max_threads,
	int max_pending )
{
	int rc;
	ERROR_IF( !threading_enabled, "ldap_pvt_thread_pool_init" );
	rc = ldap_int_thread_pool_init( tpool, max_threads, max_pending );
	if( rc ) {
		ERROR( rc, "ldap_pvt_thread_pool_init" );
	} else {
		adjust_count( Idx_tpool, +1 );
	}
	return rc;
}

int
ldap_pvt_thread_pool_submit(
	ldap_pvt_thread_pool_t *tpool,
	ldap_pvt_thread_start_t *start_routine, void *arg )
{
	int rc, has_pool;
	ERROR_IF( !threading_enabled, "ldap_pvt_thread_pool_submit" );
	has_pool = (tpool && *tpool);
	rc = ldap_int_thread_pool_submit( tpool, start_routine, arg );
	if( has_pool )
		ERROR_IF( rc, "ldap_pvt_thread_pool_submit" );
	return rc;
}

int
ldap_pvt_thread_pool_maxthreads(
	ldap_pvt_thread_pool_t *tpool,
	int max_threads )
{
	ERROR_IF( !threading_enabled, "ldap_pvt_thread_pool_maxthreads" );
	return ldap_int_thread_pool_maxthreads(	tpool, max_threads );
}

int
ldap_pvt_thread_pool_backload( ldap_pvt_thread_pool_t *tpool )
{
	ERROR_IF( !threading_enabled, "ldap_pvt_thread_pool_backload" );
	return ldap_int_thread_pool_backload( tpool );
}

int
ldap_pvt_thread_pool_destroy( ldap_pvt_thread_pool_t *tpool, int run_pending )
{
	int rc, has_pool;
	ERROR_IF( !threading_enabled, "ldap_pvt_thread_pool_destroy" );
	has_pool = (tpool && *tpool);
	rc = ldap_int_thread_pool_destroy( tpool, run_pending );
	if( has_pool ) {
		if( rc ) {
			ERROR( rc, "ldap_pvt_thread_pool_destroy" );
		} else {
			adjust_count( Idx_tpool, -1 );
		}
	}
	return rc;
}

int
ldap_pvt_thread_pool_pause( ldap_pvt_thread_pool_t *tpool )
{
	ERROR_IF( !threading_enabled, "ldap_pvt_thread_pool_pause" );
	return ldap_int_thread_pool_pause( tpool );
}

int
ldap_pvt_thread_pool_resume( ldap_pvt_thread_pool_t *tpool )
{
	ERROR_IF( !threading_enabled, "ldap_pvt_thread_pool_resume" );
	return ldap_int_thread_pool_resume( tpool );
}

int
ldap_pvt_thread_pool_getkey(
	void *xctx,
	void *key,
	void **data,
	ldap_pvt_thread_pool_keyfree_t **kfree )
{
#if 0 /* Function is used by ch_free() via slap_sl_contxt() in slapd */
	ERROR_IF( !threading_enabled, "ldap_pvt_thread_pool_getkey" );
#endif
	return ldap_int_thread_pool_getkey( xctx, key, data, kfree );
}

int
ldap_pvt_thread_pool_setkey(
	void *xctx,
	void *key,
	void *data,
	ldap_pvt_thread_pool_keyfree_t *kfree )
{
	int rc;
	ERROR_IF( !threading_enabled, "ldap_pvt_thread_pool_setkey" );
	rc = ldap_int_thread_pool_setkey( xctx, key, data, kfree );
	ERROR_IF( rc, "ldap_pvt_thread_pool_setkey" );
	return rc;
}

void
ldap_pvt_thread_pool_purgekey( void *key )
{
	ERROR_IF( !threading_enabled, "ldap_pvt_thread_pool_purgekey" );
	ldap_int_thread_pool_purgekey( key );
}

void *
ldap_pvt_thread_pool_context( void )
{
#if 0 /* Function is used by ch_free() via slap_sl_contxt() in slapd */
	ERROR_IF( !threading_enabled, "ldap_pvt_thread_pool_context" );
#endif
	return ldap_int_thread_pool_context();
}

void
ldap_pvt_thread_pool_context_reset( void *vctx )
{
	ERROR_IF( !threading_enabled, "ldap_pvt_thread_pool_context_reset" );
	ldap_int_thread_pool_context_reset( vctx );
}

#endif /* LDAP_THREAD_POOL_IMPLEMENTATION */

#endif /* LDAP_THREAD_DEBUG */
