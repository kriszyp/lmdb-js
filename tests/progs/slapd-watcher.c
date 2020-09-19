/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1999-2020 The OpenLDAP Foundation.
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
/* ACKNOWLEDGEMENTS:
 * This work was initially developed by Howard Chu for inclusion
 * in OpenLDAP Software.
 */

#include "portable.h"

#include <stdio.h>

#include "ac/stdlib.h"
#include "ac/time.h"

#include "ac/ctype.h"
#include "ac/param.h"
#include "ac/socket.h"
#include "ac/string.h"
#include "ac/unistd.h"
#include "ac/wait.h"
#include "ac/time.h"

#include "ldap.h"
#include "lutil.h"
#include "lutil_ldap.h"
#include "lber_pvt.h"
#include "ldap_pvt.h"

#include "slapd-common.h"

#define	HAS_MONITOR	1
#define	HAS_BASE	2
#define	HAS_ENTRIES	4
#define	HAS_SREPL	8

#define	MONFILTER	"(objectClass=monitorOperation)"

#define SLAP_SYNC_SID_MAX	4095

typedef enum {
    SLAP_OP_BIND = 0,
    SLAP_OP_UNBIND,
    SLAP_OP_SEARCH,
    SLAP_OP_COMPARE,
    SLAP_OP_MODIFY,
    SLAP_OP_MODRDN,
    SLAP_OP_ADD,
    SLAP_OP_DELETE,
    SLAP_OP_ABANDON,
    SLAP_OP_EXTENDED,
    SLAP_OP_LAST
} slap_op_t;

struct opname {
	struct berval rdn;
	char *display;
} opnames[] = {
	{ BER_BVC("cn=Bind"),		"Bind" },
	{ BER_BVC("cn=Unbind"),		"Unbind" },
	{ BER_BVC("cn=Search"),		"Search" },
	{ BER_BVC("cn=Compare"),	"Compare" },
	{ BER_BVC("cn=Modify"),		"Modify" },
	{ BER_BVC("cn=Modrdn"),		"ModDN" },
	{ BER_BVC("cn=Add"),		"Add" },
	{ BER_BVC("cn=Delete"),		"Delete" },
	{ BER_BVC("cn=Abandon"),	"Abandon" },
	{ BER_BVC("cn=Extended"),	"Extended" },
	{ BER_BVNULL, NULL }
};

typedef struct counters {
	struct timeval time;
	unsigned long entries;
	unsigned long ops[SLAP_OP_LAST];
} counters;

typedef struct csns {
	int num;
	int *sids;
	struct berval *vals;
	struct timeval *tvs;
} csns;

typedef struct activity {
	time_t active;
	time_t idle;
	time_t maxlag;
	time_t lag;
} activity;

typedef struct server {
	char *url;
	LDAP *ld;
	int flags;
	int sid;
	struct berval monitorbase;
	char *monitorfilter;
	counters c_prev;
	counters c_curr;
	csns csn_prev;
	csns csn_curr;
	activity *times;
} server;

static void
usage( char *name, char opt )
{
	if ( opt ) {
		fprintf( stderr, "%s: unable to handle option \'%c\'\n\n",
			name, opt );
	}

	fprintf( stderr, "usage: %s "
		"[-D <dn> [ -w <passwd> ]] "
		"[-d <level>] "
		"[-O <SASL secprops>] "
		"[-R <SASL realm>] "
		"[-U <SASL authcid> [-X <SASL authzid>]] "
		"[-x | -Y <SASL mech>] "
		"[-i <interval>] "
		"[-s <sids>] "
		"[-b <baseDN> ] URI[...]\n",
		name );
	exit( EXIT_FAILURE );
}

struct berval base;
int interval = 10;
int numservers;
server *servers;
char *monfilter;

struct berval at_namingContexts = BER_BVC("namingContexts");
struct berval at_monitorOpCompleted = BER_BVC("monitorOpCompleted");
struct berval at_olmMDBEntries = BER_BVC("olmMDBEntries");
struct berval at_contextCSN = BER_BVC("contextCSN");

void timestamp(time_t *tt)
{
	struct tm *tm = gmtime(tt);
	printf("%d-%02d-%02d %02d:%02d:%02d",
		tm->tm_year + 1900, tm->tm_mon+1, tm->tm_mday,
		tm->tm_hour, tm->tm_min, tm->tm_sec);
}

void deltat(time_t *tt)
{
	struct tm *tm = gmtime(tt);
	if (tm->tm_mday-1)
		printf("%02d+", tm->tm_mday-1);
	printf("%02d:%02d:%02d",
		tm->tm_hour, tm->tm_min, tm->tm_sec);
}

static char *clearscreen = "\033[H\033[2J";

void display()
{
	int i, j;
	struct timeval now;
	struct tm *tm;
	time_t now_t;

	gettimeofday(&now, NULL);
	now_t = now.tv_sec;
	printf("%s", clearscreen);
	timestamp(&now_t);
	printf("\n");

	for (i=0; i<numservers; i++) {
		printf("%s\n", servers[i].url );
		if ( servers[i].flags & HAS_MONITOR ) {
			double rate;
			printf("      ");
			if ( servers[i].flags & HAS_ENTRIES )
				printf("  Entries  ");
			for ( j = 0; j<SLAP_OP_LAST; j++ )
				printf(" %9s ", opnames[j].display);
			printf("\n");
			printf("Num   ");
			if ( servers[i].flags & HAS_ENTRIES )
				printf("%10lu ", servers[i].c_curr.entries);
			for ( j = 0; j<SLAP_OP_LAST; j++ )
				printf("%10lu ", servers[i].c_curr.ops[j]);
			printf("\n");
			printf("Num/s ");
			if ( servers[i].flags & HAS_ENTRIES ) {
				rate = (servers[i].c_curr.entries - servers[i].c_prev.entries) / (double)interval;
				printf("%10.2f ", rate);
			}
			for ( j = 0; j<SLAP_OP_LAST; j++ ) {
				rate = (servers[i].c_curr.ops[j] - servers[i].c_prev.ops[j]) / (double)interval;
				printf("%10.2f ", rate);
			}
			printf("\n");
			servers[i].c_prev = servers[i].c_curr;
		}
		if ( servers[i].flags & HAS_BASE ) {
			int k;
			for (j=0; j<servers[i].csn_curr.num; j++) {
				int sid = servers[i].csn_curr.sids[j];
				printf("contextCSN: %s", servers[i].csn_curr.vals[j].bv_val );
				for (k=0; k<servers[i].csn_prev.num; k++)
					if (servers[i].csn_prev.sids[k] == sid)
						break;
				if (k == servers[i].csn_prev.num ||
					ber_bvcmp(&servers[i].csn_curr.vals[j],
							&servers[i].csn_prev.vals[k])) {
					/* a difference */
					if (servers[i].times[j].idle) {
						servers[i].times[j].idle = 0;
						servers[i].times[j].active = 0;
						servers[i].times[j].maxlag = 0;
						servers[i].times[j].lag = 0;
					}
					if (!servers[i].times[j].active)
						servers[i].times[j].active = now_t;
					printf(" actv@");
					timestamp(&servers[i].times[j].active);
				} else if ( servers[i].times[j].lag ) {
					printf(" actv@");
					timestamp(&servers[i].times[j].active);
				} else {
					if (servers[i].times[j].active && !servers[i].times[j].idle)
						servers[i].times[j].idle = now_t;
					if (servers[i].times[j].active) {
						printf(" actv@");
						timestamp(&servers[i].times[j].active);
						printf(", idle@");
						timestamp(&servers[i].times[j].idle);
					} else {
						printf(" idle");
					}
				}
				if (sid != servers[i].sid) {
					int l;
					for (k=0; k<numservers; k++) {
						if (servers[k].sid == sid) {
							for (l=0; l<servers[k].csn_curr.num; l++) {
								if (servers[k].csn_curr.sids[l] == sid ) {
									if (ber_bvcmp(&servers[i].csn_curr.vals[j],
										&servers[k].csn_curr.vals[l])) {
										struct timeval delta;
										int ahead = 0;
										time_t deltatt;
										delta.tv_sec = servers[k].csn_curr.tvs[l].tv_sec -
											servers[i].csn_curr.tvs[j].tv_sec;
										delta.tv_usec = servers[k].csn_curr.tvs[l].tv_usec -
											servers[i].csn_curr.tvs[j].tv_usec;
										if (delta.tv_usec < 0) {
											delta.tv_usec += 1000000;
											delta.tv_sec--;
										}
										if (delta.tv_sec < 0) {
											delta.tv_sec = -delta.tv_sec;
											ahead = 1;
										}
										deltatt = delta.tv_sec;
										if (ahead)
											printf(", ahead ");
										else
											printf(", behind ");
										deltat( &deltatt );
										servers[i].times[j].lag = deltatt;
										if (deltatt > servers[i].times[j].maxlag)
											servers[i].times[j].maxlag = deltatt;
									} else {
										servers[i].times[j].lag = 0;
										printf(", sync'd");
									}
									if (servers[i].times[j].maxlag) {
										printf(", max delta ");
										deltat( &servers[i].times[j].maxlag );
									}
								}
							}
						}
					}
				}
				printf("\n");
			}
			if ( servers[i].csn_prev.num != servers[i].csn_curr.num ) {
				servers[i].csn_prev.sids = realloc(servers[i].csn_prev.sids,
					servers[i].csn_curr.num * sizeof(int));
				servers[i].csn_prev.vals = realloc(servers[i].csn_prev.vals,
					servers[i].csn_curr.num * sizeof(struct berval));
				servers[i].csn_prev.tvs = realloc(servers[i].csn_prev.tvs,
					servers[i].csn_curr.num * sizeof(struct timeval));
				for (j=servers[i].csn_prev.num; j < servers[i].csn_curr.num; j++) {
					BER_BVZERO( &servers[i].csn_prev.vals[j] );
				}
				servers[i].csn_prev.num = servers[i].csn_curr.num;
				for (j=0; j<servers[i].csn_curr.num; j++)
					servers[i].csn_prev.sids[j] = servers[i].csn_curr.sids[j];
			}
			for (j=0; j<servers[i].csn_curr.num; j++)
				ber_bvreplace(&servers[i].csn_prev.vals[j],
					&servers[i].csn_curr.vals[j]);
		}
	}
}

void get_counters(
	LDAP *ld,
	LDAPMessage *e,
	BerElement *ber,
	counters *c )
{
	int i, rc;
	slap_op_t op = SLAP_OP_BIND;
	struct berval dn, bv, *bvals, **bvp = &bvals;

	do {
		int done = 0;
		for ( rc = ldap_get_attribute_ber( ld, e, ber, &bv, bvp );
			rc == LDAP_SUCCESS;
			rc = ldap_get_attribute_ber( ld, e, ber, &bv, bvp )) {

			if ( bv.bv_val == NULL ) break;
			if ( !ber_bvcmp( &bv, &at_monitorOpCompleted ) && bvals ) {
				c->ops[op] = strtoul( bvals[0].bv_val, NULL, 0 );
				done = 1;
			}
			if ( bvals ) {
				ber_memfree( bvals );
				bvals = NULL;
			}
			if ( done )
				break;
		}
		ber_free( ber, 0 );
		e = ldap_next_entry( ld, e );
		if ( !e )
			break;
		ldap_get_dn_ber( ld, e, &ber, &dn );
		op++;
	} while ( op < SLAP_OP_LAST );
}

int
slap_parse_csn_sid( struct berval *csnp )
{
	char *p, *q;
	struct berval csn = *csnp;
	int i;

	p = ber_bvchr( &csn, '#' );
	if ( !p )
		return -1;
	p++;
	csn.bv_len -= p - csn.bv_val;
	csn.bv_val = p;

	p = ber_bvchr( &csn, '#' );
	if ( !p )
		return -1;
	p++;
	csn.bv_len -= p - csn.bv_val;
	csn.bv_val = p;

	q = ber_bvchr( &csn, '#' );
	if ( !q )
		return -1;

	csn.bv_len = q - p;

	i = strtol( p, &q, 16 );
	if ( p == q || q != p + csn.bv_len || i < 0 || i > SLAP_SYNC_SID_MAX ) {
		i = -1;
	}

	return i;
}

void get_csns(
	csns *c,
	struct berval *bvs
)
{
	int i;

	for (i=0; bvs[i].bv_val; i++) ;
	if ( c->num != i ) {
		int j;
		c->vals = realloc( c->vals, i*sizeof(struct berval));
		c->sids = realloc( c->sids, i*sizeof(int));
		c->tvs = realloc( c->tvs, i*sizeof(struct timeval));
		for (j=c->num; j<i; j++) {
			BER_BVZERO( &c->vals[j] );
		}
	}
	c->num = i;
	for (i=0; i<c->num; i++) {
		struct lutil_tm tm;
		struct lutil_timet tt;
		ber_bvreplace( &c->vals[i], &bvs[i] );
		c->sids[i] = slap_parse_csn_sid( &bvs[i] );
		lutil_parsetime(c->vals[i].bv_val, &tm);
		c->tvs[i].tv_usec = tm.tm_usec;
		lutil_tm2time( &tm, &tt );
		c->tvs[i].tv_sec = tt.tt_sec;
	}
}

int
main( int argc, char **argv )
{
	int		i, rc, *msg1, *msg2;
	char **sids = NULL;
	struct tester_conn_args *config;

	config = tester_init( "slapd-watcher", TESTER_TESTER );
	config->authmethod = LDAP_AUTH_SIMPLE;

	while ( ( i = getopt( argc, argv, "D:O:R:U:X:Y:b:d:i:s:w:x" ) ) != EOF )
	{
		switch ( i ) {
		case 'b':		/* base DN for contextCSN lookups */
			ber_str2bv( optarg, 0, 0, &base );
			break;

		case 'i':
			interval = atoi(optarg);
			break;

		case 's':
			sids = ldap_str2charray( optarg, "," );
			break;

		default:
			if ( tester_config_opt( config, i, optarg ) == LDAP_SUCCESS )
				break;

			usage( argv[0], i );
			break;
		}
	}

	tester_config_finish( config );

	/* don't clear the screen if debug is enabled */
	if (debug)
		clearscreen = "\n\n";

	numservers = argc - optind;
	if ( !numservers )
		usage( argv[0], 0 );

	if ( sids ) {
		for (i=0; sids[i]; i++ );
		if ( i != numservers ) {
			fprintf(stderr, "Number of sids doesn't equal number of server URLs\n");
			exit( EXIT_FAILURE );
		}
	}

	argv += optind;
	argc -= optind;
	servers = calloc( numservers, sizeof(server));

	if ( base.bv_val ) {
		monfilter = "(|(entryDN:dnOneLevelMatch:=cn=Databases,cn=Monitor)" MONFILTER ")";
	} else {
		monfilter = MONFILTER;
	}

	if ( numservers > 1 ) {
		for ( i=0; i<numservers; i++ )
			if ( sids )
				servers[i].sid = atoi(sids[i]);
			else
				servers[i].sid = i+1;
	}

	for ( i = 0; i < numservers; i++ ) {
		int version = LDAP_VERSION3;
		servers[i].url = argv[i];
		config->uri = argv[i];
		tester_init_ld( &servers[i].ld, config, 0 );
		servers[i].flags = 0;
		{
			char *attrs[] = { at_namingContexts.bv_val, at_monitorOpCompleted.bv_val,
				at_olmMDBEntries.bv_val, NULL };
			LDAPMessage *res = NULL, *e = NULL;
			BerElement *ber = NULL;
			LDAP *ld = servers[i].ld;
			struct berval dn, bv, *bvals, **bvp = &bvals;
			int j;

			rc = ldap_search_ext_s( ld, "cn=monitor", LDAP_SCOPE_SUBTREE, monfilter,
				attrs, 0, NULL, NULL, NULL, LDAP_NO_LIMIT, &res );
			switch(rc) {
			case LDAP_SIZELIMIT_EXCEEDED:
			case LDAP_TIMELIMIT_EXCEEDED:
			case LDAP_SUCCESS:
				gettimeofday( &servers[i].c_curr.time, 0 );
				servers[i].flags |= HAS_MONITOR;
				for ( e = ldap_first_entry( ld, res ); e; e = ldap_next_entry( ld, e )) {
					ldap_get_dn_ber( ld, e, &ber, &dn );
					if ( !strncasecmp( dn.bv_val, "cn=Database", sizeof("cn=Database")-1 ) ||
						!strncasecmp( dn.bv_val, "cn=Frontend", sizeof("cn=Frontend")-1 )) {
						int matched = 0;
						for ( rc = ldap_get_attribute_ber( ld, e, ber, &bv, bvp );
							rc == LDAP_SUCCESS;
							rc = ldap_get_attribute_ber( ld, e, ber, &bv, bvp )) {
							if ( bv.bv_val == NULL ) break;
							if (!ber_bvcmp( &bv, &at_namingContexts ) && bvals ) {
								for (j=0; bvals[j].bv_val; j++) {
									if ( !ber_bvstrcasecmp( &base, &bvals[j] )) {
										matched = 1;
										break;
									}
								}
								if (!matched) {
									ber_memfree( bvals );
									bvals = NULL;
									break;
								}
							}
							if (!ber_bvcmp( &bv, &at_olmMDBEntries )) {
								ber_dupbv( &servers[i].monitorbase, &dn );
								servers[i].flags |= HAS_ENTRIES;
								servers[i].c_curr.entries = strtoul( bvals[0].bv_val, NULL, 0 );
							}
							ber_memfree( bvals );
							bvals = NULL;
						}
					} else if (!strncasecmp( dn.bv_val, opnames[0].rdn.bv_val,
						opnames[0].rdn.bv_len )) {
						get_counters( ld, e, ber, &servers[i].c_curr );
						break;
					}
					if ( ber )
						ber_free( ber, 0 );
				}
				break;

			case LDAP_NO_SUCH_OBJECT:
				/* no cn=monitor */
				break;

			default:
				tester_ldap_error( ld, "ldap_search_ext_s(cn=Monitor)", NULL );
				exit( EXIT_FAILURE );
			}
			ldap_msgfree( res );
			if ( base.bv_val ) {
				char *attr2[] = { at_contextCSN.bv_val, NULL };
				rc = ldap_search_ext_s( ld, base.bv_val, LDAP_SCOPE_BASE, "(objectClass=*)",
					attr2, 0, NULL, NULL, NULL, LDAP_NO_LIMIT, &res );
				switch(rc) {
				case LDAP_SUCCESS:
					e = ldap_first_entry( ld, res );
					if ( e ) {
						servers[i].flags |= HAS_BASE;
						ldap_get_dn_ber( ld, e, &ber, &dn );
						for ( rc = ldap_get_attribute_ber( ld, e, ber, &bv, bvp );
							rc == LDAP_SUCCESS;
							rc = ldap_get_attribute_ber( ld, e, ber, &bv, bvp )) {
							int done = 0;
							if ( bv.bv_val == NULL ) break;
							if ( bvals ) {
								if ( !ber_bvcmp( &bv, &at_contextCSN )) {
									get_csns( &servers[i].csn_curr, bvals );
									done = 1;
								}
								ber_memfree( bvals );
								bvals = NULL;
								if ( done )
									break;
							}
						}
					}
					ldap_msgfree( res );
					break;

				default:
					tester_ldap_error( ld, "ldap_search_ext_s(baseDN)", NULL );
					exit( EXIT_FAILURE );
				}
			}
		}
	}

	for (i=0; i<numservers; i++) {
		int j;
		if ( servers[i].flags & HAS_ENTRIES ) {
			int len = servers[i].monitorbase.bv_len + sizeof("(|(entryDN=)" MONFILTER ")");
			char *ptr = malloc(len);
			sprintf(ptr, "(|(entryDN=%s)" MONFILTER ")", servers[i].monitorbase.bv_val );
			servers[i].monitorfilter = ptr;
		} else if ( servers[i].flags & HAS_MONITOR ) {
			servers[i].monitorfilter = MONFILTER;
		}
		servers[i].c_prev = servers[i].c_curr;
		servers[i].csn_prev.num = servers[i].csn_curr.num;
		servers[i].csn_prev.sids = malloc(servers[i].csn_curr.num * sizeof(int));
		servers[i].csn_prev.vals = malloc(servers[i].csn_curr.num * sizeof(struct berval));
		for (j=0; j<servers[i].csn_curr.num; j++) {
			servers[i].csn_prev.sids[j] = servers[i].csn_curr.sids[j];
			ber_dupbv(&servers[i].csn_prev.vals[j],
				&servers[i].csn_curr.vals[j]);
		}
		servers[i].times = calloc( numservers, sizeof(activity));
	}

	msg1 = malloc( numservers * 2 * sizeof(int));
	msg2 = msg1 + numservers;

	display();

	for (;;) {
		LDAPMessage *res = NULL, *e = NULL;
		BerElement *ber = NULL;
		struct berval dn, bv, *bvals, **bvp = &bvals;
		LDAP *ld;

		sleep(interval);
		for (i=0; i<numservers; i++) {
			ld = servers[i].ld;
			if ( servers[i].flags & HAS_MONITOR ) {
				char *attrs[3] = { at_monitorOpCompleted.bv_val };
				if ( servers[i].flags & HAS_ENTRIES )
					attrs[1] = at_olmMDBEntries.bv_val;
				rc = ldap_search_ext( ld, "cn=monitor",
					LDAP_SCOPE_SUBTREE, servers[i].monitorfilter,
					attrs, 0, NULL, NULL, NULL, LDAP_NO_LIMIT, &msg1[i] );
				if ( rc != LDAP_SUCCESS ) {
					tester_ldap_error( ld, "ldap_search_ext(cn=Monitor)", NULL );
					exit( EXIT_FAILURE );
				}
			}
			if ( servers[i].flags & HAS_BASE ) {
				char *attrs[2] = { at_contextCSN.bv_val };
				rc = ldap_search_ext( ld, base.bv_val,
					LDAP_SCOPE_BASE, "(objectClass=*)",
					attrs, 0, NULL, NULL, NULL, LDAP_NO_LIMIT, &msg2[i] );
				if ( rc != LDAP_SUCCESS ) {
					tester_ldap_error( ld, "ldap_search_ext(baseDN)", NULL );
					exit( EXIT_FAILURE );
				}
			}
		}
		for (i=0; i<numservers; i++) {
			ld = servers[i].ld;
			if ( servers[i].flags & HAS_MONITOR ) {
				gettimeofday( &servers[i].c_curr.time, 0 );
				rc = ldap_result( ld, msg1[i], LDAP_MSG_ALL, NULL, &res );
				if ( rc < 0 ) {
					tester_ldap_error( ld, "ldap_result(cn=Monitor)", NULL );
					exit( EXIT_FAILURE );
				}
				for ( e = ldap_first_entry( ld, res ); e; e = ldap_next_entry( ld, e )) {
					ldap_get_dn_ber( ld, e, &ber, &dn );
					if ( !strncasecmp( dn.bv_val, "cn=Database", sizeof("cn=Database")-1 ) ||
						!strncasecmp( dn.bv_val, "cn=Frontend", sizeof("cn=Frontend")-1 )) {
						for ( rc = ldap_get_attribute_ber( ld, e, ber, &bv, bvp );
							rc == LDAP_SUCCESS;
							rc = ldap_get_attribute_ber( ld, e, ber, &bv, bvp )) {
							if ( bv.bv_val == NULL ) break;
							if ( !ber_bvcmp( &bv, &at_olmMDBEntries )) {
								if ( !BER_BVISNULL( &servers[i].monitorbase )) {
									servers[i].c_curr.entries = strtoul( bvals[0].bv_val, NULL, 0 );
								}
							}
							ber_memfree( bvals );
							bvals = NULL;
						}
					} else if (!strncasecmp( dn.bv_val, opnames[0].rdn.bv_val,
						opnames[0].rdn.bv_len )) {
						get_counters( ld, e, ber, &servers[i].c_curr );
						break;
					}
					if ( ber )
						ber_free( ber, 0 );
				}
				ldap_msgfree( res );
			}
			if ( servers[i].flags & HAS_BASE ) {
				rc = ldap_result( ld, msg2[i], LDAP_MSG_ALL, NULL, &res );
				if ( rc < 0 ) {
					tester_ldap_error( ld, "ldap_result(baseDN)", NULL );
					exit( EXIT_FAILURE );
				}
				e = ldap_first_entry( ld, res );
				if ( e ) {
					ldap_get_dn_ber( ld, e, &ber, &dn );
					for ( rc = ldap_get_attribute_ber( ld, e, ber, &bv, bvp );
						rc == LDAP_SUCCESS;
						rc = ldap_get_attribute_ber( ld, e, ber, &bv, bvp )) {
						int done = 0;
						if ( bv.bv_val == NULL ) break;
						if ( bvals ) {
							if ( !ber_bvcmp( &bv, &at_contextCSN )) {
								get_csns( &servers[i].csn_curr, bvals );
								done = 1;
							}
							ber_memfree( bvals );
							bvals = NULL;
							if ( done )
								break;
						}
					}
				}
				ldap_msgfree( res );
			}
		}
		display();
	}

	exit( EXIT_SUCCESS );
}

