/* ldapmodify.c - generic program to modify or add entries using LDAP */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1998-2008 The OpenLDAP Foundation.
 * Portions Copyright 1998-2003 Kurt D. Zeilenga.
 * Portions Copyright 1998-2001 Net Boolean Incorporated.
 * Portions Copyright 2001-2003 IBM Corporation.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted only as authorized by the OpenLDAP
 * Public License.
 *
 * A copy of this license is available in the file LICENSE in the
 * top-level directory of the distribution or, alternatively, at
 * <http://www.OpenLDAP.org/license.html>.
 */
/* Portions Copyright (c) 1992-1996 Regents of the University of Michigan.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that this notice is preserved and that due credit is given
 * to the University of Michigan at Ann Arbor.  The name of the
 * University may not be used to endorse or promote products derived
 * from this software without specific prior written permission.  This
 * software is provided ``as is'' without express or implied warranty.
 */
/* ACKNOWLEDGEMENTS:
 * This work was originally developed by the University of Michigan
 * (as part of U-MICH LDAP).  Additional significant contributors
 * include:
 *   Kurt D. Zeilenga
 *   Norbert Klasen
 */

#include "portable.h"

#include <stdio.h>

#include <ac/stdlib.h>
#include <ac/ctype.h>
#include <ac/string.h>
#include <ac/unistd.h>
#include <ac/time.h>

#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

#ifdef HAVE_SYS_FILE_H
#include <sys/file.h>
#endif
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#include <ldap.h>

#include "lutil.h"
#include "lutil_ldap.h"
#include "ldif.h"
#include "ldap_defaults.h"
#include "ldap_log.h"
#include "ldap_pvt.h"

#include "common.h"


static int	ldapadd, force = 0;
static char *rejfile = NULL;
static LDAP	*ld = NULL;

#define LDAPMOD_MAXLINE		4096

/* strings found in replog/LDIF entries (mostly lifted from slurpd/slurp.h) */
#define T_VERSION_STR		"version"
#define T_REPLICA_STR		"replica"
#define T_DN_STR			"dn"
#define T_CONTROL_STR		"control"
#define T_CHANGETYPESTR		"changetype"
#define T_ADDCTSTR			"add"
#define T_MODIFYCTSTR		"modify"
#define T_DELETECTSTR		"delete"
#define T_MODRDNCTSTR		"modrdn"
#define T_MODDNCTSTR		"moddn"
#define T_RENAMECTSTR		"rename"
#define T_MODOPADDSTR		"add"
#define T_MODOPREPLACESTR	"replace"
#define T_MODOPDELETESTR	"delete"
#define T_MODOPINCREMENTSTR	"increment"
#define T_MODSEPSTR			"-"
#define T_NEWRDNSTR			"newrdn"
#define T_DELETEOLDRDNSTR	"deleteoldrdn"
#define T_NEWSUPSTR			"newsuperior"


static int process_ldif_rec LDAP_P(( char *rbuf, int count ));
static int parse_ldif_control LDAP_P(( char *line, LDAPControl ***pctrls ));
static void addmodifyop LDAP_P((
	LDAPMod ***pmodsp, int modop,
	const char *attr,
	struct berval *value ));
static int domodify LDAP_P((
	const char *dn,
	LDAPMod **pmods,
	LDAPControl **pctrls,
	int newentry ));
static int dodelete LDAP_P((
	const char *dn,
	LDAPControl **pctrls ));
static int dorename LDAP_P((
	const char *dn,
	const char *newrdn,
	const char *newsup,
	int deleteoldrdn,
	LDAPControl **pctrls ));
static int process_response(
	LDAP *ld,
	int msgid,
	const char *opstr,
	const char *dn );
static char *read_one_record LDAP_P(( FILE *fp ));

#ifdef LDAP_GROUP_TRANSACTION
static int txn = 0;
static int txnabort = 0;
#endif

void
usage( void )
{
	fprintf( stderr, _("Add or modify entries from an LDAP server\n\n"));
	fprintf( stderr, _("usage: %s [options]\n"), prog);
	fprintf( stderr, _("	The list of desired operations are read from stdin"
		" or from the file\n"));
	fprintf( stderr, _("	specified by \"-f file\".\n"));
	fprintf( stderr, _("Add or modify options:\n"));
	fprintf( stderr, _("  -a         add values (%s)\n"),
		(ldapadd ? _("default") : _("default is to replace")));
	fprintf( stderr, _("  -E [!]ext=extparam	modify extensions"
		" (! indicate s criticality)\n"));
#ifdef LDAP_GROUP_TRANSACTION
 	fprintf( stderr,
		_("             [!]txn                      (transaction)\n"));
#endif
	fprintf( stderr, _("  -F         force all changes records to be used\n"));
	fprintf( stderr, _("  -S file    write skipped modifications to `file'\n"));

	tool_common_usage();
	exit( EXIT_FAILURE );
}


const char options[] = "aE:FrS:"
	"cd:D:e:f:h:H:IkKMnO:p:P:QR:U:vVw:WxX:y:Y:Z";

int
handle_private_option( int i )
{
	char	*control, *cvalue;
	int		crit;

	switch ( i ) {
	case 'E': /* modify extensions */
		if( protocol == LDAP_VERSION2 ) {
			fprintf( stderr, _("%s: -E incompatible with LDAPv%d\n"),
				prog, protocol );
			exit( EXIT_FAILURE );
		}

		/* should be extended to support comma separated list of
		 *	[!]key[=value] parameters, e.g.  -E !foo,bar=567
		 */

		crit = 0;
		cvalue = NULL;
		if( optarg[0] == '!' ) {
			crit = 1;
			optarg++;
		}

		control = ber_strdup( optarg );
		if ( (cvalue = strchr( control, '=' )) != NULL ) {
			*cvalue++ = '\0';
		}

#ifdef LDAP_GROUP_TRANSACTION
		if( strcasecmp( control, "txn" ) == 0 ) {
			/* Transaction */
			if( txn ) {
				fprintf( stderr,
					_("txn control previously specified\n"));
				exit( EXIT_FAILURE );
			}
			if( cvalue != NULL ) {
				if( strcasecmp( cvalue, "abort" ) == 0 ) {
					txnabort=1;
				} else if( strcasecmp( cvalue, "commit" ) != 0 ) {
					fprintf( stderr, _("Invalid value for txn control, %s\n"),
						cvalue );
					exit( EXIT_FAILURE );
				}
			}

			txn = 1 + crit;
		} else
#endif
		{
			fprintf( stderr, _("Invalid modify extension name: %s\n"),
				control );
			usage();
		}

	case 'a':	/* add */
		ldapadd = 1;
		break;

	case 'F':	/* force all changes records to be used */
		force = 1;
		break;

	case 'r':	/* replace (obsolete) */
		break;

	case 'S':	/* skipped modifications to file */
		if( rejfile != NULL ) {
			fprintf( stderr, _("%s: -S previously specified\n"), prog );
			exit( EXIT_FAILURE );
		}
		rejfile = ber_strdup( optarg );
		break;

	default:
		return 0;
	}
	return 1;
}


int
main( int argc, char **argv )
{
#ifdef LDAP_GROUP_TRANSACTION
	BerElement *txnber;
	struct berval txnCookie = { 0, NULL };
#endif
	char		*rbuf, *start, *rejbuf = NULL;
	FILE		*fp, *rejfp;
	char		*matched_msg, *error_msg;
	int		rc, retval;
	int count, len;

	tool_init();
	prog = lutil_progname( "ldapmodify", argc, argv );

	/* strncmp instead of strcmp since NT binaries carry .exe extension */
	ldapadd = ( strncasecmp( prog, "ldapadd", sizeof("ldapadd")-1 ) == 0 );

	tool_args( argc, argv );

	if ( argc != optind ) usage();

	if ( rejfile != NULL ) {
		if (( rejfp = fopen( rejfile, "w" )) == NULL ) {
			perror( rejfile );
			return( EXIT_FAILURE );
		}
	} else {
		rejfp = NULL;
	}

	if ( infile != NULL ) {
		if (( fp = fopen( infile, "r" )) == NULL ) {
			perror( infile );
			return( EXIT_FAILURE );
		}
	} else {
		fp = stdin;
	}

	if ( debug ) ldif_debug = debug;

	ld = tool_conn_setup( not, 0 );

	if ( !not ) {
		if ( pw_file || want_bindpw ) {
			if ( pw_file ) {
				rc = lutil_get_filed_password( pw_file, &passwd );
				if( rc ) return EXIT_FAILURE;
			} else {
				passwd.bv_val = getpassphrase( _("Enter LDAP Password: ") );
				passwd.bv_len = passwd.bv_val ? strlen( passwd.bv_val ) : 0;
			}
		}
		tool_bind( ld );
	}

#ifdef LDAP_GROUP_TRANSACTION
	if( txn ) {
		struct berval *txnCookiep = &txnCookie;

		/* create transaction */
		rc = ldap_txn_create_s( ld, &txnCookiep, NULL, NULL );
		if( rc != LDAP_SUCCESS ) {
			ldap_perror( ld, "ldap_txn_create_s" );
			if( txn > 2 ) return EXIT_FAILURE;
			txn = 0;
		}
	}
#endif

	if ( assertion || authzid || manageDIT || manageDSAit || noop
#ifdef LDAP_GROUP_TRANSACTION
		|| txn
#endif
		|| preread || postread )
	{
		int i = 0;
		LDAPControl c[1];

#ifdef LDAP_GROUP_TRANSACTION
		if( txn ) {
			int err;
			txnber = ber_alloc_t( LBER_USE_DER );
			if( txnber == NULL ) return EXIT_FAILURE;

			err = ber_printf( txnber, "{o}", &txnCookie );
			if( err == -1 ) {
				ber_free( txnber, 1 );
				fprintf( stderr, _("txn grouping control encoding error!\n") );
				return EXIT_FAILURE;
			}

			err = ber_flatten2( txnber, &c[i].ldctl_value, 0 );
			if( err == -1 ) return EXIT_FAILURE;

			c[i].ldctl_oid = LDAP_CONTROL_GROUPING;
			c[i].ldctl_iscritical = 1;
			i++;
		}
#endif

		tool_server_controls( ld, c, i );
	}

	rc = 0;
	count = 0;
	retval = 0;
	while (( rc == 0 || contoper ) &&
		( rbuf = read_one_record( fp )) != NULL )
	{
		count++;

		start = rbuf;

		if ( rejfp ) {
			len = strlen( rbuf );
			if (( rejbuf = (char *)ber_memalloc( len+1 )) == NULL ) {
				perror( "malloc" );
				exit( EXIT_FAILURE );
			}
			memcpy( rejbuf, rbuf, len+1 );
		}

		rc = process_ldif_rec( start, count );

		if ( rc ) retval = rc;
		if ( rc && rejfp ) {
			fprintf(rejfp, _("# Error: %s (%d)"), ldap_err2string(rc), rc);

			matched_msg = NULL;
			ldap_get_option(ld, LDAP_OPT_MATCHED_DN, &matched_msg);
			if ( matched_msg != NULL ) {
				if ( *matched_msg != '\0' ) {
					fprintf( rejfp, _(", matched DN: %s"), matched_msg );
				}
				ldap_memfree( matched_msg );
			}

			error_msg = NULL;
			ldap_get_option(ld, LDAP_OPT_ERROR_STRING, &error_msg);
			if ( error_msg != NULL ) {
				if ( *error_msg != '\0' ) {
					fprintf( rejfp, _(", additional info: %s"), error_msg );
				}
				ldap_memfree( error_msg );
			}
			fprintf( rejfp, "\n%s\n", rejbuf );
		}

		if (rejfp) ber_memfree( rejbuf );
		ber_memfree( rbuf );
	}

#ifdef LDAP_GROUP_TRANSACTION
	if( txn ) {
		/* create transaction */
		rc = ldap_txn_end_s( ld, &txnCookie, !txnabort, NULL, NULL );
		if( rc != LDAP_SUCCESS ) {
			ldap_perror( ld, "ldap_txn_create_s" );
			if( txn > 2 ) return EXIT_FAILURE;
			txn = 0;
		}
	}
#endif

	if ( !not ) {
		tool_unbind( ld );
	}

	if ( rejfp != NULL ) {
		fclose( rejfp );
	}

	tool_destroy();
	return( retval );
}


static int
process_ldif_rec( char *rbuf, int count )
{
	char	*line, *dn, *type, *newrdn, *newsup, *p;
	int		rc, linenum, modop, replicaport;
	int		expect_modop, expect_sep, expect_ct, expect_newrdn, expect_newsup;
	int		expect_deleteoldrdn, deleteoldrdn;
	int		saw_replica, use_record, new_entry, delete_entry, got_all;
	LDAPMod	**pmods;
	int version;
	struct berval val;
	LDAPControl **pctrls;

	new_entry = ldapadd;

	rc = got_all = saw_replica = delete_entry = modop = expect_modop = 0;
	expect_deleteoldrdn = expect_newrdn = expect_newsup = 0;
	expect_sep = expect_ct = 0;
	linenum = 0;
	version = 0;
	deleteoldrdn = 1;
	use_record = force;
	pmods = NULL;
	pctrls = NULL;
	dn = newrdn = newsup = NULL;

	while ( rc == 0 && ( line = ldif_getline( &rbuf )) != NULL ) {
		++linenum;

		if ( expect_sep && strcasecmp( line, T_MODSEPSTR ) == 0 ) {
			expect_sep = 0;
			expect_ct = 1;
			continue;
		}
	
		if ( ldif_parse_line( line, &type, &val.bv_val, &val.bv_len ) < 0 ) {
			fprintf( stderr, _("%s: invalid format (line %d) entry: \"%s\"\n"),
				prog, linenum, dn == NULL ? "" : dn );
			rc = LDAP_PARAM_ERROR;
			break;
		}

		if ( dn == NULL ) {
			if ( !use_record && strcasecmp( type, T_REPLICA_STR ) == 0 ) {
				++saw_replica;
				if (( p = strchr( val.bv_val, ':' )) == NULL ) {
					replicaport = 0;
				} else {
					*p++ = '\0';
					if ( lutil_atoi( &replicaport, p ) != 0 ) {
						fprintf( stderr, _("%s: unable to parse replica port \"%s\" (line %d) entry: \"%s\"\n"),
							prog, p, linenum, dn == NULL ? "" : dn );
						rc = LDAP_PARAM_ERROR;
						break;
					}
				}
				if ( ldaphost != NULL &&
					strcasecmp( val.bv_val, ldaphost ) == 0 &&
					replicaport == ldapport )
				{
					use_record = 1;
				}
	    		} else if ( count == 1 && linenum == 1 && 
				strcasecmp( type, T_VERSION_STR ) == 0 )
			{
				int	v;
				if( val.bv_len == 0 || lutil_atoi( &v, val.bv_val) != 0 || v != 1 ) {
					fprintf( stderr,
						_("%s: invalid version %s, line %d (ignored)\n"),
						prog, val.bv_val, linenum );
				}
				version++;

			} else if ( strcasecmp( type, T_DN_STR ) == 0 ) {
				if (( dn = ber_strdup( val.bv_val )) == NULL ) {
					perror( "strdup" );
					exit( EXIT_FAILURE );
				}
				expect_ct = 1;
			}
			goto end_line;	/* skip all lines until we see "dn:" */
		}

		if ( expect_ct ) {
			/* Check for "control" tag after dn and before changetype. */
			if (strcasecmp(type, T_CONTROL_STR) == 0) {
				/* Parse and add it to the list of controls */
				rc = parse_ldif_control( line, &pctrls );
				if (rc != 0) {
					fprintf( stderr,
						_("%s: Error processing %s line, line %d: %s\n"),
						prog, T_CONTROL_STR, linenum, ldap_err2string(rc) );
				}
				goto end_line;
			}

			expect_ct = 0;
			if ( !use_record && saw_replica ) {
				printf(_("%s: skipping change record for entry: %s\n"),
					prog, dn);
				printf(_("\t(LDAP host/port does not match replica: lines)\n"));
				ber_memfree( dn );
				ber_memfree( type );
				ber_memfree( val.bv_val );
				return( 0 );
			}

			if ( strcasecmp( type, T_CHANGETYPESTR ) == 0 ) {
#ifdef LIBERAL_CHANGETYPE_MODOP
				/* trim trailing spaces (and log warning ...) */
				int icnt;
				for ( icnt = val.bv_len; --icnt > 0; ) {
					if ( !isspace( (unsigned char) val.bv_val[icnt] ) ) {
						break;
					}
				}

				if ( ++icnt != val.bv_len ) {
					fprintf( stderr, _("%s: illegal trailing space after"
						" \"%s: %s\" trimmed (line %d of entry \"%s\")\n"),
						prog, T_CHANGETYPESTR, val.bv_val, linenum, dn );
					val.bv_val[icnt] = '\0';
				}
#endif /* LIBERAL_CHANGETYPE_MODOP */

				if ( strcasecmp( val.bv_val, T_MODIFYCTSTR ) == 0 ) {
					new_entry = 0;
					expect_modop = 1;
				} else if ( strcasecmp( val.bv_val, T_ADDCTSTR ) == 0 ) {
					new_entry = 1;
				} else if ( strcasecmp( val.bv_val, T_MODRDNCTSTR ) == 0
					|| strcasecmp( val.bv_val, T_MODDNCTSTR ) == 0
					|| strcasecmp( val.bv_val, T_RENAMECTSTR ) == 0)
				{
					expect_newrdn = 1;
				} else if ( strcasecmp( val.bv_val, T_DELETECTSTR ) == 0 ) {
					got_all = delete_entry = 1;
				} else {
					fprintf( stderr,
						_("%s:  unknown %s \"%s\" (line %d of entry \"%s\")\n"),
						prog, T_CHANGETYPESTR, val.bv_val, linenum, dn );
					rc = LDAP_PARAM_ERROR;
				}
				goto end_line;
			} else if ( ldapadd ) {		/*  missing changetype => add */
				new_entry = 1;
				modop = LDAP_MOD_ADD;
			} else {
				expect_modop = 1;	/* missing changetype => modify */
			}
		}

		if ( expect_modop ) {
#ifdef LIBERAL_CHANGETYPE_MODOP
			/* trim trailing spaces (and log warning ...) */
		    int icnt;
		    for ( icnt = val.bv_len; --icnt > 0; ) {
				if ( !isspace( (unsigned char) val.bv_val[icnt] ) ) break;
			}
    
			if ( ++icnt != val.bv_len ) {
				fprintf( stderr, _("%s: illegal trailing space after"
					" \"%s: %s\" trimmed (line %d of entry \"%s\")\n"),
					prog, type, val.bv_val, linenum, dn );
				val.bv_val[icnt] = '\0';
			}
#endif /* LIBERAL_CHANGETYPE_MODOP */

			expect_modop = 0;
			expect_sep = 1;
			if ( strcasecmp( type, T_MODOPADDSTR ) == 0 ) {
				modop = LDAP_MOD_ADD;
				goto end_line;
			} else if ( strcasecmp( type, T_MODOPREPLACESTR ) == 0 ) {
				modop = LDAP_MOD_REPLACE;
				addmodifyop( &pmods, modop, val.bv_val, NULL );
				goto end_line;
			} else if ( strcasecmp( type, T_MODOPDELETESTR ) == 0 ) {
				modop = LDAP_MOD_DELETE;
				addmodifyop( &pmods, modop, val.bv_val, NULL );
				goto end_line;
			} else if ( strcasecmp( type, T_MODOPINCREMENTSTR ) == 0 ) {
				modop = LDAP_MOD_INCREMENT;
				addmodifyop( &pmods, modop, val.bv_val, NULL );
				goto end_line;
			} else {	/* no modify op:  use default */
				modop = ldapadd ? LDAP_MOD_ADD : LDAP_MOD_REPLACE;
			}
		}

		if ( expect_newrdn ) {
			if ( strcasecmp( type, T_NEWRDNSTR ) == 0 ) {
				if (( newrdn = ber_strdup( val.bv_val )) == NULL ) {
					perror( "strdup" );
					exit( EXIT_FAILURE );
				}
				expect_deleteoldrdn = 1;
				expect_newrdn = 0;
			} else {
				fprintf( stderr, _("%s: expecting \"%s:\" but saw"
					" \"%s:\" (line %d of entry \"%s\")\n"),
					prog, T_NEWRDNSTR, type, linenum, dn );
				rc = LDAP_PARAM_ERROR;
			}
		} else if ( expect_deleteoldrdn ) {
			if ( strcasecmp( type, T_DELETEOLDRDNSTR ) == 0 ) {
				deleteoldrdn = ( *val.bv_val == '0' ) ? 0 : 1;
				expect_deleteoldrdn = 0;
				expect_newsup = 1;
				got_all = 1;
			} else {
				fprintf( stderr, _("%s: expecting \"%s:\" but saw"
					" \"%s:\" (line %d of entry \"%s\")\n"),
					prog, T_DELETEOLDRDNSTR, type, linenum, dn );
				rc = LDAP_PARAM_ERROR;
			}
		} else if ( expect_newsup ) {
			if ( strcasecmp( type, T_NEWSUPSTR ) == 0 ) {
				if (( newsup = ber_strdup( val.bv_val )) == NULL ) {
					perror( "strdup" );
					exit( EXIT_FAILURE );
				}
				expect_newsup = 0;
			} else {
				fprintf( stderr, _("%s: expecting \"%s:\" but saw"
					" \"%s:\" (line %d of entry \"%s\")\n"),
					prog, T_NEWSUPSTR, type, linenum, dn );
				rc = LDAP_PARAM_ERROR;
			}
		} else if ( got_all ) {
			fprintf( stderr,
				_("%s: extra lines at end (line %d of entry \"%s\")\n"),
				prog, linenum, dn );
			rc = LDAP_PARAM_ERROR;
		} else {
			if ( new_entry && strcasecmp( type, T_DN_STR ) == 0 ) {
				fprintf( stderr, _("%s: attributeDescription \"%s\":"
					" (possible missing newline"
						" after line %d of entry \"%s\"?)\n"),
					prog, type, linenum - 1, dn );
			}
			addmodifyop( &pmods, modop, type, &val );
		}

end_line:
		ber_memfree( type );
		ber_memfree( val.bv_val );
	}

	if( linenum == 0 ) {
		return 0;
	}

	if( version && linenum == 1 ) {
		return 0;
	}

	/* If default controls are set (as with -M option) and controls are
	   specified in the LDIF file, we must add the default controls to
	   the list of controls sent with the ldap operation.
	*/
	if ( rc == 0 ) {
		if (pctrls) {
			LDAPControl **defctrls = NULL;   /* Default server controls */
			LDAPControl **newctrls = NULL;
			ldap_get_option(ld, LDAP_OPT_SERVER_CONTROLS, &defctrls);
			if (defctrls) {
				int npc=0;                       /* Num of LDIF controls */
				int ndefc=0;                     /* Num of default controls */
				while (pctrls[npc]) npc++;       /* Count LDIF controls */
				while (defctrls[ndefc]) ndefc++; /* Count default controls */
				newctrls = ber_memrealloc(pctrls,
					(npc+ndefc+1)*sizeof(LDAPControl*));

				if (newctrls == NULL) {
					rc = LDAP_NO_MEMORY;
				} else {
					int i;
					pctrls = newctrls;
					for (i=npc; i<npc+ndefc; i++) {
						pctrls[i] = ldap_control_dup(defctrls[i-npc]);
						if (pctrls[i] == NULL) {
							rc = LDAP_NO_MEMORY;
							break;
						}
					}
					pctrls[npc+ndefc] = NULL;
				}
				ldap_controls_free(defctrls);  /* Must be freed by library */
			}
		}
	}


	if ( rc == 0 ) {
		if ( delete_entry ) {
			rc = dodelete( dn, pctrls );
		} else if ( newrdn != NULL ) {
			rc = dorename( dn, newrdn, newsup, deleteoldrdn, pctrls );
		} else {
			rc = domodify( dn, pmods, pctrls, new_entry );
		}

		if ( rc == LDAP_SUCCESS ) {
			rc = 0;
		}
	}

	if ( dn != NULL ) {
		ber_memfree( dn );
	}
	if ( newrdn != NULL ) {
		ber_memfree( newrdn );
	}
	if ( newsup != NULL ) {
		ber_memfree( newsup );
	}
	if ( pmods != NULL ) {
		ldap_mods_free( pmods, 1 );
	}
    if (pctrls != NULL) {
    	ldap_controls_free( pctrls );
	}

	return( rc );
}

/* Parse an LDIF control line of the form
      control:  oid  [true/false]  [: value]              or
      control:  oid  [true/false]  [:: base64-value]      or
      control:  oid  [true/false]  [:< url]
   The control is added to the list of controls in *ppctrls.
*/      
static int
parse_ldif_control(
	char *line, 
	LDAPControl ***ppctrls )
{
	char *oid = NULL;
	int criticality = 0;   /* Default is false if not present */
	char *type=NULL;
	char *val = NULL;
	ber_len_t value_len = 0;
	int i, rc=0;
	char *s, *oidStart, *pcolon;
	LDAPControl *newctrl = NULL;
	LDAPControl **pctrls = NULL;

	if (ppctrls) pctrls = *ppctrls;
	s = line + strlen(T_CONTROL_STR);  /* Skip over "control" */
	pcolon = s;                        /* Save this position for later */
	if (*s++ != ':') {                 /* Make sure colon follows */
		return ( LDAP_PARAM_ERROR );
	}
	while (*s && isspace((unsigned char)*s)) {
		s++;                           /* Skip white space before OID */
	}

	/* OID should come next. Validate and extract it. */
	if (*s == 0) return ( LDAP_PARAM_ERROR );
	oidStart = s;
	while (isdigit((unsigned char)*s) || *s == '.') {
		s++;                           /* OID should be digits or . */
	}
	if (s == oidStart) { 
		return ( LDAP_PARAM_ERROR );   /* OID was not present */
	}
	if (*s) {                          /* End of OID should be space or NULL */
		if (!isspace((unsigned char)*s)) {
			return ( LDAP_PARAM_ERROR ); /* else OID contained invalid chars */
		}
		*s++ = 0;                    /* Replace space with null to terminate */
	}

	oid = ber_strdup(oidStart);
	if (oid == NULL) return ( LDAP_NO_MEMORY );

	/* Optional Criticality field is next. */
	while (*s && isspace((unsigned char)*s)) {
		s++;                         /* Skip white space before criticality */
	}
	if (strncasecmp(s, "true", 4) == 0) {
		criticality = 1;
		s += 4;
	} 
	else if (strncasecmp(s, "false", 5) == 0) {
		criticality = 0;
		s += 5;
	}

	/* Optional value field is next */
	while (*s && isspace((unsigned char)*s)) {
		s++;                         /* Skip white space before value */
	}
	if (*s) {
		if (*s != ':') {           /* If value is present, must start with : */
			rc = LDAP_PARAM_ERROR;
			goto cleanup;
		}

		/* Shift value down over OID and criticality so it's in the form
		     control: value
		     control:: base64-value
		     control:< url
		   Then we can use ldif_parse_line to extract and decode the value
		*/
		while ( (*pcolon++ = *s++) != 0) {   /* Shift value */
			/* EMPTY */;
		}
		rc = ldif_parse_line(line, &type, &val, &value_len);
		if (type)  ber_memfree(type);   /* Don't need this field*/
		if (rc < 0) {
			rc = LDAP_PARAM_ERROR;
			goto cleanup;
		}
    }

	/* Create a new LDAPControl structure. */
	newctrl = (LDAPControl *)ber_memalloc(sizeof(LDAPControl));
	if ( newctrl == NULL ) {
		rc = LDAP_NO_MEMORY;
		goto cleanup;
	}
	newctrl->ldctl_oid = oid;
	oid = NULL;
	newctrl->ldctl_iscritical = criticality;
	newctrl->ldctl_value.bv_len = value_len;
	newctrl->ldctl_value.bv_val = val;
	val = NULL;

	/* Add the new control to the passed-in list of controls. */
	i = 0;
	if (pctrls) {
		while ( pctrls[i] ) {    /* Count the # of controls passed in */
			i++;
		}
	}
	/* Allocate 1 more slot for the new control and 1 for the NULL. */
	pctrls = (LDAPControl **) ber_memrealloc(pctrls,
		(i+2)*(sizeof(LDAPControl *)));
	if (pctrls == NULL) {
		rc = LDAP_NO_MEMORY;
		goto cleanup;
	}
	pctrls[i] = newctrl;
	newctrl = NULL;
	pctrls[i+1] = NULL;
	*ppctrls = pctrls;

cleanup:
	if (newctrl) {
		if (newctrl->ldctl_oid) ber_memfree(newctrl->ldctl_oid);
		if (newctrl->ldctl_value.bv_val) {
			ber_memfree(newctrl->ldctl_value.bv_val);
		}
		ber_memfree(newctrl);
	}
	if (val) ber_memfree(val);
	if (oid) ber_memfree(oid);

	return( rc );
}


static void
addmodifyop(
	LDAPMod ***pmodsp,
	int modop,
	const char *attr,
	struct berval *val )
{
	LDAPMod		**pmods;
	int			i, j;

	pmods = *pmodsp;
	modop |= LDAP_MOD_BVALUES;

	i = 0;
	if ( pmods != NULL ) {
		for ( ; pmods[ i ] != NULL; ++i ) {
			if ( strcasecmp( pmods[ i ]->mod_type, attr ) == 0 &&
				pmods[ i ]->mod_op == modop )
			{
				break;
			}
		}
	}

	if ( pmods == NULL || pmods[ i ] == NULL ) {
		if (( pmods = (LDAPMod **)ber_memrealloc( pmods, (i + 2) *
			sizeof( LDAPMod * ))) == NULL )
		{
			perror( "realloc" );
			exit( EXIT_FAILURE );
		}

		*pmodsp = pmods;
		pmods[ i + 1 ] = NULL;

		pmods[ i ] = (LDAPMod *)ber_memcalloc( 1, sizeof( LDAPMod ));
		if ( pmods[ i ] == NULL ) {
			perror( "calloc" );
			exit( EXIT_FAILURE );
		}

		pmods[ i ]->mod_op = modop;
		pmods[ i ]->mod_type = ber_strdup( attr );
		if ( pmods[ i ]->mod_type == NULL ) {
			perror( "strdup" );
			exit( EXIT_FAILURE );
		}
	}

	if ( val != NULL ) {
		j = 0;
		if ( pmods[ i ]->mod_bvalues != NULL ) {
			for ( ; pmods[ i ]->mod_bvalues[ j ] != NULL; ++j ) {
				/* Empty */;
			}
		}

		pmods[ i ]->mod_bvalues = (struct berval **) ber_memrealloc(
			pmods[ i ]->mod_bvalues, (j + 2) * sizeof( struct berval * ));
		if ( pmods[ i ]->mod_bvalues == NULL ) {
			perror( "ber_realloc" );
			exit( EXIT_FAILURE );
		}

		pmods[ i ]->mod_bvalues[ j + 1 ] = NULL;
		pmods[ i ]->mod_bvalues[ j ] = ber_bvdup( val );
		if ( pmods[ i ]->mod_bvalues[ j ] == NULL ) {
			perror( "ber_bvdup" );
			exit( EXIT_FAILURE );
		}
	}
}


static int
domodify(
	const char *dn,
	LDAPMod **pmods,
	LDAPControl **pctrls,
	int newentry )
{
	int			rc, i, j, k, notascii, op;
	struct berval	*bvp;

	if ( dn == NULL ) {
		fprintf( stderr, _("%s: no DN specified\n"), prog );
		return( LDAP_PARAM_ERROR );
	}

	if ( pmods == NULL ) {
		/* implement "touch" (empty sequence)
		 * modify operation (note that there
		 * is no symmetry with the UNIX command,
		 * since \"touch\" on a non-existent entry
		 * will fail)*/
		printf( "warning: no attributes to %sadd (entry=\"%s\")\n",
			newentry ? "" : "change or ", dn );

	} else {
		for ( i = 0; pmods[ i ] != NULL; ++i ) {
			op = pmods[ i ]->mod_op & ~LDAP_MOD_BVALUES;
			if( op == LDAP_MOD_ADD && ( pmods[i]->mod_bvalues == NULL )) {
				fprintf( stderr,
					_("%s: attribute \"%s\" has no values (entry=\"%s\")\n"),
					prog, pmods[i]->mod_type, dn );
				return LDAP_PARAM_ERROR;
			}
		}

		if ( verbose ) {
			for ( i = 0; pmods[ i ] != NULL; ++i ) {
				op = pmods[ i ]->mod_op & ~LDAP_MOD_BVALUES;
				printf( "%s %s:\n",
					op == LDAP_MOD_REPLACE ? _("replace") :
						op == LDAP_MOD_ADD ?  _("add") :
							op == LDAP_MOD_INCREMENT ?  _("increment") :
								op == LDAP_MOD_DELETE ?  _("delete") :
									_("unknown"),
					pmods[ i ]->mod_type );
	
				if ( pmods[ i ]->mod_bvalues != NULL ) {
					for ( j = 0; pmods[ i ]->mod_bvalues[ j ] != NULL; ++j ) {
						bvp = pmods[ i ]->mod_bvalues[ j ];
						notascii = 0;
						for ( k = 0; (unsigned long) k < bvp->bv_len; ++k ) {
							if ( !isascii( bvp->bv_val[ k ] )) {
								notascii = 1;
								break;
							}
						}
						if ( notascii ) {
							printf( _("\tNOT ASCII (%ld bytes)\n"), bvp->bv_len );
						} else {
							printf( "\t%s\n", bvp->bv_val );
						}
					}
				}
			}
		}
	}

	if ( newentry ) {
		printf( "%sadding new entry \"%s\"\n", not ? "!" : "", dn );
	} else {
		printf( "%smodifying entry \"%s\"\n", not ? "!" : "", dn );
	}

	if ( !not ) {
		int	msgid;
		if ( newentry ) {
			rc = ldap_add_ext( ld, dn, pmods, pctrls, NULL, &msgid );
		} else {
			rc = ldap_modify_ext( ld, dn, pmods, pctrls, NULL, &msgid );
		}

		if ( rc != LDAP_SUCCESS ) {
			/* print error message about failed update including DN */
			fprintf( stderr, _("%s: update failed: %s\n"), prog, dn );
			ldap_perror( ld, newentry ? "ldap_add" : "ldap_modify" );
			goto done;
		} else if ( verbose ) {
			printf( _("modify complete\n") );
		}

		rc = process_response( ld, msgid,
			newentry ? "ldap_add" : "ldap_modify", dn );

	} else {
		rc = LDAP_SUCCESS;
	}

done:
	putchar( '\n' );
	return rc;
}


static int
dodelete(
	const char *dn,
	LDAPControl **pctrls )
{
	int	rc;
	int msgid;

	printf( _("%sdeleting entry \"%s\"\n"), not ? "!" : "", dn );
	if ( !not ) {
		rc = ldap_delete_ext( ld, dn, pctrls, NULL, &msgid );
		if ( rc != LDAP_SUCCESS ) {
			fprintf( stderr, _("%s: delete failed: %s\n"), prog, dn );
			ldap_perror( ld, "ldap_delete" );
			goto done;
		} else if ( verbose ) {
			printf( _("delete complete") );
		}

		rc = process_response( ld, msgid, "ldap_delete", dn );

	} else {
		rc = LDAP_SUCCESS;
	}

done:
	putchar( '\n' );
	return( rc );
}


static int
dorename(
	const char *dn,
	const char *newrdn,
	const char* newsup,
	int deleteoldrdn,
	LDAPControl **pctrls )
{
	int	rc;
	int msgid;

	printf( _("%smodifying rdn of entry \"%s\"\n"), not ? "!" : "", dn );
	if ( verbose ) {
		printf( _("\tnew RDN: \"%s\" (%skeep existing values)\n"),
			newrdn, deleteoldrdn ? _("do not ") : "" );
	}
	if ( !not ) {
		rc = ldap_rename( ld, dn, newrdn, newsup, deleteoldrdn,
			pctrls, NULL, &msgid );
		if ( rc != LDAP_SUCCESS ) {
			fprintf( stderr, _("%s: rename failed: %s\n"), prog, dn );
			ldap_perror( ld, "ldap_rename" );
			goto done;
		} else {
			printf( _("rename completed\n") );
		}

		rc = process_response( ld, msgid, "ldap_rename", dn );

	} else {
		rc = LDAP_SUCCESS;
	}

done:
	putchar( '\n' );
	return( rc );
}

static int process_response(
	LDAP *ld,
	int msgid,
	const char *opstr,
	const char *dn )
{
	LDAPMessage	*res;
	int		rc = LDAP_OTHER;
	struct timeval	tv = { 0, 0 };

	for ( ; ; ) {
		tv.tv_sec = 0;
		tv.tv_usec = 100000;

		rc = ldap_result( ld, msgid,
#ifdef LDAP_GROUP_TRANSACTION
			txn ? 0 : 1,
#else
			1,
#endif
			&tv, &res );
		if ( tool_check_abandon( ld, msgid ) ) {
			return LDAP_CANCELLED;
		}

		if ( rc == -1 ) {
			ldap_get_option( ld, LDAP_OPT_ERROR_NUMBER, &rc );
			tool_perror( "ldap_result", rc, NULL, NULL, NULL, NULL );
			return rc;
		}

		if ( rc != 0 ) {
			break;
		}
	}

	if ( ldap_msgtype( res ) != LDAP_RES_INTERMEDIATE ) {
		int code;
		char *matcheddn = NULL, *text = NULL, **refs = NULL;
		LDAPControl **ctrls = NULL;
		rc = ldap_parse_result( ld, res, &code, &matcheddn, &text, &refs, &ctrls, 1 );

		if ( rc != LDAP_SUCCESS ) {
			fprintf( stderr, "%s: ldap_parse_result: %s (%d)\n",
				prog, ldap_err2string( rc ), rc );
			return rc;
		}

		if ( code != LDAP_SUCCESS ) {
			tool_perror( prog, code, NULL, matcheddn, text, refs );
		} else if ( verbose && 
			((matcheddn && *matcheddn) || (text && *text) || (refs && *refs) ))
		{
			printf( _("Delete Result: %s (%d)\n"),
				ldap_err2string( code ), code );

			if ( text && *text ) {
				printf( _("Additional info: %s\n"), text );
			}

			if ( matcheddn && *matcheddn ) {
				printf( _("Matched DN: %s\n"), matcheddn );
			}

			if ( refs ) {
				int i;
				for( i=0; refs[i]; i++ ) {
					printf(_("Referral: %s\n"), refs[i] );
				}
			}
		}

		if (ctrls) {
			tool_print_ctrls( ld, ctrls );
			ldap_controls_free( ctrls );
		}

		ber_memfree( text );
		ber_memfree( matcheddn );
		ber_memvfree( (void **) refs );

		return code;
	}

#ifdef LDAP_GROUP_TRANSACTION
	/* assume (successful) transaction intermediate response */
	return LDAP_SUCCESS;

#else
	/* intermediate response? */
	return LDAP_DECODING_ERROR;
#endif
}

static char *
read_one_record( FILE *fp )
{
	char        *buf, line[ LDAPMOD_MAXLINE ];
	int		lcur, lmax;

	lcur = lmax = 0;
	buf = NULL;

	while ( fgets( line, sizeof(line), fp ) != NULL ) {
		int len = strlen( line );

		if( len < 2 || ( len == 2 && *line == '\r' )) {
			if( buf == NULL ) {
				continue;
			} else {
				break;
			}
		}

		if ( lcur + len + 1 > lmax ) {
			lmax = LDAPMOD_MAXLINE
				* (( lcur + len + 1 ) / LDAPMOD_MAXLINE + 1 );

			if (( buf = (char *)ber_memrealloc( buf, lmax )) == NULL ) {
				perror( "realloc" );
				exit( EXIT_FAILURE );
			}
		}

		strcpy( buf + lcur, line );
		lcur += len;
	}

	return( buf );
}


