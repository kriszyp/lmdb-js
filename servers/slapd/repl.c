/* repl.c - log modifications for replication purposes */
/* $OpenLDAP$ */
/*
 * Copyright 1998-2000 The OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include "portable.h"

#include <stdio.h>

#include <ac/string.h>
#include <ac/ctype.h>
#include <ac/socket.h>

#ifdef HAVE_SYS_FILE_H
#include <sys/file.h>
#endif

#include "slap.h"


void
replog(
    Backend	*be,
    Operation *op,
    char	*dn,
    void	*change
)
{
	Modifications	*ml;
	Entry	*e;
	struct replog_moddn *moddn;
	char *tmp;
	FILE	*fp, *lfp;
	int	len, i;

	if ( be->be_replogfile == NULL && replogfile == NULL ) {
		return;
	}

	ldap_pvt_thread_mutex_lock( &replog_mutex );
	if ( (fp = lock_fopen( be->be_replogfile ? be->be_replogfile :
	    replogfile, "a", &lfp )) == NULL ) {
		ldap_pvt_thread_mutex_unlock( &replog_mutex );
		return;
	}

	for ( i = 0; be->be_replica != NULL && be->be_replica[i] != NULL;
	    i++ ) {
		fprintf( fp, "replica: %s\n", be->be_replica[i] );
	}
	fprintf( fp, "time: %ld\n", (long) slap_get_time() );
	fprintf( fp, "dn: %s\n", dn );

	switch ( op->o_tag ) {
	case LDAP_REQ_MODIFY:
		fprintf( fp, "changetype: modify\n" );
		ml = change;
		for ( ; ml != NULL; ml = ml->sml_next ) {
			char *type;
#ifdef SLAPD_SCHEMA_NOT_COMPAT
			type = ml->sml_desc->ad_cname->bv_val;
#else
			type = ml->sml_type;
#endif
			switch ( ml->sml_op ) {
			case LDAP_MOD_ADD:
				fprintf( fp, "add: %s\n", type );
				break;

			case LDAP_MOD_DELETE:
				fprintf( fp, "delete: %s\n", type );
				break;

			case LDAP_MOD_REPLACE:
				fprintf( fp, "replace: %s\n", type );
				break;
			}

			for ( i = 0; ml->sml_bvalues != NULL &&
			    ml->sml_bvalues[i] != NULL; i++ ) {
				char	*buf, *bufp;

				len = strlen( type );
				len = LDIF_SIZE_NEEDED( len,
				    ml->sml_bvalues[i]->bv_len ) + 1;
				buf = (char *) ch_malloc( len );

				bufp = buf;
				ldif_sput( &bufp, LDIF_PUT_VALUE,
					type,
				    ml->sml_bvalues[i]->bv_val,
				    ml->sml_bvalues[i]->bv_len );
				*bufp = '\0';

				fputs( buf, fp );

				free( buf );
			}
			fprintf( fp, "-\n" );
		}
		break;

	case LDAP_REQ_ADD:
		e = change;
		fprintf( fp, "changetype: add\n" );
		ldap_pvt_thread_mutex_lock( &entry2str_mutex );
		tmp = entry2str( e, &len );
		while ( (tmp = strchr( tmp, '\n' )) != NULL ) {
			tmp++;
			if ( ! isspace( (unsigned char) *tmp ) )
				break;
		}
		fprintf( fp, "%s", tmp );
		ldap_pvt_thread_mutex_unlock( &entry2str_mutex );
		break;

	case LDAP_REQ_DELETE:
		fprintf( fp, "changetype: delete\n" );
		break;

	case LDAP_REQ_MODRDN:
		moddn = change;
		fprintf( fp, "changetype: modrdn\n" );
		fprintf( fp, "newrdn: %s\n", moddn->newrdn );
		fprintf( fp, "deleteoldrdn: %d\n", moddn->deloldrdn ? 1 : 0 );
		if( moddn->newsup != NULL ) {
			fprintf( fp, "newsuperior: %s\n", moddn->newsup );
		}
	}
	fprintf( fp, "\n" );

	lock_fclose( fp, lfp );
	ldap_pvt_thread_mutex_unlock( &replog_mutex );
}
