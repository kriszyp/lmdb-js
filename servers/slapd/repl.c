/* repl.c - log modifications for replication purposes */

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/file.h>
#include <sys/socket.h>
#include "slap.h"

extern pthread_mutex_t	replog_mutex;
extern pthread_mutex_t	entry2str_mutex;
extern time_t		currenttime;
extern char		*replogfile;

extern FILE	*lock_fopen();
extern int	lock_fclose();
extern char	*ch_malloc();
extern char	*entry2str();

void
replog(
    Backend	*be,
    int		optype,
    char	*dn,
    void	*change,
    int		flag
)
{
	LDAPMod	*mods;
	Entry	*e;
	char	*newrdn, *tmp;
	int	deleteoldrdn;
	FILE	*fp, *lfp;
	int	len, i;

	if ( be->be_replogfile == NULL && replogfile == NULL ) {
		return;
	}

	pthread_mutex_lock( &replog_mutex );
	if ( (fp = lock_fopen( be->be_replogfile ? be->be_replogfile :
	    replogfile, "a", &lfp )) == NULL ) {
		pthread_mutex_unlock( &replog_mutex );
		return;
	}

	for ( i = 0; be->be_replica != NULL && be->be_replica[i] != NULL;
	    i++ ) {
		fprintf( fp, "replica: %s\n", be->be_replica[i] );
	}
	fprintf( fp, "time: %ld\n", currenttime );
	fprintf( fp, "dn: %s\n", dn );

	switch ( optype ) {
	case LDAP_REQ_MODIFY:
		fprintf( fp, "changetype: modify\n" );
		mods = change;
		for ( ; mods != NULL; mods = mods->mod_next ) {
			switch ( mods->mod_op & ~LDAP_MOD_BVALUES ) {
			case LDAP_MOD_ADD:
				fprintf( fp, "add: %s\n", mods->mod_type );
				break;

			case LDAP_MOD_DELETE:
				fprintf( fp, "delete: %s\n", mods->mod_type );
				break;

			case LDAP_MOD_REPLACE:
				fprintf( fp, "replace: %s\n", mods->mod_type );
				break;
			}

			for ( i = 0; mods->mod_bvalues != NULL &&
			    mods->mod_bvalues[i] != NULL; i++ ) {
				char	*buf, *bufp;

				len = strlen( mods->mod_type );
				len = LDIF_SIZE_NEEDED( len,
				    mods->mod_bvalues[i]->bv_len ) + 1;
				buf = ch_malloc( len );

				bufp = buf;
				put_type_and_value( &bufp, mods->mod_type,
				    mods->mod_bvalues[i]->bv_val,
				    mods->mod_bvalues[i]->bv_len );
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
		pthread_mutex_lock( &entry2str_mutex );
		tmp = entry2str( e, &len, 0 );
		while ( (tmp = strchr( tmp, '\n' )) != NULL ) {
			tmp++;
			if ( ! isspace( *tmp ) )
				break;
		}
		fprintf( fp, "%s", tmp );
		pthread_mutex_unlock( &entry2str_mutex );
		break;

	case LDAP_REQ_DELETE:
		fprintf( fp, "changetype: delete\n" );
		break;

	case LDAP_REQ_MODRDN:
		newrdn = change;
		fprintf( fp, "changetype: modrdn\n" );
		fprintf( fp, "newrdn: %s\n", newrdn );
		fprintf( fp, "deleteoldrdn: %d\n", flag ? 1 : 0 );
	}
	fprintf( fp, "\n" );

	lock_fclose( fp, lfp );
	pthread_mutex_unlock( &replog_mutex );
}
