/* ldif.c - the ldif backend */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 2005 The OpenLDAP Foundation.
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
/* ACKNOWLEDGEMENTS:
 * This work was originally developed by Eric Stokes for inclusion
 * in OpenLDAP Software.
 */

#include "portable.h"
#include <stdio.h>
#include <ac/string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <ac/dirent.h>
#include <fcntl.h>
#include <ac/errno.h>
#include <ac/unistd.h>
#include "slap.h"
#include "lutil.h"
#include "config.h"

struct ldif_info {
	struct berval li_base_path;
	ID tool_current;
	Entry ** tool_entries;
	int tool_put_entry_flag;
	int tool_numentries;
	ldap_pvt_thread_mutex_t  li_mutex;
};

#define LDIF	".ldif"

#define IX_DNL	'{'
#define	IX_DNR	'}'
#ifndef IX_FSL
#define	IX_FSL	IX_DNL
#define IX_FSR	IX_DNR
#endif

#define ENTRY_BUFF_INCREMENT 500

static ObjectClass *ldif_oc;

static ConfigDriver ldif_cf;

static ConfigTable ldifcfg[] = {
	{ "", "", 0, 0, 0, ARG_MAGIC,
		ldif_cf, NULL, NULL, NULL },
	{ "directory", "dir", 2, 2, 0, ARG_BERVAL|ARG_OFFSET,
		(void *)offsetof(struct ldif_info, li_base_path),
		"( OLcfgAt:1.1 NAME 'dbDirectory' "
			"DESC 'Directory for database content' "
			"EQUALITY caseIgnoreMatch "
			"SYNTAX OMsDirectoryString )", NULL, NULL },
	{ NULL, NULL, 0, 0, 0, ARG_IGNORED,
		NULL, NULL, NULL, NULL }
};

static ConfigOCs ldifocs[] = {
	{ "( OLcfgOc:2.1 "
		"NAME 'ldifConfig' "
		"DESC 'LDIF backend configuration' "
		"SUP olcDatabaseConfig "
		"MUST ( dbDirectory ) )", Cft_Database,
		&ldif_oc },
	{ NULL, 0, NULL }
};

static int
ldif_cf( ConfigArgs *c )
{
	if ( c->op == SLAP_CONFIG_EMIT ) {
		value_add_one( &c->rvalue_vals, &ldif_oc->soc_cname );
		return 0;
	}
	return 1;
}

static void
dn2path(struct berval * dn, struct berval * rootdn, struct berval * base_path,
	struct berval *res)
{
	char *ptr, *sep, *end;

	res->bv_len = dn->bv_len + base_path->bv_len + 1 + STRLENOF( LDIF );
	res->bv_val = ch_malloc( res->bv_len + 1 );
	ptr = lutil_strcopy( res->bv_val, base_path->bv_val );
	*ptr++ = LDAP_DIRSEP[0];
	ptr = lutil_strcopy( ptr, rootdn->bv_val );
	end = dn->bv_val + dn->bv_len - rootdn->bv_len - 1;
	while ( end > dn->bv_val ) {
		for (sep = end-1; sep >=dn->bv_val && !DN_SEPARATOR( *sep ); sep--);
		*ptr++ = LDAP_DIRSEP[0];
		ptr = lutil_strncopy( ptr, sep+1, end-sep-1 );
		end = sep;
	}
	strcpy(ptr, LDIF);
#if IX_FSL != IX_DNL
	ptr = res->bv_val;
	while( ptr=strchr(ptr, IX_DNL) ) {
		*ptr++ = IX_FSL;
		ptr = strchr(ptr, IX_DNR);
		if ( ptr )
			*ptr++ = IX_FSR;
		else
			break;
	}
#endif
}

static char * slurp_file(int fd) {
	int read_chars_total = 0;
	int read_chars = 0;
	int entry_size;
	char * entry;
	char * entry_pos;
	struct stat st;

	fstat(fd, &st);
	entry_size = st.st_size;
	entry = ch_malloc( entry_size+1 );
	entry_pos = entry;
	
	while(1) {
		read_chars = read(fd, (void *) entry_pos, entry_size - read_chars_total);
		if(read_chars == -1) {
			SLAP_FREE(entry);
			return NULL;
		}
		if(read_chars == 0) {
			entry[read_chars_total] = '\0';
			break;
		}
		else {
			read_chars_total += read_chars;
			entry_pos += read_chars;
		}
	}
	return entry;
}

static int spew_file(int fd, char * spew) {
	int written = 0;
	int writeres;
	int len = strlen(spew);
	char * spewptr = spew;
	
	while(written < len) {
		writeres = write(fd, spewptr, len - written);
		if(writeres == -1) {
			perror("could not spew write");
			return -1;
		}
		else {
			spewptr += writeres;
			written += writeres;
		}
	}
	return writeres;
}

static int spew_entry(Entry * e, struct berval * path) {
	int rs;
	int openres;
	int spew_res;
	int entry_length;
	char * entry_as_string;

	openres = open(path->bv_val, O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR);
	if(openres == -1) {
		if(errno == ENOENT)
			rs = LDAP_NO_SUCH_OBJECT;
		else
			rs = LDAP_UNWILLING_TO_PERFORM;
	}
	else {
		struct berval rdn;
		int tmp;

		/* Only save the RDN onto disk */
		dnRdn( &e->e_name, &rdn );
		if ( rdn.bv_len != e->e_name.bv_len ) {
			e->e_name.bv_val[rdn.bv_len] = '\0';
			tmp = e->e_name.bv_len;
			e->e_name.bv_len = rdn.bv_len;
			rdn.bv_len = tmp;
		}

		entry_as_string = entry2str(e, &entry_length);

		/* Restore full DN */
		if ( rdn.bv_len != e->e_name.bv_len ) {
			e->e_name.bv_val[e->e_name.bv_len] = ',';
			e->e_name.bv_len = rdn.bv_len;
		}

		if(entry_as_string == NULL) {
			rs = LDAP_UNWILLING_TO_PERFORM;
			close(openres);
		}
		else {
			spew_res = spew_file(openres, entry_as_string);
			close(openres);
			if(spew_res == -1)
				rs = LDAP_UNWILLING_TO_PERFORM;
			else
				rs = LDAP_SUCCESS;
		}
	}
	return rs;
}

static Entry * get_entry_for_fd(int fd,
	struct berval *pdn,
	struct berval *pndn)
{
	char * entry = (char *) slurp_file(fd);
	Entry * ldentry = NULL;
	
	/* error reading file */
	if(entry == NULL) {
		goto return_value;
	}

	ldentry = str2entry(entry);
	if ( ldentry ) {
		struct berval rdn;
		rdn = ldentry->e_name;
		build_new_dn( &ldentry->e_name, pdn, &rdn, NULL );
		ch_free( rdn.bv_val );
		rdn = ldentry->e_nname;
		build_new_dn( &ldentry->e_nname, pndn, &rdn, NULL );
		ch_free( rdn.bv_val );
	}

 return_value:
	if(fd != -1) {
		if(close(fd) != 0) {
			/* log error */
		}
	}
	if(entry != NULL)
		SLAP_FREE(entry);
	return ldentry;
}

static Entry * get_entry(Operation *op, struct berval *base_path) {
	struct berval path, pdn, pndn;
	int fd;

	dnParent(&op->o_req_dn, &pdn);
	dnParent(&op->o_req_ndn, &pndn);
	dn2path(&op->o_req_ndn, op->o_bd->be_nsuffix, base_path, &path);
	fd = open(path.bv_val, O_RDONLY);
	/* error opening file (mebbe should log error) */
	if(fd == -1) {
		perror("failed to open file");
	}

	if(path.bv_val != NULL)
		SLAP_FREE(path.bv_val);

	if ( fd != -1 ) {
		return get_entry_for_fd(fd, &pdn, &pndn);
	}

	return NULL;
}

static void fullpath(struct berval *base, struct berval *name, struct berval *res) {
	char *ptr;
	res->bv_len = name->bv_len + base->bv_len + 1;
	res->bv_val = ch_malloc( res->bv_len + 1 );
	strcpy(res->bv_val, base->bv_val);
	ptr = res->bv_val + base->bv_len;
	*ptr++ = LDAP_DIRSEP[0];
	strcpy(ptr, name->bv_val);
}

typedef struct bvlist {
	struct bvlist *next;
	struct berval bv;
	struct berval num;
	unsigned int inum;
	int off;
} bvlist;

typedef struct enumCookie {
	Entry **entries;
	int elen;
	int eind;
	int scope;
} enumCookie;

static void r_enum_tree(enumCookie *ck, struct berval *path,
	struct berval *pdn, struct berval *pndn) {
	Entry *e;
	int fd;

	if(ck->entries == NULL) {
		ck->entries = (Entry **) SLAP_MALLOC(sizeof(Entry *) * ENTRY_BUFF_INCREMENT);
		ck->elen = ENTRY_BUFF_INCREMENT;
	}

	fd = open( path->bv_val, O_RDONLY );
	if ( fd < 0 ) {
		Debug( LDAP_DEBUG_TRACE,
			"=> ldif_enum_tree: failed to open %s\n",
			path->bv_val, 0, 0 );
		return;
	}
	e = get_entry_for_fd(fd, pdn, pndn);
	if ( !e ) {
		Debug( LDAP_DEBUG_ANY,
			"=> ldif_enum_tree: failed to read entry for %s\n",
			path->bv_val, 0, 0 );
		return;
	}

	if ( ck->scope == LDAP_SCOPE_BASE || ck->scope == LDAP_SCOPE_SUBTREE ) {
		if(! (ck->eind < ck->elen)) { /* grow entries if necessary */	
			ck->entries = (Entry **) SLAP_REALLOC(ck->entries, sizeof(Entry *) * (ck->elen) * 2);
			ck->elen *= 2;
		}

		ck->entries[ck->eind] = e;
		ck->eind++;
		fd = 0;
	} else {
		fd = 1;
	}

	if ( ck->scope != LDAP_SCOPE_BASE ) {
		DIR * dir_of_path;
		bvlist *list = NULL, *ptr;

		path->bv_len -= STRLENOF( LDIF );
		path->bv_val[path->bv_len] = '\0';

		dir_of_path = opendir(path->bv_val);
		if(dir_of_path == NULL) {/* can't open directory */
			Debug( LDAP_DEBUG_TRACE,
				"=> ldif_enum_tree: failed to opendir %s\n",
				path->bv_val, 0, 0 );
			goto leave;
		}
	
		while(1) {
			struct berval fname, itmp;
			struct dirent * dir;
			bvlist *bvl, *prev;

			dir = readdir(dir_of_path);
			if(dir == NULL) break; /* end of the directory */
			fname.bv_len = strlen( dir->d_name );
			if ( fname.bv_len <= STRLENOF( LDIF ))
				continue;
			if ( strcmp( dir->d_name + (fname.bv_len - STRLENOF(LDIF)), LDIF))
				continue;
			fname.bv_val = dir->d_name;

			bvl = ch_malloc( sizeof(bvlist) );
			ber_dupbv( &bvl->bv, &fname );
			BER_BVZERO( &bvl->num );
			itmp.bv_val = strchr( bvl->bv.bv_val, IX_FSL );
			if ( itmp.bv_val ) {
				char *ptr;
				itmp.bv_val++;
				ptr = strchr( itmp.bv_val, IX_FSR );
				if ( ptr ) {
					itmp.bv_len = ptr - itmp.bv_val;
					ber_dupbv( &bvl->num, &itmp );
					bvl->inum = strtoul( itmp.bv_val, NULL, 0 );
					itmp.bv_val[0] = '\0';
					bvl->off = itmp.bv_val - bvl->bv.bv_val;
				}
			}

			for (ptr = list, prev = (bvlist *)&list; ptr;
				prev = ptr, ptr = ptr->next) {
				int cmp = strcmp( bvl->bv.bv_val, ptr->bv.bv_val );
				if ( !cmp && bvl->num.bv_val )
					cmp = bvl->inum - ptr->inum;
				if ( cmp < 0 )
					break;
			}
			prev->next = bvl;
			bvl->next = ptr;
				
		}
		closedir(dir_of_path);

		if (ck->scope == LDAP_SCOPE_ONELEVEL)
			ck->scope = LDAP_SCOPE_BASE;
		else if ( ck->scope == LDAP_SCOPE_SUBORDINATE)
			ck->scope = LDAP_SCOPE_SUBTREE;

		while ( ptr=list ) {
			struct berval fpath;

			list = ptr->next;

			if ( ptr->num.bv_val )
				AC_MEMCPY( ptr->bv.bv_val + ptr->off, ptr->num.bv_val,
					ptr->num.bv_len );
			fullpath( path, &ptr->bv, &fpath );
			r_enum_tree(ck, &fpath, &e->e_name, &e->e_nname );
			free(fpath.bv_val);
			if ( ptr->num.bv_val )
				free( ptr->num.bv_val );
			free(ptr->bv.bv_val);
			free(ptr);
		}
	}
leave:
	if ( fd ) entry_free( e );
	return;
}

static Entry ** enum_tree(
	BackendDB *be,
	struct berval *dn,
	struct berval *ndn,
	int * length,
	int scope )
{
	struct ldif_info *ni = (struct ldif_info *) be->be_private;
	struct berval path;
	int index = 0;
	enumCookie ck = {0};
	struct berval pdn, pndn;

	ck.scope = scope;
	dnParent( dn, &pdn );
	dnParent( ndn, &pndn );
	dn2path(ndn, &be->be_nsuffix[0], &ni->li_base_path, &path);
	r_enum_tree(&ck, &path, &pdn, &pndn);
	*length = ck.eind;
	return ck.entries;
}

/* Get the parent path plus the LDIF suffix */
static void get_parent_path(struct berval * dnpath, struct berval *res) {
	int dnpathlen = dnpath->bv_len;
	int i;
	
	for(i = dnpathlen;i>0;i--) /* find the first path seperator */
		if(dnpath->bv_val[i] == LDAP_DIRSEP[0])
			break;
	res->bv_len = i;
	res->bv_val = ch_malloc( res->bv_len + 1 + STRLENOF(LDIF) );
	strncpy(res->bv_val, dnpath->bv_val, i);
	strcpy(res->bv_val+i, LDIF);
	res->bv_val[i] = '\0';
}

static int apply_modify_to_entry(Entry * entry,
				Modifications * modlist,
				Operation * op,
				SlapReply * rs)
{
	char textbuf[SLAP_TEXT_BUFLEN];
	size_t textlen = sizeof textbuf;
	int rc;
	int tempdebug;
	Modification *mods = NULL;
	Attribute *save_attrs;

	if (!acl_check_modlist(op, entry, modlist)) {
		return LDAP_INSUFFICIENT_ACCESS;
	}

	/*  save_attrs = entry->e_attrs; Why?
			entry->e_attrs = attrs_dup(entry->e_attrs); */

	for (; modlist != NULL; modlist = modlist->sml_next) {
		mods = &modlist->sml_mod;

		switch (mods->sm_op) {
		case LDAP_MOD_ADD:
			rc = modify_add_values(entry, mods,
				   get_permissiveModify(op),
				   &rs->sr_text, textbuf,
				   textlen);
			break;
				
		case LDAP_MOD_DELETE:
			rc = modify_delete_values(entry, mods,
				get_permissiveModify(op),
				&rs->sr_text, textbuf,
				textlen);

			break;
				
		case LDAP_MOD_REPLACE:
			rc = modify_replace_values(entry, mods,
				 get_permissiveModify(op),
				 &rs->sr_text, textbuf,
				 textlen);

			break;
		case LDAP_MOD_INCREMENT:
			break;
		case SLAP_MOD_SOFTADD:
			mods->sm_op = LDAP_MOD_ADD;
			rc = modify_add_values(entry, mods,
				   get_permissiveModify(op),
				   &rs->sr_text, textbuf,
				   textlen);
			mods->sm_op = SLAP_MOD_SOFTADD;
			if (rc == LDAP_TYPE_OR_VALUE_EXISTS) {
				rc = LDAP_SUCCESS;
			}
			break;
		default:
			break;
		}
		if(rc != LDAP_SUCCESS) break;
	}
	
	if(rc == LDAP_SUCCESS) {
		if ( mods->sm_desc == slap_schema.si_ad_objectClass ) {
			entry->e_ocflags = 0;
		}
		/* check that the entry still obeys the schema */
		rc = entry_schema_check(op->o_bd, entry,
				  save_attrs, &rs->sr_text,
				  textbuf, textlen);
	}
	return rc;
}

static int
ldif_back_bind( Operation *op, SlapReply *rs )
{
	struct ldif_info *ni = NULL;
	Attribute * a = NULL;
	AttributeDescription *password = slap_schema.si_ad_userPassword;
	int return_val = 0;
	Entry * entry = NULL;

	ni = (struct ldif_info *) op->o_bd->be_private;
	ldap_pvt_thread_mutex_lock(&ni->li_mutex);
	entry = (Entry *) get_entry(op, &ni->li_base_path);

	/* no object is found for them */
	if(entry == NULL) {
		if(be_isroot_pw(op)) {
			return_val = LDAP_SUCCESS;
			goto return_result;
		}
		else if(be_root_dn(op->o_bd)) {
			return_val = LDAP_INVALID_CREDENTIALS;
			rs->sr_err = LDAP_INVALID_CREDENTIALS;
			goto return_result;
		}
		else {
			rs->sr_err = LDAP_NO_SUCH_OBJECT;
			return_val = 1;
			goto return_result;
		}
	}

	/* they don't have userpassword */
	if((a = attr_find(entry->e_attrs, password)) == NULL) {
		rs->sr_err = LDAP_INAPPROPRIATE_AUTH;
		return_val = 1;
		goto return_result;
	}

	/* authentication actually failed */
	if(slap_passwd_check(op, entry, a, &op->oq_bind.rb_cred,
			     &rs->sr_text) != 0) {
		rs->sr_err = LDAP_INVALID_CREDENTIALS;
		return_val = 1;
		goto return_result;
	}

	/* let the front-end send success */
	return_val = 0;
	goto return_result;

 return_result:
	ldap_pvt_thread_mutex_unlock(&ni->li_mutex);
	if(return_val != 0)
		send_ldap_result( op, rs );
	if(entry != NULL)
		entry_free(entry);
	return return_val;
}

static int ldif_back_search(Operation *op, SlapReply *rs)
{
	struct ldif_info *ni = (struct ldif_info *) op->o_bd->be_private;
	int numentries = 0;
	int i = 0;
	Entry ** entries = NULL;

	ldap_pvt_thread_mutex_lock(&ni->li_mutex);
	entries = (Entry **) enum_tree(op->o_bd, &op->o_req_dn, &op->o_req_ndn, &numentries, op->ors_scope);

	if(entries != NULL) {
		for(i=0;i<numentries;i++) {
			if(test_filter(op, entries[i], op->ors_filter) == LDAP_COMPARE_TRUE) {
				rs->sr_entry = entries[i];
				rs->sr_attrs = op->ors_attrs;
				rs->sr_flags = REP_ENTRY_MODIFIABLE;
				send_search_entry(op, rs);
			}
			entry_free(entries[i]);
		}
		SLAP_FREE(entries);
		rs->sr_err = LDAP_SUCCESS;
		ldap_pvt_thread_mutex_unlock(&ni->li_mutex);
		send_ldap_result(op, rs);
	}
	else {
		rs->sr_err = LDAP_BUSY;
		ldap_pvt_thread_mutex_unlock(&ni->li_mutex);
		send_ldap_result(op, rs);
	}

	return 0;
}

static int ldif_back_add(Operation *op, SlapReply *rs) {
	struct ldif_info *ni = (struct ldif_info *) op->o_bd->be_private;
	Entry * e = op->ora_e;
	struct berval dn = e->e_nname;
	struct berval leaf_path = BER_BVNULL;
	struct stat stats;
	int statres;
	char textbuf[SLAP_TEXT_BUFLEN];
	size_t textlen = sizeof textbuf;

	rs->sr_err = entry_schema_check(op->o_bd, e,
				  NULL, &rs->sr_text, textbuf, textlen);
	if ( rs->sr_err != LDAP_SUCCESS ) goto send_res;
				
	ldap_pvt_thread_mutex_lock(&ni->li_mutex);

	dn2path(&dn, &op->o_bd->be_nsuffix[0], &ni->li_base_path, &leaf_path);

	if(leaf_path.bv_val != NULL) {
		struct berval base = BER_BVNULL;
		/* build path to container and ldif of container */
		get_parent_path(&leaf_path, &base);

		statres = stat(base.bv_val, &stats); /* check if container exists */
		if(statres == -1 && errno == ENOENT) { /* container missing */
			base.bv_val[base.bv_len] = '.';
			statres = stat(base.bv_val, &stats); /* check for leaf node */
			base.bv_val[base.bv_len] = '\0';
			if(statres == -1 && errno == ENOENT) {
				rs->sr_err = LDAP_NO_SUCH_OBJECT; /* parent doesn't exist */
			}
			else if(statres != -1) { /* create parent */
				int mkdirres = mkdir(base.bv_val, 0750);
				if(mkdirres == -1) {
					rs->sr_err = LDAP_UNWILLING_TO_PERFORM;
				}
			}
			else
				rs->sr_err = LDAP_UNWILLING_TO_PERFORM;
		}/* container was possibly created, move on to add the entry */
		if(rs->sr_err == LDAP_SUCCESS) {
			statres = stat(leaf_path.bv_val, &stats);
			if(statres == -1 && errno == ENOENT) {
				ldap_pvt_thread_mutex_lock(&entry2str_mutex);
				rs->sr_err = (int) spew_entry(e, &leaf_path);
				ldap_pvt_thread_mutex_unlock(&entry2str_mutex);
			}
			else /* it already exists */
				rs->sr_err = LDAP_ALREADY_EXISTS;
		}
		SLAP_FREE(base.bv_val);
		SLAP_FREE(leaf_path.bv_val);
	}

	ldap_pvt_thread_mutex_unlock(&ni->li_mutex);

send_res:
	send_ldap_result(op, rs);
	return 0;
}

static int ldif_back_modify(Operation *op, SlapReply *rs) {
	struct ldif_info *ni = (struct ldif_info *) op->o_bd->be_private;
	Modifications * modlst = op->orm_modlist;
	struct berval path = BER_BVNULL;
	Entry * entry = NULL;
	int spew_res;

	ldap_pvt_thread_mutex_lock(&ni->li_mutex);
	dn2path(&op->o_req_ndn, &op->o_bd->be_nsuffix[0], &ni->li_base_path,
		&path);
	entry = (Entry *) get_entry(op, &ni->li_base_path);

	if(entry != NULL) {
		rs->sr_err = apply_modify_to_entry(entry, modlst, op, rs);
		if(rs->sr_err == LDAP_SUCCESS) {
			ldap_pvt_thread_mutex_lock(&entry2str_mutex);
			spew_res = spew_entry(entry, &path);
			ldap_pvt_thread_mutex_unlock(&entry2str_mutex);
			if(spew_res == -1) {
				perror("could not output entry");
				rs->sr_err = LDAP_UNWILLING_TO_PERFORM;
			}
		}
	}
	else {
		rs->sr_err = LDAP_NO_SUCH_OBJECT;
	}
	
	if(entry != NULL)
		entry_free(entry);
	if(path.bv_val != NULL)
		SLAP_FREE(path.bv_val);
	rs->sr_text = NULL;
	ldap_pvt_thread_mutex_unlock(&ni->li_mutex);
	send_ldap_result(op, rs);
	return 0;
}

static int ldif_back_delete(Operation *op, SlapReply *rs) {
	struct ldif_info *ni = (struct ldif_info *) op->o_bd->be_private;
	struct berval path = BER_BVNULL;
	int res = 0;

	ldap_pvt_thread_mutex_lock(&ni->li_mutex);
	dn2path(&op->o_req_ndn, &op->o_bd->be_nsuffix[0], &ni->li_base_path, &path);

	path.bv_val[path.bv_len - STRLENOF(LDIF)] = '\0';
	res = rmdir(path.bv_val);
	path.bv_val[path.bv_len - STRLENOF(LDIF)] = '.';
	if ( res && errno != ENOENT ) {
		rs->sr_err = LDAP_NOT_ALLOWED_ON_NONLEAF;
	} else {
		res = unlink(path.bv_val);
	}

	if(res == -1) {
		if(errno == ENOENT)
			rs->sr_err = LDAP_NO_SUCH_OBJECT;
		else
			rs->sr_err = LDAP_UNWILLING_TO_PERFORM;
	}
	else
		rs->sr_err = LDAP_SUCCESS;

	SLAP_FREE(path.bv_val);
	ldap_pvt_thread_mutex_unlock(&ni->li_mutex);
	send_ldap_result(op, rs);
	return 0;
}


static int move_entry(Entry * entry, struct berval * ndn,
			   struct berval * newndn, struct berval * rootdn,
			   struct berval * base_path) {
	int res;
	int exists_res;
	struct berval path;
	struct berval newpath;

	dn2path(ndn, rootdn, base_path, &path);
	dn2path(newndn, rootdn, base_path, &newpath);

	if((entry == NULL || path.bv_val == NULL) || newpath.bv_val == NULL) {
		/* some object doesn't exist */
		res = LDAP_NO_SUCH_OBJECT;
	}
	else { /* do the modrdn */
		exists_res = open(newpath.bv_val, O_RDONLY);
		if(exists_res == -1 && errno == ENOENT) {
			res = spew_entry(entry, &newpath);
			if(res != -1) {
				/* if this fails we should log something bad */
				res = unlink(path.bv_val);
				res = LDAP_SUCCESS;
			}
			else {
				if(errno == ENOENT)
					res = LDAP_NO_SUCH_OBJECT;
				else
					res = LDAP_UNWILLING_TO_PERFORM;
				unlink(newpath.bv_val); /* in case file was created */
			}
		}
		else if(exists_res) {
			int close_res = close(exists_res);
			res = LDAP_ALREADY_EXISTS;
			if(close_res == -1) {
			/* log heinous error */
			}
		}
		else {
			res = LDAP_UNWILLING_TO_PERFORM;
		}
	}

	if(newpath.bv_val != NULL)
		SLAP_FREE(newpath.bv_val);
	if(path.bv_val != NULL)
		SLAP_FREE(path.bv_val);
	return res;
}

static int ldif_back_modrdn(Operation *op, SlapReply *rs) {
	struct ldif_info *ni = (struct ldif_info *) op->o_bd->be_private;
	struct berval new_dn = {0, NULL}, new_ndn = {0, NULL};
	struct berval * new_parent_dn = NULL;
	struct berval p_dn, bv = {0, NULL};
	Entry * entry = NULL;
	LDAPRDN new_rdn = NULL;
	LDAPRDN old_rdn = NULL;
	Modifications * mods = NULL;
	int res;

	ldap_pvt_thread_mutex_lock(&ni->li_mutex);
	ldap_pvt_thread_mutex_lock(&entry2str_mutex);
	entry = (Entry *) get_entry(op, &ni->li_base_path);

	/* build the mods to the entry */
	if(entry != NULL) {
		if(ldap_bv2rdn(&op->oq_modrdn.rs_newrdn, &new_rdn,
			(char **)&rs->sr_text, LDAP_DN_FORMAT_LDAP)) {
			rs->sr_err = LDAP_INVALID_DN_SYNTAX;
		}
		else if(op->oq_modrdn.rs_deleteoldrdn &&
			ldap_bv2rdn(&op->o_req_dn, &old_rdn, (char **)&rs->sr_text,
			LDAP_DN_FORMAT_LDAP)) {
			rs->sr_err = LDAP_OTHER;
		}
		else { /* got both rdns successfully, ready to build mods */
			if(slap_modrdn2mods(op, rs, entry, old_rdn, new_rdn, &mods)
				!= LDAP_SUCCESS) {
				rs->sr_err = LDAP_UNWILLING_TO_PERFORM;
			}
			else { /* built mods successfully */

				/* build new dn, and new ndn for the entry */
				if(op->oq_modrdn.rs_newSup != NULL) /* new superior */
					p_dn = *op->oq_modrdn.rs_newSup;
				else
					p_dn = slap_empty_bv;
				dnParent(&entry->e_name, &p_dn);
				build_new_dn(&new_dn, &p_dn, &op->oq_modrdn.rs_newrdn, NULL); 
				dnNormalize( 0, NULL, NULL, &new_dn, &bv, op->o_tmpmemctx );
				ber_dupbv( &new_ndn, &bv );
				entry->e_name = new_dn;
				entry->e_nname = new_ndn;

				/* perform the modifications */
				res = apply_modify_to_entry(entry, mods, op, rs);
				if(res == LDAP_SUCCESS) {
					rs->sr_err = move_entry(entry, &op->o_req_ndn,
								&new_ndn,
								&op->o_bd->be_nsuffix[0],
								&ni->li_base_path);
				}
				else
					rs->sr_err = res;
			}
		}
	}
	else /* entry was null */
		rs->sr_err = LDAP_NO_SUCH_OBJECT;

	if(entry != NULL)
		entry_free(entry);
	rs->sr_text = "";
	ldap_pvt_thread_mutex_unlock(&ni->li_mutex);
	ldap_pvt_thread_mutex_unlock(&entry2str_mutex);
	send_ldap_result(op, rs);
	return 0;
}

static int ldif_back_compare(Operation *op, SlapReply *rs) {
	struct ldif_info *ni = (struct ldif_info *) op->o_bd->be_private;
	Entry * e = NULL;
	Attribute	*a;

	ldap_pvt_thread_mutex_lock(&ni->li_mutex);

	e = (Entry *) get_entry(op, &ni->li_base_path);
	if(e != NULL) {
		for(a = attrs_find( e->e_attrs, op->oq_compare.rs_ava->aa_desc );
			a != NULL;
			a = attrs_find( a->a_next, op->oq_compare.rs_ava->aa_desc )) {
			rs->sr_err = LDAP_COMPARE_FALSE;
		
			if (value_find_ex(op->oq_compare.rs_ava->aa_desc,
						SLAP_MR_ATTRIBUTE_VALUE_NORMALIZED_MATCH |
						SLAP_MR_ASSERTED_VALUE_NORMALIZED_MATCH,
						a->a_nvals, &op->oq_compare.rs_ava->aa_value,
						op->o_tmpmemctx ) == 0) {
				rs->sr_err = LDAP_COMPARE_TRUE;
				break;
			}
		}
	}
	else {
		rs->sr_err = LDAP_NO_SUCH_OBJECT;
	}

	if(e != NULL)
		entry_free(e);
	ldap_pvt_thread_mutex_unlock(&ni->li_mutex);
	send_ldap_result(op, rs);
	return 0;
}

static int ldif_tool_entry_open(BackendDB * be, int mode) {
	struct ldif_info *ni = (struct ldif_info *) be->be_private;
	ni->tool_entries = NULL;
	ni->tool_numentries = 0;
	ni->tool_current = 0;
	ni->tool_put_entry_flag = 0;
	return 0;
}					

static int ldif_tool_entry_close(BackendDB * be) {
	struct ldif_info *ni = (struct ldif_info *) be->be_private;

	SLAP_FREE(ni->tool_entries);
	return 0;
}

static ID ldif_tool_entry_first(BackendDB *be) {
	struct ldif_info *ni = (struct ldif_info *) be->be_private;
	ID id = 1; /* first entry in the array of entries shifted by one */

	ni->tool_current = 1;
	if(ni->tool_entries == NULL || ni->tool_put_entry_flag) {
		ni->tool_entries = (Entry **) enum_tree(be, be->be_suffix,
			be->be_nsuffix, &ni->tool_numentries, LDAP_SCOPE_SUBTREE);
		ni->tool_put_entry_flag = 0;
	}
	return id;
}

static ID ldif_tool_entry_next(BackendDB *be) {
	struct ldif_info *ni = (struct ldif_info *) be->be_private;
	ni->tool_current += 1;
	if(ni->tool_put_entry_flag) {
		ni->tool_entries = (Entry **) enum_tree(be, be->be_suffix,
			be->be_nsuffix, &ni->tool_numentries, LDAP_SCOPE_SUBTREE);
		ni->tool_put_entry_flag = 0;
	}
	if(ni->tool_current > ni->tool_numentries)
		return NOID;
	else
		return ni->tool_current;
}

static Entry * ldif_tool_entry_get(BackendDB * be, ID id) {
	struct ldif_info *ni = (struct ldif_info *) be->be_private;
	Entry * e;

	if(id > ni->tool_numentries || id < 1)
		return NULL;
	else {
		e = ni->tool_entries[id - 1];
		ni->tool_entries[id - 1] = NULL;
		return e;
	}
}

static ID ldif_tool_entry_put(BackendDB * be, Entry * e, struct berval *text) {
	struct ldif_info *ni = (struct ldif_info *) be->be_private;
	Attribute *save_attrs;
	struct berval dn = e->e_nname;
	struct berval leaf_path = BER_BVNULL;
	struct stat stats;
	int statres;
	char textbuf[SLAP_TEXT_BUFLEN];
	size_t textlen = sizeof textbuf;
	int res = LDAP_SUCCESS;

	dn2path(&dn, &be->be_nsuffix[0], &ni->li_base_path, &leaf_path);

	if(leaf_path.bv_val != NULL) {
		struct berval base = BER_BVNULL;
		/* build path to container, and path to ldif of container */
		get_parent_path(&leaf_path, &base);

		statres = stat(base.bv_val, &stats); /* check if container exists */
		if(statres == -1 && errno == ENOENT) { /* container missing */
			base.bv_val[base.bv_len] = '.';
			statres = stat(base.bv_val, &stats); /* check for leaf node */
			base.bv_val[base.bv_len] = '\0';
			if(statres == -1 && errno == ENOENT) {
				res = LDAP_NO_SUCH_OBJECT; /* parent doesn't exist */
			}
			else if(statres != -1) { /* create parent */
				int mkdirres = mkdir(base.bv_val, 0750);
				if(mkdirres == -1) {
					res = LDAP_UNWILLING_TO_PERFORM;
				}
			}
			else
				res = LDAP_UNWILLING_TO_PERFORM;
		}/* container was possibly created, move on to add the entry */
		if(res == LDAP_SUCCESS) {
			statres = stat(leaf_path.bv_val, &stats);
			if(statres == -1 && errno == ENOENT) {
				res = (int) spew_entry(e, &leaf_path);
			}
			else /* it already exists */
				res = LDAP_ALREADY_EXISTS;
		}
		SLAP_FREE(base.bv_val);
		SLAP_FREE(leaf_path.bv_val);
	}

	if(res == LDAP_SUCCESS) {
		ni->tool_put_entry_flag = 1;
		return 1;
	}
	else
		return NOID;
}

static int
ldif_back_db_init( BackendDB *be )
{
	struct ldif_info *ni;

	ni = ch_calloc( 1, sizeof(struct ldif_info) );
	be->be_private = ni;
	be->be_cf_table = be->bd_info->bi_cf_table;
	ldap_pvt_thread_mutex_init(&ni->li_mutex);
	return 0;
}

static int
ldif_back_db_destroy(
			   Backend	*be
			   )
{
	struct ldif_info *ni = be->be_private;
	ldap_pvt_thread_mutex_destroy(&ni->li_mutex);
	free( be->be_private );
	return 0;
}

static int
ldif_back_db_open(
			Backend	*be
			)
{
	struct ldif_info *ni = (struct ldif_info *) be->be_private;
	if( BER_BVISEMPTY(&ni->li_base_path)) {/* missing base path */
		fprintf(stderr, "missing base path for back-ldif\n");
		return 1;
	}
	return 0;
}

int
ldif_back_initialize(
			   BackendInfo	*bi
			   )
{
	int rc;

	bi->bi_cf_table = ldifcfg;

	bi->bi_open = 0;
	bi->bi_close = 0;
	bi->bi_config = 0;
	bi->bi_destroy = 0;

	bi->bi_db_init = ldif_back_db_init;
	bi->bi_db_config = config_generic_wrapper;
	bi->bi_db_open = ldif_back_db_open;
	bi->bi_db_close = 0;
	bi->bi_db_destroy = ldif_back_db_destroy;

	bi->bi_op_bind = ldif_back_bind;
	bi->bi_op_unbind = 0;
	bi->bi_op_search = ldif_back_search;
	bi->bi_op_compare = ldif_back_compare;
	bi->bi_op_modify = ldif_back_modify;
	bi->bi_op_modrdn = ldif_back_modrdn;
	bi->bi_op_add = ldif_back_add;
	bi->bi_op_delete = ldif_back_delete;
	bi->bi_op_abandon = 0;

	bi->bi_extended = 0;

	bi->bi_chk_referrals = 0;

	bi->bi_connection_init = 0;
	bi->bi_connection_destroy = 0;

	bi->bi_tool_entry_open = ldif_tool_entry_open;
	bi->bi_tool_entry_close = ldif_tool_entry_close;
	bi->bi_tool_entry_first = ldif_tool_entry_first;
	bi->bi_tool_entry_next = ldif_tool_entry_next;
	bi->bi_tool_entry_get = ldif_tool_entry_get;
	bi->bi_tool_entry_put = ldif_tool_entry_put;
	bi->bi_tool_entry_reindex = 0;
	bi->bi_tool_sync = 0;
	
	bi->bi_tool_dn2id_get = 0;
	bi->bi_tool_id2entry_get = 0;
	bi->bi_tool_entry_modify = 0;

	rc = config_register_schema( ldifcfg, ldifocs );
	if ( rc ) return rc;
	ldifcfg[0].ad = slap_schema.si_ad_objectClass;
	return 0;
}
