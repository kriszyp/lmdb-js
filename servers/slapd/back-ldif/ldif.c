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

struct ldif_info {
	struct berval li_base_path;
	ID tool_current;  
	Entry ** tool_entries;
	int tool_put_entry_flag;
	int tool_numentries;
	ldap_pvt_thread_mutex_t  li_mutex;
};

#define LDIF	".ldif"

#define ENTRY_BUFF_INCREMENT 500

static char *
dn2path(struct berval * dn, struct berval * rootdn, struct berval * base_path)
{
	char *result = ch_malloc( dn->bv_len + base_path->bv_len + 2 +
		STRLENOF( LDIF ));
	char *ptr, *sep, *end;

	ptr = lutil_strcopy( result, base_path->bv_val );
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
	return result;
}

static char * slurp_file(int fd) {  
	int entry_buf_size = 40 * ENTRY_BUFF_INCREMENT;
	int read_chars_total = 0;
	int read_chars = 0;
	int entry_size = 40 * ENTRY_BUFF_INCREMENT;
	char * entry = (char *) malloc(sizeof(char) * 40 * ENTRY_BUFF_INCREMENT);
	char * entry_pos = entry;
	
	while(1) {
	  if(entry_size - read_chars_total == 0) {
	    entry = (char *) realloc(entry, sizeof(char) * 2 * entry_size);
	    entry_size = 2 * entry_size;
	  }
	  read_chars = read(fd, (void *) entry_pos, entry_size - read_chars_total);
	  if(read_chars == -1) {
	    SLAP_FREE(entry);
	    return NULL;
	  }
	  entry_pos += read_chars;
	  if(read_chars == 0) {
	    if(entry_size - read_chars_total > 0)
	entry[read_chars_total] = '\0';
	    else {
	entry = (char *) realloc(entry, sizeof(char) * entry_size + 1);
	entry_size = entry_size + 1;
	entry[read_chars_total] = '\0';
	    }	
	    break;
	  }
	  else {
	    read_chars_total += read_chars;
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

static int spew_entry(Entry * e, char * path) {
	int rs;
	int openres;
	int spew_res;
	int entry_length;
	char * entry_as_string;

	openres = open(path, O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR);
	if(openres == -1) {
	  if(errno == ENOENT)
	    rs = LDAP_NO_SUCH_OBJECT;
	  else
	    rs = LDAP_UNWILLING_TO_PERFORM;
	}
	else {
	  entry_as_string = entry2str(e, &entry_length);
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

static Entry * get_entry_for_fd(int fd) {
	char * entry = (char *) slurp_file(fd);
	Entry * ldentry = NULL;
	
	/* error reading file */
	if(entry == NULL) {
	  goto return_value;
	}

	ldentry = str2entry(entry);

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

static Entry * get_entry(struct berval * dn, struct berval * rootdn, struct berval * base_path) {
	char * path = (char *) dn2path(dn, rootdn, base_path);
	int fd = open(path, O_RDONLY);

	/* error opening file (mebbe should log error) */
	if(fd == -1) {
	  perror("failed to open file");
	  goto return_value;
	}
	goto return_value;

 return_value:
	if(path != NULL)
	  SLAP_FREE(path);
	return get_entry_for_fd(fd);
}

/* takes a base path and a filename and opens that file */
static int fd_for_path_components(char * base, char * name) {
	char * absolutepath;
	int fd;
	absolutepath = (char *) SLAP_MALLOC(sizeof(char) * 
				      (strlen(base) + 
				       strlen(name) + 2));
	absolutepath[0] = '\0';
	strcat(absolutepath, base);
	strcat(absolutepath, LDAP_DIRSEP);
	strcat(absolutepath, name);
	fd = open(absolutepath, O_RDONLY);
	SLAP_FREE(absolutepath);
	return fd;
}

static Entry ** r_enum_tree(Entry ** entries, int *elen, int *eind, char * path) {
	DIR * dir_of_path = opendir(path);
	int fd;
	struct dirent * dir;
	char * newpath;
	Entry * e;

	if(entries == NULL) {
	  entries = (Entry **) SLAP_MALLOC(sizeof(Entry *) * ENTRY_BUFF_INCREMENT);
	  *elen = ENTRY_BUFF_INCREMENT;
	}
	if(dir_of_path == NULL) {/* can't open directory */
	  perror("failed to open directory");
	  return entries;
	}
	
	while(1) {
	  dir = readdir(dir_of_path);
	  if(dir == NULL) break; /* end of the directory */
	  if(dir->d_type == DT_REG) { /* regular file, read the entry into memory */
	    if(! (*eind < *elen)) { /* grow entries if necessary */	
	entries = (Entry **) SLAP_REALLOC(entries, sizeof(Entry *) * (*elen) * 2);
	*elen = *elen * 2;
	    }
	    fd = fd_for_path_components(path, dir->d_name);
	    if(fd != -1) {
	e = get_entry_for_fd(fd);
	if(e != NULL) {
	  entries[*eind] = e;
	  *eind = *eind + 1;
	}
	else
	  perror("failed to read entry");
	    }
	    else
	perror("failed to open fd");
	  }
	  else if(dir->d_type == DT_DIR) {
	    if(! (strcasecmp(dir->d_name, ".") == 0 || strcasecmp(dir->d_name, "..") == 0)) {
	newpath = (char *) SLAP_MALLOC(sizeof(char) * 
				       (strlen(path) + strlen(dir->d_name) + 2));
	newpath[0] = '\0';
	strcat(newpath, path);
	strcat(newpath, LDAP_DIRSEP);
	strcat(newpath, dir->d_name);
	entries = r_enum_tree(entries, elen, eind, newpath);
	SLAP_FREE(newpath);
	    }
	  }
	}
	closedir(dir_of_path);
	return entries;
}

static Entry ** enum_tree(struct berval * path, int * length) {
	int index = 0;
	return r_enum_tree(NULL, &index, length, path->bv_val);
}

static char * get_parent_path(char * dnpath) {
	int dnpathlen = strlen(dnpath);
	char * result;
	int i;
	
	for(i = dnpathlen;i>0;i--) /* find the first path seperator */
	  if(dnpath[i] == LDAP_DIRSEP[0])
	    break;
	result = ch_malloc( i + 1 );
	strncpy(result, dnpath, i);
	result[i] = '\0';
	return result;
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
	entry = (Entry *) get_entry(&op->o_req_ndn, &op->o_bd->be_nsuffix[0], &ni->li_base_path);

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
	entries = (Entry **) enum_tree(&ni->li_base_path, &numentries);

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
	Attribute *save_attrs;
	struct berval dn = e->e_nname;
	char * leaf_path = NULL;
	char * base = NULL;
	char * base_ldif = NULL;
	struct stat stats;
	int statres;
	char textbuf[SLAP_TEXT_BUFLEN];
	size_t textlen = sizeof textbuf;

	ldap_pvt_thread_mutex_lock(&ni->li_mutex);
	ldap_pvt_thread_mutex_lock(&entry2str_mutex);

	leaf_path = (char *) dn2path(&dn, &op->o_bd->be_nsuffix[0], &ni->li_base_path);

	/*  save_attrs = e->e_attrs; why?
	    e->e_attrs = attrs_dup(e->e_attrs);*/

	if(leaf_path != NULL) {
	  char * tmp;
	  /* build path to container, and path to ldif of container */
	  base = (char *) get_parent_path(leaf_path);
	  base_ldif = (char *) SLAP_MALLOC(sizeof(char) * (strlen(base) + 6));
	  tmp = (char *) lutil_strcopy(base_ldif, base);
	  lutil_strcopy(tmp, LDIF);

	  rs->sr_err = entry_schema_check(op->o_bd, e,
				    save_attrs, 
				    &rs->sr_text, 
				    textbuf, textlen);
	  if(rs->sr_err == LDAP_SUCCESS) {
	    statres = stat(base, &stats); /* check if container exists */
	    if(statres == -1 && errno == ENOENT) { /* container missing */
	statres = stat(base_ldif, &stats); /* check for leaf node */
	if(statres == -1 && errno == ENOENT) {
	  rs->sr_err = LDAP_NO_SUCH_OBJECT; /* parent doesn't exist */
	}
	else if(statres != -1) { /* create parent */
	  int mkdirres = mkdir(base, 0750);
	  if(mkdirres == -1) {
	    rs->sr_err = LDAP_UNWILLING_TO_PERFORM;
	  }
	}
	else
	  rs->sr_err = LDAP_UNWILLING_TO_PERFORM;
	    }/* container was possibly created, move on to add the entry */
	    if(rs->sr_err == LDAP_SUCCESS) {
	statres = stat(leaf_path, &stats);
	if(statres == -1 && errno == ENOENT) {
	  rs->sr_err = (int) spew_entry(e, leaf_path);
	}
	else /* it already exists */
	  rs->sr_err = LDAP_ALREADY_EXISTS;
	    }  
	  }
	}    

	ldap_pvt_thread_mutex_unlock(&ni->li_mutex);
	ldap_pvt_thread_mutex_unlock(&entry2str_mutex);

	send_ldap_result(op, rs);  
	if(leaf_path != NULL)
	  SLAP_FREE(leaf_path);
	if(base != NULL)
	  SLAP_FREE(base);
	if(base_ldif != NULL)
	  SLAP_FREE(base_ldif);
	return 0;
}

static int ldif_back_modify(Operation *op, SlapReply *rs) {
	struct ldif_info *ni = (struct ldif_info *) op->o_bd->be_private;
	Modifications * modlst = op->orm_modlist;
	char * path = NULL;
	Entry * entry = NULL;
	int spew_res;

	ldap_pvt_thread_mutex_lock(&ni->li_mutex);
	ldap_pvt_thread_mutex_lock(&entry2str_mutex);
	path = (char *) dn2path(&op->o_req_ndn, &op->o_bd->be_nsuffix[0], &ni->li_base_path);
	entry = (Entry *) get_entry(&op->o_req_ndn, &op->o_bd->be_nsuffix[0], &ni->li_base_path);

	if(entry != NULL) {
	  rs->sr_err = apply_modify_to_entry(entry, modlst, op, rs);
	  if(rs->sr_err == LDAP_SUCCESS) {
	    spew_res = spew_entry(entry, path);
	    if(spew_res == -1) {
	perror("could not output entry");
	rs->sr_err = LDAP_UNWILLING_TO_PERFORM;
	    }
	  }
	}
	else {
	  rs->sr_err = LDAP_NO_SUCH_OBJECT;
	}
	
	if(path != NULL)
	  SLAP_FREE(path);
	if(entry != NULL)
	  entry_free(entry);
	rs->sr_text = "";
	ldap_pvt_thread_mutex_unlock(&ni->li_mutex);
	ldap_pvt_thread_mutex_unlock(&entry2str_mutex);
	send_ldap_result(op, rs);
	return 0;
}

static int ldif_back_delete(Operation *op, SlapReply *rs) {
	struct ldif_info *ni = (struct ldif_info *) op->o_bd->be_private;
	char * path = NULL;
	int res = 0;

	ldap_pvt_thread_mutex_lock(&ni->li_mutex);
	path = (char *) dn2path(&op->o_req_ndn, &op->o_bd->be_nsuffix[0], &ni->li_base_path);
	res = unlink(path);

	if(res == -1) {
	  if(errno == ENOENT)
	    rs->sr_err = LDAP_NO_SUCH_OBJECT;
	  else
	    rs->sr_err = LDAP_UNWILLING_TO_PERFORM;
	}
	else
	  rs->sr_err = LDAP_SUCCESS;

	SLAP_FREE(path);
	ldap_pvt_thread_mutex_unlock(&ni->li_mutex);
	send_ldap_result(op, rs);
	return 0;
}

static int is_leaf_node(char * path) {
	DIR * nonleafnode;  
	int path_len = strlen(path);
	char * nonleafpath = (char *) SLAP_MALLOC(sizeof(char) * path_len + 1);
	int res;

	strncpy(nonleafpath, path, path_len);
	nonleafpath[path_len - 5] = '\0';
	nonleafnode = opendir(nonleafpath);
	if(nonleafnode == NULL) {
	  res = 1;
	}
	else {
	  closedir(nonleafnode);
	  res = 0;
	}
	SLAP_FREE(nonleafpath);
	return res;
}

static int move_entry(Entry * entry, struct berval * ndn, 
	       struct berval * newndn, struct berval * rootdn,
	       struct berval * base_path) {
	int res;
	int exists_res;
	char * path = (char *) dn2path(ndn, rootdn, base_path);
	char * newpath = (char *) dn2path(newndn, rootdn, base_path);
	int path_len = strlen(path);

	if((entry == NULL || path == NULL) || newpath == NULL) { /* some object doesn't exist */
	  res = LDAP_NO_SUCH_OBJECT;
	}
	else if(! is_leaf_node(path)) { /* entry is not a leaf node */
	  res = LDAP_NOT_ALLOWED_ON_NONLEAF;
	}
	else { /* do the modrdn */
	  exists_res = open(newpath, O_RDONLY);
	  if(exists_res == -1 && errno == ENOENT) {
	    res = spew_entry(entry, newpath);
	    if(res != -1) {
	/* if this fails we should log something bad */
	res = unlink(path);
	res = LDAP_SUCCESS;
	    }
	    else {
	if(errno == ENOENT)
	  res = LDAP_NO_SUCH_OBJECT;
	else
	  res = LDAP_UNWILLING_TO_PERFORM;
	unlink(newpath); /* in case file was created */            
	    }
	  }
	  else if(exists_res) {
	    res = LDAP_ALREADY_EXISTS;
	    int close_res = close(exists_res);
	    if(close_res == -1) {
	/* log heinous error */
	    }
	  }
	  else {
	    res = LDAP_UNWILLING_TO_PERFORM;
	  }
	}

	if(path != NULL)
	  SLAP_FREE(path);
	if(newpath != NULL)
	  SLAP_FREE(newpath);
	return res;
}

static int ldif_back_modrdn(Operation *op, SlapReply *rs) {
	struct ldif_info *ni = (struct ldif_info *) op->o_bd->be_private;
	struct berval new_dn = {0, NULL}, new_ndn = {0, NULL};
	struct berval * new_parent_dn = NULL;
	struct berval p_dn;
	Entry * entry = NULL;
	LDAPRDN new_rdn = NULL;
	LDAPRDN old_rdn = NULL;
	Modifications * mods = NULL;
	int res;

	ldap_pvt_thread_mutex_lock(&ni->li_mutex);
	ldap_pvt_thread_mutex_lock(&entry2str_mutex);
	entry = (Entry *) get_entry(&op->o_req_ndn, &op->o_bd->be_nsuffix[0], &ni->li_base_path);

	/* build the mods to the entry */
	if(entry != NULL) {
	  if(ldap_bv2rdn(&op->oq_modrdn.rs_newrdn, &new_rdn, (char **)&rs->sr_text, 
		   LDAP_DN_FORMAT_LDAP)) {
	    rs->sr_err = LDAP_INVALID_DN_SYNTAX;
	  }
	  else if(op->oq_modrdn.rs_deleteoldrdn &&
	    ldap_bv2rdn(&op->o_req_dn, &old_rdn, (char **)&rs->sr_text,
			LDAP_DN_FORMAT_LDAP)) {
	    rs->sr_err = LDAP_OTHER;
	  }
	  else { /* got both rdns successfully, ready to build mods */
	    if(slap_modrdn2mods(op, rs, entry, old_rdn, new_rdn, &mods) != LDAP_SUCCESS) {
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
	struct berval bv = {0, NULL};
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

	e = (Entry *) get_entry(&op->o_req_ndn, &op->o_bd->be_nsuffix[0], &ni->li_base_path);
	if(e != NULL) {
	  for(a = attrs_find( e->e_attrs, op->oq_compare.rs_ava->aa_desc );
	a != NULL;
	a = attrs_find( a->a_next, op->oq_compare.rs_ava->aa_desc ))
	    {
	rs->sr_err = LDAP_COMPARE_FALSE;
	
	if (value_find_ex(op->oq_compare.rs_ava->aa_desc,
			  SLAP_MR_ATTRIBUTE_VALUE_NORMALIZED_MATCH |
			  SLAP_MR_ASSERTED_VALUE_NORMALIZED_MATCH,
			  a->a_nvals, &op->oq_compare.rs_ava->aa_value,
			  op->o_tmpmemctx ) == 0)
	  {
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
	int i;
	/*if(ni->tool_entries != NULL) {
	  for(i=0;i<ni->tool_numentries;i++) {
	    SLAP_FREE(ni->tool_entries[i]);
	    }*/
	SLAP_FREE(ni->tool_entries);
	return 0;
}

static ID ldif_tool_entry_first(BackendDB *be) {
	struct ldif_info *ni = (struct ldif_info *) be->be_private;  
	ID id = 1; /* first entry in the array of entries shifted by one */
	ni->tool_current = 1;
	if(ni->tool_entries == NULL || ni->tool_put_entry_flag) {
	  ni->tool_entries = (Entry **) enum_tree(&ni->li_base_path, &ni->tool_numentries);
	  ni->tool_put_entry_flag = 0;
	}
	return id;
}

static ID ldif_tool_entry_next(BackendDB *be) {
	struct ldif_info *ni = (struct ldif_info *) be->be_private;  
	ni->tool_current += 1;
	if(ni->tool_put_entry_flag) {
	  ni->tool_entries = (Entry **) enum_tree(&ni->li_base_path, &ni->tool_numentries);
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
	char * leaf_path = NULL;
	char * base = NULL;
	char * base_ldif = NULL;
	struct stat stats;
	int statres;
	char textbuf[SLAP_TEXT_BUFLEN];
	size_t textlen = sizeof textbuf;
	int res = LDAP_SUCCESS;

	leaf_path = (char *) dn2path(&dn, &be->be_nsuffix[0], &ni->li_base_path);

	/*  save_attrs = e->e_attrs; why?
	    e->e_attrs = attrs_dup(e->e_attrs);*/

	if(leaf_path != NULL) {
	  char * tmp;
	  /* build path to container, and path to ldif of container */
	  base = (char *) get_parent_path(leaf_path);
	  base_ldif = (char *) SLAP_MALLOC(sizeof(char) * (strlen(base) + 6));
	  tmp = (char *) lutil_strcopy(base_ldif, base);
	  lutil_strcopy(tmp, LDIF);

	  statres = stat(base, &stats); /* check if container exists */
	  if(statres == -1 && errno == ENOENT) { /* container missing */
	    statres = stat(base_ldif, &stats); /* check for leaf node */
	    if(statres == -1 && errno == ENOENT) {
	res = LDAP_NO_SUCH_OBJECT; /* parent doesn't exist */
	    }
	    else if(statres != -1) { /* create parent */
	int mkdirres = mkdir(base, 0750);
	if(mkdirres == -1) {
	  res = LDAP_UNWILLING_TO_PERFORM;
	}
	    }
	    else
	res = LDAP_UNWILLING_TO_PERFORM;
	  }/* container was possibly created, move on to add the entry */
	  if(res == LDAP_SUCCESS) {
	    statres = stat(leaf_path, &stats);
	    if(statres == -1 && errno == ENOENT) {
	res = (int) spew_entry(e, leaf_path);
	    }
	    else /* it already exists */
	res = LDAP_ALREADY_EXISTS;
	  }  
	}

	if(leaf_path != NULL)
	  SLAP_FREE(leaf_path);
	if(base != NULL)
	  SLAP_FREE(base);
	if(base_ldif != NULL)
	  SLAP_FREE(base_ldif);
	if(res == LDAP_SUCCESS) {
	  ni->tool_put_entry_flag = 1;
	  return 1;
	}
	else
	  return NOID;
}

static int
ldif_back_db_config(
		    BackendDB	*be,
		    const char	*fname,
		    int			lineno,
		    int			argc,
		    char		**argv )
{
	struct ldif_info *ni = (struct ldif_info *) be->be_private;

	if ( strcasecmp( argv[0], "directory" ) == 0 ) {
	  if ( argc < 2 ) {
	    fprintf( stderr,
	       "%s: line %d: missing <path> in \"directory <path>\" line\n",
	       fname, lineno );
	    return 1;
	  }
	  ber_str2bv(argv[1], 0, 1, &ni->li_base_path);
	} else {
	  return SLAP_CONF_UNKNOWN;
	}
	return 0;
}


static int
ldif_back_db_init( BackendDB *be )
{
	struct ldif_info *ni;

	ni = ch_calloc( 1, sizeof(struct ldif_info) );
	be->be_private = ni;
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
	bi->bi_open = 0;
	bi->bi_close = 0;
	bi->bi_config = 0;
	bi->bi_destroy = 0;

	bi->bi_db_init = ldif_back_db_init;
	bi->bi_db_config = ldif_back_db_config;
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

	return 0;
}
