/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1999-2004 The OpenLDAP Foundation.
 * Portions Copyright 1999 Dmitry Kovalev.
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
 * This work was initially developed by Dmitry Kovalev for inclusion
 * by OpenLDAP Software.
 */

#ifndef __BACKSQL_SCHEMA_MAP_H__
#define __BACKSQL_SCHEMA_MAP_H__

typedef struct backsql_oc_map_rec {
	/*
	 * Structure of corresponding LDAP objectClass definition
	 */
	ObjectClass	*bom_oc;
#define BACKSQL_OC_NAME(ocmap)	((ocmap)->bom_oc->soc_cname.bv_val)
	
	struct berval	bom_keytbl;
	struct berval	bom_keycol;
	/* expected to return keyval of newly created entry */
	char		*bom_create_proc;
	/* in case create_proc does not return the keyval of the newly
	 * created row */
	char		*bom_create_keyval;
	/* supposed to expect keyval as parameter and delete 
	 * all the attributes as well */
	char		*bom_delete_proc;
	/* flags whether delete_proc is a function (whether back-sql 
	 * should bind first parameter as output for return code) */
	int		bom_expect_return;
	unsigned long	bom_id;
	Avlnode		*bom_attrs;
} backsql_oc_map_rec;

typedef struct backsql_at_map_rec {
	/* Description of corresponding LDAP attribute type */
	AttributeDescription	*bam_ad;
	/* ObjectClass if bam_ad is objectClass */
	ObjectClass		*bam_oc;

	struct berval	bam_from_tbls;
	struct berval	bam_join_where;
	struct berval	bam_sel_expr;
	/* supposed to expect 2 binded values: entry keyval 
	 * and attr. value to add, like "add_name(?,?,?)" */
	char		*bam_add_proc;
	/* supposed to expect 2 binded values: entry keyval 
	 * and attr. value to delete */
	char		*bam_delete_proc;
	/* for optimization purposes attribute load query 
	 * is preconstructed from parts on schemamap load time */
	char		*bam_query;
	/* following flags are bitmasks (first bit used for add_proc, 
	 * second - for delete_proc) */
	/* order of parameters for procedures above; 
	 * 1 means "data then keyval", 0 means "keyval then data" */
	int 		bam_param_order;
	/* flags whether one or more of procedures is a function 
	 * (whether back-sql should bind first parameter as output 
	 * for return code) */
	int 		bam_expect_return;
	/* TimesTen */
	struct berval	bam_sel_expr_u;

	/* next mapping for attribute */
	struct backsql_at_map_rec	*bam_next;
} backsql_at_map_rec;

#define BACKSQL_AT_MAP_REC_INIT { NULL, NULL, BER_BVC(""), BER_BVC(""), BER_BVNULL, NULL, NULL, NULL, 0, 0, BER_BVNULL, NULL }

/* defines to support bitmasks above */
#define BACKSQL_ADD	0x1
#define BACKSQL_DEL	0x2

#define BACKSQL_IS_ADD(x)	( BACKSQL_ADD & (x) )
#define BACKSQL_IS_DEL(x)	( BACKSQL_DEL & (x) )

#define BACKSQL_NCMP(v1,v2)	ber_bvcmp((v1),(v2))

int backsql_load_schema_map( backsql_info *si, SQLHDBC dbh );
/* Deprecated */
backsql_oc_map_rec *backsql_name2oc( backsql_info *si, struct berval *oc_name );
backsql_oc_map_rec *backsql_oc2oc( backsql_info *si, ObjectClass *oc );
backsql_oc_map_rec *backsql_id2oc( backsql_info *si, unsigned long id );
/* Deprecated */
backsql_at_map_rec *backsql_name2at( backsql_oc_map_rec *objclass,
		struct berval *at_name );
backsql_at_map_rec *backsql_ad2at( backsql_oc_map_rec *objclass,
		AttributeDescription *ad );
int backsql_destroy_schema_map( backsql_info *si );

#endif /* __BACKSQL_SCHEMA_MAP_H__ */

