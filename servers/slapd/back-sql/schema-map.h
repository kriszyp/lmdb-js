#ifndef __BACKSQL_SCHEMA_MAP_H__
#define __BACKSQL_SCHEMA_MAP_H__

/*
 *	 Copyright 1999, Dmitry Kovalev <mit@openldap.org>, All rights reserved.
 *
 *	 Redistribution and use in source and binary forms are permitted only
 *	 as authorized by the OpenLDAP Public License.	A copy of this
 *	 license is available at http://www.OpenLDAP.org/license.html or
 *	 in file LICENSE in the top-level directory of the distribution.
 */

typedef struct {
	/*
	 * Structure of corresponding LDAP objectClass definition
	 */
	ObjectClass	*oc;
#define BACKSQL_OC_NAME(ocmap)	((ocmap)->oc->soc_cname.bv_val)
	
	struct berval	keytbl;
	struct berval	keycol;
	/* expected to return keyval of newly created entry */
	char		*create_proc;
	/* in case create_proc does not return the keyval of the newly
	 * created row */
	char		*create_keyval;
	/* supposed to expect keyval as parameter and delete 
	 * all the attributes as well */
	char		*delete_proc;
	/* flags whether delete_proc is a function (whether back-sql 
	 * should bind first parameter as output for return code) */
	int		expect_return;
	unsigned long	id;
	Avlnode		*attrs;
} backsql_oc_map_rec;

typedef struct {
	/* Description of corresponding LDAP attribute type */
	AttributeDescription	*ad;
	struct berval	from_tbls;
	struct berval	join_where;
	struct berval	sel_expr;
	/* supposed to expect 2 binded values: entry keyval 
	 * and attr. value to add, like "add_name(?,?,?)" */
	char		*add_proc;
	/* supposed to expect 2 binded values: entry keyval 
	 * and attr. value to delete */
	char		*delete_proc;
	/* for optimization purposes attribute load query 
	 * is preconstructed from parts on schemamap load time */
	char		*query;
	/* following flags are bitmasks (first bit used for add_proc, 
	 * second - for delete_proc) */
	/* order of parameters for procedures above; 
	 * 1 means "data then keyval", 0 means "keyval then data" */
	int 		param_order;
	/* flags whether one or more of procedures is a function 
	 * (whether back-sql should bind first parameter as output 
	 * for return code) */
	int 		expect_return;
	/* TimesTen */
	struct berval	sel_expr_u;
} backsql_at_map_rec;

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

