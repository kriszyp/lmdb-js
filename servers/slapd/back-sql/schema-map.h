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
	char		*name;
	char		*keytbl;
	char		*keycol;
	/* expected to return keyval of newly created entry */
	char		*create_proc;
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
	/* literal name of corresponding LDAP attribute type */
	char		*name;
	char		*from_tbls;
	char		*join_where;
	char		*sel_expr;
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
	 * second - for modify, third - for delete_proc) */
	/* order of parameters for procedures above; 
	 * 1 means "data then keyval", 0 means "keyval then data" */
	int 		param_order;
	/* flags whether one or more of procedures is a function 
	 * (whether back-sql should bind first parameter as output 
	 * for return code) */
	int 		expect_return;
	/* TimesTen */
	char		*sel_expr_u;
} backsql_at_map_rec;

/* defines to support bitmasks above */
#define BACKSQL_ADD	1
#define BACKSQL_DEL	2

int backsql_load_schema_map( backsql_info *si, SQLHDBC dbh );
backsql_oc_map_rec *backsql_oc_with_name( backsql_info *si, char *objclass );
backsql_oc_map_rec *backsql_oc_with_id( backsql_info *si, unsigned long id );
backsql_at_map_rec *backsql_at_with_name( backsql_oc_map_rec *objclass,
		char *attr );
int backsql_destroy_schema_map( backsql_info *si );

#endif /* __BACKSQL_SCHEMA_MAP_H__ */

