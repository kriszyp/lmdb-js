#ifndef __BACKSQL_ENTRYID_H__
#define __BACKSQL_ENTRYID_H__

/*
 *	 Copyright 1999, Dmitry Kovalev <mit@openldap.org>, All rights reserved.
 *
 *	 Redistribution and use in source and binary forms are permitted only
 *	 as authorized by the OpenLDAP Public License.	A copy of this
 *	 license is available at http://www.OpenLDAP.org/license.html or
 *	 in file LICENSE in the top-level directory of the distribution.
 */


typedef struct backsql_entryID {
	unsigned long		id;
	unsigned long		keyval;
	unsigned long		oc_id;
	struct berval		dn;
	struct backsql_entryID	*next;
} backsql_entryID;

int backsql_dn2id( backsql_info *bi, backsql_entryID *id,
		SQLHDBC dbh, struct berval *dn );

int backsql_count_children( backsql_info *bi, SQLHDBC dbh,
		struct berval *dn, unsigned long *nchildren );
int backsql_has_children( backsql_info *bi, SQLHDBC dbh, struct berval *dn );


/* returns next */
backsql_entryID *backsql_free_entryID( backsql_entryID *id, int freeit );

#endif /* __BACKSQL_ENTRYID_H__ */

