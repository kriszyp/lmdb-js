/* group.c - bdb2 backend acl group routine */

#include "portable.h"

#include <stdio.h>

#include <ac/socket.h>
#include <ac/string.h>

#include "slap.h"
#include "back-bdb2.h"
#include "proto-back-bdb2.h"


/* return 0 IFF op_dn is a value in member attribute
 * of entry with gr_dn AND that entry has an objectClass
 * value of groupOfNames
 */
static int
bdb2i_back_group_internal(
	BackendDB	*be,
	Entry	*target,
	const char	*gr_ndn,
	const char	*op_ndn,
	const char	*objectclassValue,
	const char	*groupattrName
)
{
	struct ldbminfo *li = (struct ldbminfo *) be->be_private;    
	Entry *e;
	int rc = 1;
	Attribute *attr;
	struct berval bv;

	Debug( LDAP_DEBUG_ARGS,
		"=> bdb2i_back_group: gr dn: \"%s\"\n",
		gr_ndn, 0, 0 ); 
	Debug( LDAP_DEBUG_ARGS,
		"=> bdb2i_back_group: op dn: \"%s\"\n",
		op_ndn, 0, 0 ); 
	Debug( LDAP_DEBUG_ARGS,
		"=> bdb2i_back_group: objectClass: \"%s\" attrName: \"%s\"\n", 
		objectclassValue, groupattrName, 0 ); 

	Debug( LDAP_DEBUG_ARGS,
		"=> bdb2i_back_group: tr dn: \"%s\"\n",
		target->e_ndn, 0, 0 ); 

	if (strcmp(target->e_ndn, gr_ndn) == 0) {
		/* we already have a LOCKED copy of the entry */
		e = target;
		Debug( LDAP_DEBUG_ARGS,
			"=> bdb2i_back_group: target is group: \"%s\"\n",
			gr_ndn, 0, 0 ); 

	} else {
		/* can we find group entry with reader lock */
		if ((e = bdb2i_dn2entry_r(be, gr_ndn, NULL )) == NULL) {
			Debug( LDAP_DEBUG_ACL,
				"=> bdb2i_back_group: cannot find group: \"%s\"\n",
					gr_ndn, 0, 0 ); 
			return( 1 );
		}

		Debug( LDAP_DEBUG_ACL,
			"=> bdb2i_back_group: found group: \"%s\"\n",
			gr_ndn, 0, 0 ); 
	}

	/* find it's objectClass and member attribute values
	 * make sure this is a group entry
	 * finally test if we can find op_dn in the member attribute value list
	 */
        
	rc = 1;

	if ((attr = attr_find(e->e_attrs, "objectclass")) == NULL)  {
		Debug( LDAP_DEBUG_ACL,
			"<= bdb2i_back_group: failed to find objectClass\n", 0, 0, 0 ); 
		goto return_results;
	}

	bv.bv_val = "ALIAS";
	bv.bv_len = sizeof("ALIAS")-1;

	if (value_find(attr->a_vals, &bv, attr->a_syntax, 1) != 0) {
		Debug( LDAP_DEBUG_ACL,
			"<= bdb2i_back_group: group is an alias\n", 0, 0, 0 ); 
		goto return_results;
	}

	bv.bv_val = "REFERRAL";
	bv.bv_len = sizeof("REFERRAL")-1;

	if (value_find(attr->a_vals, &bv, attr->a_syntax, 1) != 0) {
		Debug( LDAP_DEBUG_ACL,
			"<= bdb2i_back_group: group is a referral\n", 0, 0, 0 ); 
		goto return_results;
	}

	bv.bv_val = (char *) objectclassValue;
	bv.bv_len = strlen( bv.bv_val );

	if (value_find(attr->a_vals, &bv, attr->a_syntax, 1) != 0) {
		Debug( LDAP_DEBUG_ACL,
			"<= bdb2i_back_group: failed to find %s in objectClass\n",
			objectclassValue, 0, 0 ); 
		goto return_results;
	}

	if ((attr = attr_find(e->e_attrs, groupattrName)) == NULL) {
		Debug( LDAP_DEBUG_ACL,
			"<= bdb2i_back_group: failed to find %s\n",
			groupattrName, 0, 0 ); 
		goto return_results;
	}

	Debug( LDAP_DEBUG_ACL,
		"<= bdb2i_back_group: found objectClass %s and %s\n",
		objectclassValue, groupattrName, 0 ); 


	bv.bv_val = (char *) op_ndn;
	bv.bv_len = strlen( op_ndn );         

	if (value_find( attr->a_vals, &bv, attr->a_syntax, 1) != 0 ) {
		Debug( LDAP_DEBUG_ACL,
			"<= bdb2i_back_group: \"%s\" not in \"%s\": %s\n", 
			op_ndn, gr_ndn, groupattrName ); 
		goto return_results;
	}

	Debug( LDAP_DEBUG_ACL,
		"<= bdb2i_back_group: \"%s\" is in \"%s\": %s\n", 
		op_ndn, gr_ndn, groupattrName ); 
	rc = 0;

return_results:
	if( target != e ) {
		/* free entry and reader lock */
		bdb2i_cache_return_entry_r( &li->li_cache, e );                 
	}

	Debug( LDAP_DEBUG_ARGS, "bdb2i_back_group: rc: %d\n", rc, 0, 0 ); 
	return(rc);
}


int
bdb2_back_group(
	BackendDB	*be,
	Entry	*target,
	const char	*gr_ndn,
	const char	*op_ndn,
	const char	*objectclassValue,
	const char	*groupattrName
)
{
	DB_LOCK         lock;
	struct ldbminfo	*li = (struct ldbminfo *) be->be_private;
	struct timeval  time1;
	int             ret;

	bdb2i_start_timing( be->bd_info, &time1 );

	if ( bdb2i_enter_backend_r( &lock ) != 0 ) {

		return( 1 );

	}

	ret = bdb2i_back_group_internal( be, target, gr_ndn, op_ndn,
					objectclassValue, groupattrName );

	(void) bdb2i_leave_backend_r( lock );
	bdb2i_stop_timing( be->bd_info, time1, "GRP", NULL, NULL );

	return( ret );
}


