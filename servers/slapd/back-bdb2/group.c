/* group.c - bdb2 backend acl group routine */

#include "portable.h"

#include <stdio.h>

#include <ac/socket.h>
#include <ac/string.h>

#include "slap.h"
#include "back-bdb2.h"
#include "proto-back-bdb2.h"


#ifdef SLAPD_ACLGROUPS
/* return 0 IFF op_dn is a value in member attribute
 * of entry with gr_dn AND that entry has an objectClass
 * value of groupOfNames
 */
static int
bdb2i_back_group_internal(
	Backend	*be,
	Entry	*target,
	char	*gr_ndn,
	char	*op_ndn,
	char	*objectclassValue,
	char	*groupattrName
)
{
        struct ldbminfo *li = (struct ldbminfo *) be->be_private;    
        Entry        *e;
        char        *matched;
        Attribute   *objectClass;
        Attribute   *member;
        int          rc;

	Debug( LDAP_DEBUG_TRACE,
		"=> bdb2i_back_group: gr dn: \"%s\"\n",
		gr_ndn, 0, 0 ); 
	Debug( LDAP_DEBUG_TRACE,
		"=> bdb2i_back_group: op dn: \"%s\"\n",
		op_ndn, 0, 0 ); 
	Debug( LDAP_DEBUG_TRACE,
		"=> bdb2i_back_group: objectClass: \"%s\" attrName: \"%s\"\n", 
		objectclassValue, groupattrName, 0 ); 

	Debug( LDAP_DEBUG_TRACE,
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
		if ((e = bdb2i_dn2entry_r(be, gr_ndn, &matched )) == NULL) {
			Debug( LDAP_DEBUG_TRACE,
				"=> bdb2i_back_group: cannot find group: \"%s\" matched: \"%s\"\n",
					gr_ndn, (matched ? matched : ""), 0 ); 
			if (matched != NULL)
				free(matched);
			return( 1 );
		}
		Debug( LDAP_DEBUG_ARGS,
			"=> bdb2i_back_group: found group: \"%s\"\n",
			gr_ndn, 0, 0 ); 
        }


        /* check for deleted */

        /* find it's objectClass and member attribute values
         * make sure this is a group entry
         * finally test if we can find op_dn in the member attribute value list *
         */
        
        rc = 1;
        if ((objectClass = attr_find(e->e_attrs, "objectclass")) == NULL)  {
            Debug( LDAP_DEBUG_TRACE, "<= bdb2i_back_group: failed to find objectClass\n", 0, 0, 0 ); 
        }
        else if ((member = attr_find(e->e_attrs, groupattrName)) == NULL) {
            Debug( LDAP_DEBUG_TRACE, "<= bdb2i_back_group: failed to find %s\n", groupattrName, 0, 0 ); 
        }
        else {
            struct berval bvObjectClass;
            struct berval bvMembers;

            Debug( LDAP_DEBUG_ARGS, "<= bdb2i_back_group: found objectClass and %s\n", groupattrName, 0, 0 ); 

            bvObjectClass.bv_val = objectclassValue;
            bvObjectClass.bv_len = strlen( bvObjectClass.bv_val );         

            bvMembers.bv_val = op_ndn;
            bvMembers.bv_len = strlen( op_ndn );         

            if (value_find(objectClass->a_vals, &bvObjectClass, SYNTAX_CIS, 1) != 0) {
                Debug( LDAP_DEBUG_TRACE,
					"<= bdb2i_back_group: failed to find %s in objectClass\n", 
                        objectclassValue, 0, 0 ); 
            }
            else if (value_find(member->a_vals, &bvMembers, SYNTAX_CIS, 1) != 0) {
                Debug( LDAP_DEBUG_ACL,
					"<= bdb2i_back_group: \"%s\" not in \"%s\": %s\n", 
					op_ndn, gr_ndn, groupattrName ); 
            }
            else {
				Debug( LDAP_DEBUG_ACL,
					"<= bdb2i_back_group: \"%s\" is in \"%s\": %s\n", 
					op_ndn, gr_ndn, groupattrName ); 
                rc = 0;
            }
        }

	if( target != e ) {
		/* free entry and reader lock */
		bdb2i_cache_return_entry_r( &li->li_cache, e );                 
	}

	Debug( LDAP_DEBUG_ARGS, "bdb2i_back_group: rc: %d\n", rc, 0, 0 ); 
	return(rc);
}


int
bdb2_back_group(
	Backend	*be,
	Entry	*target,
	char	*gr_ndn,
	char	*op_ndn,
	char	*objectclassValue,
	char	*groupattrName
)
{
	DB_LOCK  lock;
	struct ldbminfo	*li = (struct ldbminfo *) be->be_private;

	struct timeval  time1, time2;
	char   *elapsed_time;
	int    ret;

	gettimeofday( &time1, NULL );

	if ( bdb2i_enter_backend_r( &li->li_db_env, &lock ) != 0 ) {

		return( 1 );

	}

	ret = bdb2i_back_group_internal( be, target, gr_ndn, op_ndn,
					objectclassValue, groupattrName );

	(void) bdb2i_leave_backend( &li->li_db_env, lock );

	if ( bdb2i_do_timing ) {

		gettimeofday( &time2, NULL);
		elapsed_time = bdb2i_elapsed( time1, time2 );
		Debug( LDAP_DEBUG_ANY, "GRP elapsed=%s\n",
				elapsed_time, 0, 0 );
		free( elapsed_time );

	}

	return( ret );
}

#endif /* SLAPD_ACLGROUPS */

