/* group.c - ldbm backend acl group routine */

#include "portable.h"

#include <stdio.h>

#include <ac/socket.h>
#include <ac/string.h>

#include "slap.h"
#include "back-ldbm.h"
#include "proto-back-ldbm.h"


#ifdef SLAPD_ACLGROUPS
/* return 0 IFF op_dn is a value in member attribute
 * of entry with gr_dn AND that entry has an objectClass
 * value of groupOfNames
 */
int
ldbm_back_group(
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
		"=> ldbm_back_group: gr dn: \"%s\"\n",
		gr_ndn, 0, 0 ); 
	Debug( LDAP_DEBUG_TRACE,
		"=> ldbm_back_group: op dn: \"%s\"\n",
		op_ndn, 0, 0 ); 
	Debug( LDAP_DEBUG_TRACE,
		"=> ldbm_back_group: objectClass: \"%s\" attrName: \"%s\"\n", 
		objectclassValue, groupattrName, 0 ); 

	Debug( LDAP_DEBUG_TRACE,
		"=> ldbm_back_group: tr dn: \"%s\"\n",
		target->e_ndn, 0, 0 ); 

	if (strcmp(target->e_ndn, gr_ndn) == 0) {
		/* we already have a LOCKED copy of the entry */
		e = target;
        	Debug( LDAP_DEBUG_ARGS,
			"=> ldbm_back_group: target is group: \"%s\"\n",
			gr_ndn, 0, 0 ); 
	} else {
		/* can we find group entry with reader lock */
		if ((e = dn2entry_r(be, gr_ndn, &matched )) == NULL) {
			Debug( LDAP_DEBUG_TRACE,
				"=> ldbm_back_group: cannot find group: \"%s\" matched: \"%s\"\n",
					gr_ndn, (matched ? matched : ""), 0 ); 
			if (matched != NULL)
				free(matched);
			return( 1 );
		}
		Debug( LDAP_DEBUG_ARGS,
			"=> ldbm_back_group: found group: \"%s\"\n",
			gr_ndn, 0, 0 ); 
        }


        /* check for deleted */

        /* find it's objectClass and member attribute values
         * make sure this is a group entry
         * finally test if we can find op_dn in the member attribute value list *
         */
        
        rc = 1;
        if ((objectClass = attr_find(e->e_attrs, "objectclass")) == NULL)  {
            Debug( LDAP_DEBUG_TRACE, "<= ldbm_back_group: failed to find objectClass\n", 0, 0, 0 ); 
        }
        else if ((member = attr_find(e->e_attrs, groupattrName)) == NULL) {
            Debug( LDAP_DEBUG_TRACE, "<= ldbm_back_group: failed to find %s\n", groupattrName, 0, 0 ); 
        }
        else {
            struct berval bvObjectClass;
            struct berval bvMembers;

            Debug( LDAP_DEBUG_ARGS, "<= ldbm_back_group: found objectClass and %s\n", groupattrName, 0, 0 ); 

            bvObjectClass.bv_val = objectclassValue;
            bvObjectClass.bv_len = strlen( bvObjectClass.bv_val );         

            bvMembers.bv_val = op_ndn;
            bvMembers.bv_len = strlen( op_ndn );         

            if (value_find(objectClass->a_vals, &bvObjectClass, SYNTAX_CIS, 1) != 0) {
                Debug( LDAP_DEBUG_TRACE,
					"<= ldbm_back_group: failed to find %s in objectClass\n", 
                        objectclassValue, 0, 0 ); 
            }
            else if (value_find(member->a_vals, &bvMembers, member->a_syntax, 1) != 0) {
                Debug( LDAP_DEBUG_ACL,
					"<= ldbm_back_group: \"%s\" not in \"%s\": %s\n", 
					op_ndn, gr_ndn, groupattrName ); 
            }
            else {
				Debug( LDAP_DEBUG_ACL,
					"<= ldbm_back_group: \"%s\" is in \"%s\": %s\n", 
					op_ndn, gr_ndn, groupattrName ); 
                rc = 0;
            }
        }

	if( target != e ) {
		/* free entry and reader lock */
		cache_return_entry_r( &li->li_cache, e );                 
	}

	Debug( LDAP_DEBUG_ARGS, "ldbm_back_group: rc: %d\n", rc, 0, 0 ); 
	return(rc);
}
#endif /* SLAPD_ACLGROUPS */

