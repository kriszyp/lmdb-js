/* compare.c - ldbm backend compare routine */

#include "portable.h"

#include <stdio.h>

#include <ac/socket.h>
#include <ac/string.h>

#include "slap.h"
#include "back-ldbm.h"
#include "proto-back-ldbm.h"

extern Attribute        *attr_find();


#ifdef SLAPD_ACLGROUPS
/* return 0 IFF edn is a value in member attribute
 * of entry with bdn AND that entry has an objectClass
 * value of groupOfNames
 */
int
ldbm_back_group(
	Backend     *be,
        char        *bdn,
        char        *edn,
        char        *objectclassValue,
        char        *groupattrName
)
{
        struct ldbminfo *li = (struct ldbminfo *) be->be_private;    
        Entry        *e;
        char        *matched;
        Attribute   *objectClass;
        Attribute   *member;
        int          rc;

	Debug( LDAP_DEBUG_TRACE, "=> ldbm_back_group: bdn: %s\n", bdn, 0, 0 ); 
	Debug( LDAP_DEBUG_TRACE, "=> ldbm_back_group: edn: %s\n", edn, 0, 0 ); 
	Debug( LDAP_DEBUG_TRACE, "=> ldbm_back_group: objectClass: %s attrName: %s\n", 
                objectclassValue, groupattrName, 0 ); 

        /* can we find bdn entry with reader lock */
        if ((e = dn2entry_r(be, bdn, &matched )) == NULL) {
                Debug( LDAP_DEBUG_TRACE, "=> ldbm_back_group: cannot find bdn: %s matched: %x\n", bdn, matched, 0 ); 
                if (matched != NULL)
                        free(matched);
                return( 1 );
        }
        Debug( LDAP_DEBUG_ARGS, "=> ldbm_back_group: found bdn: %s matched: %x\n", bdn, matched, 0 ); 

        /* check for deleted */

        /* find it's objectClass and member attribute values
         * make sure this is a group entry
         * finally test if we can find edn in the member attribute value list *
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

            bvMembers.bv_val = edn;
            bvMembers.bv_len = strlen( edn );         

            if (value_find(objectClass->a_vals, &bvObjectClass, SYNTAX_CIS, 1) != 0) {
                Debug( LDAP_DEBUG_TRACE,
					"<= ldbm_back_group: failed to find %s in objectClass\n", 
                        objectclassValue, 0, 0 ); 
            }
            else if (value_find(member->a_vals, &bvMembers, SYNTAX_CIS, 1) != 0) {
                Debug( LDAP_DEBUG_ACL, "<= ldbm_back_group: %s not in %s: %s\n", 
                        edn, bdn, groupattrName ); 
            }
            else {
                Debug( LDAP_DEBUG_ACL, "<= ldbm_back_group: %s is in %s: %s\n", 
                        edn, bdn, groupattrName ); 
                rc = 0;
            }
        }

        /* free entry and reader lock */
        cache_return_entry_r( &li->li_cache, e );                 
        Debug( LDAP_DEBUG_ARGS, "ldbm_back_group: rc: %d\n", rc, 0, 0 ); 
        return(rc);
}
#endif /* SLAPD_ACLGROUPS */

