/* compare.c - ldbm backend compare routine */

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include "slap.h"
#include "back-ldbm.h"

extern Entry            *dn2entry();
extern Attribute        *attr_find();


#ifdef ACLGROUP
/* return 0 IFF edn is a value in uniqueMember attribute
 * of entry with bdn AND that entry has an objectClass
 * value of groupOfUniqueNames
 */
int
ldbm_back_group(
	Backend     *be,
        char        *bdn,
        char        *edn
)
{
        struct ldbminfo *li = (struct ldbminfo *) be->be_private;    
        Entry        *e;
        char        *matched;
        Attribute   *objectClass;
        Attribute   *uniqueMember;
        int          rc;

	Debug( LDAP_DEBUG_TRACE, "ldbm_back_group: bdn: %s\n", bdn, 0, 0 ); 
	Debug( LDAP_DEBUG_TRACE, "ldbm_back_group: edn: %s\n", edn, 0, 0 ); 

        /* can we find bdn entry */
        if ((e = dn2entry(be, bdn, &matched )) == NULL) {
                Debug( LDAP_DEBUG_TRACE, "ldbm_back_group: cannot find bdn: %s matched: %x\n", bdn, matched, 0 ); 
                if (matched != NULL)
                        free(matched);
                return( 1 );
        }
        Debug( LDAP_DEBUG_ARGS, "ldbm_back_group: found bdn: %s matched: %x\n", bdn, matched, 0 ); 


        /* find it's objectClass and uniqueMember attribute values
         * make sure this is a group entry
         * finally test if we can find edn in the uniqueMember attribute value list *
         */
        
        rc = 1;
        if ((objectClass = attr_find(e->e_attrs, "objectclass")) == NULL)  {
            Debug( LDAP_DEBUG_TRACE, "ldbm_back_group: failed to find objectClass\n", 0, 0, 0 ); 
        }
        else if ((uniqueMember = attr_find(e->e_attrs, "uniquemember")) == NULL) {
            Debug( LDAP_DEBUG_TRACE, "ldbm_back_group: failed to find uniqueMember\n", 0, 0, 0 ); 
        }
        else {
            struct berval bvObjectClass;
            struct berval bvUniqueMembers;

            Debug( LDAP_DEBUG_ARGS, "ldbm_back_group: found objectClass and uniqueMembers\n", 0, 0, 0 ); 

            bvObjectClass.bv_val = "groupofuniquenames";
            bvObjectClass.bv_len = strlen( bvObjectClass.bv_val );         
            bvUniqueMembers.bv_val = edn;
            bvUniqueMembers.bv_len = strlen( edn );         

            if (value_find(objectClass->a_vals, &bvObjectClass, SYNTAX_CIS, 1) != 0) {
                Debug( LDAP_DEBUG_TRACE, "ldbm_back_group: failed to find objectClass in groupOfUniqueNames\n", 
                        0, 0, 0 ); 
            }
            else if (value_find(uniqueMember->a_vals, &bvUniqueMembers, SYNTAX_CIS, 1) != 0) {
                Debug( LDAP_DEBUG_ACL, "ldbm_back_group: %s not in %s: groupOfUniqueNames\n", 
                        edn, bdn, 0 ); 
            }
            else {
                Debug( LDAP_DEBUG_ACL, "ldbm_back_group: %s is in %s: groupOfUniqueNames\n", 
                        edn, bdn, 0 ); 
                rc = 0;
            }
        }

        /* free e */
        cache_return_entry( &li->li_cache, e );                 
        Debug( LDAP_DEBUG_ARGS, "ldbm_back_group: rc: %d\n", rc, 0, 0 ); 
        return(rc);
}
#endif

