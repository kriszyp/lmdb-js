/*
 * Copyright 2000, OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include<iostream.h>
#include<strstream>
#include "LDAPConnection.h"
#include "LDAPConstraints.h"
#include "LDAPSearchReference.h"
#include "LDAPSearchResults.h"
#include "LDAPAttribute.h"
#include "LDAPAttributeList.h"
#include "LDAPEntry.h"
#include "LDAPException.h"
#include "LDAPModification.h"
#include "LDAPReferralException.h"

#include"debug.h"

int main(){
    LDAPConstraints* cons=new LDAPConstraints;
    LDAPControlSet* ctrls=new LDAPControlSet;
    ctrls->add(LDAPCtrl(LDAP_CONTROL_MANAGEDSAIT));
    cons->setServerControls(ctrls);
    LDAPConnection *lc=new LDAPConnection("localhost",9009);
    lc->setConstraints(cons);
    cout << "----------------------doing bind...." <<  endl;
    try{
        lc->bind("cn=Manager,o=Organisation,c=DE" , "secret",cons);
        cout << lc->getHost() << endl;    
        bool result = lc->compare("cn=Manager,o=Organisation,c=DE", 
                LDAPAttribute("cn","Manaer"));
        cout << "Compare: " << result << endl;
    
        LDAPAttributeList* attrs=new LDAPAttributeList();
        StringList values;
        StringList s2;
        values.add("top");
        values.add("Person");
        attrs->addAttribute(LDAPAttribute("objectClass",values));
        attrs->addAttribute(LDAPAttribute("cn","Peter"));
        attrs->addAttribute(LDAPAttribute("sn","Peter,hallo"));
        LDAPEntry* entry=new LDAPEntry(
                "cn=Peter , o=Organisation, c=DE", attrs);    
//        lc->add(entry);
        
//        lc->del("ou=Groups,o=Organisation,c=DE");

        LDAPSearchResults* entries = lc->search("o=Organisation,c=DE",
                LDAPConnection::SEARCH_ONE);
        if (entries != 0){
            LDAPEntry* entry = entries->getNext();
            if(entry != 0){
                cout << *(entry) << endl;
            }
            while(entry){
                try{
                    entry = entries->getNext();
                    if(entry != 0){
                        cout << *(entry) << endl;
                    }
                    delete entry;
                }catch(LDAPReferralException e){
                    cout << "Caught Referral" << endl;
                }
            }
        }
        
        lc->unbind();
        delete lc;
   }catch (LDAPException e){
        cout << "------------------------- caught Exception ---------"<< endl;
        cout << e << endl;
    }

    /*
    cout << "--------------------starting search" << endl;
    LDAPAttributeList* attrs=new LDAPAttributeList();
    StringList values;
    values.add("top");
    values.add("organizationalUnit");
    attrs->addAttribute(LDAPAttribute("objectClass",values));
    attrs->addAttribute(LDAPAttribute("ou","Groups"));
    LDAPEntry* entry=new LDAPEntry(
            "ou=Groups, o=Organisation, c=DE", attrs);    

    LDAPAttribute newattr("description");
    LDAPModification::mod_op op = LDAPModification::OP_DELETE;
    LDAPModList *mod=new LDAPModList();
    mod->addModification(LDAPModification(newattr,op));
    LDAPMessageQueue* q=0;
    try{
        q=lc->search("o=Organisation,c=de",LDAPAsynConnection::SEARCH_SUB,
         "objectClass=*",StringList());
//        q=lc->add(entry);
//        q=lc->modify("cn=Manager,o=Organisation,c=DE",
//                mod);
        LDAPMsg *res=q->getNext();
        bool cont=true;
        while( cont  ) {
            switch(res->getMessageType()){
                LDAPSearchResult *res2;
                const LDAPEntry *entry;
                case LDAP_RES_SEARCH_ENTRY :
                    res2= (LDAPSearchResult*)res;
                    entry=  res2->getEntry();
                    cout << "Entry:            " << *entry << endl; 
                    delete res;
                    res=q->getNext();
                break;
                case LDAP_RES_SEARCH_REFERENCE :
                    cout << "Reference:         "  << endl;
                    delete res;
                    res=q->getNext();
                break;
                default :
                    cout << ( *(LDAPResult*) res) << endl;
                    delete res;
                    cout  << "-----------------search done" << endl;
                    cont=false;
                break;
            }
        }
        delete q;
    }catch (LDAPException e){
        cout << "----------------error during search" << endl;
        delete q;
        cout << e << endl;
    }
    lc->unbind();
    */
}

