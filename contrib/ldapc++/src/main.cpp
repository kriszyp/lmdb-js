/*
 * Copyright 2000, OpenLDAP Foundation, All Rights Reserved.
 * COPYING RESTRICTIONS APPLY, see COPYRIGHT file
 */

#include<iostream.h>
#include<strstream>
#include"LDAPAsynConnection.h"
#include "LDAPConstraints.h"
#include"LDAPResult.h"
#include"LDAPSearchResult.h"
#include"LDAPSearchReference.h"
#include"LDAPAttribute.h"
#include"LDAPAttributeList.h"
#include"LDAPEntry.h"
#include"LDAPException.h"
#include"LDAPModification.h"
#include"debug.h"

int main(){
	LDAPAsynConnection *lc=new LDAPAsynConnection("localhost",9009);
    cout << "----------------------doing bind...." <<  endl;
    try{
        LDAPMessageQueue *q=lc->bind("cn=Manager,o=Organisation,c=DE" ,
                "secret"); 
        LDAPMsg *res=q->getNext();
        if( ((LDAPResult*)res)->getResultCode() == LDAPResult::SUCCESS){
            cout << "--------------------...successfully bound" << endl;
        }
    }catch (LDAPException e){
        cout << "-------------------------...error during bind" << endl;
        cout << e << endl;
    }
    cout << "--------------------starting search" << endl;
    try{
        LDAPMessageQueue *q=lc->search("");
		LDAPMsg *res=q->getNext();
        bool cont=true;
		while( cont  ) {
            switch(res->getMessageType()){
                LDAPSearchResult *res2;
                LDAPEntry *entry;
                case LDAP_RES_SEARCH_ENTRY :
                    res2= (LDAPSearchResult*)res;
                    entry=  res2->getEntry();
                    cout << "Entry:            " << *entry << endl; 
                    delete res;
                    res=q->getNext();
                break;
                case LDAP_RES_SEARCH_REFERENCE :
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
		cout << e << endl;
	}
}

