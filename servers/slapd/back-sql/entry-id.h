#ifndef __BACKSQL_ENTRYID_H__
#define __BACKSQL_ENTRYID_H__

typedef struct __backsql_entryID
{
 unsigned long id;
 unsigned long keyval;
 unsigned long oc_id;
 char *dn;
 struct __backsql_entryID *next;
}backsql_entryID;

backsql_entryID* backsql_dn2id(backsql_entryID* id,SQLHDBC dbh,char *dn);
backsql_entryID* backsql_free_entryID(backsql_entryID* id);//returns next

#endif