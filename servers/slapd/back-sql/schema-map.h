#ifndef __BACKSQL_SCHEMA_MAP_H__
#define __BACKSQL_SCHEMA_MAP_H__

typedef struct
{
 char *name;
 char *keytbl;
 char *keycol;
 char *create_proc;//expected to return keyval of newly created entry
 char *delete_proc;//supposed to expect keyval as parameter and delete all the attributes as well
 unsigned long id;
 Avlnode *attrs;
}backsql_oc_map_rec;

typedef struct
{
 char *name;//literal name of corresponding LDAP attribute type
 char *from_tbls;
 char *join_where;
 char *sel_expr;
 char *add_proc; //supposed to expect 2 binded values: entry keyval and attr. value to add, like "add_name(?,?)"
 char *modify_proc; //supposed to expect two binded values: entry keyval and old and new values of attr
 char *delete_proc; //supposed to expect 2 binded values: entry keyval and attr. value to delete
 char *query; //for optimization purposes attribute load query is preconstructed from parts on schemamap load time
}backsql_at_map_rec;

int backsql_load_schema_map(backsql_info *si,SQLHDBC dbh);
backsql_oc_map_rec* backsql_oc_with_name(backsql_info *si,char* objclass);
backsql_oc_map_rec* backsql_oc_with_id(backsql_info *si,unsigned long id);
backsql_at_map_rec* backsql_at_with_name(backsql_oc_map_rec* objclass,char* attr);
int backsql_destroy_schema_map(backsql_info *si);

#endif