insert into ldap_objclasses (id,name,keytbl,keycol,create_proc,delete_proc,expect_return)
values (1,'person','persons','id','{call create_person(?)}','{call delete_person(?)}',0);

insert into ldap_objclasses (id,name,keytbl,keycol,create_proc,delete_proc,expect_return)
values (2,'document','documents','id','{call create_document(?)}','{call delete_document(?)}',0);

insert into ldap_objclasses (id,name,keytbl,keycol,create_proc,delete_proc,expect_return)
values (3,'organization','institutes','id','{call create_org(?)}','{call delete_org(?)}',0);


insert into ldap_attrs (id,oc_id,name,sel_expr,from_tbls,join_where,add_proc,modify_proc,delete_proc,param_order,expect_return)
values (1,1,'cn','persons.name','persons',NULL,'{call set_person_name(?,?)}',
        NULL,NULL,0,0);

insert into ldap_attrs (id,oc_id,name,sel_expr,from_tbls,join_where,add_proc,modify_proc,delete_proc,param_order,expect_return)
values (2,1,'telephoneNumber','phones.phone','persons,phones',
        'phones.pers_id=persons.id','{call add_phone(?,?)}',
        NULL,'{call delete_phone(?,?)}',0,0);

insert into ldap_attrs (id,oc_id,name,sel_expr,from_tbls,join_where,add_proc,modify_proc,delete_proc,param_order,expect_return)
values (3,1,'sn','persons.name','persons',NULL,'{call set_person_name(?,?)}',
        NULL,NULL,0,0);

insert into ldap_attrs (id,oc_id,name,sel_expr,from_tbls,join_where,add_proc,modify_proc,delete_proc,param_order,expect_return)
values (4,2,'abstract','documents.abstract','documents',NULL,'{call set_doc_abstract(?,?)}',
        NULL,NULL,0,0);

insert into ldap_attrs (id,oc_id,name,sel_expr,from_tbls,join_where,add_proc,modify_proc,delete_proc,param_order,expect_return)
values (5,2,'documentTitle','documents.title','documents',NULL,'{call set_doc_title(?,?)}',
        NULL,NULL,0,0);

insert into ldap_attrs (id,oc_id,name,sel_expr,from_tbls,join_where,add_proc,modify_proc,delete_proc,param_order,expect_return)                         
values (6,2,'documentAuthor','persons.name','persons,documents,authors_docs',
        'persons.id=authors_docs.pers_id AND documents.id=authors_docs.doc_id',
	NULL,NULL,NULL,0,0);

insert into ldap_attrs (id,oc_id,name,sel_expr,from_tbls,join_where,add_proc,modify_proc,delete_proc,param_order,expect_return)
values (7,3,'o','institutes.name','institutes',NULL,'{call set_org_name(?,?)}',
        NULL,NULL,0,0);

insert into ldap_attrs (id,oc_id,name,sel_expr,from_tbls,join_where,add_proc,modify_proc,delete_proc,param_order,expect_return)
values (8,1,'documentDN','ldap_entries.dn','ldap_entries,documents,authors_docs,persons',
        'ldap_entries.keyval=documents.id AND ldap_entries.objclass=2 AND authors_docs.doc_id=documents.id AND authors_docs.pers_id=persons.id',
	'{?=call make_doc_link(?,?)}',NULL,'{?=call del_doc_link(?,?)}',0,3);

insert into ldap_attrs (id,oc_id,name,sel_expr,from_tbls,join_where,add_proc,modify_proc,delete_proc,param_order,expect_return)
values (9,2,'authorDN','ldap_entries.dn','ldap_entries,documents,authors_docs,persons',
        'ldap_entries.keyval=persons.id AND ldap_entries.objclass=1 AND authors_docs.doc_id=documents.id AND authors_docs.pers_id=persons.id',
	'{?=call make_author_link(?,?)}',NULL,'{?=call del_author_link(?,?)}',0,3);
