insert into ldap_objclasses (id,name,keytbl,keycol,create_proc,delete_proc)
values (1,'person','persons','id',NULL,NULL);

insert into ldap_objclasses (id,name,keytbl,keycol,create_proc,delete_proc)
values (2,'document','documents','id',NULL,NULL);

insert into ldap_objclasses (id,name,keytbl,keycol,create_proc,delete_proc)
values (3,'organization','institutes','id',NULL,NULL);


insert into ldap_attrs (id,oc_id,name,sel_expr,from_tbls,join_where,add_proc,modify_proc,delete_proc)
values (1,1,'cn','persons.name','persons',NULL,NULL,NULL,NULL);

insert into ldap_attrs (id,oc_id,name,sel_expr,from_tbls,join_where,add_proc,modify_proc,delete_proc)
values (2,1,'telephoneNumber','phones.phone','persons,phones',
        'phones.pers_id=persons.id',NULL,NULL,NULL);

insert into ldap_attrs (id,oc_id,name,sel_expr,from_tbls,join_where,add_proc,modify_proc,delete_proc)
values (3,1,'sn','persons.name','persons',NULL,NULL,NULL,NULL);

insert into ldap_attrs (id,oc_id,name,sel_expr,from_tbls,join_where,add_proc,modify_proc,delete_proc)
values (4,2,'abstract','documents.abstract','documents',NULL,NULL,NULL,NULL);

insert into ldap_attrs (id,oc_id,name,sel_expr,from_tbls,join_where,add_proc,modify_proc,delete_proc)
values (5,2,'documentTitle','documents.title','documents',NULL,NULL,NULL,NULL);

insert into ldap_attrs (id,oc_id,name,sel_expr,from_tbls,join_where,add_proc,modify_proc,delete_proc)
values (6,2,'documentAuthor','persons.name','persons,documents,authors_docs',
        'persons.id=authors_docs.pers_id AND documents.id=authors_docs.doc_id',
	NULL,NULL,NULL);

insert into ldap_attrs (id,oc_id,name,sel_expr,from_tbls,join_where,add_proc,modify_proc,delete_proc)
values (7,3,'o','institutes.name','institutes',NULL,NULL,NULL,NULL);

insert into ldap_attrs (id,oc_id,name,sel_expr,from_tbls,join_where,add_proc,modify_proc,delete_proc)
values (8,1,'documentDN','ldap_entries.dn','ldap_entries,documents,authors_docs,persons',
        'ldap_entries.keyval=documents.id AND ldap_entries.objclass=2 AND authors_docs.doc_id=documents.id AND authors_docs.pers_id=persons.id',
	NULL,NULL,NULL);

insert into ldap_attrs (id,oc_id,name,sel_expr,from_tbls,join_where,add_proc,modify_proc,delete_proc)
values (9,2,'authorDN','ldap_entries.dn','ldap_entries,documents,authors_docs,persons',
        'ldap_entries.keyval=persons.id AND ldap_entries.objclass=1 AND authors_docs.doc_id=documents.id AND authors_docs.pers_id=persons.id',
	NULL,NULL,NULL);
