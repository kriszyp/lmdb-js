--mappings 

insert into ldap_oc_mappings (id,name,keytbl,keycol,create_proc,delete_proc,expect_return) values (1,'inetOrgPerson','persons','id','select create_person()','select delete_person(?)',0);

insert into ldap_oc_mappings (id,name,keytbl,keycol,create_proc,delete_proc,expect_return) values (2,'document','documents','id',NULL,NULL,0);

insert into ldap_oc_mappings (id,name,keytbl,keycol,create_proc,delete_proc,expect_return) values (3,'organization','institutes','id',NULL,NULL,0);


insert into ldap_attr_mappings (id,oc_map_id,name,sel_expr,from_tbls,join_where,add_proc,delete_proc,param_order,expect_return) values (1,1,'cn','text(persons.name||'' ''||persons.surname)','persons',NULL,'select update_person_cn(?,?)',NULL,3,0);

insert into ldap_attr_mappings (id,oc_map_id,name,sel_expr,from_tbls,join_where,add_proc,delete_proc,param_order,expect_return) values (2,1,'telephoneNumber','phones.phone','persons,phones','phones.pers_id=persons.id','select add_phone(?,?)','select delete_phone(?,?)',3,0);

insert into ldap_attr_mappings (id,oc_map_id,name,sel_expr,from_tbls,join_where,add_proc,delete_proc,param_order,expect_return) values (3,1,'givenName','persons.name','persons',NULL,'update persons set name=? where id=?',NULL,3,0);
insert into ldap_attr_mappings (id,oc_map_id,name,sel_expr,from_tbls,join_where,add_proc,delete_proc,param_order,expect_return) values (6,1,'sn','persons.surname','persons',NULL,'update persons set surname=? where id=?',NULL,3,0);

insert into ldap_attr_mappings (id,oc_map_id,name,sel_expr,from_tbls,join_where,add_proc,delete_proc,param_order,expect_return) values (4,2,'description','documents.abstract','documents',NULL,NULL,NULL,3,0);

insert into ldap_attr_mappings (id,oc_map_id,name,sel_expr,from_tbls,join_where,add_proc,delete_proc,param_order,expect_return) values (5,2,'documentTitle','documents.title','documents',NULL,NULL,NULL,3,0);

-- insert into ldap_attr_mappings (id,oc_map_id,name,sel_expr,from_tbls,join_where,add_proc,delete_proc,param_order,expect_return)
-- values (6,2,'documentAuthor','persons.name','persons,documents,authors_docs',
--         'persons.id=authors_docs.pers_id AND documents.id=authors_docs.doc_id',
-- 	NULL,NULL,3,0);

insert into ldap_attr_mappings (id,oc_map_id,name,sel_expr,from_tbls,join_where,add_proc,delete_proc,param_order,expect_return) values (7,3,'o','institutes.name','institutes',NULL,NULL,NULL,3,0);

insert into ldap_attr_mappings (id,oc_map_id,name,sel_expr,from_tbls,join_where,add_proc,delete_proc,param_order,expect_return) values (8,1,'documentIdentifier','ldap_entries.dn','ldap_entries,documents,authors_docs,persons','ldap_entries.keyval=documents.id AND ldap_entries.oc_map_id=2 AND authors_docs.doc_id=documents.id AND authors_docs.pers_id=persons.id',NULL,NULL,3,0);

insert into ldap_attr_mappings (id,oc_map_id,name,sel_expr,from_tbls,join_where,add_proc,delete_proc,param_order,expect_return) values (9,2,'documentAuthor','ldap_entries.dn','ldap_entries,documents,authors_docs,persons','ldap_entries.keyval=persons.id AND ldap_entries.oc_map_id=1 AND authors_docs.doc_id=documents.id AND authors_docs.pers_id=persons.id',NULL,NULL,3,0);
	
-- entries
	
insert into ldap_entries (id,dn,oc_map_id,parent,keyval) values (1,'o=sql,c=RU',3,0,1);

insert into ldap_entries (id,dn,oc_map_id,parent,keyval) values (2,'cn=Mitya Kovalev,o=sql,c=RU',1,1,1);

insert into ldap_entries (id,dn,oc_map_id,parent,keyval) values (3,'cn=Torvlobnor Puzdoy,o=sql,c=RU',1,1,2);

insert into ldap_entries (id,dn,oc_map_id,parent,keyval) values (4,'cn=Akakiy Zinberstein,o=sql,c=RU',1,1,3);

insert into ldap_entries (id,dn,oc_map_id,parent,keyval) values (5,'documentTitle=book1,o=sql,c=RU',2,1,1);

insert into ldap_entries (id,dn,oc_map_id,parent,keyval) values (6,'documentTitle=book2,o=sql,c=RU',2,1,2);
	
	
-- referrals

insert into ldap_entry_objclasses (entry_id,oc_name) values (4,'referral');

insert into ldap_referrals (entry_id,url) values (4,'ldap://localhost/');

-- procedures

create function create_person () returns int
as '
	select setval (''persons_id_seq'', (select max(id) from persons));
	insert into persons (id,name,surname) 
		values (nextval(''persons_id_seq''),'''','''');
	select max(id) from persons
' language 'sql';

create function update_person_cn (varchar, int) returns int
as '
	update persons set name = (
		select case 
			when position('' '' in $1) = 0 then $1 
			else substr($1, 1, position('' '' in $1) - 1)
		end
	),surname = (
		select case 
			when position('' '' in $1) = 0 then ''''
			else substr($1, position('' '' in $1) + 1) 
		end
	) where id = $2;
	select $2 as return
' language 'sql';

create function delete_person (int) returns int
as '
	delete from phones where pers_id = $1;
	delete from authors_docs where pers_id = $1;
	delete from persons where id = $1;
	select $1 as return
' language 'sql';

create function add_phone (varchar, int) returns int
as '
	select setval (''phones_id_seq'', (select max(id) from phones));
	insert into phones (id,phone,pers_id)
		values (nextval(''phones_id_seq''),$1,$2);
	select max(id) from phones
' language 'sql';

create function delete_phone (varchar, int) returns int
as '
	delete from phones where phone = $1 and pers_id = $2;
	select $2 as result
' language 'sql';

