insert into institutes (id,name) values (institute_ids.nextval,'sql');

insert into persons (id,name) values (person_ids.nextval,'Mitya Kovalev');

insert into persons (id,name) values (person_ids.nextval,'Torvlobnor Puzdoy');

insert into persons (id,name) values (person_ids.nextval,'Akakiy Zinberstein');


insert into phones (id,phone,pers_id) values (phone_ids.nextval,'332-2334',1);

insert into phones (id,phone,pers_id) values (phone_ids.nextval,'222-3234',1);

insert into phones (id,phone,pers_id) values (phone_ids.nextval,'545-4563',2);


insert into documents (id,abstract,title) values (document_ids.nextval,'abstract1','book1');

insert into documents (id,abstract,title) values (document_ids.nextval,'abstract2','book2');


insert into authors_docs (pers_id,doc_id) values (1,1);

insert into authors_docs (pers_id,doc_id) values (1,2);

insert into authors_docs (pers_id,doc_id) values (2,1);


insert into ldap_entries (id,dn,objclass,parent,keyval)
values (ldap_entry_ids.nextval,'o=sql,c=RU',3,0,1);

insert into ldap_entries (id,dn,objclass,parent,keyval)
values (ldap_entry_ids.nextval,'cn=Mitya Kovalev,o=sql,c=RU',1,1,1);

insert into ldap_entries (id,dn,objclass,parent,keyval)
values (ldap_entry_ids.nextval,'cn=Torvlobnor Puzdoy,o=sql,c=RU',1,1,2);

insert into ldap_entries (id,dn,objclass,parent,keyval)
values (ldap_entry_ids.nextval,'cn=Akakiy Zinberstein,o=sql,c=RU',1,1,3);

insert into ldap_entries (id,dn,objclass,parent,keyval)
values (ldap_entry_ids.nextval,'documentTitle=book1,o=sql,c=RU',2,1,1);

insert into ldap_entries (id,dn,objclass,parent,keyval)
values (ldap_entry_ids.nextval,'documentTitle=book2,o=sql,c=RU',2,1,2);
