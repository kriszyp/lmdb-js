set IDENTITY_INSERT institutes ON
insert into institutes (id,name) values (1,'sql')
set IDENTITY_INSERT institutes OFF

set IDENTITY_INSERT persons ON
insert into persons (id,name) values (1,'Mitya Kovalev')
insert into persons (id,name) values (2,'Torvlobnor Puzdoy')
insert into persons (id,name) values (3,'Akakiy Zinberstein')
set IDENTITY_INSERT persons OFF

set IDENTITY_INSERT phones ON
insert into phones (id,phone,pers_id) values (1,'332-2334',1)
insert into phones (id,phone,pers_id) values (2,'222-3234',1)
insert into phones (id,phone,pers_id) values (3,'545-4563',2)
set IDENTITY_INSERT phones OFF

set IDENTITY_INSERT documents ON
insert into documents (id,abstract,title) values (1,'abstract1','book1')
insert into documents (id,abstract,title) values (2,'abstract2','book2')
set IDENTITY_INSERT documents OFF

insert into authors_docs (pers_id,doc_id) values (1,1)
insert into authors_docs (pers_id,doc_id) values (1,2)
insert into authors_docs (pers_id,doc_id) values (2,1)

SET IDENTITY_INSERT ldap_entries ON
insert into ldap_entries (id,dn,objclass,parent,keyval)
values (1,'o=sql,c=RU',3,0,1)

insert into ldap_entries (id,dn,objclass,parent,keyval)
values (2,'cn=Mitya Kovalev,o=sql,c=RU',1,1,1)

insert into ldap_entries (id,dn,objclass,parent,keyval)
values (3,'cn=Torvlobnor Puzdoy,o=sql,c=RU',1,1,2)

insert into ldap_entries (id,dn,objclass,parent,keyval)
values (4,'cn=Akakiy Zinberstein,o=sql,c=RU',1,1,3)

insert into ldap_entries (id,dn,objclass,parent,keyval)
values (5,'documentTitle=book1,o=sql,c=RU',2,1,1)

insert into ldap_entries (id,dn,objclass,parent,keyval)
values (6,'documentTitle=book2,o=sql,c=RU',2,1,2)

SET IDENTITY_INSERT ldap_entries OFF
