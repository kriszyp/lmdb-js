-- mappings


SET IDENTITY_INSERT ldap_oc_mappings ON
insert into ldap_oc_mappings (id,name,keytbl,keycol,create_proc,delete_proc,expect_return)
values (1,'inetorgperson','persons','id','{call create_person(?)}','{call delete_person(?)}',0)

insert into ldap_oc_mappings (id,name,keytbl,keycol,create_proc,delete_proc,expect_return)
values (2,'document','documents','id','{call create_document(?)}','{call delete_document(?)}',0)

insert into ldap_oc_mappings (id,name,keytbl,keycol,create_proc,delete_proc,expect_return)
values (3,'organization','institutes','id','{call create_org(?)}','{call delete_org(?)}',0)
SET IDENTITY_INSERT ldap_oc_mappings OFF


SET IDENTITY_INSERT ldap_attr_mappings ON
insert into ldap_attr_mappings (id,oc_map_id,name,sel_expr,from_tbls,join_where,add_proc,modify_proc,delete_proc,param_order,expect_return)
values (1,1,'cn','persons.name','persons',NULL,'{call set_person_name(?,?)}',
        NULL,NULL,0,0)

insert into ldap_attr_mappings (id,oc_map_id,name,sel_expr,from_tbls,join_where,add_proc,modify_proc,delete_proc,param_order,expect_return)
values (2,1,'telephoneNumber','phones.phone','persons,phones',
        'phones.pers_id=persons.id','{call add_phone(?,?)}',
        NULL,'{call delete_phone(?,?)}',0,0)

insert into ldap_attr_mappings (id,oc_map_id,name,sel_expr,from_tbls,join_where,add_proc,modify_proc,delete_proc,param_order,expect_return)
values (3,1,'sn','persons.name','persons',NULL,'{call set_person_name(?,?)}',
        NULL,NULL,0,0)

insert into ldap_attr_mappings (id,oc_map_id,name,sel_expr,from_tbls,join_where,add_proc,modify_proc,delete_proc,param_order,expect_return)
values (4,2,'description','documents.abstract','documents',NULL,'{call set_doc_abstract(?,?)}',
        NULL,NULL,0,0)
                     
insert into ldap_attr_mappings (id,oc_map_id,name,sel_expr,from_tbls,join_where,add_proc,modify_proc,delete_proc,param_order,expect_return)
values (5,2,'documentTitle','documents.title','documents',NULL,'{call set_doc_title(?,?)}',
        NULL,NULL,0,0)

-- insert into ldap_attr_mappings (id,oc_map_id,name,sel_expr,from_tbls,join_where,add_proc,modify_proc,delete_proc,param_order,expect_return)
-- values (6,2,'documentAuthor','persons.name','persons,documents,authors_docs',
--         'persons.id=authors_docs.pers_id AND documents.id=authors_docs.doc_id',
-- 	NULL,NULL,NULL,0,0)

insert into ldap_attr_mappings (id,oc_map_id,name,sel_expr,from_tbls,join_where,add_proc,modify_proc,delete_proc,param_order,expect_return)
values (7,3,'o','institutes.name','institutes',NULL,'{call set_org_name(?,?)}',
        NULL,NULL,0,0)

insert into ldap_attr_mappings (id,oc_map_id,name,sel_expr,from_tbls,join_where,add_proc,modify_proc,delete_proc,param_order,expect_return)
values (8,1,'documentDN','ldap_entries.dn','ldap_entries,documents,authors_docs,persons',
        'ldap_entries.keyval=documents.id AND ldap_entries.oc_map_id=2 AND authors_docs.doc_id=documents.id AND authors_docs.pers_id=persons.id',
	'{call make_doc_link(?,?)}',NULL,'{call del_doc_link(?,?)}',0,0)

insert into ldap_attr_mappings (id,oc_map_id,name,sel_expr,from_tbls,join_where,add_proc,modify_proc,delete_proc,param_order,expect_return)
values (9,2,'documentAuthor','ldap_entries.dn','ldap_entries,documents,authors_docs,persons',
        'ldap_entries.keyval=persons.id AND ldap_entries.oc_map_id=1 AND authors_docs.doc_id=documents.id AND authors_docs.pers_id=persons.id',
	'{call make_author_link(?,?)}',NULL,'{call del_author_link(?,?)}',0,0)

SET IDENTITY_INSERT ldap_attr_mappings OFF

-- entries

SET IDENTITY_INSERT ldap_entries ON
insert into ldap_entries (id,dn,oc_map_id,parent,keyval)
values (1,'o=sql,c=RU',3,0,1)

insert into ldap_entries (id,dn,oc_map_id,parent,keyval)
values (2,'cn=Mitya Kovalev,o=sql,c=RU',1,1,1)

insert into ldap_entries (id,dn,oc_map_id,parent,keyval)
values (3,'cn=Torvlobnor Puzdoy,o=sql,c=RU',1,1,2)

insert into ldap_entries (id,dn,oc_map_id,parent,keyval)
values (4,'cn=Akakiy Zinberstein,o=sql,c=RU',1,1,3)

insert into ldap_entries (id,dn,oc_map_id,parent,keyval)
values (5,'documentTitle=book1,o=sql,c=RU',2,1,1)

insert into ldap_entries (id,dn,oc_map_id,parent,keyval)
values (6,'documentTitle=book2,o=sql,c=RU',2,1,2)

SET IDENTITY_INSERT ldap_entries OFF

-- referrals

insert into ldap_entry_objclasses (entry_id,oc_name)
values (4,'referral');

insert into ldap_referrals (entry_id,url)
values (4,'http://localhost');

-- support procedures

SET QUOTED_IDENTIFIER  OFF    SET ANSI_NULLS  ON 
GO


CREATE PROCEDURE add_phone @pers_id int, @phone varchar(255) AS
INSERT INTO ldap.phones (pers_id,phone) VALUES (@pers_id,@phone)
GO

CREATE PROCEDURE create_person @@keyval int OUTPUT AS
INSERT INTO ldap.persons (name) VALUES ('');
set @@keyval=(SELECT MAX(id) FROM ldap.persons)
GO

CREATE PROCEDURE delete_person @keyval int AS
DELETE FROM ldap.phones WHERE pers_id=@keyval;
DELETE FROM ldap.authors_docs WHERE pers_id=@keyval;
DELETE FROM ldap.persons WHERE id=@keyval;
GO

CREATE PROCEDURE create_org @@keyval int OUTPUT AS
INSERT INTO ldap.institutes (name) VALUES ('');
set @@keyval=(SELECT MAX(id) FROM ldap.institutes)
GO

CREATE PROCEDURE create_document @@keyval int OUTPUT AS
INSERT INTO ldap.documents (title) VALUES ('');
set @@keyval=(SELECT MAX(id) FROM ldap.documents)
GO

CREATE PROCEDURE delete_org @keyval int AS
DELETE FROM ldap.institutes WHERE id=@keyval;
GO

CREATE PROCEDURE delete_document @keyval int AS
DELETE FROM ldap.authors_docs WHERE doc_id=@keyval;
DELETE FROM ldap.documents WHERE id=@keyval;
GO

CREATE PROCEDURE delete_phone @keyval int,@phone varchar(64) AS
DELETE FROM ldap.phones WHERE pers_id=@keyval AND phone=@phone;
GO

CREATE PROCEDURE set_person_name @keyval int, @new_name varchar(255)  AS
UPDATE ldap.persons SET name=@new_name WHERE id=@keyval;
GO

CREATE PROCEDURE set_org_name @keyval int, @new_name varchar(255)  AS
UPDATE ldap.institutes SET name=@new_name WHERE id=@keyval;
GO

CREATE PROCEDURE set_doc_title @keyval int, @new_title varchar(255)  AS
UPDATE ldap.documents SET title=@new_title WHERE id=@keyval;
GO

CREATE PROCEDURE set_doc_abstract @keyval int, @new_abstract varchar(255)  AS
UPDATE ldap.documents SET abstract=@new_abstract WHERE id=@keyval;
GO

CREATE PROCEDURE make_author_link @keyval int, @author_dn varchar(255)  AS
DECLARE @per_id int;
SET @per_id=(SELECT keyval FROM ldap.ldap_entries 
	   WHERE oc_map_id=1 AND dn=@author_dn);
IF NOT (@per_id IS NULL)
 INSERT INTO ldap.authors_docs (doc_id,pers_id) VALUES (@keyval,@per_id);
GO

CREATE PROCEDURE make_doc_link @keyval int, @doc_dn varchar(255)  AS
DECLARE @doc_id int;
SET @doc_id=(SELECT keyval FROM ldap.ldap_entries 
	   WHERE oc_map_id=2 AND dn=@doc_dn);
IF NOT (@doc_id IS NULL)
 INSERT INTO ldap.authors_docs (pers_id,doc_id) VALUES (@keyval,@doc_id);
GO

CREATE PROCEDURE del_doc_link @keyval int, @doc_dn varchar(255)  AS
DECLARE @doc_id int;
SET @doc_id=(SELECT keyval FROM ldap.ldap_entries 
	   WHERE oc_map_id=2 AND dn=@doc_dn);
IF NOT (@doc_id IS NULL)
DELETE FROM ldap.authors_docs WHERE pers_id=@keyval AND doc_id=@doc_id;
GO

CREATE PROCEDURE del_author_link @keyval int, @author_dn varchar(255)  AS
DECLARE @per_id int;
SET @per_id=(SELECT keyval FROM ldap.ldap_entries 
	   WHERE oc_map_id=1 AND dn=@author_dn);
IF NOT (@per_id IS NULL)
 DELETE FROM ldap.authors_docs WHERE doc_id=@keyval AND pers_id=@per_id;
GO
