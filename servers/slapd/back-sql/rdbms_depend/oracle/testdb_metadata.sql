-- mappings 

-- objectClass mappings: these may be viewed as structuralObjectClass, the ones that are used to decide how to build an entry
--	id		a unique number identifying the objectClass
--	name		the name of the objectClass; it MUST match the name of an objectClass that is loaded in slapd's schema
--	keytbl		the name of the table that is referenced for the primary key of an entry
--	keycol		the name of the column in "keytbl" that contains the primary key of an entry; the pair "keytbl.keycol" uniquely identifies an entry of objectClass "id"
--	create_proc	a procedure to create the entry
--	delete_proc	a procedure to delete the entry; it takes "keytbl.keycol" of the row to be deleted
--	expect_return	a bitmap that marks whether create_proc (1) and delete_proc (2) return a value or not
insert into ldap_oc_mappings (id,name,keytbl,keycol,create_proc,delete_proc,expect_return)
values (1,'person','persons','id','call create_person(?)','call delete_person(?)',0);

insert into ldap_oc_mappings (id,name,keytbl,keycol,create_proc,delete_proc,expect_return)
values (2,'document','documents','id','call create_document(?)','call delete_document(?)',0);

insert into ldap_oc_mappings (id,name,keytbl,keycol,create_proc,delete_proc,expect_return)
values (3,'organization','institutes','id','call create_org(?)','call delete_org(?)',0);

-- attributeType mappings: describe how an attributeType for a certain objectClass maps to the SQL data.
--	id		a unique number identifying the attribute	
--	oc_map_id	the value of "ldap_oc_mappings.id" that identifies the objectClass this attributeType is defined for
--	name		the name of the attributeType; it MUST match the name of an attributeType that is loaded in slapd's schema
--	sel_expr	the expression that is used to select this attribute (the "select <sel_expr> from ..." portion)
--	from_tbls	the expression that defines the table(s) this attribute is taken from (the "select ... from <from_tbls> where ..." portion)
--	join_where	the expression that defines the condition to select this attribute (the "select ... where <join_where> ..." portion)
--	add_proc	a procedure to insert the attribute; it takes the value of the attribute that is added, and the "keytbl.keycol" of the entry it is associated to
--	delete_proc	a procedure to delete the attribute; it takes the value of the attribute that is added, and the "keytbl.keycol" of the entry it is associated to
--	param_order	a mask that marks if the "keytbl.keycol" value comes before or after the value in add_proc (1) and delete_proc (2)
--	expect_return	a mask that marks whether add_proc (1) and delete_proc(2) are expected to return a value or not
insert into ldap_attr_mappings (id,oc_map_id,name,sel_expr,from_tbls,join_where,add_proc,delete_proc,param_order,expect_return)
values (1,1,'cn','persons.name','persons',NULL,'call set_person_name(?,?)',
        NULL,0,0);

insert into ldap_attr_mappings (id,oc_map_id,name,sel_expr,from_tbls,join_where,add_proc,delete_proc,param_order,expect_return)
values (2,1,'telephoneNumber','phones.phone','persons,phones',
        'phones.pers_id=persons.id','call add_phone(?,?)',
        'call delete_phone(?,?)',0,0);

insert into ldap_attr_mappings (id,oc_map_id,name,sel_expr,from_tbls,join_where,add_proc,delete_proc,param_order,expect_return)
values (3,1,'sn','persons.name','persons',NULL,'call set_person_name(?,?)',
        NULL,0,0);

insert into ldap_attr_mappings (id,oc_map_id,name,sel_expr,from_tbls,join_where,add_proc,delete_proc,param_order,expect_return)
values (4,2,'abstract','documents.abstract','documents',NULL,'call set_doc_abstract(?,?)',
        NULL,0,0);

insert into ldap_attr_mappings (id,oc_map_id,name,sel_expr,from_tbls,join_where,add_proc,delete_proc,param_order,expect_return)
values (5,2,'documentTitle','documents.title','documents',NULL,'call set_doc_title(?,?)',
        NULL,0,0);

-- insert into ldap_attr_mappings (id,oc_map_id,name,sel_expr,from_tbls,join_where,add_proc,delete_proc,param_order,expect_return)                         
-- values (6,2,'documentAuthor','persons.name','persons,documents,authors_docs',
--         'persons.id=authors_docs.pers_id AND documents.id=authors_docs.doc_id',
-- 	NULL,NULL,0,0);

insert into ldap_attr_mappings (id,oc_map_id,name,sel_expr,from_tbls,join_where,add_proc,delete_proc,param_order,expect_return)
values (7,3,'o','institutes.name','institutes',NULL,'call set_org_name(?,?)',
        NULL,0,0);

insert into ldap_attr_mappings (id,oc_map_id,name,sel_expr,from_tbls,join_where,add_proc,delete_proc,param_order,expect_return)
values (8,1,'documentDN','ldap_entries.dn','ldap_entries,documents,authors_docs,persons',
        'ldap_entries.keyval=documents.id AND ldap_entries.oc_map_id=2 AND authors_docs.doc_id=documents.id AND authors_docs.pers_id=persons.id',
	'?=call make_doc_link(?,?)','?=call del_doc_link(?,?)',0,3);

insert into ldap_attr_mappings (id,oc_map_id,name,sel_expr,from_tbls,join_where,add_proc,delete_proc,param_order,expect_return)
values (9,2,'documentAuthor','ldap_entries.dn','ldap_entries,documents,authors_docs,persons',
        'ldap_entries.keyval=persons.id AND ldap_entries.oc_map_id=1 AND authors_docs.doc_id=documents.id AND authors_docs.pers_id=persons.id',
	'?=call make_author_link(?,?)','?=call del_author_link(?,?)',0,3);


-- entries mapping: each entry must appear in this table, with a unique DN rooted at the database naming context
--	id		a unique number > 0 identifying the entry
--	dn		the DN of the entry, in "pretty" form
--	oc_map_id	the "ldap_oc_mappings.id" of the main objectClass of this entry (view it as the structuralObjectClass)
--	parent		the "ldap_entries.id" of the parent of this objectClass; 0 if it is the "suffix" of the database
--	keyval		the value of the "keytbl.keycol" defined for this objectClass
insert into ldap_entries (id,dn,oc_map_id,parent,keyval)
values (ldap_entry_ids.nextval,'o=sql,c=RU',3,0,1);

insert into ldap_entries (id,dn,oc_map_id,parent,keyval)
values (ldap_entry_ids.nextval,'cn=Mitya Kovalev,o=sql,c=RU',1,1,1);

insert into ldap_entries (id,dn,oc_map_id,parent,keyval)
values (ldap_entry_ids.nextval,'cn=Torvlobnor Puzdoy,o=sql,c=RU',1,1,2);

insert into ldap_entries (id,dn,oc_map_id,parent,keyval)
values (ldap_entry_ids.nextval,'cn=Akakiy Zinberstein,o=sql,c=RU',1,1,3);

insert into ldap_entries (id,dn,oc_map_id,parent,keyval)
values (ldap_entry_ids.nextval,'documentTitle=book1,o=sql,c=RU',2,1,1);

insert into ldap_entries (id,dn,oc_map_id,parent,keyval)
values (ldap_entry_ids.nextval,'documentTitle=book2,o=sql,c=RU',2,1,2);

-- objectClass mapping: entries that have multiple objectClass instances are listed here with the objectClass name (view them as auxiliary objectClass)
--	entry_id	the "ldap_entries.id" of the entry this objectClass value must be added
--	oc_name		the name of the objectClass; it MUST match the name of an objectClass that is loaded in slapd's schema
insert into ldap_entry_objclasses (entry_id,oc_name)
values (4,'referral');

-- referrals mapping: entries that should be treated as referrals are stored here
--	entry_id	the "ldap_entries.id" of the entry that should be treated as a referral
--	url		the URI of the referral
insert into ldap_referrals (entry_id,url)
values (4,'http://localhost');


-- procedures
-- these procedures are specific for this RDBMS and are used in mapping objectClass and attributeType creation/modify/deletion
CREATE OR REPLACE PROCEDURE create_person(keyval OUT NUMBER) AS
BEGIN
INSERT INTO persons (id,name) VALUES (person_ids.nextval,' ');
SELECT person_ids.currval INTO keyval FROM DUAL;
END;
/

CREATE OR REPLACE PROCEDURE delete_person(keyval IN NUMBER) AS
BEGIN
DELETE FROM phones WHERE pers_id=keyval;
DELETE FROM authors_docs WHERE pers_id=keyval;
DELETE FROM persons WHERE id=keyval;
END;
/

CREATE OR REPLACE PROCEDURE create_org(keyval OUT NUMBER) AS
BEGIN
INSERT INTO institutes (id,name) VALUES (institute_ids.nextval,' ');
SELECT institute_ids.currval INTO keyval FROM DUAL;
END;
/

CREATE OR REPLACE PROCEDURE delete_org(keyval IN NUMBER) AS
BEGIN
DELETE FROM institutes WHERE id=keyval;
END;
/

CREATE OR REPLACE PROCEDURE create_document(keyval OUT NUMBER) AS
BEGIN
INSERT INTO documents (id,title) VALUES (document_ids.nextval,' ');
SELECT document_ids.currval INTO keyval FROM DUAL;
END;
/

CREATE OR REPLACE PROCEDURE delete_document (keyval IN NUMBER) AS
BEGIN
DELETE FROM authors_docs WHERE doc_id=keyval;
DELETE FROM documents WHERE id=keyval;
END;
/

CREATE OR REPLACE PROCEDURE add_phone(pers_id IN NUMBER, phone IN varchar2) AS
BEGIN
INSERT INTO phones (id,pers_id,phone) VALUES (phone_ids.nextval,pers_id,phone);
END;
/

CREATE OR REPLACE PROCEDURE delete_phone(keyval IN NUMBER, phone IN varchar2) AS
BEGIN
DELETE FROM phones WHERE pers_id=keyval AND phone=phone;
END;
/

CREATE OR REPLACE PROCEDURE set_person_name(keyval IN NUMBER, new_name IN varchar2) AS
BEGIN
UPDATE persons SET name=new_name WHERE id=keyval;
END;
/

CREATE OR REPLACE PROCEDURE set_org_name(keyval IN NUMBER, new_name IN varchar2) AS
BEGIN
UPDATE institutes SET name=new_name WHERE id=keyval;
END;
/

CREATE OR REPLACE PROCEDURE set_doc_title (keyval IN NUMBER, new_title IN varchar2)  AS
BEGIN
UPDATE documents SET title=new_title WHERE id=keyval;
END;
/

CREATE OR REPLACE PROCEDURE set_doc_abstract (keyval IN NUMBER, new_abstract IN varchar2)  AS
BEGIN
UPDATE documents SET abstract=new_abstract WHERE id=keyval;
END;
/

CREATE OR REPLACE FUNCTION make_author_link (keyval IN NUMBER, author_dn IN varchar2) RETURN NUMBER AS
per_id NUMBER;
BEGIN
SELECT keyval INTO per_id FROM ldap_entries 
	   				WHERE oc_map_id=1 AND dn=author_dn;
IF NOT (per_id IS NULL) THEN
 INSERT INTO authors_docs (doc_id,pers_id) VALUES (keyval,per_id);
 RETURN 1;
END IF;
RETURN 0;
END;
/

CREATE OR REPLACE FUNCTION make_doc_link (keyval IN NUMBER, doc_dn IN varchar2) RETURN NUMBER AS
docid NUMBER;
BEGIN
SELECT keyval INTO docid FROM ldap_entries 
		   WHERE oc_map_id=2 AND dn=doc_dn;
IF NOT (docid IS NULL) THEN
 INSERT INTO authors_docs (pers_id,doc_id) VALUES (keyval,docid);
 RETURN 1;
END IF;
RETURN 0;
END;
/

CREATE OR REPLACE FUNCTION del_doc_link (keyval IN NUMBER, doc_dn IN varchar2) RETURN NUMBER AS
docid NUMBER;
BEGIN
SELECT keyval INTO docid FROM ldap_entries 
	   	WHERE oc_map_id=2 AND dn=doc_dn;
IF NOT (docid IS NULL) THEN
 DELETE FROM authors_docs WHERE pers_id=keyval AND doc_id=docid;
 RETURN 1;
END IF;
RETURN 0;
END;
/

CREATE OR REPLACE FUNCTION del_author_link (keyval IN NUMBER, author_dn IN varchar2) RETURN NUMBER AS
per_id NUMBER;
BEGIN
SELECT keyval INTO per_id FROM ldap_entries
     WHERE oc_map_id=1 AND dn=author_dn;

IF NOT (per_id IS NULL) THEN
 DELETE FROM authors_docs WHERE doc_id=keyval AND pers_id=per_id;
 RETURN 1;
END IF;
 RETURN 0;
END;
/
