CREATE TABLE persons (
	id NUMBER NOT NULL,
	name varchar2(255) NOT NULL
);

CREATE TABLE institutes (
	id NUMBER NOT NULL,
	name varchar2(255)
);

CREATE TABLE documents (
	id NUMBER NOT NULL,
	title varchar2(255) NOT NULL,
	abstract varchar2(255)
);

CREATE TABLE authors_docs (
	pers_id NUMBER NOT NULL,
	doc_id NUMBER NOT NULL
);

CREATE TABLE phones (
	id NUMBER NOT NULL ,
	phone varchar2(255) NOT NULL ,
	pers_id NUMBER NOT NULL 
);


ALTER TABLE authors_docs  ADD 
	CONSTRAINT PK_authors_docs PRIMARY KEY  
	(
		pers_id,
		doc_id
	);  

ALTER TABLE documents  ADD 
	CONSTRAINT PK_documents PRIMARY KEY  
	(
		id
	);  

ALTER TABLE institutes  ADD 
	CONSTRAINT PK_institutes PRIMARY KEY  
	(
		id
	);  

ALTER TABLE persons  ADD 
	CONSTRAINT PK_persons PRIMARY KEY  
	(
		id
	);  

ALTER TABLE phones  ADD 
	CONSTRAINT PK_phones PRIMARY KEY  
	(
		id
	);  

CREATE SEQUENCE person_ids START WITH 1 INCREMENT BY 1;

CREATE SEQUENCE document_ids START WITH 1 INCREMENT BY 1;

CREATE SEQUENCE institute_ids START WITH 1 INCREMENT BY 1;

CREATE SEQUENCE phone_ids START WITH 1 INCREMENT BY 1;

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

CREATE OR REPLACE PROCEDURE make_author_link (keyval IN NUMBER, author_dn IN varchar2)  AS
per_id NUMBER;
BEGIN
SELECT keyval INTO per_id FROM ldap_entries 
	   				WHERE objclass=1 AND dn=author_dn;
IF NOT (per_id IS NULL) THEN
 INSERT INTO authors_docs (doc_id,pers_id) VALUES (keyval,per_id);
END IF;
END;
/

CREATE OR REPLACE PROCEDURE make_doc_link (keyval IN NUMBER, doc_dn IN varchar2)  AS
docid NUMBER;
BEGIN
SELECT keyval INTO docid FROM ldap_entries 
		   WHERE objclass=2 AND dn=doc_dn;
IF NOT (docid IS NULL) THEN
 INSERT INTO authors_docs (pers_id,doc_id) VALUES (keyval,docid);
END IF;
END;
/

CREATE OR REPLACE PROCEDURE del_doc_link (keyval IN NUMBER, doc_dn IN varchar2)  AS
docid NUMBER;
BEGIN
SELECT keyval INTO docid FROM ldap_entries 
	   	WHERE objclass=2 AND dn=doc_dn;
IF NOT (docid IS NULL) THEN
 DELETE FROM authors_docs WHERE pers_id=keyval AND doc_id=docid;
END IF;
END;
/

CREATE PROCEDURE del_author_link (keyval IN NUMBER, author_dn IN varchar2)  AS
per_id NUMBER;
BEGIN
SELECT keyval INTO per_id FROM ldap_entries
     WHERE objclass=1 AND dn=author_dn;

IF NOT (per_id IS NULL) THEN
 DELETE FROM authors_docs WHERE doc_id=keyval AND pers_id=per_id;
END IF;
END;
/

