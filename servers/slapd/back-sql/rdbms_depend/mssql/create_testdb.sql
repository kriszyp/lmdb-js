
CREATE TABLE authors_docs (
	pers_id int NOT NULL ,
	doc_id int NOT NULL 
)
GO

CREATE TABLE documents (
	id int IDENTITY (1, 1) NOT NULL ,
	abstract varchar (255) NULL ,
	title varchar (255) NULL ,
	body binary (255) NULL 
)
GO

CREATE TABLE institutes (
	id int IDENTITY (1, 1) NOT NULL ,
	name varchar (255) NOT NULL 
)
GO


CREATE TABLE persons (
	id int IDENTITY (1, 1) NOT NULL ,
	name varchar (255) NULL 
)
GO

CREATE TABLE phones (
	id int IDENTITY (1, 1) NOT NULL ,
	phone varchar (255) NOT NULL ,
	pers_id int NOT NULL 
)
GO

ALTER TABLE authors_docs WITH NOCHECK ADD 
	CONSTRAINT PK_authors_docs PRIMARY KEY  
	(
		pers_id,
		doc_id
	)  
GO

ALTER TABLE documents WITH NOCHECK ADD 
	CONSTRAINT PK_documents PRIMARY KEY  
	(
		id
	)  
GO

ALTER TABLE institutes WITH NOCHECK ADD 
	CONSTRAINT PK_institutes PRIMARY KEY  
	(
		id
	)  
GO


ALTER TABLE persons WITH NOCHECK ADD 
	CONSTRAINT PK_persons PRIMARY KEY  
	(
		id
	)  
GO

ALTER TABLE phones WITH NOCHECK ADD 
	CONSTRAINT PK_phones PRIMARY KEY  
	(
		id
	)  
GO

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
	   WHERE objclass=1 AND dn=@author_dn);
IF NOT (@per_id IS NULL)
 INSERT INTO ldap.authors_docs (doc_id,pers_id) VALUES (@keyval,@per_id);
GO

CREATE PROCEDURE make_doc_link @keyval int, @doc_dn varchar(255)  AS
DECLARE @doc_id int;
SET @doc_id=(SELECT keyval FROM ldap.ldap_entries 
	   WHERE objclass=2 AND dn=@doc_dn);
IF NOT (@doc_id IS NULL)
 INSERT INTO ldap.authors_docs (pers_id,doc_id) VALUES (@keyval,@doc_id);
GO

CREATE PROCEDURE del_doc_link @keyval int, @doc_dn varchar(255)  AS
DECLARE @doc_id int;
SET @doc_id=(SELECT keyval FROM ldap.ldap_entries 
	   WHERE objclass=2 AND dn=@doc_dn);
IF NOT (@doc_id IS NULL)
DELETE FROM ldap.authors_docs WHERE pers_id=@keyval AND doc_id=@doc_id;
GO

CREATE PROCEDURE del_author_link @keyval int, @author_dn varchar(255)  AS
DECLARE @per_id int;
SET @per_id=(SELECT keyval FROM ldap.ldap_entries 
	   WHERE objclass=1 AND dn=@author_dn);
IF NOT (@per_id IS NULL)
 DELETE FROM ldap.authors_docs WHERE doc_id=@keyval AND pers_id=@per_id;
GO
