CREATE TABLE ldap_attrs (
	id NUMBER NOT NULL,
	oc_id NUMBER NOT NULL,
	name varchar2(255) NOT NULL,
	sel_expr varchar2(255) NOT NULL,
	from_tbls varchar2(255) NOT NULL,
	join_where varchar2(255),
	add_proc varchar2(255),
	modify_proc varchar2(255),
	delete_proc varchar2(255),
	param_order NUMBER NOT NULL,
	expect_return NUMBER NOT NULL
);


CREATE TABLE ldap_entries (
	id NUMBER NOT NULL ,
	dn varchar2(255) NOT NULL ,
	objclass NUMBER NOT NULL ,
	parent NUMBER NOT NULL ,
	keyval NUMBER NOT NULL 
);


CREATE TABLE ldap_objclasses (
	id NUMBER NOT NULL ,
	name varchar2(64) NOT NULL ,
	keytbl varchar2(64) NOT NULL ,
	keycol varchar2(64) NOT NULL ,
	create_proc varchar2(255),
	delete_proc varchar2(255),
	expect_return NUMBER NOT NULL
);


ALTER TABLE ldap_attrs ADD 
	CONSTRAINT PK_ldap_attrs PRIMARY KEY
	(
		id
	); 

ALTER TABLE ldap_entries ADD 
	CONSTRAINT PK_ldap_entries PRIMARY KEY
	(
		id
	); 

ALTER TABLE ldap_objclasses ADD 
	CONSTRAINT PK_ldap_objclasses PRIMARY KEY
	(
		id
	); 

ALTER TABLE ldap_entries ADD 
	CONSTRAINT UNQ1_ldap_entries UNIQUE
	(
		objclass,
		keyval
	);  

ALTER TABLE ldap_entries ADD 
	CONSTRAINT UNQ2_ldap_entries UNIQUE
	(
		dn
	);  


ALTER TABLE ldap_objclasses ADD 
	CONSTRAINT UNQ_ldap_objclasses UNIQUE
	(
		name
	);  


CREATE SEQUENCE ldap_objclass_ids START WITH 1 INCREMENT BY 1;

CREATE SEQUENCE ldap_attr_ids START WITH 1 INCREMENT BY 1;

CREATE SEQUENCE ldap_entry_ids START WITH 1 INCREMENT BY 1;
