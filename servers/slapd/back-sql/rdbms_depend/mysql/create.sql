CREATE TABLE ldap_attrs (
	id int NOT NULL PRIMARY KEY AUTO_INCREMENT,
	oc_id int NOT NULL,
	name varchar(255) NOT NULL,
	sel_expr varchar(255) NOT NULL,
	from_tbls varchar(255) NOT NULL,
	join_where varchar(255),
	add_proc varchar(255),
	modify_proc varchar(255),
	delete_proc varchar(255)
);


CREATE TABLE ldap_entries (
	id int NOT NULL PRIMARY KEY AUTO_INCREMENT,
	dn varchar(255) NOT NULL ,
	objclass int NOT NULL ,
	parent int NOT NULL ,
	keyval int NOT NULL 
);


CREATE TABLE ldap_objclasses (
	id int NOT NULL PRIMARY KEY AUTO_INCREMENT,
	name varchar(64) NOT NULL ,
	keytbl varchar(64) NOT NULL ,
	keycol varchar(64) NOT NULL ,
	create_proc varchar(255),
	delete_proc varchar(255) 
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
