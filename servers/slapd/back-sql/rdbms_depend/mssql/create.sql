CREATE TABLE ldap_attrs (
	id int IDENTITY (1, 1) NOT NULL ,
	oc_id int NOT NULL ,
	name varchar (255) NOT NULL ,
	sel_expr varchar (255) NOT NULL ,
	from_tbls varchar (255) NOT NULL ,
	join_where varchar (255) NULL ,
	add_proc varchar (255) NULL ,
	modify_proc varchar (255) NULL ,
	delete_proc varchar (255) NULL 
)
GO

CREATE TABLE ldap_entries (
	id int IDENTITY (1, 1) NOT NULL ,
	dn varchar (255) NOT NULL ,
	objclass int NOT NULL ,
	parent int NOT NULL ,
	keyval int NOT NULL 
)
GO

CREATE TABLE ldap_objclasses (
	id int IDENTITY (1, 1) NOT NULL ,
	name varchar (64) NOT NULL ,
	keytbl varchar (64) NOT NULL ,
	keycol varchar (64) NOT NULL ,
	create_proc varchar (255) NULL ,
	delete_proc varchar (255) NULL 
)
GO


ALTER TABLE ldap_attrs WITH NOCHECK ADD 
	CONSTRAINT PK_ldap_attrs PRIMARY KEY  
	(
		id
	)  
GO

ALTER TABLE ldap_entries WITH NOCHECK ADD 
	CONSTRAINT PK_ldap_entries PRIMARY KEY  
	(
		id
	)  
GO

ALTER TABLE ldap_entries WITH NOCHECK ADD 
	CONSTRAINT UNQ1_ldap_entries UNIQUE
	(
		objclass,
		keyval
	)  
GO

ALTER TABLE ldap_entries WITH NOCHECK ADD 
	CONSTRAINT UNQ2_ldap_entries UNIQUE
	(
		dn
	)  
GO

ALTER TABLE ldap_objclasses WITH NOCHECK ADD 
	CONSTRAINT PK_ldap_objclasses PRIMARY KEY  
	(
		id
	)  
GO


ALTER TABLE ldap_objclasses WITH NOCHECK ADD 
	CONSTRAINT UNQ_ldap_objclasses UNIQUE
	(
		name
	)  
GO
