drop table persons;
CREATE TABLE persons (
	id int NOT NULL,
	name varchar(255) NOT NULL,
	PRIMARY KEY ( id )
);

drop table institutes;
CREATE TABLE institutes (
	id int NOT NULL,
	name varchar(255),
	PRIMARY KEY ( id )
);

drop table documents;
CREATE TABLE documents (
	id int NOT NULL,
	title varchar(255) NOT NULL,
	abstract varchar(255),
	PRIMARY KEY ( id )
);

drop table authors_docs;
CREATE TABLE authors_docs (
	pers_id int NOT NULL,
	doc_id int NOT NULL,
	PRIMARY KEY ( pers_id, doc_id )
);

drop table phones;
CREATE TABLE phones (
	id int NOT NULL ,
	phone varchar(255) NOT NULL ,
	pers_id int NOT NULL,
	PRIMARY KEY ( id )
);

