all: guide.html index.html

sdf-src: \
	abstract.sdf \
	config.sdf \
	dbtools.sdf \
	guide.sdf \
	install.sdf \
	intro.sdf \
	master.sdf \
	monitoringslapd.sdf \
	preface.sdf \
	proxycache.sdf \
	quickstart.sdf \
	referrals.sdf \
	replication.sdf \
	runningslapd.sdf \
	sasl.sdf \
	schema.sdf \
	security.sdf \
	slapdconfig.sdf \
	syncrepl.sdf \
	title.sdf \
	tls.sdf \
	tuning.sdf

sdf-img: \
	config_local.gif \
	config_ref.gif \
	config_repl.gif \
	config_x500fe.gif \
	config_x500ref.gif \
	intro_dctree.gif \
	intro_tree.gif \
	replication.gif

guide.html: guide.sdf sdf-src
	sdf -2html guide.sdf

index.html: index.sdf sdf-src
