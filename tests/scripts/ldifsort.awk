# Parses LDIF files, eliminating contnuations, and sorts
# Author: Pierangelo Masarati <ando@sys-net.it>

func parse_line( line ) {
	getline;

	while ($0 != "") {
		c = substr($0, 1, 1);
		if (c == "#") {
			continue;
		}
		if (c != " ") {
			break;
		}

		line = line substr($0, 2, length($0));

		getline;
	}

	return line;
}

/^dn: / {
	/* FIXME: works only if DN is on one line... */
	dn = $0;
	dn = parse_line(dn);

	while (1) {
		if ($0 == "") {
			break;
		}
		line = $0;
		line = parse_line(line);
		attrs[line] = line
	}

	entry[dn] = dn "\n";
	n = asort(attrs);
	for (i = 1; i <= n; i++) {
		entry[dn] = entry[dn] attrs[i] "\n"
	}
	delete attrs
}

END {
	n = asort(entry);
	for (i = 1; i <= n; i++) {
		print entry[i];
	}
}
