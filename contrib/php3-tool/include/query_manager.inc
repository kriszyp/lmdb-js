<?
class query_manager {
	function get_action() {
		global $ldap_action;
		if (isset ($ldap_action)) {
			$ldap_action = urldecode ($ldap_action);
		}
		else {
			$ldap_action = "read";
		}
		return $ldap_action;
	}
	function get_base_dn() {
		global $base_dn;
		if (isset ($base_dn)) {
			$base_dn = urldecode ($base_dn);
		}
		else {
			$base_dn = "o=University of Michigan, c=US";
		//	$base_dn = "o=Balorda and Balorda, c=UK";
		}
		return $base_dn;
	}

	function get_host() {
		global $host;
		if (isset ($host)) {
			$host = urldecode($host);
		}
		else {
			$host = "localhost";
		}
		return $host;
	}

	function get_search_filter() {
		global $objectclass, $attrib, $precision, $search_string;
//		global $search_filter;
//		if (isset ($search_filter)) {
//			$search_filter = urldecode($search_filter);
//		}
//		else {
			$search_filter = "(objectclass=";
			switch(urldecode($objectclass)) {
				case "People": $search_filter .= "person)";break;
				case "Groups": $search_filter .= "organizationalUnit)"; break;
				case "Joinable Groups": $search_filter .= "joinableGroup)"; break;
				case "Organisations": $search_filter .= "organization)"; break;
				default: $search_filter .= "*)"; break;
			}
			switch(urldecode($attrib)) {
				case "Common Name": $search_filter .= "(cn"; break;
				case "Surname": $search_filter .= "(sn"; break;
				case "Business Phone": $search_filter .= "(telephone"; break;
				case "E-mail Address": $search_filter .= "(mail"; break;
				case "Title": $search_filter .= "(title"; break;
				case "Distinguished Name": $search_filter .="(dn"; break;
				case "Location": $search_filter .="(l"; break;
				default: break;
			}
			switch(urldecode($precision)) {
				case "exactly matches": $search_filter .= "=".$search_string.")"; break;
				case "starts with": $search_filter .= "=".$search_string."*)"; break;
				case "ends with": $search_filter .= "=*".$search_string.")"; break;
				case "approximates": $search_filter .= "~=".$search_string.")"; break;
				case "contains": $search_filter .= "=*".$search_string."*)"; break;
				default: break;
			}
			$search_filter = "(&".$search_filter.")";
		//	echo $search_filter;
//		}
		return $search_filter;
	}

	cfunction get_mode() {
		global $mode;
		if (isset ($mode)) {
			$mode = urldecode($mode);
		}
		else {
			$mode = "tree";
		}
		return $mode;
	}

	function display_form() {
		global $lm, $FILE;
?>		<form method=get action=<? echo $FILE; ?>>
		<input type=text name=search_filter size=25 value="<? echo $lm->search_filter; ?>"><br>
		<input type=hidden name=ldap_action value=search>
		<input type=submit value="Search">
		<input type=reset value="Clear">
		</form>
<?
	}

	cfunction makeForm($s) {
		global $FILE;
		echo "<table border=0 cellspacing=2 cellpadding=2 bgcolor=gray>\n";
		for ($i=0; $i<count($s); $i++) {
		$parameter = $s[$i];
		echo "<form method=get action=".$FILE.">\n";
		echo "<tr>\n\t<td colspan=2 align=left bgcolor=lightgrey>\n";
		echo $parameter[0];
		echo "\t\t</td>\n\t</tr>";
		echo "<tr>\n\t<td align=left bgcolor=white>\n";
		echo "\t\t<input type=submit width=80 height=30 value=".$parameter[1].">\n";
		echo "\t\t</td>\n\t<td align=left bgcolor=lightyellow>\n";
		echo "\t\t<input type=text size=25 name=".$parameter[2].">\n";
		echo "\t\t</td>\n\t</tr>\n</form>\n";
		}
		echo "</table>\n";
	}

	cfunction display_console() {
		echo '<table width="100%" border=0 cellspacing=2 cellpadding=2 bgcolor=gray><tr>';
		echo '<td colspan=2 align=center valign=middle bgcolor=white><h2>LDAP Console</h2></td></tr><tr>';
		echo '<td align=center valign=middle>';
		$things = array(
			0 => array("Bind (authenticate) to the directory.", "bind", "who"),
			1 => array("Change the search base.", "cb", "where"),
			2 => array("Change information associated with an entry","change","entry"),
			3 => array("Create a new group entry","create","group"),
			4 => array("Edit a complete Directory entry","vedit","entry"),
			5 => array("Find an entry in the directory.","find","entry")
		);
		$this->makeForm($things);
		echo '</td><td align=center valign=middle>';
		$things = array(
			0 => array("Change the group base.","groupbase","where"),
			1 => array("Display detailed help for a function","help","command"),
			2 => array("Subscribe to a group.","join","group"),
			3 => array("List the groups owned by someone","list","who"),
			4 => array("List out the groups in which someone is a member.", "memberships", "who"),
			5 => array("Remove obsolete entries from a group.", "purge", "group")
		);
		$this->makeForm($things);
		echo '</td></tr></table>';
	}
}
?>
