<?
include 'include/ldap_entry_attribute.inc';
class ldap_entry {
	var $attributes;
	var $dn;
	var $parent;
	var $attributeCount;
	var $link_identifier;
	var $r_e_i;

	cfunction ldap_entry($l_i) {
	//	echo "creating new ldap_entry<br>\n";
		$this->link_identifier = $l_i;
	}

	cfunction getAttributes() {
		$i=0;
		$attrib = new ldap_entry_attribute($this->dn);
		$n = ldap_first_attribute($this->link_identifier, $this->r_e_i, &$ber);
		while ($n) {
			$attrib->name = $n;
			$attrib->getValues($this->link_identifier,$this->r_e_i);
			$this->attributes[$i] = $attrib;
			$i++;
			$attrib = new ldap_entry_attribute($this->dn);
			$n = ldap_next_attribute($this->link_identifier, $this->r_e_i, $ber);
		}
	}

	cfunction formatHTMLDN($dn) {
		global $FILE, $host;
		$string = "";
		$attribs = ldap_explode_dn($dn, 0);
		$names = ldap_explode_dn($dn, 1);
		for ($i=0; $i<$attribs["count"]; $i++) {
			$s = $attribs[$i];
			for ($j=$i+1; $j<$attribs["count"]; $j++) {
				$s .= ",".$attribs[$j];
			}
			if (($s[0] == "c") && ($s[1] == "n")) {
				$string .= "<a href=".$FILE."?ldap_action=read&base_dn=".urlencode($s).">".$names[$i]."</a>";
			}
			else {
				$string .= "<a href=".$FILE."?ldap_action=list&base_dn=".urlencode($s).">".$names[$i]."</a>";
			}
			if ($i<$attribs["count"]-1) { $string .= ", "; }
		}
		return $string;
	}

	cfunction formatHTMLAttributes() {
		global $FILE, $host;
		$s = "";
		$s .= "<tr>\n\t";
		$s .= '<td colspan=2 bgcolor="#9380DB" align="center" valign="middle">';
		$s .= "\n\t\t<h3 class=head>".$this->formatHTMLDN($this->dn)."</h3>\n";
		$s .= "\t\t</td>\n\t</tr>\n";	
		$c = count($this->attributes);
		for ($i=0; $i<$c; $i++) {
			$attrib = $this->attributes[$i];
			if ($attrib->isVisible($attrib->name) == "TRUE") {
				$s .= $attrib->formatHTMLValues();
			}
		}
		$a = $this->attributes[0];
		$v = $a->values[1];
		if ($v == "organizationalUnit" || $v == "organization") {
			$s .= "<tr>\n\t<td colspan=2>\n";
			$s .= "\t\t<a href=".$FILE."?host=".urlencode($host)."&ldap_action=list&base_dn=".urlencode($this->dn).">Browse</a>\n";
			$s .= "\t\t</td>\n\t</tr>\n";
		}
		else if ($v == "person") {
			$s .= "<tr>\n\t<td colspan=2>\n";
			$s .= "\t\t<a href=".$FILE."?host=".urlencode($host)."&ldap_action=read&admin_action=modify&base_dn=".urlencode($this->dn).">Modify</a>\n";
			$s .= "\t\t</td>\n\t</tr>\n";
		}
		else {
			$s .= "<tr>\n\t<td colspan=2>\n\t\t&nbsp;\n\t\t</td>\n\t</tr>\n";
		}
		return $s;
	}

	cfunction display() {
		global $FILE, $host;
		echo "<tr><td colspan=2 bgcolor=gray>";
		echo "<h3>".ldap_dn2ufn($this->dn)."</h3>";
		echo "</td></tr>";
		$c = count($this->attributes);
		for ($i=0; $i<$c; $i++) {
			$attrib = $this->attributes[$i];
			$attrib->display();
		}
		$a = $this->attributes[0];
		$v = $a->values[1];
		if ($v == "organizationalUnit" || $v == "organization") {
			echo "<tr><td colspan=2>";
			echo "<a href=".$FILE."?host=".urlencode($host)."&ldap_action=list&base_dn=".urlencode($this->dn).">Browse</a>";
			echo "</td></tr>";
		}
		else {
			echo "<tr><td colspan=2>&nbsp;</td></tr>";
		}
	}
}
?>
