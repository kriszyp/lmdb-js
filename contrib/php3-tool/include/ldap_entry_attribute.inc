<?
class ldap_entry_attribute {
	var $name, $values, $parent;
	cfunction ldap_entry_attribute($d) {
	//	echo "creating new ldap_entry_attribtute<br>\n";
		$this->dn = $d;
		$a = ldap_explode_dn($this->dn, 1);
		$this->cn = $a[0];
	}

	cfunction getAttributeName($string) {
		global $prefs;
		for ($i=0; $i<count($prefs->attribute_names); $i++) {
			if ($prefs->attribute_names[$i][0] == $string) {
				return $prefs->attribute_names[$i][1];
			}	
		}
		return $string;
	}
	cfunction isVisible($string) {
		global $prefs;
		for ($i=0; $i<count($prefs->attribute_names); $i++) {
			if ($prefs->attribute_names[$i][0] == $string) {
				return $prefs->attribute_names[$i][2];
			}
		}
		return "FALSE";
	}
	
	cfunction getValues($l_i, $r_e_i) {
		//echo "My name is ".$this->name."<br>\n";
		$this->values = ldap_get_values($l_i, $r_e_i, $this->name);
	}

	cfunction display() {
		echo "<tr>\n\t<td valign=top bgcolor=white>\n";
		echo "\t\t".$this->name."\n\t\t</td>\n\t<td valign=top bgcolor=lightyellow>\n";
		echo "<ul type=square>\n";
		for($i=0; $i<$this->values["count"]; $i++) {
			//echo "Displaying value ".$i."<br>\n";
			echo "<li>";
			$this->displayValue($i);
			echo "<br>\n";
		}
		echo "</ul>\n";
		echo "</td>\n</tr>\n";
	}

	cfunction formatHTMLValues() {
		$ct = $this->values["count"];
		$str = "";
		$str .= "<tr>\n\t<td valign=top bgcolor=white>\n";
		$n = $this->getAttributeName($this->name);
		$str .= "\t\t".$n."\n\t\t</td>\n\t<td valign=top bgcolor=lightyellow>\n\t\t<ul type=square>\n";
	//	if ($ct > 1) {
	//		$str .= "\t\t<ul type=square>\n";
	//	}
		for ($i=0; $i<$this->values["count"]; $i++) {
			$str .= "\t\t\t<li>";
			$str .= $this->formatHTMLValue($i);
			$str .= "<br>\n";
		}
		//if ($ct > 1) { $str .= "\t\t\t</ul>\n"; }
		$str .= "\t\t\t</ul>\n\t\t</td>\n\t</tr>\n";
		return $str;
	}
	
	cfunction formatHTMLValue($index) {
		global $prefs, $FILE, $host;
		$p = "";
		switch ($this->name) {
			case "cn":
				$p .= "<a href=".$FILE."?host=".urlencode($host)."&ldap_action=read&base_dn=".urlencode($this->dn).">".$this->values[$index]."</a>";
				break;
			case "ou":
				$p .= "<a href=".$FILE."?ldap_action=list&host=".urlencode($host)."&base_dn=".urlencode($this->dn).">".$this->values[$index]."</a>";
				break;
			case "seealso":
			case "member":
			case "requeststo":
			case "errorsto":
			case "owner":
			case "lastmodifiedby":
			case "modifiersname":
				$p .= "<a href=".$FILE."?host=".urlencode($host)."&ldap_action=read&base_dn=".urlencode($this->values[$index]).">".ldap_dn2ufn($this->values[$index])."</a>";
				break;
			case "mail":
				$p .= "<a href=mailto:".$this->values[$index].">".$this->values[$index]."</a>";
				break;
			case "postaladdress":
			case "homepostaladdress":
				$i=0;
				$tok = strtok($this->values[$index], "$");
				while ($tok) {
					$p .= $i." ".$tok."<br>\n";
					$tok = strtok("$");
					$i++;
				}
				break;
			case "labeledurl":
				$tok = strtok($this->values[$index], " ");
				$tok2 = strtok("\0");
				$p .=  '<a href='.$tok.'>'.$tok2.'</a>';
				break;
			case "lastmodifiedtime":
			case "modifytimestamp":
				$t = $this->values[$index];
				$hour = (int) $t[6].$t[7];
				$minute = (int) $t[8].$t[9];
				$second = (int) $t[10].$t[11];
				$month = (int) $t[2].$t[3];
				$day = (int) $t[4].$t[5];
				$year = (int) $t[0].$t[1];
				$timestamp = mktime($hour, $minute, $second, $month, $day, $year);
				$date = date("h:i:sa, on l, dS of F Y", $timestamp);
				$p .= $date;
				break;
			case "jpegphoto":
				$p .= '<a href="'.$prefs->get("PATH.photo").'?base_dn='.urlencode($this->dn).'"><img src="'.$prefs->get("PATH.photo").'?base_dn='.urlencode($this->dn).'" alt="Image of '.$this->cn.'" border=0></a>';
				break;
			default:
				$p .= $this->values[$index];
				break;
		}
		return $p;
	}

	cfunction displayValue($index) {
		//echo "ldap_entry_attribute.displayValue(".$index.")<br>\n";
		global $FILE, $host;
		if ($this->name == "cn") {
			print "<a href=".$FILE."?host=".urlencode($host)."&ldap_action=read&base_dn=".urlencode($this->dn).">".$this->values[$index]."</a>";
		}
		else if ($this->name == "ou") {
			print "<a href=".$FILE."?ldap_action=list&host=".urlencode($host)."&base_dn=".urlencode($this->dn).">".$this->values[$index]."</a>";
		}
		else if ($this->name == "seealso" || $this->name == "member" || $this->name == "requeststo" || $this->name == "errorsto" || $this->name == "owner" || $this->name == "lastmodifiedby" || $this->name == "modifiersname") {
			print "<a href=".$FILE."?host=".urlencode($host)."&ldap_action=read&base_dn=".urlencode($this->values[$index]).">".ldap_dn2ufn($this->values[$index])."</a>";
		}
		else if ($this->name == "mail") {
			print "<a href=mailto:".$this->values[$index].">".$this->values[$index]."</a>";
		}
		else if ($this->name == "labeledurl") {
			$tok = strtok($this->values[$index], " ");
			$tok2 = strtok("\0");
			print '<a href='.$tok.'>'.$tok2.'</a>';
		}
		else if ($this->name == "lastmodifiedtime" || $this->name == "modifytimestamp") {
			$t = $this->values[$index];
			$hour = (int) $t[6].$t[7];
			$minute = (int) $t[8].$t[9];
			$second = (int) $t[10].$t[11];
			$month = (int) $t[2].$t[3];
			$day = (int) $t[4].$t[5];
			$year = (int) $t[0].$t[1];
			$timestamp = mktime($hour, $minute, $second, $month, $day, $year);
			$date = date("h:i:sa, on l, dS of F Y", $timestamp);
		//	$date = getdate($timestamp);
		//	$date = getdate($this->values[$index]);
		//	echo "".$date["hours"].":".$date["minutes"].",
		//	".$date["weekday"].",".$date["month"]." ".$date["mday"].", ".$date["year"]."<br>\n";
			print $date;
		}
		else {
			print $this->values[$index];
		}
	}
}
?>
