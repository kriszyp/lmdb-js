<?
include 'include/ldap_entry.inc';
class ldap_manager {
	var $entries;
	var $result_identifier, $search_filter, $base_dn;
	var $ldap_action, $host;
	var $link_identifier;
	var $entriesCount;

	function connect($host) {
		$this->link_identifier = ldap_connect($host);
		if ($this->link_identifier) return 1;
		return 0;
	}

	function disconnect() {
		ldap_close($this->link_identifier);
	}

	function ldapTakeAction($a = "search") {
		$func_ptr = "ldap_".$a;
		if ($this->result_identifier = $func_ptr($this->link_identifier, $this->base_dn, $this->search_filter)) {
			$this->entriesCount = ldap_count_entries($this->link_identifier, $this->result_identifier);
			return 1;
		}
		return 0;
	}
	
	cfunction getEntries() {
		$i=0;
		$entry = new ldap_entry($this->link_identifier);
		$entry->r_e_i = ldap_first_entry($this->link_identifier, $this->result_identifier);
		while($entry->r_e_i) {
			$entry->dn = ldap_get_dn($this->link_identifier, $entry->r_e_i);
			$entry->getAttributes();
			$this->entries[$i] = $entry;
			$i++;
			$r = $entry->r_e_i;
			$entry = new ldap_entry($this->link_identifier);
			$entry->r_e_i = ldap_next_entry($this->link_identifier, $r);
		}
//		ldap_free_result($this->result_identifier);
	}

	cfunction displayEntries() {
		echo $this->formatHTMLEntries();
	}

	cfunction formatHTMLBaseDN($dn) {
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
				$string .= "<a href=".$FILE."?ldap_action=read&base_dn=".urlencode($s).">".$names[$i]."</a>, ";
			}
			else {
				$string .= "<a href=".$FILE."?ldap_action=list&base_dn=".urlencode($s).">".$names[$i]."</a>, ";
			}
		}
		return $string;
	}

	cfunction formatHTMLEntries() {
		$string = "";
		$string .= '<table width="100%" border=1 cellpadding=0 cellspacing=0>';
		$string .= "\n";
		for ($i=0; $i<count($this->entries); $i++) {
			$e = $this->entries[$i];
			$string .= $e->formatHTMLAttributes();
		}	
		$string .= "</table>\n";
		return $string;
	}

	cfunction calculateTime($string, $s_t, $e_t) {
		$tok1 = strtok($s_t, " ");
		$msecs1 = $tok1;
		$tok1 = strtok(" ");
		$secs1 = $tok1;
	 
		$tok2 = strtok($e_t, " ");
		$msecs2 = $tok2;
		$tok2 = strtok(" ");
		$secs2 = $tok2;
		$t_t = (float) ($secs2 + $msecs2) - (float) ($secs1 + $msecs1);
		echo "execution time for <b>".$string."</b> : <b>".$t_t."</b> seconds<br>\n";
	//	echo "start: ".$secs1."<br>\n";
	//	echo "end: ".$secs2."<br>\n";
		return (float) $t_t;
	}
	
	cfunction stripString($string, $tokens) {
		$s = $string;
		for ($i=0; $i<count($tokens); $i++) {
			$result = "";
			$tok = strtok($s, $tokens[$i]);
			while($tok) {
				$result .= $tok;
			//	echo "result = ".$result."\n";
				$tok = strtok($tokens[$i]);
			}
			$s = $result;
		//	echo "s = ".$s."\n";
		}
	//	echo "result = ".$result."\n";
		return $result;
	}
}
?>
