<!DOCTYPE PUBLIC HTML "-//W3C//HTML3.2 Final//En">
<html>
<head>
	<!-- copyright, (C) Predrag Balorda, OpenLDAP Foundation, 1998,1999,2000 -->
	<title>PHP3 Thingy</title>
	<link rel="stylesheet" type="text/css" href="style.css">
</head>
<body>
<?
include ('include/preferences.inc');
include ('include/ldap_manager.inc');
include ('include/query_manager.inc');
include ('include/search_form.inc');
$FILE = "http://$HTTP_HOST$SCRIPT_NAME";
$JPEGFILE = "http://$HTTP_HOST/ldap/php3-tool/ldap-photo.php3";
$qm = new query_manager;
$lm = new ldap_manager;
$prefs = new preferences;

function main() {
	$main_start_time = microtime();
	global $lm, $qm, $prefs, $FILE;
	$qm = new query_manager;
	$lm = new ldap_manager;
	$prefs = new preferences;
	$lm->ldap_action = $qm->get_action();
	$lm->base_dn = $qm->get_base_dn();
	$lm->host = $qm->get_host();
	$lm->search_filter = $qm->get_search_filter();
	$prefs->loadPreferences();
	display_advanced_form();
	if (!$lm->connect($lm->host)) {
		echo "Couldn't connect to <b>".$lm->host."</b><br>\n";
		echo "Bye";
		return 0;
	}
	if (!$lm->ldapTakeAction($lm->ldap_action) || $lm->entriesCount == 0) {
		echo "Didn't find anything for ".$lm->ldap_action." on ".$lm->search_filter." from ".$lm->base_dn."<br>\n";
		return 0;
	}
	else {
	//	echo "I got <b>".$lm->entriesCount."</b> entries for ".$lm->ldap_action." on ".$lm->search_filter." from ".$lm->base_dn."<br>\n";
		$get_entries_s_t = microtime();
		$lm->getEntries();
		$get_entries_e_t = microtime();
	//	echo "Disconnecting from <b>".$lm->host."</b><br>\n";
		$lm->disconnect();
	}
	if (($qm->get_mode() == "tree") && ($lm->ldap_action == "list")) {
		$display_entries_s_t = microtime();
		?><table width="100%" border=1 cellpadding=0 cellspacing=0>
		<tr>
			<td bgcolor="#9380DB" align=center valign=absmiddle>
				<h3 class=head><?echo $lm->formatHTMLBaseDN($lm->base_dn);?></h3>
				</td>
			</tr>
		</table>
		<p>
		<script language="JavaScript" src="javascript/expandable-outlines.js">
		</script><?
		$tokens = array( 0 => " ", 1 => ",");
		$e = $lm->entries[0];
		$s = ldap_dn2ufn($e->dn);
		$firstel = $lm->stripString($s, $tokens);
		for ($i=0; $i<count($lm->entries); $i++) {
			$c = "";
			$e = $lm->entries[$i];
			$s = ldap_dn2ufn($e->dn);
			$tin = $lm->stripString($s, $tokens);
			?><div id="<? echo $tin; ?>Parent" class=parent>
			<h3 class=subsection>
			<a href="#" onClick="expandIt('<? echo $tin; ?>'); return false">
			<img name="imEx" src="false.gif" border=0 alt=""></a>
			<? $n = ldap_explode_dn($e->dn, 1); echo $n[0]; ?></h3>
			</div>
			<div id="<? echo $tin; ?>Child" class=child>
			<table border=1 cellspacing=0 cellpadding=0>
			<? $c .= $e->formatHTMLAttributes(); echo $c; ?>
			</table>
			<br>
			</div><?
		}
		?><script language="JavaScript"><!--
		if (NS4) {
			firstEl = "<? echo $firstel; ?>Parent";
			firstInd = getIndex(firstEl);
			showAll();
			arrange();
		}
		//--></script><?
	}
	else {
		$display_entries_s_t = microtime();
		$c = $lm->formatHTMLEntries();
		echo $c;
	}
	$display_entries_e_t = microtime();
//	echo "<div align=right valign=bottom>";
//	$t1 = $lm->calculateTime("getEntries()", $get_entries_s_t, $get_entries_e_t);
//	$t2 = $lm->calculateTime("displayEntries()", $display_entries_s_t, $display_entries_e_t);
//	$main_end_time = microtime();
//	$t3 = $lm->calculateTime("main()", $main_start_time, $main_end_time);
//	$t = $t3 - ($t1 + $t2);
//	echo "Ether : ".$t." seconds<br>\n";
//	echo "</div>";
	return 1;
}
$return = main();
?>
</body>
</html>
