<?
if (isset($base_dn)) {
//	echo urldecode ($base_dn)."<br>\n";
}
if (isset($cn)) {
//	echo urldecode ($cn)."<br>\n";
}
$link_identifier = ldap_connect("127.0.0.1");
$result_identifier = ldap_read($link_identifier, $base_dn, 'objectclass=*');
if(!$result_identifier) {
	echo "No results.\n";
}
else {
	$num_entries = ldap_count_entries($link_identifier, $result_identifier);
	if ($num_entries == 0) {
		echo "No results\n";
		return 1;
	}
	Header("Content-type: image/jpeg");
	$info = ldap_get_entries($link_identifier, $result_identifier);
	ldap_close($link_identifier);
	for ($i=0; $i<$info["count"]; $i++) {
//		echo $i;
		if ($info[$i]["cn"][0] == $cn) {
			//echo "<b>".$info[$i]["cn"][0]."</b><br>";
		}
		for ($j=0; $j<$info[$i]["count"]; $j++) {
			$attribute = $info[$i][$j];
			if (strtolower ($attribute) == "jpegphoto") {
			//	$file = fopen("/tmp/tmpphoto.jpg", "w");
			//	echo $info[$i]["jpegphoto"][0];
				$p = $info[$i]["jpegphoto"][0];
				$photo = base64_decode($p);
				echo $photo;
			//	fwrite($file, $photo);
			//	flush();
			//	fclose($file);
			//	$file = fopen("/tmp/tmpphoto.jpg", r);
			//	$contents = fread ($file, filesize("/tmp/tmpphoto.jpg"));
			//	fclose($file);
			//	echo $contents;
			}
		}
	}
}
?>
