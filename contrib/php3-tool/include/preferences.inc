<?
class preferences {
	var $name;
	var $sections = array();
	var $base_dn;
	var $host;
	var $attribute_names = array();

	cfunction getSection($s) {
	////	echo "getSection(".$s.")<br>";
		$sect = array();
		for ($i=0; $i<count($this->sections); $i++) {
			$sect = $this->sections[$i];
	//		echo $sect[0]."<br>";
			if ($sect[0] == $s) {
	//			echo "Found ".$sect[0]."<br>";
				return $sect[1];
			}	
		}
	//	echo "Didn't find ".$s."<br>";
	}
	cfunction get($s) {
		$class = explode(".", $s);
		$sect = $this->getSection($class[0]);
		$values = array();
		$values = $sect[1];
		for ($i=0; $i<count($sect); $i++) {
			$values = $sect[$i];
	//		echo $values[0]."<br>";
			if ($values[0] == $class[1]) {
	//			echo "Found ".$values[0]."<br>";
				return $values[1];
			}
		}
	//	echo "Didn't find ".$class[1]."<br>";
	}
	cfunction getName($s) {
		$n = trim(strtok($s, "{"));
		return $n;
	}
	cfunction getBody($s) {
		$i = strpos($s, "{") + 1;
		$j = strpos($s, "}") - 1;
		$tok = substr($s, $i, $j-$i);
		return $tok;
	}
	cfunction getValues($b) {
		$t = '" ","\" ","\n"';
		$av_pairs = array();
		$pairs = array();
		$av_pair = array();
		$pairs = explode(";", $b);
		for ($i=0; $i<count($pairs)-1; $i++) {
			$av_pair = explode(":", $pairs[$i]);
			$av_pair[0] = trim($av_pair[0]);
			$av_pair[1] = trim($this->stripString($av_pair[1], $t));
	//		echo "<li>".$av_pair[0].":".$av_pair[1];
			$av_pairs[$i] = $av_pair;
		}
		return $av_pairs;
	}
	cfunction getStatements($s) {
		$i = 0;
		$end = strpos($s, "}");
		while($end != FALSE) {
			$tok = substr($s, 0, $end+1);
			$s = substr($s, $end+1, strlen($s));
	//		echo "<ul>";
			$this->sections[$i] = $this->getStatement($tok);
	//		echo "</ul>\n";
			$end = strpos($s, "}");
			$i++;
		}
	//	echo count($this->sections)." sections<br>";
	}
	cfunction getStatement($s) {
		$values[0] = $this->getName($s);
//		echo "<li>Name ".$values[0];
		$body = $this->getBody($s);
//		echo "<li>Values<ul>";
		$values[1] = $this->getValues($body);
//		echo "</ul></li>";
		return $values;
	}
	cfunction loadPreferences() {
		if (count($preferences) != 0) {
			echo "I have got ".count($this->sections)." preferences here<br>\n";
		}
		else {
			$fp = fopen("php3tool.conf", "r");
			$i = 0;
			$string = "";
			while (!feof($fp)) {
				$string .= fgets($fp, 80);
			}
			fclose($fp);
			$this->getStatements($string);
		}
		$this->loadAttributeNames($this->get("PATH.attributes"));
	}

	cfunction loadAttributeNames($s = "at.conf") {
	//	global $attribute_names;
		if (count($this->attribute_names) != 0) {
			//This is bullshit here..how do we make php3
			//preserve an array in memory between re-loads?
			//And no, I'm not going to send it every time
			//I make a subsequent request..
			//If we don't fix these things it won't run
			//on anything smaller than a StarFire 10000
			//EVEN THOUGH this stuff is suprisingly fast.
			echo "I have got attribute_names here<br>\n";
		}
		else {
			//echo "I dont have attribute_names here<br>\n";
			$fp = fopen($s, "r");
			$i = 0;
			while (!feof($fp)) {
				$string = "";
				$foo = "";
				$string = fgets($fp, 80);
				$foo = strtok($string, ",");
				$this->attribute_names[$i][0] = $foo;
				$foo = strtok(",");
				$this->attribute_names[$i][1] = $foo;
				$foo = strtok("\n");
				$this->attribute_names[$i][2] = $foo;
				$i++;
			}
		}
	//	echo "Hello world:<b>".count($this->attribute_names)."</b>\n";
	//	for ($i=0; $i<count($this->attribute_names)-1; $i++) {
	//		echo $this->attribute_names[$i][0]." - <strong>".$this->attribute_names[$i][1]."</strong> - ".$this->attribute_names[$i][2]."<br>\n";
	//	}	
		return $this->attribute_names;
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
