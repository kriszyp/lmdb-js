<?
function display_options($string) {
?>
	<select name="precision">
		<option>exactly matches</option>
		<option selected>approximates</option>
		<option>starts with</option>
		<option>ends with</option>
		<option>contains</option>
		</select>
<?
}
function display_items($string) {
?>
	<select name="objectclass">
		<option selected>People</option>
		<option>Groups</option>
		<option>Joinable Groups</option>
		<option>Services</option>
		<option>Organisations</option>
		<option>Documents</option>
		</select>
<?
}
function display_attribs($string) {
?>
	<select name="attrib">
		<option selected>Common Name</option>
		<option>Surname</option>
		<option>Business Phone</option>
		<option>E-mail Address</option>
		<option>Distinguished Name</option>
		<option>Title</option>
		<option>Location</option>
		</select>
<?
}

function display_base_dn($string) {
?>
	<select name="base_dn">
		<option value="c=US">US</option>
		<option value="o=University of Michigan, c=US" selected>University of Michigan</option>
		<option value="o=Balorda and Balorda, c=UK">Balorda and Balorda</option>
		</select>
<?
}
		
function display_simple_form() {
	global $lm, $FILE;
?>	<form method=form action=<? echo $FILE; ?>>
	<input type=text name=search_filter size=25 value="<? echo $lm->search_filter; ?>"><br>
	<input type=hidden name=ldap_action value=search>
	<input type=submit value="Search"><input type=reset value="Clear">
	</form><?
}

function display_advanced_form() {
	global $lm, $FILE;
?>
	<table width="100%" border=1 cellspacing=0 cellpadding=0>
	<tr>
		<td colspan=2 bgcolor="lightyellow"> <!bgcolor=#9380DB>
			<p class=form>
			<form method=get action=<? echo $FILE; ?>>
			Find <?display_items("objectclass")?>
			within <?display_base_dn("base_dn")?>
			whose <?display_attribs("attrib")?><br>
			<?display_options("precision")?>
			<input type=text name=search_string size=25 value="">
			<input type=hidden name=ldap_action value=search>
			<input type=submit value="Search">
			</form>
			</p>
			</td>
		</tr>
	</table>
<?
}
?>
