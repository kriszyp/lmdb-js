#
# ldaperr.tcl: scan ldap.h for error return codes for initializing
# errorCode table.
#

proc genstrings {path} {
    set fp [open $path]
    while {[gets $fp line] != -1 &&
	![string match "#define LDAP_SUCCESS*" $line]} { }
    puts "/* This file automatically generated, hand edit at your own risk! */"
    puts -nonewline "char *ldaptclerrorcode\[\] = {
	NULL"
    set lasterr 0
    while {[gets $fp line] != -1} {
	if {[clength $line] == 0 || [ctype space $line]} continue
	if {![string match #define* $line]} break
	if {![string match "#define LDAP_*" $line]} continue
	lassign $line define macro value
	incr lasterr
	while {$lasterr < $value} {
	    puts -nonewline ",\n\tNULL"
	    incr lasterr
	}
	puts -nonewline ",\n\t\"$macro\""
    }
    puts "\n};"
    puts "#define LDAPTCL_MAXERR\t$value"
}

#cmdtrace on
if !$tcl_interactive {
    genstrings [lindex $argv 0]
}
