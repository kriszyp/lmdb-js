
=head1 Introduction

This is a sample Perl module for the OpenLDAP server slapd.
It also contains the documentation that you will need to
get up and going.

WARNING: the interfaces of this backen to the perl module
MAY change.  Any suggestions would greatly be appreciated.


=head1 Overview

The Perl back end works by embedding a Perl interpreter into
the slapd backend. Then when the configuration file indicates
that we are going to be using a Perl backend it will get an
option that tells it what module to use.  It then creates a 
new Perl object that handles all the request for that particular
instance of the back end.


=head1 Interface

You will need to create a method for each one of the
following actions that you wish to handle.

   * new        # Creates a new object.
   * search     # Performs the ldap search
   * compare    # does a compare
   * modify     # modify's and entry
   * add        # adds an entry to back end
   * modrdn     # modifies a an entries rdn
   * delete     # deletes an ldap entry
   * config     # process unknow config file lines

=head2 new

This method is called when the config file encounters a 
B<perlmod> line. The module in that line is then effectively
used into the perl interpreter, then the new method is called
to create a new object.  Note that multiple instances of that
object may be instantiated, as with any perl object.

The new method doesn't receive any arguments other than the
class name.

RETURN: 

=head2 search

This method is called when a search request comes from a client.
It arguments are as follow.

  * obj reference
  * filter string
  * size limit
  * time limit
  * attributes only flag ( 1 for yes )
  * list of attributes that are to be returned. (could be empty)

RETURN:

=head2 compare

This method is called when a compare request comes from a client.
Its arguments are as follows.

  * obj reference
  * dn
  * attribute assertion string

RETURN:

=head2 modify

This method is called when a modify request comes from a client.
Its arguments are as follows.

  * obj reference
  * dn
  * lists formatted as follows
   { ADD | DELETE | REPLACE }, key, value

RETURN:

=head2 add

This method is called when a add request comes from a client.
Its arguments are as follows.

  * obj reference
  * entry in string format.

RETURN:

=head2 modrdn

This method is called when a modrdn request comes from a client.
Its arguments are as follows.

  * obj reference
  * dn
  * new rdn
  * delete old dn flage ( 1 means yes )

RETURN:

=head2 delete

This method is called when a delete request comes from a client.
Its arguments are as follows.

  * obj reference
  * dn

RETURN:

=head2 config

  * obj reference
  * arrray of arguments on line

RETURN: non zero value if this is not a valid option.

=head1 Configuration

The perl section of the config file recognizes the following 
options.  It should also be noted that any option not recoginized
will be sent to the B<config> method of the perl module as noted
above.

  database perl         # startn section for the perl database

  suffix          "o=AnyOrg, c=US"

  perlModulePath /path/to/libs  # addes the path to @INC variable same
                             # as "use lib '/path/to/libs'"

  perlModule ModName       # use the module name ModName from ModName.pm



=cut

package SampleLDAP;

use POSIX;

sub new
{
	my $class = shift;

	my $this = {};
	bless $this, $class;
        print STDERR "Here in new\n";
	print STDERR "Posix Var " . BUFSIZ . " and " . FILENAME_MAX . "\n";
	return $this;
}

sub search
{
	my $this = shift;
	my( $filterStr, $sizeLim, $timeLim, $attrOnly, @attrs ) = @_;
        print STDERR "====$filterStr====\n";
	$filterStr =~ s/\(|\)//g;
	$filterStr =~ s/=/: /;

	my @match_dn = ();
	foreach my $dn ( keys %$this ) {
		if ( $this->{ $dn } =~ /$filterStr/im ) {
			push @match_dn, $dn;
			last if ( scalar @match_dn == $sizeLim );

		}
	}

	my @match_entries = ();
	
	foreach my $dn ( @match_dn )  {
		push @match_entries, $this->{ $dn };
	}

	return ( 0 , @match_entries );

}

sub compare
{
	my $this = shift;
	my ( $dn, $avaStr ) = @_;
	my $rc = 0;

	$avaStr =~ s/=/: /;

	if ( $this->{ $dn } =~ /$avaStr/im ) {
		$rc = 1;
	}

	return $rc;
}

sub modify
{
	my $this = shift;

	my ( $dn, @list ) = @_;

	while ( @list > 0 ) {
		my $action = shift @list;
		my $key    = shift @list;
		my $value  = shift @list;

		if( $action eq "ADD" ) {
			$this->{ $dn } .= "$key: $value\n";

		}
		elsif( $action eq "DELETE" ) {
			$this->{ $dn } =~ s/^$key:\s*$value\n//mi ;

		}
		elsif( $action eq "REPLACE" ) {
			$this->{ $dn } =~ s/$key: .*$/$key: $value/im ;
		}
	}

	return 0;
}

sub add
{
	my $this = shift;

	my ( $entryStr ) = @_;

	my ( $dn ) = ( $entryStr =~ /dn:\s(.*)$/m );

	#
	# This needs to be here untill a normalize dn is
	# passed to this routine.
	#
	$dn = uc( $dn );
	$dn =~ s/\s*//g;


	$this->{$dn} = $entryStr;

	return 0;
}

sub modrdn
{
	my $this = shift;

	my ( $dn, $newdn, $delFlag ) = @_;

	$this->{ $newdn } = $this->{ $dn };

	if( $delFlag ) {
		delete $this->{ $dn };
	}
	return 0;

}

sub delete
{
	my $this = shift;

	my ( $dn ) = @_;
	
        print STDERR "XXXXXX $dn XXXXXXX\n";
	delete $this->{$dn};
}

sub config
{
	my $this = shift;

	my ( @args ) = @_;
        local $, = " - ";
        print STDERR @args;
        print STDERR "\n";
	return 0;
}

1;


