=pod
    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
=cut

use strict;
use warnings;

package Gallifrey::iptables;

sub generate {
	print " " x 20, "**" x 20, "\n";
	print "\e[1mHere starts the output:\e[0m\n\n";
	#print ("-----One of the possible ways to go-----\n");
	my $output = "";
	foreach (@_) {
		#$output .= "iptables -A ".$_->{chain}." -t ".$_->{table}." -p ".$_->{protocol};
		#$output .= " -s ".$_->{source}." -d ".$_->{dest};
		#if ($_->{fate} eq "accept") {
		#	$output .= " -j ACCEPT";
		#} elsif ($_->{fate} eq "discard") {
		#	$output .= " -j DROP";
		#}
		#$output .= "\n";
		$output .= $_->get_original."\n";
	}
	return $output;
}

sub parse {
	my $input = shift @_;
	my $output;
	my $counter = 0;
	my @stack;
	while (<$input>) {
		if (/^iptables\s\-A/) {
			my ($table, $chain, $fate, $protocol, $source, $source_wild,
			$dest, $dest_wild, $original);
			($table) = /\-t\s+(\w+)/;
			($chain) = /\-A\s+(\w+)/;
			($protocol) = /\-p\s+(\w+)/;
			($source) = /\-s\s+([0-9\.\/]+)/;
			($dest) = /\-d\s+([0-9\.\/]+)/;
			($fate) = /\-j\s+(\w+)/;
			if (!$source) { $source = "null" };
			if (!$dest) { $dest = "null" };
			($original) = /(.*)/;
			my $rule = Gallifrey::rule->new(++$counter, $table, $chain, $fate,
			$source, $dest, $protocol, $original);
			push @stack, $rule;
			print $rule->get_original."\n";
			#$rule->print();
			#print $counter." ".$chain." ".$table." ".$fate." ".$source." ".$dest." ".$protocol."\n";
		}
	}
	return @stack;
}

return 1;
