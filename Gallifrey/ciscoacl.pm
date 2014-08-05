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

package Gallifrey::ciscoacl;

sub generate {
	print " " x 20, "**" x 20, "\n";
	print "\e[1mHere starts the output:\e[0m\n\n";
	my $output = "";
	foreach (@_) {
		#$output .= "access-list 0";
		#if ($_->{fate} eq "accept") {
		#	$output .= " permit ";
		#} elsif ($_->{fate} eq "discard") {
		#	$output .= " deny ";
		#}
		#$output .= $_->{protocol}." ".$_->{source}." ".$_->{dest}."\n";
		$output .= $_->get_original."\n";
	}
	return $output;
}

sub parse {
	my $input = shift @_;
	my $output;
	my @stack;
	my $counter = 0;
	while (<$input>) {
		# todo icmp, igmp protocol
		if (/^access\-list/) {
#			my ($list_number, $fate, $protocol, $source, $source_wc, $operator1,
#				$port1, $destination, $destionation_wc, $operator2, $port2,
#				$established, $precedence, $tos, $fragments, $log, $log_input,
#				$time_range, $dscp, $flag);
#			($list_number) = /access\-list\s*([\d]+)/;
#			$output .= $list_number;
			my ($list_number, $fate, $protocol,
			$source, $source_wild, $dest, $dest_wild, $original);
			($original) = /(.*)/;
			($list_number) = /access\-list\s+([\d]+)/;
			($fate, $protocol) = /(permit|deny)\s+(\w+)\s+
				(((?<source>[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\s+
				[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})|
				(?<source>any)|
				(?<source>host\s+[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}))
				\s+
				((?<dest>[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\s+
				[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})|
				(?<dest>any)|
				(?<dest>host\s+[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})))
				/x;
			$source = $+{source};
			$dest = $+{dest};
			if ($source eq "any") {
				$source = "0.0.0.0/0";
			} elsif ($source =~ /host/) {
				($source) = /host\s+([0-9\.]+)/;
				$source .= "/32";
			} else {
				($source, $source_wild) = $source =~ /([0-9\.]+)\s+([0-9\.]+)/;
				my $wild_mask_packed = pack 'C4', split /\./, $source_wild;
				my $norm_mask_packed = ~$wild_mask_packed;
				my $norm_mask_dotted = join '.', unpack 'C4', $norm_mask_packed;
				my $ip = new NetAddr::IP($source, $norm_mask_dotted);
				$source = $ip;
			}
			if ($dest eq "any") {
				$dest = "0.0.0.0/0";
			} elsif ($dest =~ /host/) {
				($dest) = /host\s+([0-9\.]+)/;
				$dest .= "/32";
			} else {
				($dest, $dest_wild) = $dest =~ /([0-9\.]+)\s+([0-9\.]+)/;
				my $wild_mask_packed = pack 'C4', split /\./, $dest_wild;
				my $norm_mask_packed = ~$wild_mask_packed;
				my $norm_mask_dotted = join '.', unpack 'C4', $norm_mask_packed;
				my $ip = new NetAddr::IP($dest, $norm_mask_dotted);
				$dest = $ip;
			}
			if (!$source) { $source = "null" };
			if (!$dest) { $dest = "null" };
			my $rule = Gallifrey::rule->new(++$counter, 0, $list_number, $fate,
			$source, $dest, $protocol, $original);
			push @stack, $rule;
			print $rule->get_original."\n";
			#$output .= $counter++." ".$fate." ".$source." ".$dest." ".$protocol."\n";
		}
	}
	return @stack;
}

return 1;

# basic ACL syntax:
# access-list [1-1199] [permit|deny] [protocol|protocol-keyword]
#	[source source-wildcard|any] [source port] [destination destination-wildcard|any]
#	[destination port] [precedence precedence#] [options]
