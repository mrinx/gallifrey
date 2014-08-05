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

package Gallifrey::main;

require Gallifrey::iptables;
require Gallifrey::ciscoacl;
require Gallifrey::juniper;

sub run {
	my $file = shift @_;
	my $type = shift @_;
	my $int = shift @_;
	my $outfile = shift @_;
	open(my $fh, "<", $file) || die "Couldn't open '".$file."' for reading";
	#my $output;
	#while (<$fh>) {
	#	$output .= $_;
	#}
	my $output;
	my (@stack, @stack2);
	if ($type eq "iptables") {
		@stack = Gallifrey::iptables::parse($fh);
	} elsif ($type eq "cisco") {
		@stack = Gallifrey::ciscoacl::parse($fh);
	} elsif ($type eq "juniper") {
		@stack = Gallifrey::juniper::parse($fh);
	} else {
		print "Wrong type of firewall rules was specified...\n";
		exit 0;
	}
	#print " " x 20, "*" x 40, "\n";
	my ($s_size1, $s_size2, $s_dup, $s_drop);
	$s_size1 = scalar @stack;
	$s_dup = 0;
	$s_drop = 0;
	for (my $i = 0; $i < scalar @stack; $i++) {
		if ($stack[$i]->is_dirty) { next; }
		push @stack2, $stack[$i];
		for (my $j = $i; $j < scalar @stack; $j++) {
			if ($stack[$i]->is_dirty || $stack[$j]->is_dirty || $i == $j) { next; }
			if ($stack[$i]->get_table ne $stack[$j]->get_table) { next; }
			if ($stack[$i]->get_chain ne $stack[$j]->get_chain) { next; }
			if (($stack[$j]->get_protocol() eq $stack[$i]->get_protocol()) || ($stack[$j]->get_protocol eq "any")) {
				my $addrsj = new NetAddr::IP($stack[$j]->get_source);
				my $addrsi = new NetAddr::IP($stack[$i]->get_source);
				my $addrdj = new NetAddr::IP($stack[$j]->get_dest);
				my $addrdi = new NetAddr::IP($stack[$i]->get_dest);
				if ($addrsj->within($addrsi) && $addrdj->within($addrdi)) {
					$s_dup++;
					my $output = " " x 20 ."--" x 20 ."\n";
					$output .= "Possible duplicity found: ";
					if ($addrsj == $addrsi && $addrdj == $addrdi) {
						$output .= "rules ".$stack[$i]->get_counter." and "
						.$stack[$j]->get_counter." seem to be the same.\n";
					} else {
						$output .= "the rule ".$stack[$j]->get_counter
						." could be a subset of ".$stack[$i]->get_counter.".\n";
					}
					if (lc($stack[$j]->get_fate) ne lc($stack[$i]->get_fate)) {
						$output .= "The fate of packets differs.\n";
					}
					print $output;
					print $stack[$i]->get_counter." ".$stack[$i]->get_original."\n";
					print $stack[$j]->get_counter." ".$stack[$j]->get_original."\n";
					if ($int) {
						while (1) {
							print "Ignore and keep both, first or second? (ignore/first/second): ";
							my $resp = lc(<STDIN>);
							chomp $resp;
							if ($resp eq "ignore" || $resp eq "i") {}
							elsif ($resp eq "first" || $resp eq "f") {
								$stack[$j]->be_dirty(1);
								$s_drop++;
							}
							elsif ($resp eq "second" || $resp eq "s") {
								pop @stack2;
								$stack[$i]->be_dirty(1);
								$s_drop++;
							}
							else { next; }
							last;
						}
					} else {
						$stack[$j]->be_dirty(1);
						$s_drop++;
					}
					#pop @stack2; next;
				}
			}
		}
	}
	$s_size2 = scalar @stack2;
	my $orf = "";
	if ($type eq "iptables") {
		$orf = Gallifrey::iptables::generate(@stack2);
	} elsif ($type eq "cisco") {
		$orf = Gallifrey::ciscoacl::generate(@stack2);
	} elsif ($type eq "juniper") {
		$orf = Gallifrey::juniper::generate(@stack2);
	}
	print $orf;
	print "\n\e[1mLets look at some stats:\e[0m\n";
	print "Number of processed / output rules; duplicities found / dropped:\n";
	print $s_size1." / ".$s_size2."; ".$s_dup." / ".$s_drop."\n";
	if ($outfile) {
		open(my $fho, ">", $outfile) || die "Couldn't open '".$outfile."' for writing";
		print $fho $orf;
	}
	return 1;
}

return 1;
