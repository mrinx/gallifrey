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

package Gallifrey::juniper;

sub generate {
	my $stacksize = scalar @_;
	print " " x 20, "**" x 20, "\n";
	print "\e[1mHere starts the output:\e[0m\n\n";
	my $output = "";
	$output .= "firewall {\n";
	my $filter = "";
	foreach (@_) {
		if ($filter ne $_->get_chain) {
			if ($filter ne "") { $output .= "\t}\n"; }
			$filter = $_->get_chain;
			$output .= "\tfilter ".$filter." {\n";
		}
		#$output .= "access-list 0";
		#if ($_->{fate} eq "accept") {
		#	$output .= " permit ";
		#} elsif ($_->{fate} eq "discard") {
		#	$output .= " deny ";
		#}
		#$output .= $_->{protocol}." ".$_->{source}." ".$_->{dest}."\n";
		$output .= "\t\t".$_->get_original."\n";
	}
	$output .= ($stacksize > 0 ? "\t}\n}\n" : "}\n");
	return $output;
}

sub parse {
	my $input = shift @_;
	my $output;
	my @stack;
	my $counter = 0;
	my $content = do { local $/; <$input> };
	#my $filex = qr/(?<filter>filter\s[^{}]*\{(?<terms>([^{}]*\{([^{}]*(?<poop3>\{([^{}]*)\})*[^{}]*)*\}[^{}]*)*)\})/s;
	($content) = $content =~ m/.*?firewall\s*\{\s*(.*)\s*\}\s*$/s;
	if (!$content) { return @stack; }
	#print $content;
	while (1) {
		#($filter, $infilter, $xxx) = $content =~ m/.*?firewall\s*\{\s*filter\s(.*?)\s*\{(.*)\s*\}\s*\}\s*/s;
		my $filex = qr/(?<filter>filter\s[^{}]*\{(?<terms>([^{}]*\{([^{}]*(?<poop3>\{([^{}]*)\})*[^{}]*)*\}[^{}]*)*)\})/s;
		#my ($xxx) = $content =~ m/.*?firewall\s*\{\s*(filter\s.*?\s*(\{(.*?\{.*?\}.*?)*?\}))*\s*\}\s*$/s;
		$content =~ m/(?<first>${filex})(?<next>.*)/s;
		my $filtergrp = $+{filter};
		#print "\n\n\n", $+{filter}, "\n\n\n";
		$content = ($+{next} ? $+{next} : 0);
		###
		my ($filter) = $filtergrp =~ /filter\s+([^{}\s]*)/s;
		while (1) {
			my $termex = qr/(?<terms>[^{}]*\{([^{}]*(?<poop3>\{([^{}]*)\})*[^{}]*)*\}\s*)/;
			$filtergrp =~ /(?<term>$termex)(?<nterm>.*)/s;
			$filtergrp = $+{nterm};
			my ($term, $fate, $protocol,
				$source, $dest, $original);
			my $termgrp = $+{term};
			($term) = $termgrp =~ /term\s+([^{}\s]*)/s;
			($original) = $termgrp =~ /^\s*(.*?)\s*$/s;
			($protocol) = $termgrp =~ /protocol\s+([^;\s]*)/s;
			if (!$protocol) { $protocol = "any"; }
			($source) = $termgrp =~ /source-address\s+([^;\s]*)/s;
			($dest) = ($termgrp =~ m/destination-address\s+([^;\s]*)/s);
			$source = "0.0.0.0/0" if !$source;
			$dest = "0.0.0.0/0" if !$dest;
			($fate) = $termgrp =~ /then\s*\{(.*?)\}/s;
			$fate = "" if !$fate;
			$fate =~ s/\s//gm;
			my $rule = Gallifrey::rule->new(++$counter, 0, $filter, $fate,
				$source, $dest, $protocol, $original);
			push @stack, $rule;
			print $filter.":\t".$rule->get_original."\n";
			last if $filtergrp !~ /${termex}/s;
		}
		###
		last if $content !~ /${filex}/s;
	}
	return @stack;
}

return 1;
