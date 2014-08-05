#!/usr/bin/env perl

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
use Getopt::Long;
use NetAddr::IP;

require Gallifrey::main;
require Gallifrey::rule;

my $version = "0.9";

my $help = <<END;
\e[1mNeed some help?\e[0m

gallifrey --help
	Will print out this help

gallifrey --version
	Will show the current version of itself

gallifrey --interactive
	Will ask questions whenever the next step isn't clear

gallifrey --type=fw_rules
	One of the iptables, cisco and juniper

gallifrey --file=input_file
	File containing fw rules

gallifrey --out=output_file
	Optional output file

Some options can be combined
END

my ($opt_version, $opt_help, $opt_interactive, $opt_type, $opt_file, $opt_out);

#$opt_file = "sample-iptables";

GetOptions ("version" => \$opt_version,
			"help" => \$opt_help,
			"interactive" => \$opt_interactive,
			"type=s" => \$opt_type,
			"file=s" => \$opt_file,
			"out=s" => \$opt_out);

if ($opt_help) {
	print $help;
	exit 0;
}

if ($opt_version) {
	print $version."\n";
	exit 0;
}

if ($opt_file) {
	if ($opt_type) {
		if ($opt_type ne "iptables" && $opt_type ne "cisco"
			&& $opt_type ne "juniper") {
			print "The type of firewall rules wasn't specified...\n";
			exit 0;
		}
		Gallifrey::main::run($opt_file, $opt_type, $opt_interactive, $opt_out);
		exit 0;
	}
} else {
	print "The input file containing firewall rules wasn't specified...\n";
	exit 0;	
}

exit 0;
