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

package Gallifrey::rule;

sub new {
	my $class = shift @_;
	my $self = {
		counter => shift @_,
		table => shift @_,
		chain => shift @_,
		fate => shift @_,
		source => shift @_,
		dest => shift @_,
		protocol => shift @_,
		dirty => 0,
		original => shift @_,
	};
	return bless $self, $class;
}

sub print {
	my $self = shift;
	print $self->{counter}." ".$self->{table}." ".$self->{chain}." ".$self->{fate}." ".$self->{source}." ".$self->{dest}." ".$self->{protocol}."\n";
}

sub get_counter {
	my $self = shift;
	return $self->{counter};
}

sub get_table {
	my $self = shift;
	return $self->{table};
}

sub get_chain {
	my $self = shift;
	return $self->{chain};
}

sub get_fate {
	my $self = shift;
	return $self->{fate};
}

sub get_source {
	my $self = shift;
	return $self->{source};
}

sub get_dest {
	my $self = shift;
	return $self->{dest};
}

sub get_protocol {
	my $self = shift;
	return $self->{protocol};
}

sub is_dirty {
	my $self = shift;
	return $self->{dirty};
}

sub be_dirty {
	my $self = shift;
	$self->{dirty} = shift @_;
}

sub get_original {
	my $self = shift;
	return $self->{original};
}

return 1;
