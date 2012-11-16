#!/usr/bin/env perl 
#
# OWASPscanner - OWASP testing guide v3 scanner
# Copyright (C) 2012
# http://code.googlecode.com/owasp-test-scanner
# Woody Hughes <whughes@ingresssecurity.com>
# 
# OWASPscanner is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# OWASPscanner is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with OWASPscanner. If not, see <http://www.gnu.org/licenses/>.

# Setup variables
use strict;
use Config;
use IO::Socket;
use IO::Handle;
use Getopt::Std;
use Getopt::Long;
use Fcntl;

my $release = "0.9b";
my $host = "";
my $port = "";
my $proxyhost = "";
my $proxyport = "8080";
my $method;
my $httpversion = 0;
my $timeout = 5;
my $ssl = "";
my $lhost = "";
my $dev = "eth0";
my $domain;
my $hostnamelen = 250;
my $dnssock = "/tmp/.scannerlock";
my $resolvedip = "10.255.255.254";
my $xsserpath = "";
my $skipfishpath = "";
my $website = "";

# Process command line arguments
my $confile = "";
my $xss = "";
my $spider = "";
my $all = "";
my $debug = "";

print ("\nOWASPscanner.pl Version ".$release."\n");
print ("Copyright (C) 2012 Woody Hughes <whughes\@ingresssecurity.com>\n");
print ("\n");

if (GetOptions ('xss' => \$xss, 'spider' => \$spider, 'all' => \$all, 'debug' => \$debug))
{
	if ($xss)
	{
		xss();
	}
	elsif ($spider)
	{
		spider();
	}
	elsif ($all)
	{
		all();
	}
	elsif($debug)
	{
		debug();
	}	
}
usage();
exit(1);

sub spider
{	
	print ("Please enter the path to skipfish: ");
	chomp($skipfishpath = <STDIN>);
	print ("Enter the website to spider: ");
	chomp($website = <STDIN>);
	print ("Spidering ".$host."...\n");
	system $skipfishpath . '/skipfish -W' . $skipfishpath . '/dictionaries/complete.wl -o test ' . $website;
}

sub xss
{
	print ("Please enter the path to xsser: ");
	chomp($xsserpath = <STDIN>);	
	print ("Enter the website to test: ");
	chomp($website = <STDIN>);
	print ("Scanning ".$host."...\n");
}

sub all
{
	print("Alright yo, here we go... time to spider the host...\n");
	spider();
	print("We're done spidering the host... now let's test for XSS vulnerabilities...\n'");
	xss();
	print("We're done... enjoy the results. Play on playa!");
	exit(1);
}

sub usage
{
	die <<EOF;
	Usage: $0
	
	--config <config_file>
	--all : Run all tests
	--xss : Only run XSS testing
	--spider : Only spider the hostname
EOF
}