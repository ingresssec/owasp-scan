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
my $nmappath = "";
my $website = "";

# Process command line arguments
my %options;
my $verbose = $options{verbose};
my $confile = $options{config} || "OWASPscanner.conf";
my $xss = $options{xss};
my $spider = $options{spider};
my $all = $options{all};
my $user = $options{user};
my $password = $options{password} || "";
my $wordlist = $options{wlist};
my $debug = $options{debug};

print ("\nOWASPscanner.pl. ".$release."\n");
print ("Copyright (C) 2012 Woody Hughes <whughes\@ingresssecurity.com>\n");
print ("\n");

my $mode = $options{""};
if ($mode ne "--config" && $mode ne "--all" && $mode ne "--verbose" && $mode ne "--xss" && $mode ne "--spider")
{
	usage();
	exit(1);
	}

print ("We need to determine where some important files are located.\n");
print ("Please enter the path to nmap: ");
chomp($nmappath = <STDIN>);
print ("Please enter the path to xsser: ");
chomp($xsserpath = <STDIN>);
print ("Enter the website to test: ");
chomp($website = <STDIN>);

print ("Scanning ".$host."...\n");



sub usage
{
	die <<EOF;
	Usage: $0
	
	--verbose : Verbose mode
	--config <config_file>
	--all : Run all tests
	--xss : Only run XSS testing
	--spider : Only spider the hostname
EOF
}