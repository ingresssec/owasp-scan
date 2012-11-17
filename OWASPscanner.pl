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
use Config::Tiny;
use IO::Socket;
use IO::Handle;
use Getopt::Std;
use Getopt::Long;
use Fcntl;

my $release = "0.9b";
my $verbose = "";
my $host = "";
my $port = "";
my $proxyhost = "";
my $proxyport = "";
my $lhost = "";
my $sock = "/tmp/.scannerlock";
my $xsserpath = "";
my $website = "";
my $owaspdir = "";
my $xsserpath = "";
my $xsserbinpath = "";
my $sqlmappath = "";
my $sqlmapbinpath = "";
my $sqlninjapath = "";
my $nmappath = "";
my $niktopath = "";
my $niktobinpath = "";
my $testdebug;
my $Config;

# Process command line arguments
my $confile = "config.ini";
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
	usage();
}

exit(1);

sub spider
{	
	print ("Enter the website to spider: ");
	chomp($website = <STDIN>);
	print ("[+] Spidering ".$website."...\n\n");
	
	my $cfg = Config::Tiny->read( $confile );
	my $niktobinpath = $cfg->{options}->{ niktobinpath };
	my $niktopath = $cfg->{options}->{ niktopath };
	my $owaspdir = $cfg->{options}->{ owaspdir };
	
	system ($niktobinpath . "nikto -Display off -nointeractive -Tuning x 6 -Format xml -o " . $owaspdir . "nikto.xml -host " . $website . "\n");
	print ("[+] Spidering of ". $website." is completed\n");
}

sub xss
{
	print ("Enter the website to test: ");
	chomp($website = <STDIN>);
	print ("[+] Scanning ".$website."...\n");
}

sub all
{
	print("[+] ]Spidering host...\n");
	spider();
	print("[+] ]Done... now let's test for XSS vulnerabilities...\n'");
	xss();
	print("[+] ]We're done... enjoy.");
	exit(1);
}

sub usage
{
	die <<EOF;
	Usage: $0
	
	--all : Run all tests
	--xss : Only run XSS testing
	--spider : Only spider the hostname
	
EOF
}

sub parseconfig
{
	unless (-e $confile) {
		print "[-] ".$confile." does not exist. Exiting...\n";
		exit(-1);
	}
	print "[+] Parsing ".$confile."...\n";
	my $confline;
	open(FILE,"<".$confile) || die "[-] Can't open configuration file...".
						"exiting\n";
	while ($confline = <FILE>) {
		chomp($confline);
		# comment line
		if ($confline =~ m/^#\.*/) {
			next;
		}

		# We start with parameters that might require spaces
		#  Proxy host
		if ($confline =~ m/^proxyhost=(\S+)/) {
			$proxyhost = $1;
			if ($verbose == 1) {
				print "  - Proxy host: ".$proxyhost."\n";
			}
		}
		# Proxy port
		elsif ($confline =~ m/^proxyport=(\d+)/) {
			$proxyport = $1;
			if ($verbose == 1) {
				print "  - Proxy port: ".$proxyport."\n";
			}
		}		
		# local host 
		elsif ($confline =~ m/lhost=(\S+)/) {
			$lhost = $1;
			if ($verbose == 1) {
				print "  - local host: ".$lhost."\n";
			}
		}
		# OWASP scanner directory path
		elsif ($confline =~ m/^owaspdir=(\S+)$/) {
			$owaspdir = $1;
			unless ($owaspdir=~m/\/$/) {
				$owaspdir = $owaspdir."/";
			}
		}
		# nikto path
		elsif ($confline =~ m/^niktopath=(\S+)$/) {
			$niktopath = $1;
			unless ($niktopath=~m/\/$/) {
				$niktopath = $niktopath."/";
			}
		}
		# nikto binary path
		elsif ($confline =~ m/^niktobinpath=(\S+)$/) {
			$niktobinpath = $1;
			unless ($niktobinpath=~m/\/$/) {
				$niktobinpath = $niktobinpath."/";
			}
		}
		# xsser path
		elsif ($confline =~ m/^xsserpath=(\S+)$/) {
			$xsserpath = $1;
			unless ($xsserpath=~m/\/$/) {
				$xsserpath = $xsserpath."/";
			}
		}

		# xsser binary path
		elsif ($confline =~ m/^xsserbinpath=(\S+)$/) {
			$xsserbinpath = $1;
			unless ($xsserbinpath=~m/\/$/) {
				$xsserbinpath = $xsserbinpath."/";
			}
		}
		
		# sqlmap path
		elsif ($confline =~ m/^sqlmappath=(\S+)$/) {
			$sqlmappath = $1;
			unless ($sqlmappath=~m/\/$/) {
				$sqlmappath = $sqlmappath."/";
			}
		}
		
		# sqlmap binary path
		elsif ($confline =~ m/^sqlmapbinpath=(\S+)$/) {
			$sqlmapbinpath = $1;
			unless ($sqlmapbinpath=~m/\/$/) {
				$sqlmapbinpath = $sqlmapbinpath."/";
			}
		}
		
		# sqlninja path
		elsif ($confline =~ m/^sqlninjapath=(\S+)$/) {
			$sqlninjapath = $1;
			unless ($sqlninjapath=~m/\/$/) {
				$sqlninjapath = $sqlninjapath."/";
			}
		}		
		
		# nmap path
		elsif ($confline =~ m/^nmappath=(\S+)$/) {
			$nmappath = $1;
			unless ($nmappath=~m/\/$/) {
				$nmappath = $nmappath."/";
			}
		}		
	close FILE;
	}
}
