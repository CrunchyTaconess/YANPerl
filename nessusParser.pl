#Xavier Alers | PERL Nessus Parser | YANP to YANPerl
#!/usr/bin/perl

use strict;
use warnings;
use XML::LibXML;
use Excel::Writer::XLSX;

print "Beginning Nessus parsing script ...\n";

my $nessus_source = $ARGV[0];
my $output_file = $ARGV[1] || 'output.xlsx';

die "Usage: $0 <nessus_source> [output_file]\n" unless defined $nessus_source;

my %results;
my %categories;

# Add Nessus Plugin IDs to blacklist
my @blacklist = (
    "11154",  # Unknown Service Detection
    "19506",  # Nessus Scan Information
    "56468",  # Time of Last System Startup
    "57033",  # Microsoft Patch Bulletin Feasibility Check
);

# Create a new Excel workbook
my $workbook = Excel::Writer::XLSX->new($output_file);
my $summary_sheet = $workbook->add_worksheet('Live Host Summary');
my $port_matrix_sheet = $workbook->add_worksheet('Open Port Matrix');
my $vulnerability_details_sheet = $workbook->add_worksheet('Vulnerability Details');
my $missing_patches_sheet = $workbook->add_worksheet('Missing Patches');

# Set up Excel column formats
my $bold_format = $workbook->add_format(bold => 1);
my $wrap_format = $workbook->add_format(text_wrap => 1);

# Adjust column widths as needed
$summary_sheet->set_column('A:D', 20);  
$vulnerability_details_sheet->set_column('A:M', 20);  
$port_matrix_sheet->set_column('A:B', 20);
$missing_patches_sheet->set_column('A:D', 20);    

#Set bold format to row
$summary_sheet->set_row(0, undef, $bold_format);
$vulnerability_details_sheet->set_row(0, undef, $bold_format);
$port_matrix_sheet->set_row(0, undef, $bold_format);
$missing_patches_sheet->set_row(0, undef, $bold_format);

# Define headings for sheets
my @summary_headings = (
    'Hostname',
    'IP Address',
    'Device Type',
    'Operating System',
);

my @port_matrix_headings = (
    'Hostname',
    'IP Address',
);

my @vulnerability_details_headings = (
    'Hostname',
    'IP Address',
    'CVSS',
    'Severity',
    'Port',
    'Protocol',
    'Vulnerability',
    'Description',
    'Remediation',
    'Output',
    'CVE',
    'Exploit Available',
);

my @missing_patches_headings = (
    'Hostname',
    'IP Address',
    'Missing Patches',
    'CVEs',
);

# Write headings to sheets
$summary_sheet->write_row('A1', \@summary_headings);
$port_matrix_sheet->write_row('A1', \@port_matrix_headings);
$vulnerability_details_sheet->write_row('A1', \@vulnerability_details_headings);
$missing_patches_sheet->write_row('A1', \@missing_patches_headings);

my $summary_row = 1;
my $port_matrix_row = 1;
my $vulnerability_details_row = 1;
my $missing_patches_row = 1;

# Add a hash to store unique hostname and IP address pairs
my %host_ip_pairs;
my %added_pairs;  # Hash to keep track of added pairs

# Process Nessus files
if (-d $nessus_source) {
    opendir my $dir, $nessus_source or die "Cannot open directory: $!";
    my @files = grep { /\.nessus$/ } readdir $dir;
    closedir $dir;

    if (@files) {
        foreach my $file (@files) {
            my $file_path = "$nessus_source/$file";
            parse_nessus_results($file_path);
        }
    } else {
        die "No .nessus files found in '$nessus_source'\n";
    }
} elsif (-f $nessus_source && $nessus_source =~ /\.nessus$/) {
    parse_nessus_results($nessus_source);
} else {
    die "Invalid input: '$nessus_source' is neither a directory nor a .nessus file\n";
}

sub parse_nessus_results {
    my ($file_report) = @_;

    print "Parsing: $file_report\n";

    my $dom = XML::LibXML->load_xml(location => $file_report);

    foreach my $host ($dom->findnodes('//ReportHost')) {
        my $ip = $host->getAttribute('name');

        next unless $ip;

        my @items = $host->findnodes('ReportItem');

        my %host_info = (
            'scan_name'       => '',
            'scan_start'      => '',
            'scan_stop'       => '',
            'os'              => '',
            'hostname'        => '',
            'netbios_name'    => '',
            'mac_address'     => '',
            'other_hostnames' => '',
            'os_app'          => '',
            'os_confidence'   => '',
            'device_type'     => '',
        );

        my @vulnerabilities;

        foreach my $item (@items) {
            my $plugin_id = $item->getAttribute('pluginID');

            next if grep { $_ eq $plugin_id } @blacklist;

            if ($plugin_id == 10150) {
                # NetBios
                my $plugin_output = $item->findvalue('plugin_output');
                my ($computer_name, $workgroup_domain) = ('', '');

                $computer_name = $1 if $plugin_output =~ /Computer name\s*:\s*(\S+)/;
                $workgroup_domain = $1 if $plugin_output =~ /Workgroup \/ Domain name\s*:\s*(\S+)/;

                $host_info{'netbios_name'} = "$computer_name.$workgroup_domain";
            } elsif ($plugin_id == 46180) {
                # Other hostnames
                my $plugin_output = $item->findvalue('plugin_output');
                my @hostnames = map { s/^\s*-\s*//; $_ } split(/,\s*/, $plugin_output);
                $host_info{'other_hostnames'} = join(', ', @hostnames);
            } elsif ($plugin_id == 45590) {
                # OS CPE
                my $plugin_output = $item->findvalue('plugin_output');
                my @os_apps = map { s/^cpe:\/a://; $_ } split(/\n/, $plugin_output);
                $host_info{'os_app'} = join(', ', @os_apps);
            } elsif ($plugin_id == 11936) {
                # OS Guesses
                my $plugin_output = $item->findvalue('plugin_output');
                if ($plugin_output =~ /Confidence Level : (\d+)/) {
                    $host_info{'os_confidence'} = $1;
                }
            } elsif ($plugin_id == 54615) {
                # Device Type
                my $plugin_output = $item->findvalue('plugin_output');
                if ($plugin_output =~ /Remote device type : (.+)/) {
                    $host_info{'device_type'} = $1;
                }
            } else {
                # Other vulnerabilities
                my %vuln_info = (
                    'plugin_name'       => $item->getAttribute('pluginName'),
                    'plugin_id'         => $plugin_id,
                    'port'              => $item->getAttribute('port'),
                    'protocol'          => $item->getAttribute('protocol'),
                    'description'       => $item->getAttribute('description'),
                    'plugin_output'     => $item->findvalue('plugin_output'),
                    'service_name'      => $item->getAttribute('svc_name'),
                    'severity'          => $item->getAttribute('severity'),
                    'cvss_base_score'   => '0.0',
                    'cvss_vector'       => '',
                    'exploit_available' => 'false',
                    'exploit'           => '',
                    'cve'               => '',
                );

                # Extract CVSS information if available
                my $cvss_base_score_node = $item->findnodes('cvss_base_score')->[0];
                my $cvss_vector_node = $item->findnodes('cvss_vector')->[0];

                if ($cvss_base_score_node) {
                    $vuln_info{'cvss_base_score'} = $cvss_base_score_node->textContent;
                }

                if ($cvss_vector_node) {
                    $vuln_info{'cvss_vector'} = $cvss_vector_node->textContent;
                }

                # Check for exploit availability
                my $exploit_node = $item->findnodes('exploit_available')->[0];
                if ($exploit_node && $exploit_node->textContent eq 'true') {
                    $vuln_info{'exploit_available'} = 'true';
                }

                # Check for Metasploit exploit
                my $metasploit_node = $item->findnodes('exploit_framework_metasploit')->[0];
                if ($metasploit_node) {
                    $vuln_info{'exploit'} = 'true - metasploit';
                }

                # Check for CVE information
                my $cve_node = $item->findnodes('cve')->[0];
                if ($cve_node) {
                    $vuln_info{'cve'} = $cve_node->textContent;
                }

                push @vulnerabilities, \%vuln_info;

                # Collect hostname and IP address pair
                push @{$host_ip_pairs{$host_info{'hostname'}}}, $ip;
            }

        }

        

        # Write data to appropriate worksheets
        my @summary_data = (
            $host_info{'hostname'},
            $ip,
            $host_info{'device_type'},
            $host_info{'os'},
        );
        $summary_sheet->write_row($summary_row, 0, \@summary_data);

        foreach my $vuln (@vulnerabilities) {
            my @vuln_data = (
                $host_info{'hostname'},
                $ip,
                $vuln->{'cvss_base_score'},
                $vuln->{'severity'},
                $vuln->{'port'},
                $vuln->{'protocol'},
                $vuln->{'plugin_name'},
                $vuln->{'description'},
                $vuln->{'solution'},
                $vuln->{'plugin_output'},
                $vuln->{'cve'},
                $vuln->{'exploit_available'},
            );
            $vulnerability_details_sheet->write_row($vulnerability_details_row, 0, \@vuln_data);
            $vulnerability_details_row++;
        }

                # Handle missing patches and CVEs
        my @missing_patches = map { /MS(\d+-\d+)/ ? $1 : () } grep { /MS\d+-\d+/ } map { $_->{'plugin_name'} } @vulnerabilities;
        my @cves = grep { $_ } map { $_->{'cve'} } @vulnerabilities;  # Filter out empty strings

        if (@missing_patches || @cves) {
            my @missing_patches_data = (
                $host_info{'hostname'},
                $ip,
                join(', ', @missing_patches),
                join(', ', @cves),
            );
            $missing_patches_sheet->write_row($missing_patches_row, 0, \@missing_patches_data);
            $missing_patches_row++;
        }


        $summary_row++;
    }
}

# After processing all Nessus files, write the data to the "Open Port Matrix" worksheet
foreach my $hostname (keys %host_ip_pairs) {
    my @ip_addresses = @{$host_ip_pairs{$hostname}};
    foreach my $ip (@ip_addresses) {
        my $pair_key = "$hostname:$ip";

        # Check if this pair has already been added
        unless ($added_pairs{$pair_key}) {
            my @port_matrix_data = (
                $hostname,
                $ip,
            );
            $port_matrix_sheet->write_row($port_matrix_row, 0, \@port_matrix_data);
            $port_matrix_row++;
            $added_pairs{$pair_key} = 1;  # Mark the pair as added
        }
    }
}

$workbook->close();

print "Parsing completed. Output saved to: $output_file\n";

exit(0);
