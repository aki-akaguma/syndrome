#!/usr/bin/perl
#
# pflog-day-cfrh.pl
#
# depends:
#   apt install libtest-mockmodule-perl
#
#   v0.6.0  2024/05/21  added: SSL_accept error.
#   v0.5.0  2024/05/20  added: spamcop.
#   v0.4.0  2024/05/20  added: S25R.
#   v0.3.1  2024/05/20  added: Named: some us domains.
#   v0.3.0  2024/05/18  added: Named: client_p.
#   v0.2.0  2024/05/02  refactoring full.
#   v0.1.0  2024/05/01  first release.
#

=pod
Purpose of this script:
+ Analyze maillog and detect spam mails
+ Aggregate source IP addresses
+ If there is a lot of spam from the same IP network, it will be combined into a CIDR.
+ Finally, output in a format like 'check_client_access cidr:...' of postfix
=cut

#
use v5.28;
use strict;
use warnings;
#
my $version = '0.6.0';
#
our $DT_PATH   = "/usr/local/etc/pflog-hour-date.txt";
our $MAIL_LOG  = "/var/log/mail.log";
our $TODAY     = "/etc/postfix/cidr/client_access_reject_cidr_today";
our $TODAY_TXT = "/etc/postfix/cidr/client_access_reject_cidr_today.txt";

our $mock_send_command_vmail_get_cc_input = '';

#---- init ----
use Carp;
use Getopt::Long qw(:config posix_default no_ignore_case gnu_compat);
use Test::MockModule;
use JSON::XS;

#---- main ----
#---- command ----
my $opt_help = 0;
my $opt_test = 0;
GetOptions(
    'help|h' => \$opt_help,
    'test'   => \$opt_test,
) or die "Error in command line arguments\n";
my $argc = scalar @ARGV;
if ($opt_help || $argc < 0) {
    print STDERR "[usage] $0 [-h] [--test]\n";
    print STDERR "    -h       print this help\n";
    print STDERR "    --test   test mode\n";
    exit 1;
}
if ($opt_test) {
    setup_test_mode();
}

###
my ($mlog_ary, $dt) = read_curr_maillog($MAIL_LOG, $DT_PATH);
my (
    $cfrh_ip4s, $unk_sasl_ip4s, $host_sasl_ip4s, $client_n_ip4s, $client_p_ip4s,
    $s25r_ip4s, $spamcop_ip4s,  $ptrcloud_ip4s,  $kagoya_ip4s,   $ssl_err_ip4s,
) = extract_spam_sources($mlog_ary);
output_process(
    $dt,            $cfrh_ip4s,     $unk_sasl_ip4s, $host_sasl_ip4s,
    $client_n_ip4s, $client_p_ip4s, $s25r_ip4s,     $spamcop_ip4s,
    $ptrcloud_ip4s, $kagoya_ip4s,   $ssl_err_ip4s
);
if ($opt_test) {
    my %json_map;
    $json_map{'cfrh_ip4s'}      = $cfrh_ip4s;
    $json_map{'unk_sasl_ip4s'}  = $unk_sasl_ip4s;
    $json_map{'host_sasl_ip4s'} = $host_sasl_ip4s;
    $json_map{'client_n_ip4s'}  = $client_n_ip4s;
    $json_map{'client_p_ip4s'}  = $client_p_ip4s;
    $json_map{'s25r_ip4s'}      = $s25r_ip4s;
    $json_map{'spamcop_ip4s'}   = $spamcop_ip4s;
    $json_map{'ptrcloud_ip4s'}  = $ptrcloud_ip4s;
    $json_map{'kagoya_ip4s'}    = $kagoya_ip4s;
    $json_map{'ssl_err_ip4s'}   = $ssl_err_ip4s;
    output_json(\%json_map, "map.json");

    #print "vmail input: $mock_send_command_vmail_get_cc_input\n";
}

exit 0;

sub setup_test_mode {
    ## test mode
    ### replace test path
    replace_test_path(\$DT_PATH);
    replace_test_path(\$MAIL_LOG);
    replace_test_path(\$TODAY);
    replace_test_path(\$TODAY_TXT);
    ##
    ### test mock
    ## our $mock_send_command_vmail_get_cc_input = '';
    our $mock_run_fail2ban_command_net_output = <<'END';
0
END
    our $mock_run_fail2ban_command_host_output = <<'END';
0
END
    our $mock = Test::MockModule->new('main');
    $mock->mock(
        'send_command_vmail_get_cc',
        sub {
            my ($ip4s) = @_;
            foreach my $ip (@$ip4s) {
                $mock_send_command_vmail_get_cc_input .= "$ip\n";
            }
        }
    );
    $mock->mock(
        'run_fail2ban_command_net',
        sub {
            my ($s) = @_;
            my $line = $mock_run_fail2ban_command_net_output;
            chomp($line);
            return $line;
        }
    );
    $mock->mock(
        'run_fail2ban_command_host',
        sub {
            my ($s) = @_;
            my $line = $mock_run_fail2ban_command_host_output;
            chomp($line);
            return $line;
        }
    );
    return;
}

sub replace_test_path {
    my ($path_ref) = @_;
    if ($$path_ref =~ /^\/usr\/local\/(.+)$/) {
        $$path_ref = "fixtures/$1";
    }
    elsif ($$path_ref =~ /^\/var\/(.+)$/) {
        $$path_ref = "fixtures/$1";
    }
    elsif ($$path_ref =~ /^\/etc\/postfix\/(.+)$/) {
        $$path_ref = "fixtures/$1";
    }
    return;
}

sub read_curr_maillog {
    my ($mlog_path, $dt_path) = @_;
    my $dt = do {
        open(my $fh, "<", $dt_path) or croak "can not open: '$dt_path': $!";
        my $line = <$fh>;
        close($fh);
        chomp($line);
        ##print "$line\n";
        $line;
    };
    my @mlog_ary = cut_day_on_mail_log($mlog_path, $dt);
    my $len      = @mlog_ary;
    if ($len == 0) {
        my $mlog_path2 = glob("$mlog_path-????????");
        @mlog_ary = cut_day_on_mail_log($mlog_path2, $dt);
    }
    return (\@mlog_ary, $dt);
}

sub cut_day_on_mail_log {
    my ($mlog, $dt) = @_;
    open(my $fh, "<", $mlog) or croak "can not open file: '$mlog': $!";
    my @ary = cut_day_on_mail_log_loop($fh, $dt);
    close($fh);
    return @ary;
}

sub cut_day_on_mail_log_loop {
    my ($fh, $dt) = @_;
    ## date format: '2025-04-27T01:43:16.317318+09:00'
    my $re_date = qr/\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d/;
    my @ary;
    while (my $line = <$fh>) {
        if ($line =~ /^${dt}T/) {
            chomp($line);
            push(@ary, $line);
        }
        elsif ($line =~ /^$re_date/) {
            ## nothing todo
        }
        else {
            warn "Unmatched line: $line";
        }
    }
    return @ary;
}

sub output_process {
    my (
        $dt,            $cfrh_ip4s,     $unk_sasl_ip4s, $host_sasl_ip4s,
        $client_n_ip4s, $client_p_ip4s, $s25r_ip4s,     $spamcop_ip4s,
        $ptrcloud_ip4s, $kagoya_ip4s,   $ssl_err_ip4s
    ) = @_;
    my @ks = ();
    ##
    @ks = sort sort_ip4_host keys(%$cfrh_ip4s);
    output_cfrh($dt, \@ks);
    ##
    @ks = sort sort_ip4_net keys(%$client_n_ip4s);
    output_net("client_n", \@ks);
    ##
    @ks = sort sort_ip4_host keys(%$unk_sasl_ip4s);
    output_host("unknown sasl", \@ks);
    ##
    @ks = sort sort_ip4_host keys(%$host_sasl_ip4s);
    output_host("host sasl", \@ks);
    ##
    @ks = sort sort_ip4_host keys(%$client_p_ip4s);
    output_host("client_p", \@ks);
    ##
    @ks = sort sort_ip4_host keys(%$s25r_ip4s);
    output_host("s25r", \@ks);
    ##
    @ks = sort sort_ip4_host keys(%$spamcop_ip4s);
    output_host("spamcop", \@ks);
    ##
    @ks = sort sort_ip4_host keys(%$ptrcloud_ip4s);
    output_host("ptrcloud.net", \@ks);
    ##
    @ks = sort sort_ip4_host keys(%$kagoya_ip4s);
    output_host("vir.kagoya.net", \@ks);
    ##
    @ks = sort sort_ip4_host keys(%$ssl_err_ip4s);
    output_host("ssl err", \@ks);
    ##
    return;
}

sub sort_ip4_host {
    return ip4_to_int($a) <=> ip4_to_int($b);
}

sub sort_ip4_net {
    my @aa  = split(/\//, $a);
    my @bb  = split(/\//, $b);
    my $aa0 = ip4_to_int($aa[0]);
    my $bb0 = ip4_to_int($bb[0]);
    my $ret = 0;
    if ($aa0 != $bb0) {
        $ret = $aa0 <=> $bb0;
    }
    elsif (defined $aa[1] && defined $bb[1]) {
        $ret = $aa[1] <=> $bb[1];
    }
    return $ret;
}

sub ip4_to_int {
    my ($ip4s) = @_;
    return unpack("N", pack("C4", split(/\./, $ip4s)));
}

sub send_command_vmail_get_cc {
    my ($ip4s) = @_;
    my $cmd =
"sudo -u master ssh master\@vmail.priv 'cat | /opt/nicnum/bin/get-cc-by-ipv4 --no-host' > $TODAY_TXT";
    open(my $outf, '|-', $cmd)
      or croak "can not open pipe: get-cc-by-ipv4:$!";
    foreach my $ip (@$ip4s) {
        ##print "$ip\n";
        print $outf "$ip\n";
    }
    close($outf);
    return;
}

sub output_cfrh {
    my ($dt, $ip4s) = @_;
    send_command_vmail_get_cc($ip4s);
    ###
    {
        my $dt2 = $dt =~ tr/-//dr;
        open(my $inf, "<", $TODAY_TXT)
          or croak "can not open file: '$TODAY_TXT':$!";
        open(my $outf, ">", $TODAY)
          or croak "can not open file: '$TODAY':$!";
        my $cnt = convert_full($inf, $outf, $dt2);
        close($outf);
        close($inf);
        if ($opt_test) {
            my $a = split(/\n/, $mock_send_command_vmail_get_cc_input);
            $cnt = scalar $a;
        }
        print "cfrh: $cnt\n";
    }
    return;
}

sub convert_full {
    my ($inf, $outf, $dt) = @_;
    my $cnt = 0;
    while (my $line = <$inf>) {
        chomp($line);
        if ($line =~ /^\S+ => (..) (\S+) .*$/) {
            ## 181.232.249.57 => BR 181.232.248.0/23 [181.232.248.0]..[181.232.249.255]
            my $cc  = $1;
            my $net = $2;
            $cc =~ tr/A-Z/a-z/;
            print $outf "$net\t\tREJECT Fishing SPAM $dt client_n_${net}_$cc\n";
            $cnt += 1;
        }
    }
    return $cnt;
}

sub run_fail2ban_command_host {
    my ($s) = @_;
    my $cmd = "fail2ban-client set blocking-manual-host banip $s";
    open(my $inf, '-|', $cmd)
      or croak "can not open pipe: fail2ban-client:$!";
    my $line = <$inf>;
    chomp($line);
    close($inf);
    return $line;
}

sub output_host {
    my ($label, $ip4s) = @_;
    my $cnt = 0;
    my $s   = "";
    foreach my $ip (@$ip4s) {
        $s .= " $ip";
        $cnt += 1;
    }
    ##print "$s\n";
    my $line = run_fail2ban_command_host($s);
    print "$label host: $line/$cnt\n";
    return;
}

sub run_fail2ban_command_net {
    my ($s) = @_;
    my $cmd = "fail2ban-client set blocking-manual banip $s";
    open(my $inf, '-|', $cmd)
      or croak "can not open pipe: fail2ban-client:$!";
    my $line = <$inf>;
    chomp($line);
    close($inf);
    return $line;
}

sub output_net {
    my ($label, $ip4s) = @_;
    my $cnt = 0;
    my $s   = "";
    foreach my $ip (@$ip4s) {
        $s .= " $ip";
        $cnt += 1;
    }
    ##print "$s\n";
    my $line = run_fail2ban_command_net($s);
    print "$label net: $line/$cnt\n";
    return;
}

sub output_json {
    my ($map, $file_path) = @_;
    my $json_txt = JSON::XS->new->ascii->pretty->canonical->encode($map);
    open my $fh, '>', $file_path;
    print $fh $json_txt;
    close $fh;
    return;
}

sub map_count_up {
    my ($map, $key) = @_;
    $map->{$key} = 0 unless $map->{$key};
    $map->{$key} += 1;
    return;
}

sub extract_spam_sources {
    my ($mlog_ary) = @_;
    my %cfrh_ip4s;
    my %unk_sasl_ip4s;
    my %host_sasl_ip4s;
    my %client_n_ip4s;
    my %client_p_ip4s;
    my %s25r_ip4s;
    my %spamcop_ip4s;
    my %ptrcloud_ip4s;
    my %kagoya_ip4s;
    my %ssl_err_ip4s;

    foreach my $line (@$mlog_ary) {
        ##print "$line\n";
        if ($line =~ /^\S+ \S+ postfix\S+: warning: (\S.+)$/) {
            ## 2025-04-27T01:43:16.317318+09:00 sys01 postfix/smtps/smtpd[1060212]: warning:
            my $rest = $1;
            extract_spam_sources_warning($rest, \%unk_sasl_ip4s, \%host_sasl_ip4s);
        }
        elsif ($line =~ /^\S+ \S+ postfix\S+: NOQUEUE: reject: RCPT from (\S.+)$/) {
            ## 2025-05-01T16:37:21.954955+09:00 sys01 postfix/smtpd[196102]: NOQUEUE: reject: RCPT from
            my $rest = $1;
            extract_spam_sources_reject($rest, \%cfrh_ip4s, \%client_n_ip4s, \%client_p_ip4s,
                \%s25r_ip4s, \%spamcop_ip4s, \%ptrcloud_ip4s, \%kagoya_ip4s);
        }
        elsif ($line =~ /^\S+ \S+ postfix\S+: SSL_accept error from (\S.+)$/) {
            ## 2025-04-20T00:00:37.397100+02:00 exp01 postfix/smtps/smtpd[86355]: SSL_accept error from
            my $rest = $1;
            extract_spam_sources_ssl($rest, \%ssl_err_ip4s);
        }
    }
    return (
        \%cfrh_ip4s, \%unk_sasl_ip4s, \%host_sasl_ip4s, \%client_n_ip4s, \%client_p_ip4s,
        \%s25r_ip4s, \%spamcop_ip4s,  \%ptrcloud_ip4s,  \%kagoya_ip4s,   \%ssl_err_ip4s,
    );
}

sub extract_spam_sources_warning {
    my ($rest, $unk_sasl_ip4s, $host_sasl_ip4s) = @_;
    if ($rest =~ /^(\S+)\[(\d+\.\d+\.\d+\.\d+)\]: SASL (LOGIN|PLAIN) authentication failed:/) {
        ## unknown[193.32.162.92]: SASL LOGIN authentication failed: (reason unavailable), sasl_username=chacha
        my $host = $1;
        my $ip4  = $2;
        if ($host =~ /^unknown$/) {
            map_count_up($unk_sasl_ip4s, $ip4);
        }
        elsif ($host =~ /\.com$/) {
            my @known_host_patterns_com = (
                qr/\.[^.]+\.spectrum\.com$/,
                qr/\.compute(?:-1)?\.amazonaws\.com$/,
                qr/\.static\.netvigator\.com$/,
                qr/\.bc\.googleusercontent\.com$/,
                qr/\.tbcn\.telia\.com$/,
                qr/\.cust\.bredband2\.com$/,
                qr/\.myvzw\.com$/,
                qr/\.rcncustomer\.com$/,    # cable.rcncustomer.com ftth.rcncustomer.com
                qr/\.telus\.com$/,          # cidc.telus.com wireless.telus.com
            );
            foreach my $re (@known_host_patterns_com) {
                if ($host =~ $re) {
                    map_count_up($host_sasl_ip4s, $ip4);
                    last;
                }
            }
        }
        elsif ($host =~ /\.net$/) {
            my @known_host_patterns_net = (
                qr/\.[^.]+\.hinet\.net$/,   qr/\.adsl\.fetnet\.net$/,
                qr/\.optonline\.net$/,      qr/\.vps\.ovh\.net$/,
                qr/\.fios\.verizon\.net$/,  qr/\.comcast\.net$/,
                qr/\.rev\.sfr\.net$/,       qr/\.cox\.net$/,
                qr/\.ctm\.net$/,            qr/\.frontiernet\.net$/,
                qr/\.grandenetworks\.net$/, qr/\.orangecustomers\.net$/,
                qr/\.proxad\.net$/,         qr/\.ptd\.net$/,
                qr/\.rima-tde\.net$/,       qr/\.sbcglobal\.net$/,
                qr/\.secureserver\.net$/,   qr/\.sfr\.net$/,
                qr/\.shawcable\.net$/,      qr/\.reverse.socket\.net$/,
                qr/\.sparklight\.net$/,     qr/\.telus\.net$/,
                qr/\.zsttk\.net$/,
            );
            foreach my $re (@known_host_patterns_net) {
                if ($host =~ $re) {
                    map_count_up($host_sasl_ip4s, $ip4);
                    last;
                }
            }
        }
        elsif ($host =~ /\.(ru|se|au|de|br|pl|ch|sg|bg|fr|ca|ua|pt|tw|th|nl|eu|mx|es|gr|lt)$/) {
            map_count_up($host_sasl_ip4s, $ip4);
        }
    }
    return;
}

sub extract_spam_sources_reject {
    my ($rest, $cfrh_ip4s, $client_n_ip4s, $client_p_ip4s, $s25r_ip4s, $spamcop_ip4s,
        $ptrcloud_ip4s, $kagoya_ip4s)
      = @_;
    if ($rest =~ /^([^\[\] ]+)\[(\d+\.\d+\.\d+\.\d+)\]: (.+)$/) {
        my $host  = $1;
        my $ip4   = $2;
        my $rest2 = $3;
        if ($host eq 'unknown') {
            if ($rest2 =~ /^\S+ \S+ Client host rejected: cannot find your hostname,/) {
                ## unknown[103.154.148.50]: 450 4.7.25 Client host rejected: cannot find your hostname, [103.154.148.50]; from=<bnu-vbl@example.com> to=<bnu-vbl@example.com> proto=ESMTP helo=<smtpclient.apple>
                map_count_up($cfrh_ip4s, $ip4);
                return;
            }
            elsif ($rest2 =~ /^\S+ \S+ Client host rejected: cannot find your reverse hostname,/) {
                ## unknown[200.107.119.187]: 450 4.7.1 Client host rejected: cannot find your reverse hostname, [200.107.119.187]; from=<tabuchi@example.com> to=<tabuchi@example.com> proto=ESMTP helo=<[200.107.119.187]>
                map_count_up($cfrh_ip4s, $ip4);
                return;
            }
        }
        if ($rest2 =~
/^\S+ \S+ \S+ Client host rejected: Fishing SPAM \d+ client_n_(\d+\.\d+\.\d+\.\d+\/\d+)_..; /
          )
        {
            ## unknown[45.6.0.58]: 554 5.7.1 <unknown[45.6.0.58]>: Client host rejected: Fishing SPAM 20240220 client_n_45.6.0.0/22_br; from=<shin@example.com> to=<shin@example.com> proto=ESMTP helo=<[45.6.0.58]>
            my $ip4_net = $1;
            map_count_up($client_n_ip4s, $ip4_net);
        }
        elsif ($rest2 =~
            /^\S+ \S+ \S+ Client host rejected: Fishing SPAM Named \d+ client_p_[^ ;]+_(..)\.; /)
        {
            ## static-200-105-212-198.acelerate.net[200.105.212.198]: 554 5.7.1 <static-200-105-212-198.acelerate.net[200.105.212.198]>: Client host rejected: Fishing SPAM Named 20240220 client_p_acelerate.net_bo.; from=<xooxoxo@mailxtr.eu> to=<syndy@example.com> proto=ESMTP helo=<static-200-105-212-198.acelerate.net>
            my $cc = $1;
            extract_spam_sources_reject_client_p($host, $ip4, $cc, $client_p_ip4s);
        }
        elsif ($rest2 =~ /^\S+ \S+ \S+ Client host rejected: S25R check, be patient \[[^]]+\]; /) {
            ## 132-255-37-205.starman.net.br[132.255.37.205]: 450 4.7.1 <132-255-37-205.starman.net.br[132.255.37.205]>: Client host rejected: S25R check, be patient [r1]; from=<z3hovxbiys44r@bqao.com> to=<leyla@example.com> proto=ESMTP helo=<bqao.com>
            extract_spam_sources_reject_s25r($host, $ip4, $s25r_ip4s);
        }
        elsif ($rest2 =~
/^\S+ \S+ Service unavailable; Client host \[\d+\.\d+\.\d+\.\d+\] blocked using bl\.spamcop\.net; /
          )
        {
            ## u148-34.static.grape.cz[93.91.148.34]: 554 5.7.1 Service unavailable; Client host [93.91.148.34] blocked using bl.spamcop.net; Blocked - see https://www.spamcop.net/bl.shtml?93.91.148.34; from=<vzefjiws@icloud.com> to=<hannah@example.com> proto=SMTP helo=<u148-34.static.grape.cz>
            if ($host =~ /\.jp$/) {
                ## nothing todo
            }
            else {
                map_count_up($spamcop_ip4s, $ip4);
            }
        }
        elsif ($rest2 =~ /^\S+ \S+ \S+: Sender address rejected: /) {
            ## by.ptr245.ptrcloud.net[153.122.192.178]: 450 4.1.7 <admin@mail021.gascensori.com>: Sender address rejected: unverified address: connect to mail021.gascensori.com[153.122.192.178]:25: Connection refused; from=<admin@mail021.gascensori.com> to=<yu-yu-sa@example.com> proto=ESMTP helo=<mail021.gascensori.com>
            ## v133-18-163-104.vir.kagoya.net[133.18.163.104]: 450 4.1.7 <no-reply@retajmc.com>: Sender address rejected: unverified address: connect to retajmc.com[133.18.163.104]:25: Connection refused; from=<no-reply@retajmc.com> to=<tadaharu@example.com> proto=ESMTP helo=<mail1.retajmc.com>
            if ($host =~ /^\S+\.ptrcloud\.net$/) {
                map_count_up($ptrcloud_ip4s, $ip4);
            }
            elsif ($host =~ /^\S+\.vir\.kagoya\.net$/) {
                map_count_up($kagoya_ip4s, $ip4);
            }
        }
    }
    return;
}

sub extract_spam_sources_reject_client_p {
    my ($host, $ip4, $cc, $client_p_ip4s) = @_;
    if ($cc eq 'jp') {
        ## nothing todo
    }
    elsif ($cc eq 'us') {
        if ($host =~ /\.com$/) {
            my @client_p_patterns_com = (
                qr/\.myvzw\.com$/,             qr/\.spectrum\.com$/,
                qr/\.linodeusercontent\.com$/, qr/\.hostwindsdns\.com$/,
                qr/\.onlinehome-server\.com$/, qr/\.linode\.com$/,
            );
            foreach my $re (@client_p_patterns_com) {
                if ($host =~ $re) {
                    map_count_up($client_p_ip4s, $ip4);
                    last;
                }
            }
        }
        elsif ($host =~ /\.net$/) {
            my @client_p_patterns_net = (
                qr/\.contaboserver\.net$/, qr/\.nxcli\.net$/,
                qr/\.maxxsouthbb\.net$/,   qr/\.verizon\.net$/,
                qr/\.secureserver\.net$/,
            );
            foreach my $re (@client_p_patterns_net) {
                if ($host =~ $re) {
                    map_count_up($client_p_ip4s, $ip4);
                    last;
                }
            }
        }
        elsif ($host =~ /\.jp$/) {
            ## nothing todo
        }
        elsif ($host =~ /\.(cn|br)$/) {
            map_count_up($client_p_ip4s, $ip4);
        }
    }
    else {
        map_count_up($client_p_ip4s, $ip4);
    }
    ## client_p_t-ipconnect.de_de.
    ## client_p_link.net.pk_pk.
    ## client_p_clients.your-server.de_de.
    ## client_p_cpe.netcabo.pt_pt.
    ## client_p_dialup.adsl.anteldata.net.uy_uy.
    ## client_p_dialup.mobile.ancel.net.uy_uy.
    ## client_p_dsl.telepac.pt_pl.
    ## client_p_home.otenet.gr_gr.
    ## client_p_net.vodafone.it_it.
    ## client_p_pools.vodafone-ip.de_de.
    ## client_p_rev.vodafone.pt_pt.
    ## client_p_telkomadsl.co.za_za.
    ## client_p_umts.vodacom.co.za_za.
    ## client_p_access.hol.gr_gr.
    ## client_p_acelerate.net_bo.
    ## client_p_cust.vodafonedsl.it_it.
    ## client_p_dynamic.gprs.plus.pl_pl.
    ## client_p_ip.btc-net.bg_bg.
    ## client_p_play-internet.pl_pl.
    ## client_p_multi.internet.cyfrowypolsat.pl_pl.
    ## client_p_hwclouds-dns.com_sg.
    ## client_p_|.dynamic-ip.hinet.net_tw.
    ## client_p_|.hinet-ip.hinet.net_tw.
    ## client_p_|.staticip.rima-tde.net_es.
    ## client_p_|.business.telecomitalia.it_it.
    ## client_p_|.customers.tmcz.cz_cz.
    ## client_p_|.dynamic.kabel-deutschland.de_de.
    ## client_p_|.home.otenet.gr_gr.
    ## client_p_|.isp.valenet.com.br_br.
    ## client_p_|.telecom.net.ar_ar.
    ## client_p_|.adsl.net.t-com.hr_hr.
    ## client_p_|.btcentralplus.com_gb.
    ## client_p_|.cable.virginm.net_gb.
    ## client_p_|.cm.vtr.net_cl.
    ## client_p_|.pool.telefonica.de_de.
    ## client_p_|.red.bezeqint.net_il.
    ## client_p_|.rev.sfr.net_fr.
    ## client_p_|.revip6.asianet.co.th_th.
    ## client_p_|.versanet.de_de.
    ## client_p_|.dynamic.orange.es_es.
    ## client_p_|spooky69.eu_fr.
    ## client_p_|ip-51-91-221.eu_fr.
    ## client_p_|v-tal.net.br_br.
    return;
}

sub extract_spam_sources_reject_s25r {
    my ($host, $ip4, $s25r_ip4s) = @_;
    if ($host =~ /\.(..)$/) {
        my $cc = $1;
        if ($cc eq 'jp') {
            ## nothing todo
        }
        else {
            map_count_up($s25r_ip4s, $ip4);
        }
    }
    return;
}

sub extract_spam_sources_ssl {
    my ($rest, $ssl_err_ip4s) = @_;
    if ($rest =~ /^([^\[\] ]+)\[(\d+\.\d+\.\d+\.\d+)\]: (.+)$/) {
        my $host  = $1;
        my $ip4   = $2;
        my $rest2 = $3;
        ## SSL_accept error from i15-les03-ix2-176-180-52-57.dsl.dyn.abo.bbox.fr[176.180.52.57]: lost connection
        ## SSL_accept error from unknown[183.171.236.113]: Connection timed out
        ## SSL_accept error from unknown[183.171.236.113]: Connection reset by peer
        ## SSL_accept error from unknown[115.86.227.79]: -1
        ## SSL_accept error from outbound-402da309.pinterestmail.com[64.45.163.9]: -1
        if ($host =~ /\.jp$/) {
            ## nothing todo
        }
        elsif ($rest2 =~ /^(-1|lost connection|Connection timed out|Connection reset by peer)$/) {
            map_count_up($ssl_err_ip4s, $ip4);
        }
    }
    return;
}

# support on:
#   perltidy -l 100 --check-syntax --paren-tightness=2
#   perlcritic -4
# vim: set ts=4 sw=4 sts=0 expandtab:
