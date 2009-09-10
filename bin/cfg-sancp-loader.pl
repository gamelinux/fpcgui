#!/usr/bin/perl -w

use strict;
use warnings;
use POSIX qw(setsid);
use DateTime;
use Getopt::Long qw/:config auto_version auto_help/;
use DBI;

=head1 NAME

fpc-sancp-loader.pl - Load sancp sessions into db

=head1 VERSION

0.1

=head1 SYNOPSIS

 $ fpc-sancp-loader.pl [options]

 OPTIONS:

 --dir          : set the dir to monitor for sancp files
 --daemon       : enables daemon mode
 --debug        : enable debug messages (default: 0 (disabled))
 --help         : this help message
 --version      : show fpc-sancp-loader.pl version

=cut

our $VERSION       = 0.1;
our $DEBUG         = 0;
our $DAEMON        = 0;
our $TIMEOUT       = 5;
our $HOSTNAME      = q();
my  $SDIR          = q(/nsm_data/hostname/sancp/);
my  $LOGFILE       = q(/var/log/fpc-sancp-loader.log);
my  $PIDFILE       = q(/var/run/fpc-sancp-loader.pid);
our $DATABASE      = q(dbi:SQLite:dbname=prads.db);
our $DB_USERNAME;
our $DB_PASSWORD;
our $AUTOCOMMIT    = 0;
my $SANCP_DB       = {};

GetOptions(
   'dir=s'         => \$SDIR,
   'debug=s'       => \$DEBUG,
   'daemon'        => \$DAEMON,
);

# Signal handlers
use vars qw(%sources);
$SIG{"HUP"}   = \&dump_active_sessions;
$SIG{"INT"}   = sub { game_over() };
$SIG{"TERM"}  = sub { game_over() };
$SIG{"QUIT"}  = sub { game_over() };
$SIG{"KILL"}  = sub { game_over() };
$SIG{"ALRM"}  = sub { end_sessions(); alarm $TIMEOUT; };

warn "Starting fpc-sancp-loader.pl...\n";
warn "Setting up database ". $DATABASE ."\n" if ($DEBUG > 0);
$OS_SYN_DB = setup_db($DATABASE,$DB_USERNAME,$DB_PASSWORD);
warn "Looking for session data in: $SDIR \n" if $DEBUG;

# Prepare to meet the world of Daemons
if ( $DAEMON ) {
   print "Daemonizing...\n";
   chdir ("/") or die "chdir /: $!\n";
   open (STDIN, "/dev/null") or die "open /dev/null: $!\n";
   open (STDOUT, "> $LOGFILE") or die "open > $LOGFILE: $!\n";
   defined (my $dpid = fork) or die "fork: $!\n";
   if ($dpid) {
      # Write PID file
      open (PID, "> $PIDFILE") or die "open($PIDFILE): $!\n";
      print PID $dpid, "\n";
      close (PID);
      exit 0;
   }
   setsid ();
   open (STDERR, ">&STDOUT");
}

# Start dir_watch() which looks for new sancp session files and put them into db
dir_watch();
exit;

=head1 FUNCTIONS

=head2 dir_watch

 This sub looks for new session data from sancp in a dir.
 Takes $dir to watch as input.

=cut

sub dir_watch {
   #infinite loop
   while (1) {
      my @FILES;
      # Open the directory
      if( opendir( DIR, $SDIR ) ) {
         # Find sancp files in dir (stats.eth0.1229062136)
         while( my $FILE = readdir( DIR ) ) {
            next if( ( "." eq $FILE ) || ( ".." eq $FILE ) );
            next unless ($FILE =~ /^stats\..*\.\d{10}$/);
            push( @FILES, $FILE ) if( -f "$SDIR$FILE" );
         }
         closedir( DIR );
      }
      foreach my $FILE ( @FILES ) {
         get_sancp_session ("$SDIR$FILE");
      }
      # Dont pool files to often, or to seldom...
      sleep $TIMEOUT;                    
   }   
}

=head2 get_sancp_session

 This sub extracts the session data from a sancp session data file (sancp fpc format).
 Takes $file as input parameter.

=cut

sub get_sancp_session {
   my $SFILE = shift;
   my %signatures;
   if (open (FILE, $SFILE)) {
      print "Found sancp session file: ".$SFILE."\n" if $DEBUG;
      # Verify the data in the sancp session files
      LINE:
      while (my $line = readline FILE) {
         chomp $line;
         $line =~ /^\d{19}/;
         unless($line) {
            warn "Error: Not valid session start format in: '$SFILE'";
            next LINE;
         }
         my @elements = split/\|/,$line;
         unless(@elements == 15) {
            warn "Error: Not valid Nr. of session args format in: '$SFILE'";
            next LINE;
         }
         # Things should be OK now to send to the DB
         put_session2db($line);
    }

      close FILE;
   }
}


=head2 put_session2db

 takes a sancp session line as input and stores it in DB

=cut

{
   # store prepared statements for re-execution
   my $h_select;
   my $h_update;
   my $h_insert;
   my $records;
   my $table;

sub put_session2db {
   my $SESSION = shift;
   my( $cx_id, $s_t, $e_t, $tot_time, $ip_type, $src_dip, $src_port,
       $dst_dip, $dst_port, $src_packets, $src_byte, $dst_packets, $dst_byte, 
       $src_flags, $dst_flags) = split /\|/, $SESSION, 15;
   
    
}
}

=head2 setup_db

 Load persistent database

=cut

sub setup_db {
   my ($db,$user,$password) = @_;
   # sancp_hostname_20090827
   # $allsancptables= SHOW TABLES LIKE 'sancp_%'
   my $tablename = "sancp_$sensor_$date";
   my $print_error = $DEBUG ? 1 : 0;
   my $dbh = DBI->connect($db,$user,$password,
                          {AutoCommit => $AUTOCOMMIT,
                          RaiseError => 1, PrintError=> $print_error});
   my ($sql, $sth);
   eval{
#      $sql = "CREATE TABLE asset (ip TEXT, service TEXT, time TEXT, fingerprint TEXT,".
#         "mac TEXT, os TEXT, details TEXT, link TEXT, distance TEXT, reporting TEXT)";

       $sql = "                                            \
        CREATE TABLE `$tablename`                          \
        (                                                  \
        sid           INT UNSIGNED            NOT NULL,    \
        sancpid       BIGINT UNSIGNED         NOT NULL,    \
        start_time    DATETIME                NOT NULL,    \
        end_time      DATETIME                NOT NULL,    \
        duration      INT UNSIGNED            NOT NULL,    \
        ip_proto      TINYINT UNSIGNED        NOT NULL,    \
        src_ip        INT UNSIGNED,                        \
        src_port      SMALLINT UNSIGNED,                   \
        dst_ip        INT UNSIGNED,                        \
        dst_port      SMALLINT UNSIGNED,                   \
        src_pkts      INT UNSIGNED            NOT NULL,    \
        src_bytes     INT UNSIGNED            NOT NULL,    \
        dst_pkts      INT UNSIGNED            NOT NULL,    \
        dst_bytes     INT UNSIGNED            NOT NULL,    \
        src_flags     TINYINT UNSIGNED        NOT NULL,    \
        dst_flags     TINYINT UNSIGNED        NOT NULL,    \
        PRIMARY KEY (sid,sancpid),                         \
        INDEX src_ip (src_ip),                             \
        INDEX dst_ip (dst_ip),                             \
        INDEX dst_port (dst_port),                         \
        INDEX src_port (src_port),                         \
        INDEX start_time (start_time)                      \
        )                                                  \
        "

      $sth = $dbh->prepare($sql);
      $sth->execute;
   };
   if($DEBUG){
      $sql = "SELECT * from asset";
      $sth = $dbh->prepare($sql) or die "foo $!";
      $sth->execute or die "$!";
      $sth->dump_results;
   }
   return $dbh;
}

=head2 game_over

 Terminates the program in a sainfull way.

=cut

sub game_over {
#    dump_active_sessions();
#    dump_stats();
    warn " Terminating...\n";
    unlink ($PIDFILE);
    exit 0;
}

=head1 AUTHOR

 Edward Fjellskaal

=head1 COPYRIGHT

 This library is free software, you can redistribute it and/or modify
 it under the same terms as Perl itself.

=cut


