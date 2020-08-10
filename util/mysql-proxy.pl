#!/usr/bin/perl

#
#
# mysql-proxy.pl - mysql trafic/protocol analysing debug proxy
#  -S server-socket
#  -C client-socket
#  -v verbose
#  -n no fork


use strict;
use Socket;
use IO::Socket::UNIX;
use IO::Select;
use POSIX ":sys_wait_h";
use Getopt::Long;
use POSIX ":sys_wait_h"; # for nonblocking read
use Data::Dumper;
use Scalar::Util qw/ openhandle /;
use Hash::Util qw/ lock_keys /;

Getopt::Long::Configure("no_ignore_case");

my $deps = 0x01000000;



use constant {
    CLIENT_MYSQL            => 1,    #  (1 << 1) mysql/old mariadb server/client 
    CLIENT_FOUND_ROWS       => 2,    #  (1 << 2)Found instead of affected rows 
    CLIENT_LONG_FLAG        => 4,    #  (1 << 3)Get all column flags 
    CLIENT_CONNECT_WITH_DB  => 8,    #  (1 << 4)One can specify db on connect 
    CLIENT_NO_SCHEMA        => 16,   #  (1 << 5)Don't allow database.table.column 
    CLIENT_COMPRESS         => 32,   #  (1 << 6)Can use compression protocol 
    CLIENT_ODBC             => 64,   #  (1 << 7)Odbc client 
    CLIENT_LOCAL_FILES      => 128,  #  (1 << 8)Can use LOAD DATA LOCAL 
    CLIENT_IGNORE_SPACE     => 256,  #  (1 << 9)Ignore spaces before '(' 
    CLIENT_PROTOCOL_41      => 512,  #  (1 << 10)New 4.1 protocol 
    CLIENT_INTERACTIVE      => 1024, #  (1 << 11)This is an interactive client 
    CLIENT_SSL              => 2048, #  (1 << 12)Switch to SSL after handshake 
    CLIENT_IGNORE_SIGPIPE   => 4096, #  (1 << 13)IGNORE sigpipes 
    CLIENT_TRANSACTIONS     => 8192, #  Client knows about transactions 
    CLIENT_RESERVED         => 16384,      #  Old flag for 4.1 protocol  
    CLIENT_SECURE_CONNECTION => 32768,     #  New 4.1 authentication 
    CLIENT_MULTI_STATEMENTS  => (1 << 16), # Enable/disable multi-stmt support 
    CLIENT_MULTI_RESULTS     => (1 << 17), # Enable/disable multi-results 
    CLIENT_PS_MULTI_RESULTS  => (1 << 18), # Multi-results in PS-protocol 
    CLIENT_PLUGIN_AUTH       => (1 << 19), # Client supports plugin authentication 
    CLIENT_CONNECT_ATTRS     => (1 << 20), # Client supports connection attributes 
    CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA => (1 << 21),
    CLIENT_CAN_HANDLE_EXPIRED_PASSWORDS => (1 << 22),
    CLIENT_SESSION_TRACK => (1 << 23),
    CLIENT_DEPRECATE_EOF => (1 << 24),
    CLIENT_PROGRESS_OBSOLETE =>  (1 << 29),
    LIENT_SSL_VERIFY_SERVER_CERT =>  (1 << 30), 
    CLIENT_REMEMBER_OPTIONS => (1 << 31),
    MARIADB_CLIENT_FLAGS_MASK => 0xffffffff00000000,  # MariaDB extended capability flags 
    MARIADB_CLIENT_PROGRESS => (1 << 32), # Client support progress indicator 
    MARIADB_CLIENT_COM_MULTI => (1 << 33),
    MARIADB_CLIENT_STMT_BULK_OPERATIONS => (1 << 34),
};

use constant {
    WAIT_HANDSHAKE        => 'WAIT_HANDSHAKE',
    WAIT_HANDSHAKE_REPLY  => 'WAIT_HANDSHAKE_REPLY',
    WAIT_HANDSHAKE_STATUS => 'WAIT_HANDSHAKE_STATUS',
    WAIT_COM              => 'WAIT_COM',
    QUERY_WAIT_RESPONSE   => 'QUERY_WAIT_RESPONSE',
    QUERY_WAIT_COLS       => 'QUERY_WAIT_COLS',
    QUERY_WAIT_COLS_EOF   => 'QUERY_WAIT_COLS_EOF',
    QUERY_WAIT_ROWS       => 'QUERY_WAIT_ROWS',
};

use constant {
     SERVER_STATUS_IN_TRANS             =>      1,	# Transaction has started 
     SERVER_STATUS_AUTOCOMMIT           =>      2,	# Server in auto_commit mode 
     SERVER_MORE_RESULTS_EXIST          =>      8,
     SERVER_QUERY_NO_GOOD_INDEX_USED    =>     16,
     SERVER_QUERY_NO_INDEX_USED         =>     32,
     SERVER_STATUS_CURSOR_EXISTS        =>     64,
     SERVER_STATUS_LAST_ROW_SENT        =>    128,
     SERVER_STATUS_DB_DROPPED           =>    256,
     SERVER_STATUS_NO_BACKSLASH_ESCAPES =>    512,
     SERVER_STATUS_METADATA_CHANGED     =>   1024,
     SERVER_QUERY_WAS_SLOW              =>   2048,
     SERVER_PS_OUT_PARAMS               =>   4096,
     SERVER_STATUS_IN_TRANS_READONLY    =>   8192,
     SERVER_SESSION_STATE_CHANGED       =>  16384,
     SERVER_STATUS_ANSI_QUOTES          =>  32768,
};

use constant {
     COM_SLEEP =>                  0,
     COM_QUIT =>                   1,
     COM_INIT_DB =>                2, 
     COM_QUERY =>                  3, 
     COM_FIELD_LIST =>             4, 
     COM_CREATE_DB =>              5, 
     COM_DROP_DB =>                6, 
     COM_REFRESH =>                7, 
     COM_SHUTDOWN =>               8, 
     COM_STATISTICS =>             9, 
     COM_PROCESS_INFO =>          10, 
     COM_CONNECT =>               11, 
     COM_PROCESS_KILL =>          12, 
     COM_DEBUG =>                 13, 
     COM_PING =>                  14, 
     COM_TIME =>                  15, 
     COM_DELAYED_INSERT =>        16, 
     COM_CHANGE_USER =>           17, 
     COM_BINLOG_DUMP =>           18, 
     COM_TABLE_DUMP =>            19, 
     COM_CONNECT_OUT =>           20, 
     COM_REGISTER_SLAVE =>        21, 
     COM_STMT_PREPARE =>          22, 
     COM_STMT_EXECUTE =>          23, 
     COM_STMT_SEND_LONG_DATA =>   24, 
     COM_STMT_CLOSE =>            25, 
     COM_STMT_RESET =>            26, 
     COM_SET_OPTION =>            27, 
     COM_STMT_FETCH =>            28, 
     COM_DAEMON =>                29, 
     COM_UNSUPPORTED =>           30, 
     COM_RESET_CONNECTION =>      31,
     COM_STMT_BULK_EXECUTE =>    250,

     PACKET_OK  => 0x00,
     PACKET_EOF => 0xFE,
     PACKET_ERR => 0xFF,

     LENC_NULL => 0xFB,
     LENC_B2   => 0xFC,
     LENC_B3   => 0xFD,
     LENC_B8   => 0xFE,
     LENC_EOF  => 0xFF,
     
};

my @server_status = (
    'IN_TRANS',                    #  0=>      1,	# Transaction has started 
    'AUTOCOMMIT',                  #  1=>      2,	# Server in auto_commit mode
    'STATUS4',                     #  2=>      4,	
    'MORE_RESULTS_EXIST',          #  3=>      8,
    'QUERY_NO_GOOD_INDEX_USED',    #  4=>     16,
    'QUERY_NO_INDEX_USED',         #  5=>     32,
    'CURSOR_EXISTS',               #  6=>     64,
    'LAST_ROW_SENT',               #  7=>    128,
    'DB_DROPPED',                  #  8=>    256,
    'NO_BACKSLASH_ESCAPES',        #  9=>    512,
    'METADATA_CHANGED',            # 10=>   1024,
    'QUERY_WAS_SLOW',              # 11=>   2048,
    'PS_OUT_PARAMS',               # 12=>   4096,
     'IN_TRANS_READONLY',          # 13=>   8192,
    'SESSION_STATE_CHANGED',       # 14=>  16384,
    'ANSI_QUOTES',                 # 15=>  32768,
    );


my @caps = (
    'CLIENT_MYSQL',                          # => 1,    #  mysql/old mariadb server/client 
    'CLIENT_FOUND_ROWS',                     # => 2,    #  Found instead of affected rows 
    'CLIENT_LONG_FLAG',                      # => 4,    #  Get all column flags 
    'CLIENT_CONNECT_WITH_DB',                # => 8,    #  One can specify db on connect 
    'CLIENT_NO_SCHEMA',                      # => 16,   #  Don't allow database.table.column 
    'CLIENT_COMPRESS',                       # => 32,   #  Can use compression protocol 
    'CLIENT_ODBC',                           # => 64,   #  Odbc client 
    'CLIENT_LOCAL_FILES',                    # => 128,  #  Can use LOAD DATA LOCAL 
    'CLIENT_IGNORE_SPACE',                   # => 256,  #  Ignore spaces before '(' 
    'CLIENT_PROTOCOL_41',                    # => 512,  #  New 4.1 protocol 
    'CLIENT_INTERACTIVE',                    # => 1024, #  This is an interactive client 
    'CLIENT_SSL',                            # => 2048, #  Switch to SSL after handshake 
    'CLIENT_IGNORE_SIGPIPE',                 # => 4096, #  IGNORE sigpipes 
    'CLIENT_TRANSACTIONS',                   # => 8192, #  Client knows about transactions 
    'CLIENT_RESERVED',                       # => 16384,      #  Old flag for 4.1 protocol  
    'CLIENT_SECURE_CONNECTION',              #  => 32768,     #  New 4.1 authentication 
    'CLIENT_MULTI_STATEMENTS',               #  => (1 << 16), # Enable/disable multi-stmt support 
    'CLIENT_MULTI_RESULTS',                  #  => (1 << 17), # Enable/disable multi-results 
    'CLIENT_PS_MULTI_RESULTS',               #  => (1 << 18), # Multi-results in PS-protocol 
    'CLIENT_PLUGIN_AUTH',                    #  => (1 << 19), # Client supports plugin authentication 
    'CLIENT_CONNECT_ATTRS',                  #  => (1 << 20), # Client supports connection attributes 
    'CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA', #  => (1 << 21),
    'CLIENT_CAN_HANDLE_EXPIRED_PASSWORDS',   #  => (1 << 22),
    'CLIENT_SESSION_TRACK',                  #  => (1 << 23),
    'CLIENT_DEPRECATE_EOF',                  #  => (1 << 24), 
    'CLIENT_25',                             #  => (1 << 25), 
    'CLIENT_26',                             #  => (1 << 26), 
    'CLIENT_27',                             #  => (1 << 27), 
    'CLIENT_28',                             #  => (1 << 28), 
    'CLIENT_PROGRESS_OBSOLETE',              #  => (1 << 29),
    'CLIENT_SSL_VERIFY_SERVER_CERT',         #  => (1 << 30), 
    'CLIENT_REMEMBER_OPTIONS',               #  => (1 << 31),
    'MARIADB_CLIENT_PROGRESS',               #  => (1 << 32), # Client support progress indicator 
    'MARIADB_CLIENT_COM_MULTI',              #  => (1 << 33),
    'MARIADB_CLIENT_STMT_BULK_OPERATIONS' => #  => (1 << 34),
    );


sub show_server_status {
    my ($status) = @_;
    my $index = 0;
    my @list;
    while($status) {
	if($status & 1) {
	    push @list, $server_status[$index];
	}
	$index++;
	$status >>= 1;
    }
    return join(", ",@list);
}

sub show_caps {
    my ($cap) = @_;
    my $index = 0;
    my @list;
    while($cap) {
	if($cap & 1) {
	    push @list, $caps[$index];
	}
	$index++;
	$cap >>= 1;
    }
    return join(", ",@list);
}


my @com_array = (
    [ "COM_SLEEP",                 0, ],
    [ "COM_QUIT",                  1, ],
    [ "COM_INIT_DB",               2, ], 
    [ "COM_QUERY" ,                3, \&parse_com_query, ], 
    [ "COM_FIELD_LIST",            4, ], 
    [ "COM_CREATE_DB",             5, ], 
    [ "COM_DROP_DB",               6, ], 
    [ "COM_REFRESH",               7, ], 
    [ "COM_SHUTDOWN",              8, ], 
    [ "COM_STATISTICS",            9, ], 
    [ "COM_PROCESS_INFO",         10, ], 
    [ "COM_CONNECT",              11, ], 
    [ "COM_PROCESS_KILL",         12, ], 
    [ "COM_DEBUG",                13, ], 
    [ "COM_PING",                 14, ], 
    [ "COM_TIME",                 15, ], 
    [ "COM_DELAYED_INSERT",       16, ], 
    [ "COM_CHANGE_USER",          17, ], 
    [ "COM_BINLOG_DUMP",          18, ], 
    [ "COM_TABLE_DUMP",           19, ], 
    [ "COM_CONNECT_OUT",          20, ], 
    [ "COM_REGISTER_SLAVE",       21, ], 
    [ "COM_STMT_PREPARE",         22, ], 
    [ "COM_STMT_EXECUTE",         23, ], 
    [ "COM_STMT_SEND_LONG_DATA",  24, ], 
    [ "COM_STMT_CLOSE",           25, ], 
    [ "COM_STMT_RESET",           26, ], 
    [ "COM_SET_OPTION",           27, ], 
    [ "COM_STMT_FETCH",           28, ], 
    [ "COM_DAEMON",               29, ], 
    [ "COM_UNSUPPORTED",          30, ], 
    [ "COM_RESET_CONNECTION",     31, ],
    );
@com_array[250] = [ "COM_STMT_BULK_EXECUTE",  250 ];


my $conn_id;



my %states = (
    
    WAIT_HANDSHAKE  =>  {
	'name' => WAIT_HANDSHAKE,
	
	'client' => sub {
	    my ($st,$p,$seq) = @_;
	    print " (C>S)($st->{state}) illegal packet in handshake\n";
	},
	
	'server' => sub {
	    my ($st,$p,$seq) = @_;
	    my ($pversion, $sversion, $conid, $seed, $pad0, $cap0, $col, $flags,$cap1,$auth_data_len,$filler6,$r) =
		unpack("CZ*V A8 C v C v v C A6 A*", $p);
	    my $cap = $cap1 << 16 | $cap0;

	    my $session_track  = ($cap & CLIENT_SESSION_TRACK) ? 1 : 0;
	    my $client_mysql   = ($cap & CLIENT_MYSQL) ? 1 : 0;
	    my $plugin_auth    = ($cap & CLIENT_PLUGIN_AUTH) ? 1 : 0;
	    my $deprecate_eof  = ($cap & CLIENT_DEPRECATE_EOF) ? 1 : 0;	    
	    my $mariadb_ext    = $client_mysql ? 0 : 1;

	    if($st->{client_mysql}) {
		$r = substr($r,4);
	    } else {
		my $cap2;
		($cap2,$r) = unpack("VA*",$r);
		$cap = $cap2 << 32 | $cap;
	    }
	    
	    print " (S>C) handshanke: proto=$pversion, server='$sversion',connection_id=$conid, collation=$col, " .
		"$cap : dep-eof=$deprecate_eof track=$session_track, ext=$mariadb_ext, client-mysql=$client_mysql\n";

	    print " (S>C) caps: " . show_caps($cap) . "\n";
	    $st->{connection_id} = $conid;
	    $st->{server_cap} = $cap;
	    set_state($st,"WAIT_HANDSHAKE_REPLY");
	},
    },

    WAIT_HANDSHAKE_REPLY  =>  {

	'name' => WAIT_HANDSHAKE_REPLY,
	
	'client' => sub {
	    my ($st,$p,$seq) = @_;

	    my ($cap0, $max_packet, $coll, $reserve, $cap1, $username, $rest) = unpack("V V C C19 V Z* A*", $p);

	    my $cap = $cap1 << 32 | $cap1 << 4 | $cap0;

	    my $session_track  = $st->{session_track} = ($cap & CLIENT_SESSION_TRACK) ? 1 : 0;
	    my $client_mysql   = $st->{client_mysql}  = ($cap & CLIENT_MYSQL)         ? 1 : 0;
	    my $plugin_auth    = $st->{plugin_auth}   = ($cap & CLIENT_PLUGIN_AUTH)   ? 1 : 0;
	    my $deprecate_eof  = $st->{deprecate_eof} = ($cap & CLIENT_DEPRECATE_EOF) ? 1 : 0;	    
	    my $mariadb_ext    = $st->{mariadb_ext}   = ($st->{client_mysql}) ? 0 : 1;
	    
	    $st->{cap} = $cap;
	    $st->{username} = $username;

	    printf(" (C>S)($st->{state}) handhsnake reply: %08x user=%s coll=$coll max-packet($max_packet)"
		   . ": session-track=%d, plugin=%d, mysql=%d dep-eof=%d\n",
		   $cap, $username,  $coll, $max_packet, $session_track, $plugin_auth, $client_mysql, $deprecate_eof);

	    print " (S>C) caps: " . show_caps($cap) . "\n";
	    # print " (S>C) caps: " . Dumper($st);
		
	    set_state($st,"WAIT_HANDSHAKE_STATUS");
	},
	'server' => sub {
	    my ($st,$p,$seq) = @_;
	    my $name = $st->{state};
	    print " (S>C)($name) illegal packet\n";
	},
    },

    WAIT_HANDSHAKE_STATUS  =>  {
	'name' => WAIT_HANDSHAKE_STATUS,
	
	'client' => sub {
	    my ($st,$p,$seq) = @_;
	    print " (C>S)($st->{state}) illegal packet in handshake\n";
	},
	'server' => sub {
	    my ($st,$p,$seq) = @_;
	    my $c = ord($p);
	    printf(" (S>C)($st->{state}) handshanke reply: %02x\n", $c);
	    if($c == PACKET_OK) {
		parse_ok_packet($st,$p);
		set_state($st,WAIT_COM);
	    } elsif($c == PACKET_ERR) {
		parse_err_packet($st,$p);	
	    } else {
		set_state($st,WAIT_HANDSHAKE_REPLY);		

	    }
	},
    },

    WAIT_COM  =>  {
	
	'name' => WAIT_COM,
	
	'client' => sub {
	    my ($st,$p,$seq) = @_;

	    my $com = ord(substr($p,0,1));
	    my $c = @com_array[$com];
	    if($c) {
		my ($str,$num,$func) = @$c;
		my $val = "-";
		if($func) {
		    $val = $func->($st,$p,$seq);
		}
		print " (C>S)($st->{state}) COM($str) $val\n";
	    } else {
		print " (C>S)($st->{state}) uknown com($com)\n";
	    }
	},
	    
	'server' => sub {
	    my ($st,$p,$seq) = @_;
	    my $c = ord(substr($p,0,1));
	    printf(" (S>C)($st->{state}) com reply %02x\n", $c);	    
	},
    },

    QUERY_WAIT_RESPONSE  =>  {
	
	'name' => QUERY_WAIT_RESPONSE,
	
	'client' => sub {
	    my ($st,$p,$seq) = @_;

	    my $com = ord(substr($p,0,1));
	    my $c = @com_array[$com];
	    if($c) {
		my ($str,$num,$func) = @$c;
		my $val = "-";
		if($func) {
		    $val = $func->($st,$p,$seq);
		}
		print " (C>S)($st->{state}) COM($str) $val\n";
	    } else {
		print " (C>S)($st->{state}) uknown com($com)\n";
	    }
	},
	'server' => sub {
	    my ($st,$p,$seq) = @_;
	    my $c = ord(substr($p,0,1));

	    if($c == 0xFF) {
		parse_err_packet($st,$p,$seq);
		set_state($st,WAIT_COM);
		return;
	    } elsif($c == 0x00) {
		parse_ok_packet($st,$p,$seq);
		set_state($st,WAIT_COM);
		return;
	    } elsif($c == 0xFB) {
		print "  LOCAL_INLINE???\n";
		set_state($st,WAIT_COM);
		return;
	    }

	    my ($cols,$p,$c) = parseLenc($p);

	    $st->{cols} = $cols;
	    $st->{col_index} = 0;
	    $st->{row_count} = 0;	    

	    print " (C>S)($st->{state}) RESULTSET: $cols dep-eof($st->{deprecate_eof})\n";

	    set_state($st,QUERY_WAIT_COLS);
	},

    },

    QUERY_WAIT_COLS  =>  {
	
	'name' => QUERY_WAIT_COLS,
	
	'client' => sub {
	    my ($st,$p,$seq) = @_;

	    my $com = ord(substr($p,0,1));
	    my $c = @com_array[$com];
	    if($c) {
		my ($str,$num,$func) = @$c;
		my $val = "-";
		if($func) {
		    $val = $func->($st,$p,$seq);
		}
		print " (C>S)($st->{state}) COM($str) $val\n";
	    } else {
		print " (C>S)($st->{state}) uknown com($com)\n";
	    }
	},
	'server' => sub {
	    my ($st,$p,$seq) = @_;

	    my ($cat,$schema,$table_alias,$table, $col_alias, $col) ;

	    my $c = ord($p);

	    if(is_eof_packet($p)) {
		print "  (S>C)($st->{state}) ($c) COLUMN EOF ($st->{col_index}/$st->{cols})  eof($st->{deprecate_eof})\n";
		print "  COLUMN EOF\n";
		set_state($st,QUERY_WAIT_ROWS);
		return;
	    }
	    
	    if(is_err_packet($p)) {
		print "  (S>C)($st->{state}) ($c) COLUMN ERR ($st->{col_index}/$st->{cols}) eof($st->{deprecate_eof})\n";
		parse_err_packet($st,$p);
		set_state($st,WAIT_COM);
		return;
	    }

	    ($cat,$p) = parseLencStr($p);
	    ($schema,$p) = parseLencStr($p);
	    ($table_alias,$p) = parseLencStr($p);
	    ($table,$p) = parseLencStr($p);
	    ($col_alias,$p) = parseLencStr($p);
	    ($col,$p) = parseLencStr($p);

	    print "  COLUMN($st->{col_index}/$st->{cols}) DATA table_alias($table_alias) table($table) col_alias($col_alias) col($col)\n";

	    $st->{col_index}++;
	    if($st->{col_index} >= $st->{cols}) {
		if($st->{deprecate_eof}) {
		    set_state($st,QUERY_WAIT_ROWS);
		} else {
		    set_state($st,QUERY_WAIT_COLS_EOF);
		}
	    }
	},

    },

    QUERY_WAIT_COLS_EOF  =>  {
	
	'name' => QUERY_WAIT_COLS_EOF,
	
        'client' => sub {
	    my ($st,$p,$seq) = @_;
		
	    my $com = ord($p);
	    my $c = @com_array[$com];
	    if($c) {
		my ($str,$num,$func) = @$c;
		my $val = "-";
		if($func) {
		    $val = $func->($st,$p,$seq);
		}
		print " (C>S)($st->{state}) COM($str) $val .. strange\n";
	    } else {
		print " (C>S)($st->{state}) uknown com($com)\n";
	    }
	},
        'server' => sub { 
	    my ($st,$p,$seq) = @_;
	    my $com = ord($p);
	    if(is_eof_packet($p) and length($p) < 0xffffff) {
		parse_eof_packet($st,$p);
		set_state($st,QUERY_WAIT_ROWS);
	    } elsif(is_err_packet($p)) {
		parse_err_packet($st,$p);
		set_state($st,WAIT_COM);
	    } else {
		print " (S>C)($st->{state}) BAD PACKET: $com\n";
		set_state($st,WAIT_COM);
	    }
	},

    },
    
    

    QUERY_WAIT_ROWS  =>  {
	
	'name' => QUERY_WAIT_ROWS,
	
        'client' => sub {
		my ($st,$p,$seq) = @_;
		
	    my $com = ord(substr($p,0,1));
	    my $c = @com_array[$com];
	    if($c) {
		my ($str,$num,$func) = @$c;
		my $val = "-";
		if($func) {
		    $val = $func->($st,$p,$seq);
		}
		print " (C>S)($st->{state}) COM($str) $val\n";
	    } else {
		print " (C>S)($st->{state}) uknown com($com)\n";
	    }
	},
        'server' => sub { 
	    my ($st,$p,$seq) = @_;
	    my $com = ord($p);

	    if(not $st->{deprecate_eof} and is_eof_packet($p)) {
		print " (S>C)($st->{state}) EOF ($com) rows($st->{row_count})\n";
		parse_eof_packet($st,$p);		
	    } elsif($st->{deprecate_eof} and is_ok_or_eof_packet($p) and length($p) < 0xffffff) {
		print " (S>C)($st->{state}) OK ($com) rows($st->{row_count})\n";
		parse_ok_packet($st,$p);
		set_state($st,WAIT_COM);
	    } elsif(is_err_packet($p)) {
		print " (S>C)($st->{state}) ERR ($com) rows($st->{row_count})\n";
		parse_err_packet($st,$p);
		set_state($st,WAIT_COM);
	    } else {
		my $val;
		my $c;
		my @vals;
		for(my $i=0; $i < $st->{cols}; $i++) {
		    ($val,$p,$c) = parseLencStr($p);
		    push @vals, quote($val);
		}
		$st->{row_count}++;
		print " ROW ($st->{row_count}): " . join(", ", @vals) . "\n";

	    }
	},

    },
    
    
    );

sub quote {
    local $_ = length(@_) ? $_[0] : $_;
    return "NULL" unless defined($_);
    s/\\/\\\\/g;
    s/\n/\\n/g;
    s/\r/\\r/g;
    s/\t/\\t/g;
    s/\'/\\\'/g;
    return "'$_'";
}

sub is_eof_packet {
    my ($p) = @_;
    return (length($p) < 9 and ord($p) == 0xFE) ? 1 : 0;
}

sub is_ok_packet {
    my ($p) = @_;
    return (length($p) >= 5 and ord($p) == 0x00) ? 1 : 0;
}

sub is_err_packet {
    my ($p) = @_;
    my $l = length($p) >= 3;
    my $c = ord($p);
    return $c == 0xff ? 1 : 0;
}


sub is_ok_or_eof_packet {
    my ($p) = @_;
    return 0 unless length($p) >= 5;
    my $c = ord($p);
    return ($c == 0x00 or $c == 0xFE)  ? 1 : 0;
}


sub parse_err_packet {
    my ($st, $p) = @_;
    return unless length($p) >= 3;

    my ($c,$code,$p) = unpack("CvA*",$p);
    return unless $c == 0xff;

    if($code == 0xffff) {
	my ($stage,$max_stage,$prog0,$prog1,$rest) = unpack("CCvCA*",$p);
	my $progress = $prog1 << 16 | $prog0;
	my ($info,undef,undef) = parseLenc($rest);
	printf "  PROGRESS($stage/$max_stage)progress($progress) : $info\n";
	return 0;
    } else {
	$st->{error_code} = $code;
	$st->{error_text} = $p;
	print " ($st->{state}) ERR_PACKET: ($code) : $p\n";
	return 1;
    }
}

sub parse_ok_packet {
    my ($st, $p) = @_;
    return unless length($p) >= 3;

    my $c = ord($p);
    return unless $c == 0x00 || $c == 0XxE;

    my $rows;
    my $insert_id;
    my $status;
    my $warnings;
    my $info;
    my $infolen;

    ($rows,$p) = parseLenc(substr($p,1));
    ($insert_id,$p) = parseLenc($p);
    ($status,$warnings,$p) = unpack("vvA*",$p);

    if($st->{session_track}) {
	($infolen,$p) = parseLenc($p);
	$info = substr($p,1,$infolen);
    } else {
	$info = $p;
    }

    $st->{insert_id} = $insert_id;
    $st->{op_rows} = $rows;
    $st->{server_status} = $status;
    $st->{warnings} = $warnings;
    $st->{info} = $info;

    my $ss = show_server_status($status);
    
    print "  ($st->{state}) OK_PACKET com($c) rows($rows) insert_id($insert_id) server_status($status) warnings($warnings) : $ss : $info\n";
    return 1;
}


sub parse_eof_packet {
    my ($st, $p) = @_;
    return 0 unless length($p) >= 5;
    return 0 unless length($p) < 9;

    my $c;
    my ($c,$warnings,$status) = unpack("Cvv*",$p);
    return 0 unless $c == 0xfe;

    $st->{server_status} = $status;
    $st->{warnings} = $warnings;

    my $ss = show_server_status($status);    
    
    print "  ($st->{state}) EOF_PACKET warnings($warnings) status($status): $ss\n";
    return 1;
}



sub parseLenc {
    my ($p,$off) = @_;
    $off = 0 unless defined $off;
    my $c = substr($p,$off,1);
    return unless defined $c;
    $c = ord($c);
    if($c < 0xFB) {
	return ($c,substr($p,$off+1),$c);
    }
    if($c == 0xFB) {
	return (undef,substr($p,$off+1),$c);
    }
    if($c == 0xFC) {
	my $s = substr($p,$off+1,2);
	return unless length($s) == 2;
	my ($val) = unpack("v", $s);
	return ($val,substr($p,$off+3),$c);
    }
    if($c == 0xFD) {
	my $s = substr($p,$off+1,3);
	return unless length($s) == 3;	
	my ($val0,$val1) = unpack("vC",$s);
	return ($val1 << 16 | $val0,substr($p,$off+4),$c);
    }
    if($c == 0xFE) {
	my $s = substr($p,$off+1,8);
	return unless length($s) == 8;
	my ($val0,$val1) = unpack("VV",$s);
	return ($val1 << 32 | $val0,substr($p,$off+9),$c);
    }
    return (undef, substr($p,$off+1), $c);
}

sub parseLencStr {
    my ($p,$off) = @_;
    my ($len,$rest,$c) = parseLenc($p,$off);
    if($c == LENC_NULL) {
	return (undef,$rest,$c);
    }
    return(substr($rest,0,$len),substr($rest,$len),$c);
}

sub parse_com_query {
    my ($st,$p,$seq) = @_;
    my $query = substr($p,1);
    set_state($st,QUERY_WAIT_RESPONSE);
    return "QUERY($query)";
}

sub set_state {
    my ($st,$name) = @_;
    die "not a state" unless defined $st;
    die "not state" unless defined($st->{state});
    die "bad state" unless $name;
    my $old = $st->{state};
    $st->{state} = $name;
    print "  STATE $old => $name\n";
}

my $readsize = 4 * 1024;
my $sock = "/tmp/mysql2.sock";
my $dst = "/tmp/mysql.sock";
my %children;
my $verbose = 0;
my $nofork = 0;

GetOptions(
    'v|verbose+' => \$verbose,
    'M|master-socket=s' => \$dst,
    'C|client-socket=s' => \$sock,
    'n|no-fork' => \$nofork,
    ) or die "bad opts";


$SIG{CHLD} = sub {
    # don't change $! and $? outside handler
    local ($!, $?);
    my $pid = waitpid(-1, WNOHANG);
    print("(child: $pid) ended\n");
    return if $pid == -1;
    return unless defined $children{$pid};
    delete $children{$pid};
};

# do something that forks...

if ( -S $sock ) {
    print("unlink my socket ($sock)\n") if $verbose;
    unlink($sock);
}


my $ss = IO::Socket::UNIX->new( Type => SOCK_STREAM,
				 Local => $sock,
				 Listen => 20) or die "cannot create server socket: $!";



for(;;) {
    
    my $c = $ss->accept();
    next unless $c;    
    
    print "new connection: $c\n";

    if($nofork) {
	run_child_do($c);
    } else {
	my $child = fork();
	
	if(not defined($child)) {
	    die "cannot create child: $!\n";
	}
	if($child == 0) {
	    run_child_do($c);
	    exit(0);
	}
    }
    $c = undef;    
}




sub init_direction {
    my ($from,$to,$idir,$st) = @_;

    my $buffer = '';
    my $off = 0;
    my $plen;
    my $pseq;

    my $dir = $idir ? "S>C" : "C>S";
    
    return sub {
	print "($$)($dir) has data\n" if $verbose >= 2;
	my $buf = '';
	if(! openhandle($from)) {
	    print "($$)($dir) socket closed\n";
	    $st->{quit} = 1;
	    return;
	}
	
	my $ret = $from->sysread($buf, $readsize);
	if(not defined($ret)) {
	    print "($$)($dir) read error: $!\n";
	    $st->{quit} = 1;
	    return;
	}
	if($ret == 0) {
	    close($from);
	    close($to);
	    print "($$)($dir) quits\n";
	    $st->{quit} = 1;
	    return;
	}
	print "($$)($dir) data=$ret\n" if $verbose >= 2;
	print $to $buf;

	$buffer .= $buf;
	my $len = length($buffer);
	while($off < $len - 3) {
	    last unless $len > 3;
	    my $l0  = ord(substr($buffer,$off+0,1));
	    my $l1  = ord(substr($buffer,$off+1,1));
	    my $l2  = ord(substr($buffer,$off+2,1));
	    $pseq   = ord(substr($buffer,$off+3,1));
	    $plen = ($l2 << 16) + ($l1 << 8) + $l0;
	    print "($$)($dir)($st->{state}) pseq($pseq) plen($plen) ($l0,$l1,$l2)\n";
	    my $data = substr($buffer,$off+4, $plen);
	    print " ($dir) : " . join ' ', map { sprintf("%02X", ord($_)) } split(//, $data);
	    print "\n";

	    my $sd = $states{$st->{state}};	
	    die "illegal state: $st->{state}" unless $sd;
	    if($idir) {
		die "($st->{state}) no server" unless ref($sd->{server}) eq 'CODE';
		$st->{dir} = 'S>C';
		$sd->{server}->($st, $data, $pseq);

	    } else {
		
		die "($st->{state}) no client" unless ref($sd->{client}) eq 'CODE';
		$st->{dir} = 'C>S';
		$sd->{client}->($st, $data, $pseq);
	    }
	    $st->{dir} = undef;	    
	    $off += $plen + 4;
	} 
	if($off < $len) {
	    $buffer = substr($buffer,$off);
	    $off = 0;
	}
    };
}

sub run_child_do {
    my ($c) = @_;
    eval {
	run_child($c);
    };
    if($@) {
	print "($$) child error: $@\n";
    }
    eval {
	if(openhandle($c)) {
	    close($c);
	}
	$c = undef;
    };
}

sub run_child {
    my ($c) = @_;

    print "($$) connect\n";

    $|=1;    

    my $m =  IO::Socket::UNIX->new( Type => SOCK_STREAM,
				    Peer => $dst)  or die "($$) cannot create client socket($dst): $!";

    print "($$) connected: $m\n";

    my $sel = IO::Select->new();
    
    $sel->add($c);
    $sel->add($m);

    my $buf= '';

    print "($$) wait sockets\n";

    my $st = {
	kind => 'CONNSTATE',
	com => undef,
	state => WAIT_HANDSHAKE,
	quit => 0,
	session_track => undef,
	mariadb_ext => undef,
	deprecate_eof => undef,
	quit => 0,
	server_cap => undef,
	username => undef,
	client_mysql => undef,
	com => undef,
	connection_id => undef,
	cap => undef,
	plugin_auth => undef,
	cols => undef,
	op_rows => undef,
	insert_id => undef,
	col_index => undef,
	server_status => undef,
	warnings => undef,
	info => undef,
	error_code => undef,
	error_text => undef,
	row_count => undef,
	dir => undef,
    };

    lock_keys(%$st);

    my $cdir = init_direction($c,$m,0, $st);
    my $mdir = init_direction($m,$c,1, $st);
    
    while(my @ready = $sel->can_read(10)) {
	$buf = '';
	for my $sock (@ready) {
	    if($sock == $c) {
		$cdir->();
	    }
	    last if $st->{quit};
	    if($sock == $m) {
		$mdir->();
	    }
	    last if $st->{quit};	    
	}

    }
}

