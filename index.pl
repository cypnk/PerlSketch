#!"C:\xampp\perl\bin\perl.exe" -wT

# This is typicaly #!/usr/bin/perl, but I'm currently testing this on a Windows PC wih XAMPP
# Change the top line to the following on *nix systems:
#!/usr/bin/perl -wT

package PerlSketch;

# Basic security
use strict;
use warnings;

# Default encoding
use utf8;

# Modules in use
use MIME::Base64;
use File::Basename;
use File::Copy;
use File::Temp qw( tempfile tempdir );
use File::Spec::Functions qw( catfile canonpath file_name_is_absolute rel2abs );
use Encode;
use Digest::SHA qw( sha1_hex sha1_base64 sha256_hex sha384_hex sha384_base64 sha512_hex hmac_sha384 );
use Fcntl qw( SEEK_SET O_WRONLY O_EXCL O_RDWR O_CREAT );
use Errno qw( EEXIST );
use Time::HiRes ();
use Time::Piece;
use JSON qw( decode_json encode_json );

# Extra modules
use Template;
use DBI;

# Perl version
use 5.32.1;



# Default settings
use constant {
	# Core defaults
 	
	# Writable content location
	STORAGE_DIR		=> "storage",
	
	# Uploaded file subfolder in storage
	UPLOADS			=> "uploads",
	
	# Maximum number of posts per page
	POST_LIMIT		=> 10,
	
	# Form validation nonce length
	NONCE_SIZE		=> 64,
	
	# CAPTCHA field character length
	CAPTCHA_SIZE		=> 8,
	
	# File stream buffer size
	BUFFER_SIZE		=> 10240,
	
	# Password hashing rounds
	HASH_ROUNDS		=> 10000,
	
	# Maximum file name length
	FILE_NAME_LIMIT		=> 255,
	
	# File lock attempts
	LOCK_TRIES		=> 4,
	
	
	# Cookie defaults
	
	# Base expiration
	COOKIE_EXP		=> 604800,
	
	# Base domain path
	COOKIE_PATH		=> '/',
	
	
	# Session defaults
	
	# Time before session cookie expires
	SESSION_LIFETIME	=> 1800,
	
	# Time between cleaning up old cookies
	SESSION_GC		=> 3600
};


# Request methods and path handler map
our %path_map = (
	get	=> [
		# Main installation page
		{ path => "install",			handler => \&viewInstall },
		
		# Blog-style page paths
		{ path => ":year",			handler => \&viewPosts },
		{ path => ":year/page:page",		handler => \&viewPosts },
		
		{ path => ":year/:month",		handler => \&viewPosts },
		{ path => ":year/:month/page:page",	handler => \&viewPosts },
		
		{ path => ":year/:month/:day",		handler => \&viewPosts },
		{ path => ":year/:month/:day/:slug",	handler => \&viewPosts },
		
		{ path => "archive",			handler => \&viewArchive },
		{ path => "archive/page:page",		handler => \&viewArchive },
		
		# Content creation
		{ path => "new/:year/:month/:day",	handler => \&viewCreatePost },
		{ path => "new",			handler => \&viewCreatePost },
		
		# Content editing
		{ path => "edit/:year/:month/:day/:slug",handler => \&viewEditPost },
		
		# Optional area or homepage
		{ path => "pages/:slug",		handler => \&viewArea },
		{ path => "pages/:slug/page:page",	handler => \&viewArea },
		
		# Tag/category content
		{ path => "tags/:tags",			handler => \&viewTags },
		{ path => "tags/:tags/page:page",	handler => \&viewTags },
		
		# Searching and search pagination
		{ path => "\\?find=:all&page=:page",	handler => \&viewSearch },
		{ path => "\\?find=:all",		handler => \&viewSearch },
		
		# User acccess
		{ path => "login",			handler => \&viewLogin },
		{ path => "register",			handler => \&viewRegister },
		{ path => "profile",			handler => \&viewProfile },
		{ path => "password",			handler => \&viewChangePass },
		
		# Static content
		{ path => ":tree/:file",		handler=> \&sendResource },
		{ path => ":file",			handler=> \&sendResource },
		
		# Homepage
		{ path => "",				handler => \&viewHome }
	],
	
	post	=> [
		{ path => "new",			handler => \&handleCreatePost },
		{ path => "edit",			handler => \&handleEditPost },
		
		{ path => "login",			handler => \&handleLogin },
		{ path => "register",			handler => \&handleRegister }, 
  		
		{ path => "profile",			handler => \&handleProfile },
		{ path => "password",			handler => \&handleChangePass }
	],
	
	head	=> [ 
		{ path => ":year",			handler => \&viewPosts },
		{ path => ":year/page:page",		handler => \&viewPosts },
		
		{ path => ":year/:month",		handler => \&viewPosts },
		{ path => ":year/:month/page:page",	handler => \&viewPosts },
		
		{ path => ":year/:month/:day",		handler => \&viewPosts },
		{ path => ":year/:month/:day/:slug",	handler => \&viewPosts },
		
		{ path => "archive",			handler => \&viewArchive },
		{ path => "archive/page:page",		handler => \&viewArchive },
		
		{ path => "pages/:slug",		handler => \&viewArea },
		
		{ path => ":tree/:file",		handler=> \&sendResource },
		{ path => ":file",			handler=> \&sendResource },
		
		{ path => "",				handler => \&viewHome },
	],
 
	options => [
		{ path => "install",			handler => \&viewInstall },
  		
		{ path => "new",			handler => \&handleCreatePost },
		{ path => "edit",			handler => \&handleEditPost },
  		
  		{ path => "login",			handler => \&viewLogin },
		{ path => "register",			handler => \&viewRegister },
		{ path => "profile",			handler => \&viewProfile },
		{ path => "password",			handler => \&viewChangePass },
  
		{ path => "new/:year/:month/:day",	handler => \&viewCreatePost },
		{ path => "new",			handler => \&viewCreatePost },
		
  		{ path => "edit/:year/:month/:day/:slug",handler => \&viewEditPost }
 	]
);

# URL routing placeholders
our %markers = (
	":all"		=> "(?<all>.+)",
	':id'		=> "(?<id>[1-9][0-9]*)",
	':page'		=> "(?<page>[1-9][0-9]*)",
	':label'	=> "(?<label>[\\pL\\pN\\s_\\-]{1,30})",
	":nonce"	=> "(?<nonce>[a-z0-9]{10,30})",
	":token"	=> "(?<token>[a-z0-9\\+\\=\\-\\%]{10,255})",
	":meta"		=> "(?<meta>[a-z0-9\\+\\=\\-\\%]{7,255})",
	":tag"		=> "(?<tag>[\\pL\\pN\\s_\\,\\-]{1,30})",
	":tags"		=> "(?<tags>[\\pL\\pN\\s_\\,\\-]{1,255})",
	':year'		=> "(?<year>[2][0-9]{3})",
	':month'	=> "(?<month>[0-3][0-9]{1})",
	':day'		=> "(?<day>[0-9][0-9]{1})",
	':slug'		=> "(?<slug>[\\pL\\-\\d]+)",
	":tree"		=> "(?<tree>[\\pL\\/\\-_\\d\\s]{1,255})",
	":file"		=> "(?<file>[\\pL_\\-\\d\\.\\s]{1,120})"
);

# Content Security and Permissions Policy headers
our %sec_headers = (			
	'Content-Security-Policy'
				=>
		"default-src 'none'; base-uri 'self'; img-src *; font-src 'self'; " . 
		"style-src 'self' 'unsafe-inline'; script-src 'self'; " . 
		"form-action 'self'; media-src 'self'; connect-src 'self'; " . 
		"worker-src 'self'; child-src 'self'; object-src 'none'; " . 
		"frame-src 'self'; frame-ancestors 'self'",
	
	# These aren't usually necessary unless for a special web app
	'Permissions-Policy'	=> 
		"accelerometer=(none), camera=(none), geolocation=(none), "  . 
		"fullscreen=(self), gyroscope=(none), magnetometer=(none), " . 
		"microphone=(none), interest-cohort=(), payment=(none), usb=(none)",
	
	'Referrer-Policy'	=> "no-referrer strict-origin-when-cross-origin",
	
	'Strict-Transport-Security'
				=> "max-age=31536000; includeSubDomains",
	
	'X-Content-Type-Options'=> "nosniff",
	'X-Frame-Options'	=> "SAMEORIGIN",
	'X-XSS-Protection'	=> "1; mode=block"
);



# Basic filtering



# Trim leading and trailing space 
sub trim {
	my ( $txt ) = @_;
	$$txt	=~ s/^\s+|\s+$//g;
}

# Usable text content
sub pacify {
	my ( $term ) = @_;
	$term =~ s/
		^\s*				# Remove leading spaces
		| [^[:print:]\x00-\x1f\x7f]	# Unprintable characters
		| [\x{fdd0}-\x{fdef}]		# Invalid Unicode ranges
		| [\p{Cs}\p{Cf}\p{Cn}]		# Surrogate or unassigned code points
		| \s*$				# Trailing spaces
	//gx; 
	return $term;
}

# Convert all spaces to single character
sub unifySpaces {
	my ( $text, $rpl, $br ) = @_;
	
	return '' unless defined( $text ) && $text ne '';
	
	$text	= pacify( $text );
	
	$br	//= 0;		# Preserve line breaks?
	$rpl	//= ' ';	# Replacement space, defaults to ' '
	
	if ( $br ) {
		$text	=~ s/[ \t\v\f]+/$rpl/;
	} else {
		$text	=~ s/[[:space:]]+/$rpl/;
	}
	
	trim( \$text );
	return $text;
}

# Decode URL encoded strings
sub utfDecode {
	my ( $term ) = @_;
	return '' if !defined( $term ) || $term eq '';
	
	$term	= pacify( $term );
	$term	=~ s/\.{2,}/\./g;
	$term	=~ s/\+/ /g;
	$term	=~ s/\%([\da-fA-F]{2})/chr(hex($1))/ge;
	
	if ( Encode::is_utf8( $term ) ) {
		$term	= Encode::decode_utf8( $term );
	}
	
	trim( \$term );
	return $term;
}

# Safely decode JSON to hash
sub jsonDecode {
	my ( $text )	= @_;
	return {} if !defined( $text ) || $text eq '';
	
	$text	= pacify( $text );
	if ( !Encode::is_utf8( $text ) ) {
		$text	= Encode::encode( 'UTF-8', $text );
	}
	
	my $out;
	eval {
		$out = decode_json( $text );
	};
	
	return {} if ( $@ );
	return $out;
}

# Length of given string
sub strsize {
	my ( $str ) = @_;
	
	$str = pacify( $str );
	if ( !Encode::is_utf8( $str ) ) {
		$str = Encode::encode( 'UTF-8', $str );
	}
	return length( $str );
}

# Find if text starts with given search needle
sub textStartsWith {
	my ( $text, $needle ) = @_;
	
	$needle	//= '';
	$text	//= '';
	
	my $nl	= length( $needle );
	return 0 if $nl > length($text);
	
	return substr( $text, 0, $nl ) eq $needle;
}

# Find differences between blocks of text
sub findDiffs {
	my ( $oblock, $eblock )	= @_;
	
	return {} unless defined( $oblock ) && !ref( $oblock );
	return {} unless defined( $eblock ) && !ref( $eblock );
	
	# Presets
	$oblock		=~ s/\r\n|\r/\n/g;
	$eblock		=~ s/\r\n|\r/\n/g;
	
	if ( $eblock eq $oblock ) {
		return { 
			total	=> 0, 
			added	=> 0, 
			deleted	=> 0, 
			changed	=> 0, 
			diffs	=> [] 
		};
	}
	
	my @original	= split /\n/, $oblock, -1;
	my @edited	= split /\n/, $eblock, -1;
	
	# Line sizes
	my $olen	= scalar( @original );
	my $elen	= scalar( @edited );
	my $max_lines	= ( $olen > $elen ) ? $olen : $elen;
	
	
	# Totals
	my $added	= 0;
	my $deleted	= 0;
	my $changed	= 0;
	
	my @diffs;
	
	for ( my $i = 0; $i < $max_lines; $i++ ) {
		# No change? Skip
		next if defined( $edited->[$i] ) && 
			defined( $original->[$i] ) && 
			$edited->[$i] eq $original->[$i];
		
		# Added lines
		if ( defined( $edited->[$i] ) && !defined( $original->[$i] ) ) {
			push( @diffs, { 
				line	=> $i, 
				change	=> "+", 
				text	=> $edited->[$i] 
			} );
			$added++;
			next;
		} 
		
		# Deleted lines
		if ( !defined( $edited->[$i] ) && defined( $original->[$i] ) ) {
			push( @diffs, { 
				line	=> $i, 
				change	=> "-", 
				text	=> $original->[$i]
			} );
			
			$deleted++;
			next;
		}
		
		# Edited lines
		push( @diffs, { 
			line	=> $i, 
			change	=> "+", 
			text	=> $edited->[$i]
		} );
		push( @diffs, { 
			line	=> $i, 
			change	=> "-", 
			text	=> $original->[$i]
		} );
		$changed++;
	}
	
	return { 
		total	=> $max_lines,
		added	=> $added, 
		deleted	=> $deleted, 
		changed	=> $changed,
		diffs	=> \@diffs 
	};
}

# Merge arrays and return unique items
sub mergeArrayUnique {
	my ( $items, $nitems ) = @_;
	
	# Check for array or return as-is
	unless ( ref( $items ) eq 'ARRAY' ) {
		die "Invalid parameter type for mergeArrayUnique\n";
	}
	
	if ( ref( $nitems ) eq 'ARRAY' && @{$nitems} ) {
		push ( @{$items}, @{$nitems} );
		
		# Filter duplicates
		my %dup;
		@{$items} = grep { !$dup{$_}++ } @{$items};
	}
	
	return $items;
}

# Append hash value by incrementing numerical key index
sub append {
	my ( $ref, $key, $msg ) = @_;
	
	# Nothing to append
	unless ( defined( $ref ) && ref( $ref ) eq 'HASH' ) {
		return;
	}
	
	if ( exists( $ref->{$key} ) ) {
		# Increment indexed hash value
		$ref->{$key}{ 
			scalar( keys %{ $ref->{$key} } ) + 1 
		} = $msg;
		return;
	}
	$ref->{$key} = { 1 => $msg };
}

# Helper to find nested caller subroutine details for debugging, logging etc...
sub callerTrace {
	my ( $max_depth, $filter )	= @_;
	
	my @callers;
	my $depth		= 0;
	
	# Presets
	$max_depth		= 20 
		unless defined( $max_depth ) && $max_depth =~ /^\d+$/;
	
	$filter			= {} if ref( $filter ) ne 'HASH';
	$filter->{exclude}	= [] 
		unless defined( $filter->{exclude} ) && 
			ref( $filter->{exclude} ) ne 'ARRAY';
	
	while ( my $info = caller( $depth ) ) {
		last if ( $max_depth > 0 && $depth >= $max_depth );
		next if grep { $_ eq $info[0] } @{$filter->{exclude}};
		
		push( @callers, {
			pkg	=> $info[0] // 'Unknown',
			fname	=> $info[1] // 'Unknown',
			line	=> $info[2] // 'Unknown',
			func	=> $info[3] // 'Unknown',
		} );
		$depth++;
	}
	
	return @callers;
}

# Error and message report formatting helper
sub report {
	my ( $msg, $depth )	= @_;
	
	$msg	//= 'Empty message';
	$msg	= unifySpaces( $msg );
	$depth	//= 1;
	
	my ( $pkg, $fname, $line, $func ) = caller( $depth );
	return "${msg} ( No caller info at depth ${depth} )" 
		unless defined $pkg; 
	
	$fname	= filterPath( $fname );
	
	return 
	"${msg} ( Package: ${pkg}, File: ${fname}, " . 
		"Subroutine: ${func}, Line: ${line} )";
}

# Check if hash has an 'error' key set and is not 0
sub hasErrors {
	my ( $ref )	= @_;
	
	return 
	defined( $ref->{error} ) && ( 
		( $ref->{error} eq 'HASH' && keys %{ $ref->{error} } ) || 
		$ref->{error}
	) ? 1 : 0;
}

# Ensure sent names are handler key appropriate, returns '' on failiure
sub eventName {
	my ( $self, $name )	= @_;
	return '' if !defined( $name );
	return '' if ref( $name );
	
	return lc( unifySpaces( "$name", '_' ) ) if $name =~ /.+/;
	
	return '';
}

# Hooks and extensions
sub hook {
	my ( $data, $out )	= @_;
	state	%handlers;
	state	%output;
	
	$out		//= 0;
	
	# Hook event name
	my $name	= eventName( $data->{event} // '' );
	return {} unless $name ne '';
	
	# Register new handler?
	if ( $data->{handler} ) {
		my $handler	= $data->{handler};
		my $is_code	= ref( $handler ) eq 'CODE';
		my $is_sub	= !ref( $handler ) && defined( \&{$handler} );
		# Check if subroutine exists and doesn't return undef
		return {} unless $is_sub || $is_code;

		# Safe handler name
		$handler	= unifySpaces( $handler ) unless $is_code;
		# Limit hook to current package scope
		my $pkg		= __PACKAGE__;
		unless ( !$is_code && $handler !~ /^${pkg}::/ ) {
			return {};
		}
		
		# Initialize event
		$handlers{$name} //= [];
		
		# Skip duplicate handlers for this event and add handler
		unless (
			grep { 
				( ref( $_ ) eq 'CODE' && $_ == $handler ) || 
				( !ref( $_ ) && $_ eq $handler ) 
			} @{$handlers{$name}}
		) {
			push( @{$handlers{$name}}, $handler );
		}
		return {};
	}
	
	# Check event registry
	return {} unless exists $handlers{$name};
	
	# Get output only without executing event
	if ( $out ) {
		return $output{$name} // {};
	}
	
	# Check params integrity
	my $params	= 
	( defined( $data->{params} ) && ref( $data->{params} ) eq 'HASH' ) ? 
		%{$data->{params}} : {};
	
	# Trigger event
	for my $handler ( @{$handlers{$name}} ) {
		my $temp;
		eval {
			# Trigger with called event name, previous output, and params
			$temp =
			( ref( $handler ) eq 'CODE' ) ? 		
				$handler->( $name, $output{$name} // {}, $params ) // {} : 
				\&{$handler}->( $name, $output{$name} // {}, $params ) // {};
		};
		
		if ( $@ ) {
			# Skip saving output
			next;
		}
		
		# Merge temp with current output
		$output{$name} = { %$output{$name}, %$temp };
	}
}


# Helpers 



# Template rendering
sub render {
	my ( $html, $params ) = @_;
	
	my $settings = {
		ENCODING	=> 'utf8',
		TRIM		=> 1,
		RELATIVE	=> 1,
		CHOMP_ONE	=> 1
	};
	
	# Template module with options
	my $tpl		= Template->new( $settings );
	
	binmode( STDOUT, ":encoding(UTF-8)" );
	$tpl->process( $html, $params ) or exit 1;
}

# Convert to a valid file or directory path
sub filterPath {
	my ( $path, $ns ) = @_;
	
	# Define reserved characters
	state @reserved	= qw( : * ? " < > | ; );
	
	# New filter characters?
	if ( $ns ) {
		@reserved = @{ mergeArrayUnique( \@reserved, $ns ) };
	}
	
	my $chars	= join( '', map { quotemeta( $_ ) } @reserved );
	$path		=~ s/[$chars]//g;
	$path		= unifySpaces( $path );
	
	# Convert relative path to absolute path if needed
	if ( !file_name_is_absolute( $path ) && $path =~ /\S/ ) {
		$path = rel2abs( $path );
	}
	
	# Canonical filter
	return canonpath( $path );
}

sub filterFileName {
	my ( $fname, $ns ) = @_;
	state @reserved = 
	qw(
		CON PRN AUX NUL COM1 COM2 COM3 COM4 COM5 COM6 COM7 COM8 COM9 \
		LPT1 LPT2 LPT3 LPT4 LPT5 LPT6 LPT7 LPT8 LPT9
	);
	
	# Append to reserved list?
	if ( $ns ) {
		@reserved = @{ mergeArrayUnique( \@reserved, $ns ) };
	}
	
	# Basic filtering
	$fname = filterPath( $fname );
	$fname =~ s/[\/\\]/_/g;
	$fname =~ s/^./_/;
	
	# Reserved filtering
	for my $res ( @reserved ) {
		if ( lc( $fname ) eq lc( $res ) ) {
			$fname	= "_$fname";
			last;
		}
	}
	
	return substr( $fname, 0, FILE_NAME_LIMIT );
}

# Relative storage directory
sub storage {
	my ( $path ) = @_;
	state $dir;
	
	unless ( defined $dir ) {
		$dir = pacify( STORAGE_DIR );
		if ( $dir eq '' ) {
			die "Storage directory is empty";
		}
		
		$dir = filterPath( $dir );
		unless ( -d $dir && -r $dir && -w $dir ) {
			die "Storage directory is not accessible";
		}
	}
	
	$path	= pacify( $path );
	
	# Remove leading slashes and spaces, if any, and double dots
	$path	=~ s/^[\s\/]+//;
	$path	=~ s/\.{2,}/\./g;
	
	return catfile( $dir, $path );
}

# Rename duplicate files until the filename doesn't conflict
sub dupRename {
	my ( $dir, $fname, $path ) = @_;
	
	my ( $base, $ext ) = fileparse( $fname, qr/\.[^.]*/ );
	my $i	= 1;
	
	# Keep modifying until file name doesn't exist
	while ( -e $path ) {
		$path	= catfile( $dir, "${base} ($i)$ext" );
                $i++;
	}
	
	return $path;
}

# File lock/unlock helper
sub fileLock {
	my ( $fname, $ltype ) = @_;
	
	$fname	= unifySpaces( $fname );
	unless ( $fname =~ /^(.*)$/ ) {
		# File name failure
		return 0;
	}
	$fname	= canonpath( $1 );
	
	# Lockfile name
	my $fl	= "$fname.lock___";
	
	# Default to removing lock
	$ltype	//= 0;
	
	# Remove lock
	if ( $ltype == 0 ) {
		# No lock
		if ( ! -f $fl ) {
			return 1;
		}
		unlink( $fl ) or return 0;
		return 1; # Lock removed
	}
	
	my $tries	= LOCK_TRIES;
	while ( not sysopen ( my $fh, $fl, O_WRONLY | O_EXCL | O_CREAT ) ) {
		if ( $tries == 0 ) {
			return 0;
		}
		
		# Couldn't open lock even without lock file existing?
		if ( $! && $! != EEXIST ) {
			return 0; # Lock failed
		}
		
		$tries--;
		sleep 0.1;
	}
	
	# Lock acquired
	return 1;
}

# Search path(s) for files by given pattern
sub fileList {
	my ( $dir, $fref, $pattern ) = @_;
	unless ( -d $dir ) {
		return;
	}
	
	$pattern	= 
	quotemeta( $pattern ) unless ref( $pattern ) eq 'Regexp';
	
	find( sub {
		push( @{$fref}, $File::Find::name ) if ( $_ =~ $pattern );
	}, $dir );
}

# Get file contents
sub fileRead {
	my ( $file ) = @_;
	my $out	= '';
	
	$file	=~ /^(.*)$/ and $file = $1;
	
	open ( my $lines, '<:encoding(UTF-8)', $file ) or exit 1;
	while ( <$lines> ) {
		$out .= $_;
	}
	
	close ( $lines );
	return $out;
}

# Write contents to file
sub fileWrite {
	my ( $file, $data ) = @_;
	
	$file	=~ /^(.*)$/ and $file = $1;
	
	open ( my $lines, '>:encoding(UTF-8)', $file ) or exit 1;
	print $lines $data;
	
	close ( $lines );
}

# Search directory for words
sub searchFiles {
	my ( $dir, $words, $ext, $page, $limit )	= @_;
	
	unless ( -d $dir ) {
		return ();
	}
	
	my $pattern	= join( '|', map { quotemeta } @$ext );
	$pattern	= qr/\Q$pattern\E$/i;
	
	$limit		//= 10;
	$page		//= 1;
	
	my $offset	= $limit * $page - 1;
	
	my @files;
	fileList( $dir, \@files, $pattern );
	
	@files = sort( @files );
	
	my @items	= ();
	my $count	= 0;
	my $found	= 0;
	
	foreach my $fpath ( @files ) {
		if ( @items >= $limit ) {
			last;
		}
		
		open ( my $fh, '<', $fpath ) or next;
		
		# Line-by line search
		while ( my $line = <$fh> ) {
			# Iterate through search terms
			foreach my $word ( @$words ) {
				if ( $line =~ /\b\Q$word\E\b/i) {
					$found = 1;
					last;
				}
			}
			
			# Skip rest of the lines
			if ( $found ) {
				last;
			}
		}
		
		close( $fh );
		
		if ( $found ) {
			$count++;
			if ( $count > $offset ) {
				push( @items, $fpath );
			}
			$found	= 0;
		}
	}
	
	return @items;
}

# Send output buffer to client and enable auto flush
sub startFlush() {
	STDOUT->flush();
	STDOUT->autoflush( 1 );
}

# Filter number within min and max range, inclusive
sub intRange {
	my ( $val, $min, $max ) = @_;
	my $out = sprintf( "%d", "$val" );
 	
	return 
	( $out > $max ) ? $max : ( ( $out < $min ) ? $min : $out );
}

# Get raw __DATA__ content as text
sub getRawData {
	state $data;
	
	unless (defined $data) {
		local $/ = undef;
		$data = <DATA>;
	}
	
	return $data;
}

# Get allowed file extensions, content types, and file signatures ("magic numbers")
sub mimeList {
	state %mime_list	= {};
	return %mime_list if keys %mime_list;
	
	my $data	= getRawData();
	
	# Mime data block
	unless ( $data =~ /--\s*MIME\s*data\s*:\s*\n(?<mime>.*?)\n--\s*End\s*MIME\s*data\s*/msi ) {
		return {};
	}
	
	my $find = $+{mime};
	trim( \$find );
	
	while ( $find =~ /^(?<ext>\S+)\s+(?<type>\S+)\s*(?<sig>.*?)\s*$/mg ) {
		my ( $ext, $type, $sig ) = ( $+{ext}, $+{type}, $+{sig} );
		$type	//= 'application/octet-stream';
		$sig	//= '';
			
		my @sig = split( /\s+/, $sig );
		$mime_list->{$ext} = { type => $type, sig => \@sig };
	}
	
	unless ( keys %mime_list ) {
		return {};
	}
	return %mime_list;
}

# Timestamp helper
sub dateRfc {
	my ( $stamp ) = @_;
	
	# Fallback to current time
	$stamp = time() unless defined $stamp;
	my $t = Time::Piece->strptime( "$stamp", '%s' );
	
	# RFC 2822
	return $t->strftime( '%a, %d %b %Y %H:%M:%S %z' );
}

# Limit the date given to a maximum value of today
sub verifyDate {
	my ( $stamp, $now ) = @_;
	
	# Current date ( defaults to today )
	$now	//= localtime->strftime('%Y-%m-%d');
	
	# Split stamp to components ( year, month, day )
	my ( $year, $month, $day ) = $stamp =~ m{^(\d{4})/(\d{2})/(\d{2})$};
	
	# Set checks
	return 0 unless defined( $year ) && defined( $month ) && defined( $day );
	
	# Range checks for year, month, day
	return 0 if  $year < 1900 ||  $month < 1 || $month > 12 || $day < 1 || $day > 31;
	
	# Current date ( year, month, day )
	my ( $year_, $month_, $day_ ) = $now =~ m{^(\d{4})-(\d{2})-(\d{2})$};
	
	# Given year greater than current year?
	if ( $year > $year_ ) {
		return 0;
	}
	
	# This year given?
	if ( $year == $year_ ) {
		
		# Greater than current month?
		if ( $month > $month_ ) {
			return 0;
		}
		
		# Greater than current day?
		if ( $month == $month_ && $day > $day_ ) {
			return 0;
		}
	}
	
	# Leap year?
	my $is_leap = (
		( $year % 4 == 0 && $year % 100 != 0 ) || 
		( $year % 400 == 0 ) 
	);
	
	# Days in February, adjusting for leap years
	my @dm	= ( 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 );
	$dm[1]	= 29 if $month == 2 && $is_leap;
	
	# Maximum day for given month
	return 0 if $day > $dm[$month - 1];
	
	return 1;
}




# Response




# Set expires header
sub setCacheExp {
	my ( $ttl ) = @_;
	
	my $exp = dateRfc( time() + $ttl );
	print "Cache-Control: max-age=$ttl\n";
	print "Expires: $exp\n";
}

# Generate HTTP entity tag and related headers
sub genFileHeaders {
	my ( $rs ) = @_;
	if ( ! -f $rs ) {
		return;
	}
	
	my $fsize	= -s $rs;
	my $mtime	= ( stat( $rs ) )[9];
	my $lmod	= dateRfc( $mtime );
 	
	# Similar to Nginx ETag algo
	my $etag		= 
	\sprintf( "%x-%x", 
		$mtime		//= 0, 
		$fsize		//= 0
	);
	print "Content-Length: $fsize\n";
	print "Last-Modified: $lmod\n";
	print "ETag: $etag\n";
}

# Send HTTP status code
sub httpCode {
	my ( $code, $all ) = @_;
	state %http_codes	= ();
	
	# Preload HTTP status codes
	if ( !keys %http_codes ) {
		my $data = getRawData();
		my $pattern = qr/
		^(?<codes>--\s*HTTP\s*response\s*codes:\s*\n	# HTTP codes start
		.*?						# Code list
		\n--\s*End\s*response\s*codes\s*)		# End codes
		/ixsm;
	
		while ( $data =~ /$pattern/g ) {
			my $find = $+{codes};
			chomp( $find );
			
			while ( $find =~ /^(?<code>\S+)\s+(?<message>.*?)\s*$/mg ) {
				$http_codes{$+{code}}	= $+{message};
			}
		}
	}
	
	# If this is a list request only
	if ( defined( $all ) ) {
		return %http_codes;
	}
	
	# Check if status is currently present
	if ( !exists( $http_codes{$code} ) ) {
		print "Status: 501 Not Implemented\n";
		exit;
	}
	
	print "Status: $code $http_codes{$code}\n";
}

# Safety headers
sub preamble {
	my ( $skip_type, $min_csp ) = @_;
	
	# Default to not skipping content type
	$skip_type	//= 0;
	
	# Minimal Content-Security-Policy ( E.G. for error pages or images )
	$min_csp	//= 0;
	
	# Print security headers
	foreach my $header ( keys %sec_headers ) {
		
		# Minimal CSP
		if ( $header eq 'Content-Security-Policy' && $min_csp ) {
			print 
			"Content-Security-Policy: default-src 'none'; " . 
				"script-src 'self'; style-src 'self' 'unsafe-inline'; " . 
				"img-src 'self'\n";
		
		# Full CSP
		} else {
			print "$header: $sec_headers{$header}\n";
		}
	}
	
	if ( !$skip_type ) {
		# Default content type html, charset UTF-8
		print "Content-type: text/html; charset=UTF-8\n\n";
	}
}

# Set the CORS origin to current URL
sub sendOrigin {
	my ( $realm, $root ) = @_;
	my %request	= getRequest();
	
 	$realm		//= $request{'realm'};
	$root		//= '/';
	
	my $http = ( $request{'secure'} ) ? 'http://' : 'https://';
	my $path = $http . $realm . $root;
	print "Access-Control-Allow-Origin: $path\n";
}

# Redirect to another path
sub redirect {
	my ( $path ) = @_;
	httpCode( '303' );
	print "Location: $path\n\n";
	exit;
}



# Request 




# Raw request headers
sub requestHeaders {
	state %headers	= ();
	
	# Relevant header names
	state @prefix	= 
	qw/CONTENT CONTEXT HTTP QUERY REMOTE REQUEST SCRIPT SERVER/;
	
	if ( keys %headers ) {
		return %headers;
	}
	
	for ( sort( keys ( %ENV ) ) ) {
		foreach my $p ( @prefix ) {
			if ( $_ =~ /^\Q$p\E/ ) {
				$headers{lc( $_ )} = $ENV{$_};
				last;
			}
		}
	}
	
	return %headers;
}

# Temporary storage for incoming form data
sub formDataStream {
	my ( $clen ) = @_;
	
	my $bytes		= 0;
	my $chunk;
	my %err;
	
	my ( $tfh, $tfn )	= 
	tempfile(
		DIR	=> storage( UPLOADS ), 
		SUFFIX	=> '.tmp' 
	);
	
	unless ( defined( $tfh ) && defined( $tfn ) ) {
		append( 
			\%err, 'formDataStream', 
			report( "Failed to create a temp file for form data" ) 
		);
		return { error => \%err };
	}
	
	# Streaming chunk size
	my $chunk_size	= 65536;
	
	# Flush frequency
	my $flush_freq	= 100;
	my $flush_count	= 0;
	
	while ( $bytes < $clen ) {
		my $remaining	= $clen - $bytes;	# Default chunk size to remaining bytes
		my $read_size	= $remaining > $chunk_size ? $chunk_size : $remaining;
		
		# Reset chunk
		$chunk		= '';
		my $read	= sysread( STDIN, $chunk, $read_size );
		
		if ( !defined( $read ) || $read == 0 ) {
			append( 
				\%err, 'formDataStream', 
				report( "Error reading input data" ) 
			);
			
			close( $tfh );
			unlink( $tfh );
			return { error => \%err };
		}
		
		print $tfh $chunk or do {
			append( 
				\%err, 'formDataStream', 
				report( "Error writing to form data temporary file: $!" ) 
			);
			
			close( $tfh );
			unlink( $tfh );
			return { error => \%err };
		};
		
		$flush_count++;
		if ( $flush_count >= $flush_freq ) {
			$tfh->flush();
			$flush_count = 0;
		}
		
		$bytes	+= $read;
	}
	
	# Recheck boundary size
	if ( $bytes != $clen ) {
		append( 
			\%err, 'formDataStream', 
			report( "Boundary overflow: expected $clen, got $bytes" ) 
		);
		
		close( $tfh );
		unlink( $tfh );
		return { error => \%err };
	}
	
	# Flush remaining chunks, if any
	$tfh->flush() if $flush_count > 0;
	
	# Reset seek to beginning of file
	seek( $tfh, 0, 0 ) or do {
		append( 
			\%err, 'formDataStream', 
			report( "Failed to reset seek position to beginning of temp file" ) 
		);
		
		close( $tfh );
		unlink( $tfh );
		return { error => \%err };
	};
	
	return { name => $tfn, stream => $tfh };
}

# Process form data boundary segments
sub formDataSegment {
	my ( $buffer, $boundary, $fields, $uploads ) = @_;
	
	# Split the segment by boundary
	my @segs = split(/--\Q$boundary\E(?!-)/, $buffer );
	shift @segs if @segs > 0;
	pop @segs if @segs && $segs[-1] eq '';
	
	my $pattern	= 
	qr/
		form-data;\s?					# Marker
		name="([^"]+)"(?:;\s?filename="([^"]+)")?	# Labeled names
	/ix;

	# File uploads and form handling temp file directory
	my $dir		= storage( UPLOADS );
	my %err;
	
	foreach my $part ( @segs ) {
		
		# Break by new lines
		my ( $headers, $content ) = split(/\r?\n\r?\n/, $part, 2 ) or do  {
			append( 
				\%err, 'formDataSegment', 
				report( "Header and content split failed" ) 
			);
			return { error => \%err };
		};
		
		if ( 
			!defined( $headers )	|| 
			!defined( $content )	|| 
			$content =~ /^\s*$/ 
		) {
			append( 
				\%err, 'formDataSegment', 
				report( "Malformed multipart data, missing headers or content" ) 
			);
			return { error => \%err };
		}
		
		# Parse headers
		my %parts;
		foreach my $line ( split( /\r?\n/, $headers ) ) {
			next unless $line;
			next unless $line =~ /^(\S+):\s*(.*)/;
			
			my ( $key, $value ) = ( lc( unifySpaces( $1, '-' ) ), $2 );
			trim( \$value );
			
			if ( exists( $parts{$key} ) ) {
				if ( ref( $parts{$key} ) ne 'ARRAY' ) {
   					# Convert to array
					$parts{$key} = [$parts{$key}, $value];
				} else {
					push( @{$parts{$key}}, $value );
				}
			} else {
				$parts{$key} = $value;
			}
		}
		
		# File uploads
		if ( $parts{'content-disposition'} =~ /$pattern/ ) {
			my ( $name, $fname )	= ( $1, $2 );
			
			if ( !defined( $fname ) || !defined( $name ) ) {
				next;
			}
			
			my $ptype	= 
			$parts{'content-type'} // 'application/octet-stream';
			
			$fname		= filterFileName( $fname );
			$name		= filterFileName( $name );
			
			my ( $tfh, $tname ) = tempfile();
			
			# Temp file failed?
			unless ( defined( $tfh ) && defined( $tname ) ) {
				append( 
					\%err, 'formDataSegment', 
					report( "Temp file creation error for file upload ${name} at ${tname}" ) 
				);
				return { error => \%err };
			}
			
			print $tfh $content or do {
				append( 
					\%err, 'formDataSegment', 
					report( "Error writing to form data temporary file: $!" ) 
				);
				
				close( $tfh );
				unlink( $tfh );
				return { error => \%err };
			};
			
			$tfh->flush();
			close( $tfh ) or do {
				append( 
					\%err, 'formDataSegment', 
					report( "Error closing temporary file: ${tname}" ) 
				);
				return { error => \%err };
			};
			
			# Special case if file was moved/deleted mid-operation
			unless ( -e $tname ) {
				append( 
					\%err, 'formDataSegment', 
					report( "Temporary file was moved, deleted, or quarantined: ${tname}" ) 
				);
				# Nothing left to close or delete
				return { error => \%err };
			}
			
			my $fpath	= catfile( $dir, $fname );
			
			# Find conflict-free file name
			$fpath		= dupRename( $dir, $fname, $fpath );
			
			move( $tname, $fpath ) or do {
				append( 
					\%err, 'formDataSegment', 
					report( "Error moving temp upload file $!" ) 
				);
				unlink( $tname );
				
				# Don't continue until moving issue is resolved
				return { error => \%err };
			};
			
			push( @{$uploads}, {
				name		=> $name,
				filename	=> $fname,
				path		=> $fpath,
				content_type	=> $ptype
			} );
			
			# Done with upload file
			next;
		}
		
		# Ordinary form data
		my $name = $parts{'name'};
		$fields->{$name} = $content;
	}
	
	if ( keys %err ) {
		return { error => \%err };
	}
	
	return {};
}

# Sent binary data
sub formData {
	state %data = ();
	
	if ( keys %data ) {
		return \%data;
	}
	
	my %err;
	my %request_headers	= requestHeaders();
	my $clen		= $request_headers{'content_length'} // 0;
	unless ( $clen && $clen =~ /^\d+$/ ) {
		append( \%err, 'formData', report( "Invalid content length" ) );
		
		return { fields => [], files => [], error => \%err };
	}
	
	my $ctype		= $request_headers{'content_type'} // '';
	
	# Check multipart boundary
	my $boundary;
	if ( $ctype =~ /^multipart\/form-data;.*boundary=(?:"([^"]+)"|([^;]+))/ ) {
		$boundary = $1 || $2;
		$boundary = unifySpaces( $boundary );
	} else {
		append( \%err, 'formData', report( "No multipart boundary found" ) );
		
		return { fields => [], files => [], error => \%err };
	}
	
	my $state		= formDataStream( $clen );
	if ( hasErrors( %{$state} ) ) {
		%err = %{$state->{error}};
		# Merge stream errors
		append( 
			\%err, 'formData', 
			report( "Error saving form data stream" )
		);
		
		return { fields => [], files => [], error => \%err };
	}
	
	my %fields	= ();
	my @uploads	= [];
	
	# Process the file content in chunks
	my $buffer	= '';
	my $stream	= %{$state->{stream}};
	while ( my $line = <$stream> ) {
		$buffer .= $line;

		# Once a boundary is reached, process the segment
		if ( $buffer =~ /--\Q$boundary\E(?!-)/ ) {
			my $segment	= 
			formDataSegment( $buffer, $boundary, \%fields, \@uploads );
			
			if ( hasErrors( %{$segment} ) ) {
				%err = %{$segment->{error}};
				append( 
					\%err, 'formData', 
					report( "Form data stream failed" )
				);
				
				# Cleanup form data stream
				close( %{$state->{stream}} );
				unlink( %{$state->{name}} );
				return { fields => [], files => [], error => \%err };
			}
			
			# Reset
			$buffer = '';  
		}
	}
	
	# Cleanup form data stream
	close( %{$state->{stream}} );
	unlink( %{$state->{name}} );
	
	$data{'fields'}	= \%fields;
	$data{'files'}	= \@uploads;
	
	return \%data;
}

# Verify sent form data with nonce and CAPTCHA
sub validateCaptcha {
	my ( $snonce )	= @_;
	
	my $data	= formData();
	unless ( hasErrors( $data ) ) {
		return 0;
	}
	
	my %fields	= %{$data->{fields}} // {};
	unless ( keys %fields ) {
		return 0;
	}
	
	if ( 
		!defined( $fields{nonce} )	|| 
		!defined( $fields{cnonce} )	|| 
		!defined( $fields{captcha} )
	) {
		return 0;
	}
	
	my ( $nonce, $cnonce, $captcha ) = ( 
		$fields{nonce}, $fields{cnonce}, $fields{captcha} 
	);

	# Filter everything
	$nonce		= unifySpaces( $nonce );
	$cnonce		= unifySpaces( $cnonce );
	$captcha	= unifySpaces( $captcha );
	
	if ( $snonce ne $nonce ) {
		return 0;
	}
	
	# Match fixed sizes
	if  ( 
		CAPTCHA_SIZE	!= length( $captcha )	|| 
		NONCE_SIZE	!= length( $cnonce ) 
	) {
		return 0;
	}
	
	# Create a hash with nonce and cnonce and widen character set
	my $chk	= encode_base64( sha256_hex( $nonce . $cnonce ), '' );
	
	# Remove confusing characters (must match client-side code)
	$chk	=~ s/[0oO1liNzZ2m3=\/]//g;
	
	# Limit to CAPTCHA length (must match client-side code)
	if ( lc( substr( $chk, 0, CAPTCHA_SIZE ) ) eq lc( $captcha ) ) {
		return 1;
	}
	
	# Default to fail
	return 0;
}

# Current host or server name/domain/ip address
sub siteRealm {
	my $realm	= lc( $ENV{SERVER_NAME} // '' );
	$realm		=~ s/[^a-zA-Z0-9\.\-]//g;
	
	# End early on empty realm
	sendBadRequest() if ( $realm eq '' );
	
	# Check for reqested realm, if it exists
	my $dir = storage( catfile( 'sites', $realm ) );
	if ( ! -d $dir ) {
		sendBadRequest();
	}
	
	return $realm;
}

# Guess if current request is secure
sub isSecure {
	# Request protocol scheme HTTP/HTTPS etc..
	my $scheme	= lc( $ENV{REQUEST_SCHEME} // 'http' );
	
	# Forwarded protocol, if set
	my $frd		= lc(
		$ENV{HTTP_X_FORWARDED_PROTO}	//
		$ENV{HTTP_X_FORWARDED_PROTOCOL}	//
		$ENV{HTTP_X_URL_SCHEME}		// 'http'
	);
	
	return ( $scheme eq 'https' || $frd  =~ /https/ );
}

# HTTP Client request
sub getRequest {
	
	state %request;
	if ( keys %request ) {
		return %request;
	}
	
	%request = (
		# Server/website name
		'realm'		=> siteRealm(),
	
		# Requested path
		'url'		=> $ENV{REQUEST_URI}		//= '/',
		
		# Client request method
		'verb'		=> lc( $ENV{REQUEST_METHOD}	//= '' ),
		
		# TLS connection status
		'secure'	=> isSecure(),
		
		# Request query string
		'query'		=> $ENV{QUERY_STRING}		//= ''
	);
	
	return %request;
}

# Accept header content types and their given priority
sub getAcceptMedia {
	state %types;
	if ( keys %types ) {
		return %types;
	}
	
	my $header		= lc( $ENV{ACCEPT} // '' );
	if ( $header eq '' ) {
		return \%types;
	}
	
	my @content_types	= split( /\s*,\s*/, $header );
	
	foreach my $type ( @content_types ) {
		
		if ( $type =~ /^([^;]+)(?:\s*;\s*q\s*=\s*(\d(\.\d+)?))?$/ ) {
			my $content		= $1;
			$content		=~ s/[^a-z0-9\/\+\-]+//g;
			if ( $content eq '' ) {
				next;
			}
			
			my $q_value		= defined( $2 ) ? $2 : 1;
			$q_value		= 1 if $q_value > 1;
			$q_value		= 0 if $q_value < 0;
			
			$types{lc($content)}	= $q_value;
		}
	}
	
	return \%types;
}

# Get requested file range, return range error if range was invalid
sub requestRanges {
	my $fr = $ENV{HTTP_RANGE} //= '';
	return () unless $fr;
	
	# Range is too long
	if ( length( $fr ) > 100 ) {
		sendRangeError();
	}
	
	my @ranges;
	
	# Check range header
	my $pattern	= qr/
		bytes\s*=\s*				# Byte range heading
		(?<ranges>(?:\d+-\d+(?:,\s*\d+-\d+)*))	# Comma delimited ranges
	/x;
	
	# Check range header
	while ( $fr =~ m/$pattern/g ) {
		
		my $capture = $+{ranges};
		while ( $capture =~ /(?<range>\d+-(?:\d+)?)/g ) {
			my ( $start, $end ) = split /-/, $+{range};
			
			# End can't be greater than start
			if ( defined( $end ) && $start >= $end ) {
				sendRangeError();
			}
			
			# Check overlapping ranges
			foreach my $check ( @ranges ) {
				my ( $cs, $ce ) = @{$check};
				
				# New range crosses prior start-end ranges?
				if ( 
					$start <= $ce	&& 
					( defined( $end ) ? $end >= $cs : 1 )
				) {
					sendRangeError();
				}
			}
			
			push( @ranges, [$start, $end] );
		}
	}
	
	# Invalid range syntax?
	if ( !@ranges ) {
		sendRangeError();
	}
	
	# Send filtered file ranges
	return \@ranges;
}



# Response handlers ( All should exit after doing their work )



# Send allowed options header in request mode and invalid method mode
sub sendOptions {
	my ( $fail, $allow ) = @_;
	
	# Set fail to off by default
	$fail	//= 0;
	$allow	//= 'GET, POST, HEAD, OPTIONS';
 
	# Fail mode?, send 405 HTTP status code, default 200 OK
	httpCode( $fail ? '405' : '200' );
	print $fail ? 
 		"Allow: $allow\n" : 
 		"Access-Control-Allow-Methods: $allow\n" . 
   		"Access-Control-Allow-Headers: Accept, Accept-Language, Content-Type\n" . 
     		"Access-Control-Expose-Headers: Content-Type, Cache-Control, Expires\n";
	exit;
}

# Response to invalid realm or other shenanigans
sub sendBadRequest {
	httpCode( '400' );
	preamble( 1 );
	
	# Don't need HTML for this
	print "Content-type: text/plain; charset=UTF-8\n\n";
	print "Bad Request";
	exit;
}

# Send an HTTP code matching response file or text status
sub sendErrorResponse {
	my ( $realm, $verb, $code ) = @_;
	
	httpCode( $code );
	
	if ( $verb eq 'head' ) {
		# No content in response to HEAD request
		exit;
	}
	
	# Try to send the realm-specific response file, if it exists
	my $tpl		= storage( "sites/$realm/errors/$code.html" );
	my $ctpl	= storage( "errors/$code.html" );
	if ( -f $tpl ) {
		preamble( 0, 1 );
		render( $tpl );
	
	# Or common error
	} elsif ( -f $ctpl ) {
		preamble( 0, 1 );
		render( $ctpl );
		
	# Default to plaintext
	} else {
		preamble( 1, 1 );
		print "Content-type: text/plain; charset=UTF-8\n\n";
	}
	
	exit;
}

# File/directory not found page
sub sendNotFound {
	my ( $realm, $verb ) = @_;
	sendErrorResponse( $realm, $verb, 404 );
}

# Invalid file range request
sub sendRangeError {
	httpCode( '416' );
	preamble( 1 );
	print "Content-type: text/plain; charset=UTF-8\n\n";
	print "Invalid file range requested";
	exit;
}

# Simple send or buffered stream file
sub sendFile {
	my ( $rs, $stream ) = @_;
	
	# Binary output and file opened in raw mode
	binmode( STDOUT );
	open( my $fh, '<:raw', $rs ) or exit 1;
	
	startFlush();
	if ( $stream ) {
		my $buf;
		while ( read( $fh, $buf, BUFFER_SIZE ) ) {
			print $buf;
		}
	} else {
		while ( my $r = <$fh> ) {
			print $r;
		}
	}
	
	close( $fh );
	exit;
}

# Send ranged content
sub streamRanged {
	my ( $rs, $verb, $type, $ranges ) = @_;
	
	my $fsize	= -s $rs;
	my $fend	= $fsize - 1;
	
	# Total byte size
	my $totals	= 0;
	
	foreach my $r ( @{$ranges} ) {
		my ( $start, $end ) = @{$r};
		if ( 
			$start >= $fend ||
			( defined $end && $end >= $fend ) 
		) {
			sendRangeError();
		}
		
		$totals += ( defined $end ) ? 
			( $start - $end ) + 1 :
			( $fend - $start ) + 1;
	}
	
	if ( $totals > $fend ) {
		sendRangeError();
	}
	
	httpCode( 206 );
	
	# End here if this is a file range check only
	if ( $verb eq 'head' ) {
		exit;
	}
	
	preamble( 1, 1 );
	
	# Generate content boundary
	my $bound	= sha1_hex( $rs . $type );
	
	print "Accept-Ranges: bytes\n";
	print "Content-Type: multipart/byteranges; boundary=$bound\n";
	print "Content-Length: $totals\n";
	
	# Binary output and file opened in raw mode
	binmode( STDOUT );
	open( my $fh, '<:raw', $rs ) or exit 1;
	
	my $limit = 0;
	my $buf;
	my $chunk;
	
	startFlush();
	foreach my $range ( @{$ranges} ) {
		my ( $start, $end ) = @{$range};
		
		print "\n--$bound\n";
		print "Content-type: $type\n\n";
		
		if ( defined $end ) {
			$limit = $end - $start + 1;
			print "Content-Range: bytes $start-$end/$fsize\n";
		} else {
			$limit = $fend - $start + 1;
			print "Content-Range: bytes $start-$fend/$fsize\n";
		}
		
		# Move to start position
		my $cursor = seek( $fh, $start, SEEK_SET );
		if ( ! $cursor ) {
			close( $fh );
			exit 1;
		}
		
		# Send chunks until end of range
		while ( $limit > 0 ) {
			# Reset chunk size until below max buffer size
			$chunk	= $limit > BUFFER_SIZE ? BUFFER_SIZE : $limit;
			
			my $ld	= read( $fh, $buf, $chunk );
			if ( !defined( $ld ) || $ld == 0 ) {
				# Something went wrong while reading 
				# TODO : Log the error
				close( $fh );
				exit 1;
			}
			
			print $buf;
			$limit -= $ld;
		}
	}
	
	close( $fh );
	exit;
}

# Find and send a file resource
sub sendResource {
	my ( $realm, $verb, $params ) = @_;
	
	my $tree	= $params->{tree}	//= '';
	my $file	= $params->{file}	//= '';
	
	# Filter file name
	chomp ( $file, $tree );
	$file =~ s/\.{2,}/\./g;
	$tree =~ s/\.{2,}/\./g;
	
	if ( $file eq '' ) {
		sendNotFound( $realm, $verb );
	}
	
	# Try to get the file extension
	my ( $name, $dir, $ext ) = fileparse( $file, qr/\.[^.]*/ );
	$ext =~ s/\.//g;
	
	# Empty extension?
	if ( $ext eq '' ) {
		sendNotFound( $realm, $verb );
	}
	
	# Mime type
	my %mime_list	= mimeList();
	my $type	= $mime_list{$ext}{type} //= '';
	
	# Not in whitelist?
	if ( $type eq '' ) {
		sendNotFound( $realm, $verb );
	}
	
	# File location relative to requested realm
	my $rs		= storage( "sites/$realm/" );
	
	# Subfolder?
	$rs .= ( $tree ne '' ) ? $tree . '/' . $file : $file;
	
	# Try to locate the file
	if ( !-f $rs ) {
		sendNotFound( $realm, $verb );
	}
	
	# Scan for file request ranges
	my @ranges = requestRanges();
	if ( @ranges ) {
		streamRanged( $rs, $verb, $type, \@ranges );
	}
	
	# Test for type (has file signatures or "magic numbers")
	# Types without signatures are treated as text
	my $text = exists( $mime_list{$ext}{sig} ) ? 0 : 1;
	
	httpCode( '200' );
	if ( !$text ) {
		# Allow ranges for non-text types
		print "Accept-Ranges: bytes\n";
	}
	
	# End here if sending is not necessary
	if ( $verb eq 'head' ) {
		exit;
	}
	
	genFileHeaders( $rs );
	
	preamble( 1, 1 );
	
	# Send the file content type header
	print "Content-type: $type\n\n";
	
	# Send text as-is
	if ( $text ) {
		sendFile( $rs, 0 );
	}
	
	# Buffered stream
	sendFile( $rs, 1 );
}




# Database connectivity




# Read SQL table schema for each database in __DATA__ content
sub databaseSchema {
	my ( $label ) = @_;
	
	# List of SQL database schema
	state %table_schema = ();
	
	if ( keys %table_schema ) {
		return $table_schema{$label} //= '';
	}
	
	# Preload tables
	my $data	= getRawData();
	my $pattern	= qr/
	--\s*Database:\s*   		# Database delimeter prefix
		(?<base>[\w_]+\.db)	# Database name E.G. sessions.db
	\s*--
	
	(?<schema>.*?)			# Table and index schema
	
	--\s*End\s*database\s*--	# Database delimeter suffix
	/ixs;
	
	# Load schema list
	while ( $data =~ /$pattern/g ) {
		$table_schema{$+{base}} = $+{schema};
	}
	return $table_schema{$label} //= '';
}

# Get database connection
sub getDb {
	my ( $db, $close ) = @_;
	state @created;
	
	# Database connection handles
	state %dbh;
	
	if ( $close ) {
		unless ( keys %dbh ) {
			return;
		}
		
		# Close every open connection
		foreach my $key ( keys %dbh ) {
			$dbh{$key}->disconnect();
		}
		%dbh = ();
		return { created = \@created };
	}
	
	# Database connection string format
	$db	= pacify( $db );
	$db	=~ s/\.{2,}/\./g;
	
	trim( \$db );
	
	if ( exists( $dbh{$db} ) ) {
		return { cxn => $dbh{$db} };
	}
	
	# Database file
	my $df		= storage( $db );
	my $first_run	= ( ! -f $df );
	my $dsn		= "DBI:SQLite:dbname=$df";
	
	$dbh{$db}	= 
	DBI->connect( $dsn, '', '', {
		AutoInactiveDestroy	=> 0,
		PrintError		=> 0,
		RaiseError		=> 1,
		Taint			=> 1
	} );
	
	# Database connection failed?
	unless ( $dbh{$db} ) { 
		return {
			cxn	=> undef,
			error	=> 
			report( "Failed to connect to database: " . 
				$DBI::errstr )
		};
	}
	
	# Preemptive defense
	my $quick	= $dbh{$db}->do( 'PRAGMA quick_check;' );
	unless ( $quick ) {
		return {
			cxn	=> undef,
			error	=> 
			report( "Error executing PRAGMA quick_check: " . 
				$dbh{$db}->errstr )
		};
	}
	
	$dbh{$db}->do( 'PRAGMA trusted_schema = OFF;' );
	$dbh{$db}->do( 'PRAGMA cell_size_check = ON;' );
	
	# Prepare defaults if first run
	if ( $first_run ) {
		push( @created, $db );
		$dbh{$db}->do( 'PRAGMA encoding = "UTF-8";' );
		$dbh{$db}->do( 'PRAGMA page_size = "16384";' );
		$dbh{$db}->do( 'PRAGMA auto_vacuum = "2";' );
		$dbh{$db}->do( 'PRAGMA temp_store = "2";' );
		$dbh{$db}->do( 'PRAGMA secure_delete = "1";' );
		
		# Install SQL, if available
		my $schema	= databaseSchema( $db );
		
		if ( $schema ne '' ) {
			my @sql = split( /-- --/, $schema );
			for my $stmt ( @sql ) {
				$dbh{$db}->do( $stmt ) 
				or return {
					cxn	=> undef,
					error	=> 
					report( "Error executing schema statement: $stmt, " . 
						$dbh{$db}->errstr )
				};
			}
		}
		
		# Instalation check
		my $chk = $dbh{$db}->do( 'PRAGMA integrity_check;' );
		if ( $chk ne 'ok' ) { 
			return { 
				cxn	=> undef,
				error	=> 
				report( "Integrity check failed: $chk" ) 
			};
		}
		
		$dbh{$db}->do( 'PRAGMA foreign_key_check;' );
	}
	
	$dbh{$db}->do( 'PRAGMA journal_mode = WAL;' );
	$dbh{$db}->do( 'PRAGMA foreign_keys = ON;' );
	return { cxn => $dbh{$db} };
}

# Get last insert ID
sub lastId {
	my ( $dbh, $table, $field ) = @_;
	my $dtype	= lc( $dbh->{type} // 'sqlite' );
	
	$table = unifySpaces( $table, '_' );
	$field = unifySpaces( $field, '_' );
	
	return ( $dtype eq 'sqlite' ) ? 
		$dbh->{cxn}->last_insert_rowid() : 
		$dbh->{cxn}->last_insert_id( undef, undef, $table, $field );
}

# Cleanup
END {
	sessionWriteClose();
	getDb( undef, 1 );
}




# Cookie handling




# Get all cookie data from request
sub getCookies {
	state %sent;
	
	return %sent if keys %sent;
	
	my @items	= split( /;/, $ENV{'HTTP_COOKIE'} // '' );
	foreach my $item ( @items ) {
		my ( $k, $v )	= split( /=/, $item, 2 );
		
		# Clean prefixes, if any
		$k		=~ s/^__(Host|Secure)\-//gi;
		$sent{pacify( $k )} = pacify( $v );
	}
	
	return %sent;
}

# Get specific cookie key value, if it exists
sub getCookieData {
	my ( $key ) = @_;
	my %cookies = getCookies();
	
	return $cookies{$key} //= '';
}

# Set host/secure limiting prefix
sub cookiePrefix {
	my %request	= getRequest();
	return 
	( COOKIE_PATH eq '/' && $request{'secure'} ) ? 
		'__Host-' : ( $request{'secure'} ? '__Secure-' : '' );
}

# Set cookie values to user
sub cookieHeader {
	my ( $data, $ttl ) = @_;
	
	my %request	= getRequest();
	my $prefix	= cookiePrefix();
	my @values	= ( 
		$prefix . $data,
		'Path=' . ( COOKIE_PATH // '/' ),
		'SameSite=Strict',
		'HttpOnly',
	);
	
	# Cookies without explicit expiration left up to the browser
	if ( $ttl != 0 ) {
		push ( @values, 'Max-Age=' . $ttl );
		push ( @values, 'Expires=' . gmtime( $ttl + time() ) .' GMT' );
	}
	
	if ( $request{'secure'} ) {
		push ( @values, 'Secure' );
	} 
	
	if ( $prefix eq '__Secure' || $prefix eq '' ) {
		push ( @values, 'Domain=' . $request{'realm'} );
	}
	
	my $cookie	= join( '; ', @values );
	print "Set-Cookie: $cookie\n";
}

# Set a cookie with default parameters
sub setCookie {
	my ( $name, $value, $ttl ) = @_;
	
	$ttl	//= COOKIE_EXP;
	if ( $ttl < 0 ) {
		$ttl = 0;
	}
	
	cookieHeader( "$name=$value", $ttl );
}

# Erease already set cookie by name
sub deleteCookie {
	my ( $name ) = @_;
	
	cookieHeader( "$name=", 0 );
}




# Session management




# Strip any non-cookie ID data
sub sessionCleanID {
	my ( $id ) = @_;
	$id		= pacify( $id );
	$id		=~ /^([a-zA-Z0-9]{20,255})$/;
	
	return $id;
}

# Generate or return session ID
sub sessionID {
	my ( $sent ) = @_;
	state $id = '';
	
	$sent //= '';
	if ( $sent ne '' ) {
		$id = sessionCleanID( $sent ); 
	}
	
	if ( $id eq '' ) {
		# New pseudorandom ID
		$id = sha256_hex( 
			Time::HiRes::time() . rand( 2**32 ) 
		);
	}
	
	return $id;
}

# Send session cookie
sub sessionSend {
	setCookie( 'session', sessionID(), SESSION_EXP );
}

# Create a new session with blank data
sub sessionNew {
	sessionID( '' );
	sessionSend();
}

# Get or store session data to scoped hash
sub sessionWrite {
	my ( $key, $value ) = @_;
	
	# Session stroage data
	state %session_data = ();
	
	if ( $key ) {
		$session_data{$key} = $value;
		return;
	}
	
	return %session_data;
}

# Read cookie data from database, given the ID
sub sessionRead {
	my ( $id ) = @_;
	my %err;
	
	# Strip any non-cookie ID data
	my ( $find ) = $id =~ /^([a-zA-Z0-9]{20,255})$/;
	
	my $dbh	= getDb( 'sessions.db' );
	unless( hasErrors( $dbh ) ) {
		# Fall through any errors from getDb()
		%err = %{$dbh->{error}};
		append( 
			\%err, 'sessionRead', 
			report( "Error in call to db connection" )
		);
		
		return { error => \%err };
	}
		
	my $sth	= $dbh->{cxn}->prepare( qq(
		SELECT session_data FROM sessions 
			WHERE session_id = ? LIMIT 1;
	) );
	$sth->execute( $find );
	my $data = $sth->fetchrow_hashref and $sth->finish;
	
	# Load data to session, if it exists
	if ( $data ) {
		return { data => $data->{session_data} };
	}
	
	return {};
}

# Start session with ID, if given, or a fresh session
sub sessionStart {
	my ( $id ) = @_;
	
	state $start = 0;
	if ( $start ) {
		return;
	}
	
	# Get raw ID from cookie
	$id	//= getCookieData( 'session' );
	
	# Clean ID
	$id	= sessionCleanID( $id );
	
	# Mark started
	$start	= 1;
	
	if ( $id eq '' ) {
		# New session data
		sessionNew();
		return;
	}
	
	my %err;
	my $info	= sessionRead( $id );
	unless( hasErrors( $info ) ) {
		%err = %{$info->{error}};
		append( 
			\%err, 'sessionStart', 
			report( "Error starting session" )
		);
		
		return { error => \%err };
	}
	my $data	= $info->{data} // '';
	
	# Invalid existing cookie? Reset
	if ( $data eq '' ) {
		sessionNew();
		return;
	}
	
	# Restore session from cookie
	sessionID( $id );
	
	my $values = decode_json( "$data" );
	foreach my $key ( keys %{$values} ) {
		sessionWrite( $key, $values->{$key} );
	}
}

# Get data by session key value
sub sessionGet {
	my ( $key ) = @_;
	
	sessionStart();
	my %data = sessionWrite();
	return $data{$key} //= '';
}

# Send session cookie
sub sessionSend {
	setCookie( 'session', sessionID(), SESSION_LIFETIME );
}

# Delete seession
sub sessionDestroy {
	my ( $id ) = @_;
	my %err;
	
	$id		= sessionCleanID( $id );
	my $dbh		= getDb( 'sessions.db' );
	unless( hasErrors( $dbh ) ) {
		%err = %{$dbh->{error}};
		append( 
			\%err, 'sessionDestroy', 
			report( "Error destroying session ${id} in database" )
		);
		
		return { error => \%err };
	}
	
	my $ok = $dbh->{cxn}->do( 'DELETE FROM sessions WHERE session_id = ?;', undef, $id );
	unless ( $ok ) {
		my $estr = $dbh->{cxn}->errstr // 'Unknown error';
		append( 
			\%err, 'sessionDestroy', 
			report( "Error destroying session ${id} in database: ${estr}")
		);
		
		return { error => \%err };
	};
		
	return { id => $id };
}

# Garbage collection
sub sessionGC {
	my %err;
	my $dbh		= getDb( 'sessions.db' );
	
	unless( $dbh ) {
		%err = %{$dbh->{error}};
		append( \%err, 'sessionGC', report( "Error connecting to session database" ) );
		return { error => \%err };
	}
	
	
	# Delete sessions exceeding garbage collection timeframe
	my $sth = 
	$dbh->{cxn}->prepare( qq(
		DELETE FROM sessions WHERE (
		strftime( '%s', 'now' ) - 
		strftime( '%s', updated ) ) > ? ;
	) );
	unless ( $sth ) {
		my $msg =  $dbh->{cxn}->errstr // 'Unknown error';
		append( \%err, 'sessionGC', 
			report( "Failed to prepare session GC statement: ${msg}" ) );
		
		return { error => \%err };
	}
	
	my $status = $sth->execute( SESSION_GC );
	unless ( $status ) {
		$msg = $sth->errstr // 'Unknown error';
		append( \%err, 'sessionGC', 
			report( "Execution failed: ${msg}") );
		
		return { error => \%err };
	}
	$sth->finish;
	return {};
}

# Finish and save session data, if it exists
sub sessionWriteClose {
	state $written	= 0;
	
	# Avoid double write and close
	if ( $written ) {
		return;
	}
	
	my %data = sessionWrite();
	
	# Skip writing if there is no data
	if ( ! keys %data ) {
		return;
	}
	
	my %err;
	my $dbh		= getDb( 'sessions.db' );
	unless( hasErrors( $dbh ) ) {
		%err = %{$dbh->{error}};
		append( 
			\%err, 'sessionWriteClose', 
			report( "Error writing to session database" )
		);
		
		return { error => \%err };
	}
	
	my $msg;
	my $sth		= $dbh->{cxn}->prepare( qq(
		REPLACE INTO sessions ( session_id, session_data ) 
			VALUES( ?, ? );
	) );
	unless( $sth ) {
		$msg = $dbh->{cxn}->errstr // 'Unknown error';
		append( \%err, 'sessionWriteClose', 
			report( "Failed to prepare session saving statement: ${msg}" ) );
		return { error => \%err };
	}
	
	my $status = $sth->execute( 
		sessionID(),
		encode_json( \%data )
	);
	unless ( $status ) {
		$msg = $sth->errstr // 'Unknown error';
		append( \%err, 'sessionWriteClose', 
			report( "Session saving failed: ${msg}") );
		
		return { error => \%err };
	}
	$sth->finish;
	
	$written = 1;
}

# Create a typical response for a limited access view, E.G. login page etc...
sub safeView {
	my ( $realm, $verb ) = @_;
	
	if ( $verb eq 'options' ) {
		httpCode( '204' );
		sendOptions();
		setCacheExp( 604800 );
		sendOrigin( $realm );
		exit;
	}
	
	httpCode( '200' );
	if ( $verb eq 'head' ) {
		# Nothing else to send
		exit;
	}
	
	sendOrigin( $realm );
	preamble();
}



# User functionality



# Generate random salt up to given length
sub genSalt {
	my ( $len ) = @_;
	state @pool	= ( '.', '/', 0..9, 'a'..'z', 'A'..'Z' );
	
	return join( '', map( +@pool[rand( 64 )], 1..$len ) );
}

# Generate HMAC digest
sub hmacDigest {
	my ( $key, $data )	= @_;
	my $hmac		= hmac_sha384( $data, $key );
	
	return unpack( "H*", $hmac );
}

# Generate a hash from given password and optional salt
sub hashPassword {
	my ( $pass, $salt, $rounds ) = @_;
	
	# Generate new salt, if empty
	$salt		//= genSalt( 16 );
	$rounds		//= HASH_ROUNDS;
	
	# Crypt-friendly blocks
	my @chunks	= 
		split( /(?=(?:.{8})+\z)/s, sha512_hex( $salt . $pass ) );
	
	my $out		= '';	# Hash result
	my $key		= '';	# Digest key per block
	my $block	= '';	# Hash block
	
	for ( @chunks ) {
		# Generate digest with key from crypt
		$key	= crypt( $_, substr( sha256_hex( $_ ), 0, -2 ) );
		$block	= hmacDigest( $key, $_ );
		
		# Generate hashed block from digest
		for ( 1..$rounds ) {
			$block	= sha384_hex( $block );
		}
		
		# Add block to output
		$out		.= sha384_hex( $block );
	}
	
	return $salt . ':' . $rounds . ':' . $out;
}

# Match raw password against stored hash
sub verifyPassword {
	my ( $pass, $stored ) = @_;
	
	my ( $salt, $rounds, $spass ) = split( /:/, $stored );
	
	if ( $stored eq hashPassword( $pass, $salt, $rounds ) ) {
		return 1;
	}
	
	return 0;
}

# Find form-specific anti-CSRF token
sub getCSRFToken {
	my ( $form )	= @_;
	return sessionGet( 'csrf_' . $form );
}

# Generate an anti-CSRF token
sub setCSRFToken {
	my ( $form )	= @_;
	
	my $nonce	= genSalt( 32 );
	my $key		= genSalt( 6 );
	
	sessionWrite( 'csrf_' . $form, $key );
	
	my %data	= (
		nonce => $nonce,
		token => sha1_base64( $key . $nonce )
	);
	
	return %data;
}

# Verify anti-cross-site request forgery token
sub validateCSRFToken {
	my ( $token, $nonce, $form ) = @_;
	
	my $ln = strsize( $nonce );
	my $lt = strsize( $token );
	
	# Sanity check
	if ( 
		$ln > 100 || 
		$ln <= 10 || 
		$lt > 350 || 
		$lt <= 10
	) {
		return 0;
	}
	
	my $key = getCSRFToken( $form );
	
	return ( $token eq sha1_base64( $key . $nonce ) ) ? 1 : 0;
}



# Templates and rendering



# Template placeholder replacements
sub replace {
	my ( $tpl, %data, $clean ) = @_;
	
	while ( my ( $term, $html ) = each %data ) {
		$tpl =~ s/\{$term\}/$html/ge;
	}
	
	$clean = $clean // 1;
	
	# Remove any unset placeholders
	if ( $clean == 1 ) {
		$tpl =~ s/\{.*\}//g;
	}
	
	return $tpl;
}

# Load and find rendering templates by label
sub template {
	my ( $label ) = @_;
	
	state %tpl_list = ();
	
	if ( keys %tpl_list ) {
		return $tpl_list{$label} //= '';
	}
	
	my $data	= getRawData();
	my $pattern	= qr/
	\s*(?<tpl>tpl_[\w_]+):\s*	# Template name E.G. tpl_page
		(?<html>.*?)		# HTML Content
	\s*end_tpl			# Template delimeter suffix
	/ixs;
	
	# Load templates list
	while ( $data =~ /$pattern/g ) {
		$tpl_list{$+{tpl}} = $+{html};
	}
	return $tpl_list{$label} //= '';
}

# Get allowed HTML tags
sub allowedTags {
	state %whitelist;
	
	if ( keys %whitelist ) {
		return %whitelist;
	}
	
	my %default_json =<<"JSON";
{
		"p"	: { 
			"attributes"	: [ 
				"style", "class", "align", 
				"data-pullquote", "data-video", "data-media" 
			]
		},
		
		"div"	: { 
			"attributes"	: [ "style", "class", "align" ]
		},
		
		"span"	: { 
			"attributes"	: [ "style", "class" ]
		},
		
		"br"	: { 
			"attributes"	: [ "style", "class" ],
			"self_closing"	: 1,
			"no_nest"	: 1
		},
		
		"hr"	: { 
			"attributes"	: [ "style", "class" ],
			"self_closing"	: 1,
			"no_nest"	: 1
		},
		
		"h1"	: { 
			"attributes"	: [ "style", "class" ]
		},
		"h2"	: { 
			"attributes"	: [ "style", "class" ]
		},
		"h3"	: { 
			"attributes"	: [ "style", "class" ]
		},
		"h4"	: { 
			"attributes"	: [ "style", "class" ]
		},
		"h5"	: { 
			"attributes"	: [ "style", "class" ]
		},
		"h6"	: { 
			"attributes"	: [ "style", "class" ]
		},
		
		"strong"	: { 
			"attributes"	: [ "style", "class" ]
		},
		"em"	: { 
			"attributes"	: [ "style", "class" ]
		},
		"u"	: { 
			"attributes"	: [ "style", "class" ]
		},
		"strike"	: { 
			"attributes"	: [ "style", "class" ]
		},
		"del"	: { 
			"attributes"	: [ "style", "class", "cite", "datetime" ],
			"uri_attr"	: [ "cite" ]
		},
		"ins"	: { 
			"attributes"	: [ "style", "class", "cite", "datetime" ],
			"uri_attr"	: [ "cite" ]
		},
		
		"ol"	: {
			"attributes"	: [ "style", "class" ]
		},
		"ul"	: {
			"attributes"	: [ "style", "class" ]
		},
		"li"	: {
			"attributes"	: [ "style", "class" ]
		},
		
		"code"	: {
			"attributes"	: [ "style", "class" ],
			"no_nest"	: 1
		},
		"pre"	: {
			"attributes"	: [ "style", "class" ]
		},
		
		"sup"	: {
			"attributes"	: [ "style", "class" ]
		},
		"sub"	: {
			"attributes"	: [ "style", "class" ]
		},
		
		"a"	: {
			"attributes"	: [ 
				"style", "class", "rel", "title", "href" 
			],
			"uri_attr"	: [ "href" ]
		},
		
		"img"	: {
			"attributes"	: [ 
				"style", "class", "src", "height", "width", 
				"alt", "title", "srcset", "sizes",
				"data-srcset", "data-src", "data-sizes" 
			],
			"uri_attr"	: [ 
				"data-src", "data-srcset", "srcset", "src" 
			],
			"no_nest"	: 1
		},
		
		"figure"	: {
			"attributes"	: [ "style", "class" ]
		},
		"figcaption"	: {
			"attributes"	: [ "style", "class" ]
		},
		"picture"	: {
			"attributes"	: [ "style", "class" ]
		},
		
		"table"	: {
			"attributes"	: [ 
				"style", "class", "cellspacing", 
				"border-collapse", "cellpadding" 
			]
		},
		"thead"	: {
			"attributes"	: [ "style", "class" ]
		},
		"tbody"	: {
			"attributes"	: [ "style", "class" ]
		},
		"tfoot"	: {
			"attributes"	: [ "style", "class" ]
		},
		"tr"	: {
			"attributes"	: [ "style", "class" ]
		},
		"td"	: {
			"attributes"	: [ 
				"style", "class", "colspan", "rowspan" 
			]
		},
		"th"	: {
			"attributes"	: [ 
				"style", "class", "scope", "colspan", "rowspan" 
			]
		},
		
		"caption"	: {
			"attributes"	: [ "style", "class" ]
		},
		"col"	: {
			"attributes"	: [ "style", "class" ]
		},
		"colgroup"	: {
			"attributes"	: [ "style", "class" ]
		},
		
		"address"	: {
			"attributes"	: [ "style", "class" ]
		},
		
		"summary"	: {
			"attributes"	: [ "style", "class" ]
		},
		"details"	: {
			"attributes"	: [ "style", "class" ]
		},
		
		"q"	: {
			"attributes"	: [ "style", "class", "cite" ],
			"uri_attr"	: [ "cite" ],
			"no_nest"	: 1
		},
		"cite"	: {
			"attributes"	: [ "style", "class" ]
		},
		"abbr"	: {
			"attributes"	: [ "style", "class", "title" ]
		},
		"dfn"	: {
			"attributes"	: [ "style", "class", "title" ]
		},
		"blockquote"	: {
			"attributes"	: [ "style", "class", "cite" ],
			"uri_attr"	: [ "cite" ]
		}
}
JSON
	my %whitelist = jsonDecode( $default_json );
	return %whitelist;
}

# Intercept HTML tag attribute(s)
sub parseAttributes {
	my ( $params )	= @_;
	my %attrs;
	while ( $params =~ m/(\w+)\s*=\s*"([^"]*)"/g ) {
		$attrs{$1} = $2;
	}
	
	return \%attrs;
}

# Check if given tag matches limited set of self-closing tags
sub isSelfClosing {
	my ( $tag )	= @_;
	# Limited set of self-closing tags
	state %closing = 
	map { 
		$_ => 1 
	} qw(area base br col embed hr img input link meta param source track wbr);
	
	return 0 unless exists( $closing{$tag} );
	return 1;
}

# Load given HTML segment into a hash
sub parseHTML {
	my ( $html ) = @_;
	my $tree = {};
	
	while ( $html =~ m{<(\w+)([^>]*)\s*/?>|<(\w+)([^>]*)>(.*)</\3>}gs ) {
		if ( defined $1 && isSelfClosing( $1 ) ) {
			my $tag		= $1;
			my $attr	= unifySpaces( $2 );
			
			$tree->{$tag} = {
				attributes => parseAttributes( $attr ),
				content    => undef
			};
		} elsif ( defined $3 ) {
			my $tag		= $3;
			my $attr	= unifySpaces( $4 );
			my $content	= trim( $5 );
			
			$tree->{$tag} = {
				attributes => parseAttributes( $attr ),
				content    => 
					$content =~ /</ ? 
					parseHTML( $content ) : $content
			};
		}
	}
	
	return $tree;
}

# Sanitize tag attributes against whitelist
sub filterAttribute {
	my ( $tag, $attr_name, $data )	= @_;
	if ( $data eq '' ) {
		return '';
	}
	
	my $whitelist	= allowedTags();
	# URI types get special treatment
	if ( 
		grep{ $_ eq $attr_name } 
			@{$whitelist->{$tag}{attributes}{uri_attr} // ()} 
	) {
		$data	= unifySpaces( $data );
		
		# Strip tags
		$data	=~ s/<.*?>//g;
		
		return trim( $data );
	}
	
	# Entities for everything else
	return escapeCode( $data );
}

# Raw collapse of HTML node to text
sub flattenNode {
	my ( $node )	= @_;
	my $out	= '';
	
	foreach my $tag ( keys %{$node} ) {
		my $attr = '';
		foreach my $attr_name ( keys %{node->{$tag}{attributes}} ) {
			$attr .= sprintf( ' %s="%s"', $attr_name, $data );
		}
		
		if ( isSelfClosing( $tag ) ) {
			$out .= sprintf( '<%s%s />', $tag, $attr );
			next;
		}
		
		unless( exists( $node->{$tag}{content} ) ) {
			$out .= sprintf( '<%s%s></%s>', $tag, $attr, $tag );
			next;
		}
		
		my $content	= '';
		if ( ref( $node->{$tag}{content} ) eq 'HASH' ) {
			$content = flattenNode( $node );
		} else {
			$content = $node->{$tag}{content};
		}
		$out .= sprintf( '<%s%s>%s</%s>', $tag, $attr, $content );
	}
	
	return $out;
}

# Build HTML block from nested hash of tags and their attributes
sub buildHTML {
	my ( $node )	= @_;
	my $out	= '';
	
	my $whitelist	= allowedTags();
	foreach my $tag ( keys %{$node} ) {
		# Skip unless tag exists in whitelist
		next unless exists $whiltelist->{$tag};
		
		my $attr	= '';
		if ( exists( $node->{$tag}{attributes} ) ) {
			foreach my $attr_name ( keys %{node->{$tag}{attributes}} ) {
				# Skip unless attribute exists for this tag
				next unless grep { $_ eq $attr_name } 
					@{$whitelist->{$tag}{attributes} // {}};
				
				my $data	= 
				$node->{$tag}{attributes}{$attr_name} // '';
				
				$data		= 
				filterAttribute( $tag, $attr_name, $data );
				
				$attr		.= 
				sprintf( ' %s="%s"', $attr_name, $data );
			}
		}
		
		# Ignore content if this is meant to be self-closing
		if ( isSelfClosing( $tag ) || $whitelist{$tag}{self_closing} // 0 ) {
			$out .= sprintf( '<%s%s />', $tag, $attr );
			next;
		}
		
		# No content? Close tag
		unless( exists( $node->{$tag}{content} ) ) {
			$out .= sprintf( '<%s%s></%s>', $tag, $attr, $tag );
			next;
		}
		
		my $content	= '';
		if ( ref( $node->{$tag}{content} ) eq 'HASH' ) {
			# Ignore nesting if it isn't allowed
			if ( $whitelist{$tag}{no_nest} // 0 ) {
				$content	= 
				escapeCode( $node->{$tag}{content} );
			
			# Move on to child nodes
			} else {
				$content	= 
				buildHTML( $node->{$tag}{content} );
			}
		} else {
			$content	= 
			escapeCode( $node->{$tag}{content} );
		}
		
		$out .= sprintf( '<%s%s>%s</%s>', $tag, $attr, $content );
	}
	
	return $out;
}

# Wrap sent HTML with protected placeholders, optionally adding new tags
sub startProtectedTags {
	my ( $html, $ns )	= @_;
	
	# Base level protected tags
	state @protected	= 
	( 'p', 'ul', 'ol', 'pre', 'code', 'table', 'figure', 'figcaption', 
		'address', 'details', 'span', 'embed', 'video', 'audio', 
		'texteara', 'input' );
	
	if ( $ns ) {
		@protected = @{ mergeArrayUnique( \@protected, $ns ) };
	}
	
	my $tags	= join( '|', @protected );
	
	# Wrap protected tags in placeholders
	$$html		=~ 
	s|(<($tags)[^>]*>.*?</\2>)|__PROTECT__$1__ENDPROTECT__|gs;
}

# Restore protected tags
sub endProtectedTags {
	my ( $html )		= @_;
	
	$$html		=~ s/__PROTECT__(.*?)__ENDPROTECT__/$1/g;
}

# Format code to HTML
sub escapeCode {
	my ( $code ) = @_;
	
	return '' if !defined( $code ) || $code eq ''; 
	
	if ( !Encode::is_utf8( $code ) ) {
		$code = Encode::decode( 'UTF-8', $code );
	}
	
	# Double esacped ampersand workaround
	$code =~ s/&(?!(amp|lt|gt|quot|apos);)/&amp;/g; 
	
	$code =~ s/</&lt;/g;
	$code =~ s/>/&gt;/g;
	$code =~ s/"/&quot;/g;
	$code =~ s/'/&apos;/g;
	$code =~ s/\\/&#92;/g;
	
	$code =~ s/([^\x00-\x7F])/sprintf("&#x%X;", ord($1))/ge;
	trim( \$code );
	
	return $code;
}

# TODO: Process footnotes
sub footnote {
	my ( $ref, $note ) = @_;
	
	return '';
}

# Process uploaded media embeds
sub embeds {
	my ( $ref, $source, $title, $caption, $preview  ) = @_;
	
	my %data	= (
		src	=> $source,
		title	=> $title,
		caption	=> $caption,
		preview	=> $preview
	);
	
	for ( $ref ) {
		/audio/ and do {
			return replace( template( 'tpl_audio_embed' ), %data );
		};
		
		/video/ and do {
			return replace( template( 'tpl_video_embed' ), %data );
		};
		
		/figure/ and do {
			return replace( template( 'tpl_figure_embed' ) );
		};
	}
	
	# Some matching went wrong
	return '';
}

# Third-party hosted media embedding
sub hostedEmbeds {
	my ( $host, $url ) = @_;
	
	my %data;
	my @pats;
	
	for ( $host ) {
		/youtube/ and do {
			@pats = (
				qr/http(s)?\:\/\/(www)?\.?youtube\.com\/watch\?v=
					(?<src>[0-9a-z_\-]*)
					(?:\&t\=(?<time>[\d]*)s)?/is,
				qr/http(s)?\:\/\/(www)?\.?youtu\.be\/
					(?<src>[0-9a-z_\-]*)
					(?:\?t\=(?<time>[\d]*))?/is,
				qr/(?<src>[0-9a-z_\-]*)/is
			);
			
			# Try to find a matching YouTube URL
			foreach my $rx ( @pats ) {
				if ( $url =~ $rx ) {
					return replace( template( 'tpl_youtube' ), %+ );
				}
			}
			
			# Or just return the URL as-is
			return '[youtube ' . $url . ']';
		};
		
		/vimeo/ and do {
			@pats = (
				qr/http(s)?\:\/\/(www)?\.?vimeo\.com\/(?<src>[0-9]*)/is,
				qr/(?<src>[0-9]*)/is
			);
			
			foreach my $rx ( @pats ) {
				if ( $url =~ $rx ) {
					return replace( template( 'tpl_vimeo' ), %+ );
				}
			}
			
			return '[vimeo ' . $url . ']';
		};
		
		/peertube/ and do {
			if ( $url =~ qr/http(s)?\:\/\/(?<src_host>.*?)\/videos\/watch\/
					(?<src>[0-9\-a-z_]*)\]/is ) {
				return replace( template( 'tpl_peertube' ), %+ );
			}
		};
		
		/archive/ and do {
			@pats = (
				qr/http(s)?\:\/\/(www)?\.?archive\.org\/details\/
					(?<src>[0-9\-a-z_\/\.]*)\]/is,
				qr/(?<src>[0-9a-z_\/\.]*)\]/is
			);
			
			foreach my $rx ( @pats ) {
				if ( $url =~ $rx ) {
					return replace( template( 'tpl_archiveorg' ), %+ );
				}
			}
		};
		
		/lbry|odysee/ and do {
			@pats = (
				qr/http(s)?\:\/\/(?<src_host>.*?)\/\$\/download\/
					(?<slug>[\pL\pN\-_]*)\/\-?
					(?<src>[0-9a-z_]*)\]/is,
				qr/lbry\:\/\/\@(?<src_host>.*?)\/([\pL\pN\-_]*)
					(?<slug>\#[\pL\pN\-_]*)?(\s|\/)
					(?<src>[\pL\pN\-_]*)\]/is
			);
			
			foreach my $rx ( @pats ) {
				return replace( template( 'tpl_lbry' ), %+ );
			}
		};
		
		/utreon|playeur/ and do {
			if ( $url =~ qr/(?:http(s)?\:\/\/(www\.)?)?
					(?:utreon|playeur)\.com\/v\/
					(?<src>[0-9a-z_\-]*)
				(?:\?t\=(?<time>[\d]{1,}))?\]/is 
			) {
				return replace( template( 'tpl_playeur' ), %+ );
			}
		};
	}
	
	# Nothing else found
	return '';
}

# Close open list types
sub formatCloseList {
	my ( $lstack, $indent, $html, $ltype ) = @_;
	while (
		@$lstack				&&
		$lstack->[-1]{indent} > $indent		&&
		$lstack->[-1]{type} eq $ltype
	) {
		$$html .= "</$ltype>\n";
		pop @$lstack;
	}
}

# Create new list type
sub formatNewList {
	my ( $lstack, $html, $indent, $ltype ) = @_;
	if (
		!@$lstack				||
		$lstack->[-1]{type} ne $ltype		||
		$lstack->[-1]{indent} != $indent
	) {
		# Close the current list if needed
		if ( @$lstack && $lstack->[-1]{type} eq $ltype ) {
			$$html .= "</$ltype>\n"
		}
		
		# Start a new list
		$$html .= "<$ltype>\n";
		push( @$lstack, { type => $ltype, indent => $indent } ) ;
	}
}

# Finish closing any remaining open list types based on stack
sub formatEndLists {
	my ( $lstack, $html ) = @_;
	while ( @$lstack ) {
		$$html .= 
		( $lstack->[-1]{type} eq 'ul' ) ? '</ul>' : (
			 ( $lstack->[-1]{type} eq 'ol' ) ? '</ol>' : '</dl>'
		);
		pop @$lstack;
	}
}

# Convert indented lists into HTML lists
sub formatListBlock {
	my ( $text ) = @_;

	my @lines = split /\n/, $text;
	my $html = '';
	my @lstack;  # Stack to manage nested lists
	
	foreach my $line ( @lines ) {
		# Match ordered list items
		if ( $line =~ /^(\s*)([\*\+\d\.]+)\s+(.*)$/ ) {
			my $indent	= length( $1 );
			my $marker	= $2;
			my $content	= $3;
			
			# Unordered type
			if ( $marker =~ /^[\*\+]/ ) {
				# Close ordered list if needed
				formatCloseList( \@lstack, \$html, $indent, 'ol');
				
				# Start a new unordered list if needed
				formatNewList( \@lstack, \$html, $indent, 'ul');
			
			# Ordered type
			} else {
				# Close unordered list if needed
				formatCloseList( \@lstack, \$html, $indent, 'ul');
				
				# Start a new ordered list if needed
				formatNewList( \@lstack, \$html, $indent, 'ol');
			}
			$html .= "<li>$content</li>\n";
			next;
		}
		
		# Close any remaining open lists before adding non-list content
		formatEndLists( \@lstack, $html );
		$html .= "$line\n";
	}

	# Close any remaining open lists at the end
	formatEndLists( \@lstack, \$html );
	return $html;
}

# Convert plain text lists to HTML list blocks
sub formatLists {
	my ( $text )	= @_;
	my @lists;
	
	# Prevent formatting inside existing block level tags
	startProtectedTags( \$text );
	
	# Save a placeholder after finding each list block
	while ( $text =~ /(__PROTECT__(.*?)__ENDPROTECT__)|([^\r\n]+)/g ) {
		if ( !defined( $3 ) ) {
			next;
		}
		
		my $idx	= scalar( @lists );
		push( @lists, { index => $idx, html => $3 } );
		$text =~ s/$&/__STARTLIST__${idx}__ENDLIST__/;
	}
	
	for my $block ( @lists ) {
		# Format the non-protected text block
		$block->{html} = formatListBlock( $block->{html} );
		
		# Restore from placeholder
		$text =~ 
		s/__STARTLIST__$block->{index}__ENDLIST__/$block->{html}/g;
	}
	
	# Restore other block level tags
	endProtectedTags( \$text );
	return $text;
}

# Table data row
sub formatRow {
	my ( $row, $header )	= @_;
	$header		//= 0;
	
	my $tag		= $header ? 'th' : 'td';
	
	# Split on pipe symbol, skipping escaped pipes '\|'
	my @data	= split( /(?<!\\)\|/, $row );
	my $html	= join( '', map { "<$tag>$_</$tag>" } @data );
	
	return "<tr>$html</tr>\n";
}

# Convert ASCII table to HTML
sub formatTable {
	my ( $table ) = @_;
	my $html	= '';
	
	# Lines = Rows
	my @rows	= split( /\n/, $table );
	
	# In header row, if true
	my $first	= 1;
	
	foreach my $row ( @rows ) {
		trim( \$row );
		
		# Skip empty rows or lines with just separator
		next if $row eq '' || $row =~ /^(\+|-)+$/;
		
		# First round is the header
		$html	.= formatRow( $row, $first );
		next unless $first;
		
		$first	= 0;
	}
	
	return "<table>$html</table>\n";
}

# Wrap body text and line breaks in paragraphs
sub makeParagraphs {
	my ( $html, $ns )	= @_;
	
	startProtectedTags( \$html, $ns );
	
	# Wrap paragraphs
	$html		=~ 
	s/(?<!__PROTECT__)\r?\n\s*\r?\n(?!__ENDPROTECT__)/<\/p><p>/g;
	
	$html		= 
	"<p>$html</p>" unless $html =~ /^<p>/ || $html =~ /__PROTECT__/;
	
	endProtectedTags( \$html );
	return $html;
}

# Simple subset of Markdown formatting with embedded media extraction
sub markdown {
	my ( $data ) = @_;
	
	state %patterns = (
		# Links, Images
		qr/(?<img>\!)?						# Image if present
			\[(?<text>[^\]]+)\]				# Main text
			(?:\(
				(?:\"(?<title>([^\"]|\\\")+)\")?	# Alt or title
				(?<dest>.*?)\)				# Destination URL
			)
		/ixs
		=> sub {
			my $text	= $+{text};
			my $dest	= $+{dest};
			my $img		= $+{img}	// '';
			my $title	= $+{title}	// '';
			
			# Image?
			if ( $img ne '' ) {
				if ( $title ne '' ) {
					return '<img src="' . $dest . 
						' title="' . $title . '">';
				}
				return '<img src="' . $dest . '">';
			}
			
			# Link with title?
			if ( $title ne '' ) {
				return 
				'<a href="'. $dest . '" title="' . 
					$title . '">' . $text . '</a>';
			}
			
			# Plain link
			return '<a href="'. $dest . '">' . $text . '</a>';
		},
		
		# Bold, Italic, Delete, Quote
		'(\*(\*+)?|\~\~|\:\")(.*?)\1'
		=> sub {
			for ( $1 ) {
				/\~/ and do { return '<del>' . $1 . '</del>'; };
				/\:/ and do { return '<q>' . $1 . '</q>'; };
			}
			
			my $i = strsize( $1 );
			for ( $i ) {
				( $i == 2 ) and do { return '<strong>' . $3 . '</strong>'; };
				( $i == 3 ) and do { return '<strong><em>' . $3 . '</em></strong>'; };
			}
			return '<em>' . $3 . '</em>';
		},
		
		# Headings
		'(^|\n)(?<delim>[#=]{1,6})\s?(?<text>.*?)\s?\2?\n?' 
		=> sub {
			my $level	= length( $+{delim} );	# Indent depth
			my $text	= $+{text};		# Heading
			
			trim( \$text );
			return "<h$level>$text</h$level>";
		},
		
		# Inline code
		'`(?<code>[^`]*)`' 
		=> sub {
			my $code = escapeCode( $+{code} );
			return "<code>$code</code>";
		},
		
		# Multi-line code
		'^|\n```(?<code>.*?)```'
		=> sub {
			my $code = escapeCode( $+{code} );
			return "<pre><code>$code</code></pre>";
		},
		
		# Tables
		'(\+[-\+]+[\+\-]+\s*\|\s*.+?\n(?:\+[-\+]+[\+\-]+\s*\|\s*.+?\n)*)'
		=> sub {
			return formatTable( $_[0] );
		},
		
		# Horizontal rule
		'\n(\-|_|\+){5,}\n'
		=> sub {
			return '<hr />';
		},
		
		# References, Media, Embeds etc...
		qr/
			\[
				(?<ref>[^\]\[\"\s]+)			# Reference or embed marker
				(?:\"(?<title>([^\"]|\\\")+)\")?	# Alt or title
				(?:\[(?<caption>.*?)\] )? 		# Caption(s), if present
				(?:\((?<preview>.*?)\) )?		# Preview image, if present
				(?<source>.*?)				# Source URL or note
			\]
		/ixs
		=> sub {
			my $ref		= $+{ref};
			my $source	= $+{source}	// '';
			
			my $title	= $+{title}	// '';
			my $caption	= $+{caption}	// '';
			my $preview	= $+{preview}	// '';
			
			chomp( $ref );
			for ( $ref ) {
				# TODO: Process footnotes
				/ref|footnote/ and do { 
					return 'footnote'; 
				};
				
				# Uploaded media embedding
				/audio|video|figure/ and do {
					return embeds( $ref, $source, $title, $caption, $preview );
				};
				
				# Third-party hosted media embedding
				/youtube|vimeo|archive|peertube|lbry|odysee|utreon|playeur/ and do {
					return hostedEmbeds( $ref, $source );
				};
			}
			
			return '';
		},
		
	);
	
	# Replace placeholders with formatted HTML
	foreach my $pat ( keys %patterns ) {
		my $subr	= $patterns{$pat};
		if ( $pat =~ /<\w+>/ ) {
			$data =~ s/$pat/sub { $subr->(%+) }/ge;
		} else {
			$data =~ s/$pat/sub { $subr->($&) }/ge;
		}
	}
	
	# Format lists
	$data = formatLists( $data );
	
	# Wrap paragraphs 
	return makeParagraphs( $data );
}

# Generate pagination link data
sub paginate {
	my ( $total, $idx, $show )	= @_;
	
	# Total number of pages
	$total		||= 1;
	
	# Current page index
	$idx		||= 1;
	
	# Maximum number of page links to show
	$show		||= 5;
	
	# Range of pages to show
	my $half	= int( $show / 2 );
	my $start_page	= $idx - $half;
	my $end_page	= $idx + $half;
	
	# List of page items
	my @links;
	
	# Limit display ranges
	if ( $start_page < 1 ) {
		$start_page	= 1;
		$end_page	= $show < $total ? $show : $total;
	}
	
	if ( $end_page > $total ) {
		$end_page = $total;
		if ( $total - $show + 1 > 0 ) {
			$start_page = $total - $show + 1;
		}
	}
	
	if( $idx > 1 ) {
		push( @links, { 
			text		=> '{page_first}', 
			page		=> 1,
			is_current	=> 0
		} );
		
		if ( $idx > 2 ) {
			push( @links, { 
				text		=> '{page_previous}', 
				page		=> $idx - 1,
				is_current	=> 0
			} );
		}
	}
	
	for my $i ( $start_page .. $end_page ) {
		push( @links, { 
			text		=> $i, 
			page		=> $i,
			is_current	=> $i == $idx
		} );
	}
	
	if ( $idx < $total ) {
		if ( $idx + 1 < $total ) {
			push( @links, { 
				text		=> '{page_next}', 
				page		=> $idx + 1,
				is_current	=> 0
			} );
		}
		
		push( @links, { 
			text		=> '{page_last}', 
			page		=> $total,
			is_current	=> 0
		} );
	}
	
	return @links;
}




# Site views ( Also exit after completing their tasks )

sub viewInstall {
	my ( $realm, $verb, $params ) = @_;
	
	safeView( $realm, $verb );
	print "TODO: Installation";
	exit;
}

# TODO: Main homepage
sub viewHome {
	my ( $realm, $verb, $params ) = @_;
	# Homepage template
	my $tpl = storage( "sites/$realm/index.html" );
	
	if ( ! -f $tpl ) {
		sendNotFound( $realm, $verb )
	}
	
	httpCode( '200' );
	if ( $verb eq 'head' ) {
		# Nothing else to send
		exit;
	}
	
	my $cval	= '<p>Cookie values (visible after first refresh): <br />';
	my %cookies	= getCookies();
	
	while ( my ( $k, $v ) = each %cookies ) {
		$cval .= "$k -> $v\<br />";
	}
	$cval		.= '</p>';
	
	my $stime = sessionGet( 'start' );
	if ( $stime eq '' ) {
		$stime = time();
		sessionWrite( 'start', $stime );
	}
	
	my %data = (
		title	=> 'Your Homepage',
		body	=> "<p>Home requested with {$verb} on {$realm}</p>" . 
			"<p>Your session started at {$stime}</p>" . 
			$cval
	);
	
	preamble();
	render( $tpl, \%data );
	exit;
}

# TODO: Content regions
sub viewArea {
	my ( $realm, $verb, $params ) = @_;
	
	my $label	= $params->{slug}	//= '';
	my $page	= $params->{page}	//= 1;
	
	$label		= pacify( $label );
	
	if ( $label eq '' ) {
		sendNotFound();
	}
	
	httpCode( '200' );
	if ( $verb eq 'head' ) {
		# Nothing else to send
		exit;
	}
	
	my %data = (
		title	=> $label,
		body	=> 
		"<p>Area requested <strong>$label</strong> with " . 
			"<strong>$verb</strong> on <em>$realm</em></p>" . 
			 "<p>Page $page</p>"
	);
	
	preamble();
	
	render( storage( "sites/$realm/index.html" ), \%data );
	exit;
}

# TODO: Tag sorted content
sub viewTags {
	my ( $realm, $verb, $params ) = @_;
	
	my $tags	= $params->{tags}	//= '';
	my $page	= $params->{page}	//= 1;
	
	$tags = pacify( $tags );
	
	if ( $tags eq '' ) {
		sendNotFound();
	}
	
	httpCode( '200' );
	if ( $verb eq 'head' ) {
		# Nothing else to send
		exit;
	}
	
	my %data = (
		title	=> $tags,
		body	=> 
		"<p>Tag(s) requested <strong>$tags</strong> with " . 
			"<strong>$verb</strong> on <em>$realm</em></p>" . 
			 "<p>Page $page</p>"
	);
	
	preamble();
	
	render( storage( "sites/$realm/index.html" ), \%data );
	exit;
}

# TODO: Blog path
sub viewPosts {
	my ( $realm, $verb, $params ) = @_;
	
	my $year	= $params->{year}	//= 0;
	my $month	= $params->{month}	//= 0;
	my $day		= $params->{day}	//= 0;
	
	my $slug	= $params->{slug}	//= '';
	my $page	= $params->{page}	//= 1;
	
	httpCode( '200' );
	if ( $verb eq 'head' ) {
		exit;
	}
	
	my %data = (
		title	=> 'Blog index',
		body	=> 
		"<p>Blog index with <strong>$verb</strong> on <em>$realm</em></p>" . 
			"<p>Path - Year: $year, Month: $month, Day: $day, Slug: $slug</p>" . 
			"<p>Page $page</p>"
	);
	
	preamble();
	
	render( storage( "sites/$realm/index.html" ), \%data );
	exit;	
}

# TODO: New post creation form
sub viewCreatePost {
	my ( $realm, $verb, $params ) = @_;
	
	my $tpl = storage( "sites/$realm/newpost.html" );
	
	if ( ! -f $tpl ) {
		sendNotFound( $realm, $verb );
	}
	
	my $year	= $params->{year}	//= 0;
	my $month	= $params->{month}	//= 0;
	my $day		= $params->{day}	//= 0;
	
	my $id		= $params->{id}		//= 0;
	
	safeView( $realm, $verb );
	
	my %data = (
		title		=> 'New post view',
		token		=> 'token',
		nonce		=> 'nonce',
		meta		=> 'meta',
		
		form_title	=> 'New post'
	);
	
	preamble();
	
	render( $tpl, \%data );
	exit;
}

# TODO: Post created
sub handleCreatePost {
	my ( $realm, $verb, $params ) = @_;
	httpCode( '200' );
	preamble();
	foreach my $key ( keys %$params ) {
		print "<p>$key: $params->{$key}</p>";
	}
}

# TODO: Edit existing post
sub viewEditPost {
	my ( $realm, $verb, $params ) = @_;
	
	my $year	= $params->{year}	//= 0;
	my $month	= $params->{month}	//= 0;
	my $day		= $params->{day}	//= 0;
	
	my $slug	= $params->{slug}	//= '';
	my $id		= $params->{id}		//= 0;
	
	safeView( $realm, $verb );
	
	my %data = (
		title		=> 'Edit existing post',
		token		=> 'token',
		nonce		=> 'nonce',
		meta		=> 'meta',
		
		form_title	=> 'Edit post'
	);
	
	preamble();
	
	render( storage( "sites/$realm/editpost.html" ), \%data );
	exit;
}

# TODO: Post edited
sub handleEditPost {
	my ( $realm, $verb, $params ) = @_;
	httpCode( '200' );
	preamble();
	foreach my $key ( keys %$params ) {
		print "<p>$key: $params->{$key}</p>";
	}
}


# TODO: List view
sub viewArchive {
	my ( $realm, $verb, $params ) = @_;
	
	my $page	= $params->{page}	//= 1;
	
	httpCode( '200' );
	if ( $verb eq 'head' ) {
		exit;
	}
	
	my %data = (
		title	=> 'Archive view',
		body	=> 
		"<p>Archive with {$verb} on {$realm}</p>" . 
			"<p>Page $page</p>"
	);
	
	preamble();
	
	render( storage( "sites/$realm/index.html" ), \%data );
	exit;
}

# TODO: Searching index
sub viewSearch {
	my ( $realm, $verb, $params ) = @_;
	
	my $all		= $params->{all}	//= '';
	my $page	= $params->{page}	//= 1;
	
	httpCode( '200' );
	if ( $verb eq 'head' ) {
		exit;
	}
	
	preamble();
	$all = utfDecode( $all );
	
	print "<p>Searching term {$all} with {$verb} on {$realm}</p>";
	print "<p>Page $page</p>";
	
	exit;
}

# TODO: New user register page
sub viewRegister {
	my ( $realm, $verb, $params ) = @_;
	
	my %data = (
		title		=> 'Register',
		token		=> 'token',
		nonce		=> 'nonce',
		meta		=> 'meta',
		
		form_title	=> 'Register'
	);
	
	safeView( $realm, $verb );
	
	render( storage( "sites/$realm/register.html" ), \%data );
	exit;
}

# TODO: Posted login data
sub handleRegister {
	my ( $realm, $verb, $params ) = @_;
	httpCode( '200' );
	preamble();
	foreach my $key ( keys %$params ) {
		print "<p>$key: $params->{$key}</p>";
	}
}

# TODO: Existing user login page
sub viewLogin {
	my ( $realm, $verb, $params ) = @_;
	
	my %data = (
		title		=> 'Login',
		token		=> 'token',
		nonce		=> 'nonce',
		meta		=> 'meta',
		
		form_title	=> 'Login'
	);
	
	safeView( $realm, $verb );
	
	render( storage( "sites/$realm/login.html" ), \%data );
	exit;
}

# TODO: Posted login data
sub handleLogin {
	my ( $realm, $verb, $params ) = @_;
	httpCode( '200' );
	preamble();
	foreach my $key ( keys %$params ) {
		print "<p>$key: $params->{$key}</p>";
	}
}

# TODO: Current user profile
sub viewProfile {
	my ( $realm, $verb, $params ) = @_;
	
	my %data = (
		title		=> 'Profile',
		token		=> 'token',
		nonce		=> 'nonce',
		meta		=> 'meta',
		
		form_title	=> 'Profile'
	);
	
	safeView( $realm, $verb );
	
	render( storage( "sites/$realm/profile.html" ), \%data );
	exit;
}

# TODO: Posted profile data
sub handleProfile {
	my ( $realm, $verb, $params ) = @_;
	httpCode( '200' );
	preamble();
	foreach my $key ( keys %$params ) {
		print "<p>$key: $params->{$key}</p>";
	}
}

# TODO: Password changing form
sub viewChangePass {
	my ( $realm, $verb, $params ) = @_;
	
	my %data = (
		title		=> 'Change Password',
		token		=> 'token',
		nonce		=> 'nonce',
		meta		=> 'meta',
		
		form_title	=> 'Password'
	);
	
	safeView( $realm, $verb );
	
	#render( storage( "sites/$realm/password.html" ), \%data );
	exit;
}

# TODO: Posted password data
sub handleChangePass {
	my ( $realm, $verb, $params ) = @_;
	httpCode( '200' );
	preamble();
	foreach my $key ( keys %$params ) {
		print "<p>$key: $params->{$key}</p>";
	}
}

# Startup
sub begin() {
	my %request	= getRequest();
	my $verb 	= $request{'verb'};
	
	my $realm	= $request{'realm'};
	
	# Begin router
	if ( exists ( $path_map{$verb} ) ) {
		foreach my $path ( @{$path_map{$verb}} ) {
		
			# Cleaned route path
			chomp( my $route = $path->{path} );
			$route = '^/' . $route . '/?$';
			
			# Replace URL routing placeholders
			$route =~ s/$_/$markers{$_}/g for keys %markers;
			
			my $url = $request{'url'};
			if ( $url =~ $route ) {
				my %params = ();
				if ( $url =~ $route ) {
					%params = %+;
				}
				
				$path->{handler}->( $realm, $verb, \%params );
				exit;
			}
		}
		
		# Nothing matched
		sendNotFound( $realm, $verb );
	}
	
	# Unkown request method
	sendOptions( 1 );
}


begin();

__DATA__


Configuration and lists:
The following is a set of settings used by PerlSketch to serve content.

MIME Data consists of a file extension, a MIME type (to send to the browser),
and a set of file signatures or "magic numbers", which are the first few bytes 
of a file which give an indication of what type of file this is. This method is 
used as a quick way to detect file types without having to reading the entire 
file.

Files without signatures are treated as text types. E.G. css, js, html etc...

More file types may be added to this list.

Convention: 
File extension	MIME type	Byte signature(s) delimited by spaces

-- MIME data:
css	text/css
js	text/javascript 
txt	text/plain
html	text/html
vtt	text/vtt
csv	text/csv
svg	image/svg+xml

ico	image/vnd.microsoft.icon	\x00\x00\x01\x00
jpg	image/jpeg			\xFF\xD8\xFF\xE0  \xFF\xD8\xFF\xE1  \xFF\xD8\xFF\xEE  \xFF\xD8\xFF\xDB
jpeg	image/jepg			\xFF\xD8\xFF\xE0  \xFF\xD8\xFF\xEE
gif	image/gif			\x47\x49\x46\x38\x37\x61  \x47\x49\x46\x38\x39\x61
bmp	image/bmp			\x42\x4D
png	image/png			\x89\x50\x4E\x47\x0D\x0A\x1A\x0A
tif	image/tiff			\x49\x49\x2A\x00  \x4D\x4D\x00\x2A
tiff	image/tiff			\x49\x49\x2A\x00  \x4D\x4D\x00\x2A
webp	image/webp			\x52\x49\x46\x46  \x57\x45\x42\x50

ttf	font/ttf			\x00\x01\x00\x00\x00
otf	font/otf			\x4F\x54\x54\x4F
woff	font/woff			\x77\x4F\x46\x46
woff2	font/woff2			\x77\x4F\x46\x32

oga	audio/oga			\x4F\x67\x67\x53
mpa	audio/mpa			\xFF\xE  \xFF\xF
mp3	audio/mp3			\xFF\xFB  \xFF\xF3  \xFF\xF2  \x49\x44\x33
m4a	audio/m4a			\x00\x00\x00\x18\x66\x74\x79\x70\x4D
wav	audio/wav			\x52\x49\x46\x46  \x57\x41\x56\x45
wma	audio/x-ms-wma			\x30\x26\xB2\x75\x8E\x66\xCF\x11  \xA6\xD9\x00\xAA\x00\x62\xCE\x6C
flac	audio/flac			\x66\x4C\x61\x43\x00\x00\x00\x22
weba	audio/webm			\x1A\x45\xDF\xA3

avi	video/x-msvideo			\x52\x49\x46\x46  \x41\x56\x49\x20
mp4	video/mp4			\x00\x00\x00\x18\x66\x74\x79\x70\x4D
mpeg	video/mpeg			\xFF\xE  \xFF\xF
mkv	video/x-matroska		\x1A\x45\xDF\xA3
mov	video/quicktime			\x00\x00\x00\x14\x66\x74\x79\x70\x4D
ogg	video/ogg			\x4F\x67\x67\x53
ogv	video/ogg			\x4F\x67\x67\x53
webm	video/webm			\x1A\x45\xDF\xA3
wmv	video/x-ms-asf			\x30\x26\xB2\x75\x8E\x66\xCF\x11  \xA6\xD9\x00\xAA\x00\x62\xCE\x6C

doc	application/msword		\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1
docx	application/vnd.openxmlformats-officedocument.wordprocessingml.document		\x50\x4B\x03\x04
ppt	application/vnd.ms-powerpoint	\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1
pptx	application/vnd.openxmlformats-officedocument.presentationml.presentation	\x50\x4B\x03\x04  \x50\x4B\x07\x08
odt	application/vnd.oasis.opendocument.text		\x50\x4B\x03\x04
odp	application/vnd.oasis.opendocument.presentation	\x50\x4B\x03\x04
ods	application/vnd.oasis.opendocument.spreadsheet	\x50\x4B\x03\x04
ott	application/vnd.oasis.opendocument.text-template	\x50\x4B\x03\x04

pdf	application/pdf			\x25\x50\x44\x46\x2D
epub	application/epub+zip		\x50\x4B\x03\x04  \x50\x4B\x05\x06

zip	pplication/zip			\x50\x4B\x03\x04  \x50\x4B\x05\x06
7z	application/x-7z-compressed	\x37\x7A\xBC\xAF\x27\x1C
gz	application/gzip		\x1F\x8B
rar	application/vnd.rar		\x52\x61\x72\x21\x1A\x07
tar	application/x-tar		\x75\x73\x74\x61\x72\x00\x30\x30  \x75\x73\x74\x61\x72\x20\x20\x00
-- End mime data



The following are a set of HTTP response codes sent to the user before any 
other headers, including the preamble and content types. This response is 
required for the script to function correctly when serving web pages.

The most common type should be 200 OK to indicate the request has succeeded.
Next likely is 404 Not Found to indicate a particular resource hasn't been 
located at the address used by the visitor.

Some responses have been omitted as they should be handled at the web server 
level instead of at the Perl script, and/or they're unsuitable to implement 
here.

Convention: 
Numeric code	Text message

-- HTTP response codes:
200	OK
201	Created
202	Accepted

204	No Content
205	Reset Content
206	Partial Content

300	Multiple Choices
301	Moved Permanently
302	Found
303	See Other
304	Not Modified

400	Bad Request
401	Unauthorized

403	Denied
404	Not Found
405	Method Not Allowed
406	Not Acceptable
407	Proxy Authentication Required

409	Conflict
410	Gone
411	Length Required
412	Precondition Failed
413	Payload Too Large
414	Request-URI Too Long
415	Unsupported Media Type
416	Range Not Satisfiable

422	Unprocessable Entity

425	Too Early

429	Too Many Requests

431	Request Header Fields Too Large

500	Internal Server Error
501	Not Implemented
-- End response codes 



Site databases section.

These table schema don't use any special functionality unique to SQLite and can 
be adapted to other databse types if neeed, however the data methods would need 
to be updated to reflect the new database type(s).

The following is the session storage database as a SQLite schema. The main 
sessions table is the only table in the sessions.db database.


-- Database: sessions.db --

-- Visitor/User sessions
CREATE TABLE sessions(
	id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
	session_id TEXT DEFAULT NULL COLLATE NOCASE,
	session_ip TEXT DEFAULT NULL COLLATE NOCASE,
	session_data TEXT DEFAULT NULL COLLATE NOCASE,
	created TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
	updated TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);-- --
CREATE UNIQUE INDEX idx_session_id ON sessions( session_id )
	WHERE session_id IS NOT NULL;-- --
CREATE INDEX idx_session_ip ON sessions( session_ip ) 
	WHERE session_ip IS NOT NULL;-- --
CREATE INDEX idx_session_created ON sessions( created DESC );-- --
CREATE INDEX idx_session_updated ON sessions( updated DESC );-- --

CREATE TRIGGER session_update AFTER UPDATE ON sessions
BEGIN
	UPDATE sessions SET updated = CURRENT_TIMESTAMP 
		WHERE id = NEW.id;
END;

-- End database --



The following is the main content database, including the user credential 
tables. The schema is designed to handle multiple regions or "realms", which 
include the domain name and relative path. Multiple websites can be created, 
each with its own unique domain name or relative path.
E.G. example.com or example.com/second-site



-- Database: perlsketch.db --

-- Content areas
CREATE TABLE realms (
	id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
	basename TEXT NOT NULL COLLATE NOCASE,
	basepath TEXT NOT NULL DEFAULT '/'
);-- --
CREATE UNIQUE INDEX idx_realm_base ON realms ( basename, basepath );
CREATE INDEX idex_realm_name ON realms ( basename );
CREATE INDEX idx_realm_path ON realms ( basepath );


-- User access accounts
CREATE TABLE IF NOT EXISTS users (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	username TEXT NOT NULL COLLATE NOCASE,
	password TEXT NOT NULL,
	email TEXT NOT NULL COLLATE NOCASE,
	display TEXT DEFAULT NULL COLLATE NOCASE,
	bio TEXT DEFAULT NULL COLLATE NOCASE
);-- --
CREATE UNIQUE INDEX idx_user_username ON users ( username );-- --
CREATE UNIQUE INDEX idx_user_email ON users ( email );-- --

-- Access metadata
CREATE TABLE user_meta (
	user_id INTEGER NOT NULL,
	
	-- Activity
	last_ip TEXT DEFAULT NULL COLLATE NOCASE,
	last_ua TEXT DEFAULT NULL COLLATE NOCASE,
	last_active DATETIME DEFAULT NULL,
	last_login DATETIME DEFAULT NULL,
	last_pass_change DATETIME DEFAULT NULL,
	
	-- Auth status,
	is_approved INTEGER NOT NULL DEFAULT 0,
	is_locked INTEGER NOT NULL DEFAULT 0,
	
	created DATETIME DEFAULT CURRENT_TIMESTAMP,
	updated DATETIME DEFAULT CURRENT_TIMESTAMP,
	status INTEGER NOT NULL DEFAULT 0,
	
	CONSTRAINT fk_meta_user 
		FOREIGN KEY ( user_id ) 
		REFERENCES users ( id )
		ON DELETE CASCADE
);-- --
CREATE UNIQUE INDEX idx_user_meta ON user_meta ( user_id );-- --
CREATE INDEX idx_user_created ON user_meta ( created );
CREATE INDEX idx_user_updated ON user_meta ( updated );
CREATE INDEX idx_user_ip ON user_meta( last_ip )
	WHERE last_ip IS NOT NULL;-- --
CREATE INDEX idx_user_ua ON user_meta( last_ua )
	WHERE last_ua IS NOT NULL;-- --
CREATE INDEX idx_user_active ON user_meta( last_active )
	WHERE last_active IS NOT NULL;-- --
CREATE INDEX idx_user_login ON user_meta( last_login )
	WHERE last_login IS NOT NULL;-- --
CREATE INDEX idx_user_pass_change ON user_meta( last_pass_change )
	WHERE last_pass_change IS NOT NULL;-- --
CREATE INDEX idx_user_status ON user_meta ( status );

CREATE TRIGGER user_insert AFTER INSERT ON users FOR EACH ROW 
BEGIN
	INSERT INTO user_meta( user_id ) VALUES ( NEW.id );
END;-- --

CREATE TRIGGER user_update AFTER UPDATE ON users FOR EACH ROW 
BEGIN
	UPDATE user_meta SET updated = CURRENT_TIMESTAMP 
		WHERE user_id = NEW.id;
END;-- --

-- Cookie-based logins
CREATE TABLE logins(
	user_id INTEGER NOT NULL,
	lookup TEXT NOT NULL COLLATE NOCASE,
	updated DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	hash TEXT DEFAULT NULL COLLATE NOCASE,
	
	CONSTRAINT fk_login_user 
		FOREIGN KEY ( user_id ) 
		REFERENCES users ( id )
		ON DELETE CASCADE
);-- --
CREATE UNIQUE INDEX idx_login_user ON logins ( user_id );-- --
CREATE UNIQUE INDEX idx_login_lookup ON logins ( lookup );-- --
CREATE INDEX idx_login_updated ON logins ( updated );-- --
CREATE INDEX idx_login_hash ON logins ( hash )
	WHERE hash IS NOT NULL;-- --

CREATE TABLE roles (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	label TEXT NOT NULL COLLATE NOCASE
);-- --
CREATE UNIQUE INDEX idx_role_label ON roles ( label );-- --

-- Privileges and permissions
CREATE TABLE authority (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	settings TEXT NOT NULL DEFAULT '{}' COLLATE NOCASE
);-- --

CREATE TABLE role_authority (
	role_id INTEGER NOT NULL REFERENCES roles( id )
		ON DELETE CASCADE,
	auth_id INTEGER NOT NULL REFERENCES authority( id ) 
		ON DELETE CASCADE,
	
	PRIMARY KEY ( role_id, auth_id )
);-- --

CREATE TABLE user_roles (
	role_id INTEGER NOT NULL REFERENCES roles( id )
		ON DELETE CASCADE,
	user_id INTEGER NOT NULL REFERENCES users( id )
		ON DELETE CASCADE,
	
	PRIMARY KEY ( role_id, user_id )
);-- --

CREATE VIEW login_view AS SELECT 
	lg.user_id AS id, 
	lg.lookup AS lookup,
	lg.updated AS updated, 
	lg.hash AS hash, 
	
	u.username AS username, 
	
	um.status AS status, 
	um.created AS created,
	um.is_approved AS is_approved,
	um.is_locked AS is_locked
	
	FROM logins lg 
	LEFT JOIN users u ON lg.user_id = u.id 
	LEFT JOIN user_meta um ON u.id = um.user_id;-- --


CREATE TABLE post_types(
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	label TEXT DEFAULT NULL COLLATE NOCASE,
	status INTEGER NOT NULL DEFAULT 0
);-- --
CREATE UNIQUE INDEX idx_ptype_label ON post_types ( label );
CREATE INDEX idx_ptype_status ON post_types ( status );-- --



-- Site content
CREATE TABLE posts (
	id INTEGER PRIMARY KEY,
	
	-- NULL for categories, parent ID for others
	parent_id INTEGER DEFAULT NULL 
		REFERENCES posts( id ) ON DELETE SET NULL,
	title TEXT DEFAULT NULL COLLATE NOCASE,
	content TEXT NOT NULL COLLATE NOCASE,
	summary TEXT DEFAULT NULL COLLATE NOCASE,
	
	 -- 'board', 'post', 'comment' etc...
	post_type TEXT NOT NULL COLLATE NOCASE,
	anon NOT NULL DEFAULT 0,
	user_id INTEGER DEFAULT NULL,
	
	CONSTRAINT fk_post_user 
		FOREIGN KEY ( user_id ) 
		REFERENCES users( id )
		ON DELETE SET NULL
);-- --
CREATE INDEX idx_post_parent ON posts ( parent_id )
	WHERE parent_id IS NOT NULL;-- --
CREATE INDEX idx_post_user ON posts ( user_id )
	WHERE user_id IS NOT NULL;-- --
CREATE INDEX idx_post_type ON posts ( post_type );-- --

CREATE TABLE post_meta (
	post_id INTEGER NOT NULL UNIQUE, 
	
	-- Breadcrumb path, excluding realm
	crumbs TEXT DEFAULT NULL,
	
	child_count INTEGER DEFAULT 0,
	flag_count INTEGER NOT NULL DEFAULT 0,
	
	last_user_id INTEGER DEFAULT NULL,
	last_created DATETIME DEFAULT NULL,
	
	created DATETIME DEFAULT CURRENT_TIMESTAMP,
	updated DATETIME DEFAULT CURRENT_TIMESTAMP,
	sort_order INTEGER NOT NULL DEFAULT 0,
	status INTEGER NOT NULL DEFAULT 0,
	
	CONSTRAINT fk_post_meta 
		FOREIGN KEY ( post_id ) 
		REFERENCES posts( id )
		ON DELETE CASCADE
);-- --
CREATE INDEX idx_post_meta ON post_meta ( post_id );-- --
CREATE INDEX idx_post_created ON post_meta ( created );-- --
CREATE INDEX idx_post_updated ON post_meta ( updated );-- --
CREATE INDEX idx_post_last_user ON post_meta ( last_user_id )
	WHERE last_user_id IS NOT NULL;-- --
CREATE INDEX idx_post_last_created ON post_meta ( last_created )
	WHERE last_created IS NOT NULL;-- --
CREATE INDEX idx_post_sort ON post_meta ( sort_order );-- --

CREATE TRIGGER post_insert AFTER INSERT ON posts FOR EACH ROW 
BEGIN
	INSERT INTO post_meta ( post_id ) VALUES ( NEW.id );
END;-- --

CREATE TRIGGER post_update AFTER UPDATE ON posts FOR EACH ROW 
BEGIN
	UPDATE post_meta SET updated = CURRENT_TIMESTAMP 
		WHERE rowid = NEW.rowid;
END;-- --

-- Searching
CREATE VIRTUAL TABLE post_search 
	USING fts4( body, tokenize=unicode61 );-- --


-- Content realms
CREATE TABLE post_realms (
	post_id INTEGER NOT NULL REFERENCES posts( id )
		ON DELETE CASCADE,
	realm_id INTEGER NOT NULL REFERENCES realms( id )
		ON DELETE RESTRICT,
	
	PRIMARY KEY ( post_id, realm_id )
);-- --


-- PMs/Direct messages etc...
CREATE TABLE mentions(
	post_id INTEGER NOT NULL REFERENCES posts( id )
		ON DELETE CASCADE,
	user_id INTEGER NOT NULL REFERENCES users( id )
		ON DELETE CASCADE,
	
	PRIMARY KEY ( post_id, user_id )
);-- --



CREATE TABLE tags(
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	term TEXT NOT NULL UNIQUE COLLATE NOCASE,
	slug TEXT NOT NULL UNIQUE COLLATE NOCASE
);-- --

CREATE TABLE post_tags(
	tag_id INTEGER NOT NULL REFERENCES tags( id )
		ON DELETE CASCADE,
	user_id INTEGER NOT NULL REFERENCES users( id )
		ON DELETE CASCADE,
	
	PRIMARY KEY ( tag_id, user_id )
);-- --

-- Moderation queue
CREATE TABLE flags(
	user_id INTEGER NOT NULL,
	post_id INTEGER DEFAULT NULL,
	content TEXT DEFAULT NULL,
	
	CONSTRAINT fk_flag_user 
		FOREIGN KEY ( user_id ) 
		REFERENCES users ( id )
		ON DELETE CASCADE,
	
	CONSTRAINT fk_flag_post
		FOREIGN KEY ( post_id ) 
		REFERENCES posts ( id )
		ON DELETE CASCADE
);-- --

CREATE TRIGGER flag_insert AFTER INSERT ON flags FOR EACH ROW 
BEGIN 
	UPDATE post_meta SET flag_count = ( flag_count + 1 ) 
		WHERE post_id = NEW.post_id;
END;-- --

CREATE TRIGGER flag_delete BEFORE DELETE ON flags FOR EACH ROW
BEGIN
	UPDATE post_meta SET flag_count = ( flag_count - 1 ) 
		WHERE post_id = OLD.post_id;
END;-- --

-- End database --




The following are a set of reusable HTML templates for rendering content. 
The convention for template is "tpl_label:" followed by "end_tpl", without 
quotes, where "label" is the unique identifier. Add and extend as needed.


Basic page:

tpl_page:
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>{title}</title>
<link rel="stylesheet" href="/style.css">
</head>
<body>{body}</body>
</html>
end_tpl



The following are mbedded media templates for use with uploaded files.

Embedded video with preview:

tpl_audio_embed:
<div class="media"><audio src="{src}" preload="none" controls></audio></div>
end_tpl


Embedded video without preview:

tpl_video_np_embed:
<div class="media">
	<video width="560" height="315" src="{src}" preload="none" 
		controls>{detail}</video>
</div>
end_tpl


Embedded video with preview:

tpl_video_embed:
<div class="media">
	<video width="560" height="315" src="{src}" preload="none" 
		poster="{preview}" controls>{detail}</video>
</div>
end_tpl


Video caption track without language:

tpl_cc_nl_embed:
<track kind="subtitles" src="{src}" {default}>
end_tpl


Video caption with language
tpl_cc_embed:
<track label="{label}" kind="subtitles" srclang="{lang}" src="{src}" {default}>
end_tpl



The following are third-party hosted media templates



YouTube video wrapper:

tpl_youtube:
<div class="media">
	<iframe width="560" height="315" frameborder="0" 
		sandbox="allow-same-origin allow-scripts" 
		src="https://www.youtube.com/embed/{src}?start={time}" 
		allow="encrypted-media;picture-in-picture" 
		loading="lazy" allowfullscreen></iframe>
</div>
end_tpl


Vimeo video wrapper:

tpl_vimeo:
<div class="media">
	<iframe width="560" height="315" frameborder="0" 
		sandbox="allow-same-origin allow-scripts" 
		src="https://player.vimeo.com/video/{src}" 
		allow="picture-in-picture" loading="lazy" 
		allowfullscreen></iframe>
</div>
end_tpl


Peertube video wrapper (any instance):

tpl_peertube:
<div class="media">
	<iframe width="560" height="315" frameborder="0" 
		sandbox="allow-same-origin allow-scripts" 
		src="https://{src_host}/videos/embed/{src}" 
		allow="picture-in-picture" loading="lazy" 
		allowfullscreen></iframe>
</div>
end_tpl


Internet Archive media wrapper:

tpl_archiveorg:
<div class="media">
	<iframe width="560" height="315" frameborder="0" 
		sandbox="allow-same-origin allow-scripts" 
		src="https://archive.org/embed/{src}" 
		allow="picture-in-picture" loading="lazy" 
		allowfullscreen></iframe></div>
end_tpl


LBRY/Odysee video wrapper:

tpl_lbry:
<div class="media">
	<iframe width="560" height="315" frameborder="0" 
		sandbox="allow-same-origin allow-scripts" 
		src="https://{src_host}/$/embed/{slug}/{src}" 
		allow="picture-in-picture" loading="lazy" 
		allowfullscreen></iframe>
</div>
end_tpl


Playeur/Utreon video wrapper:
tpl_playeur:
<div class="media">
	<iframe width="560" height="315" frameborder="0" 
		sandbox="allow-same-origin allow-scripts" 
		allow="encrypted-media;picture-in-picture"
		src="https://playeur.com/embed/{src}?t={time}" 
		loading="lazy" allowfullscreen></iframe>
</div>
end_tpl




__END__

BSD 2-Clause License

Copyright (c) 2024, Rustic Cyberpunk

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


