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
use File::Temp qw( tempfile tempdir );
use Encode;
use Digest::SHA qw( sha1_hex sha1_base64 sha384_hex sha384_base64 sha512_hex );
use Fcntl qw( SEEK_SET );
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
	
	# Maximum number of posts per page
	POST_LIMIT		=> 10,

	# File stream buffer size
	BUFFER_SIZE		=> 10240,
	
	# Password hashing rounds
	HASH_ROUNDS		=> 1000,
	
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

# Client request
our %request	= (
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



# Basic filtering



# Usable text content
sub pacify {
	my ( $term ) = @_;
	
	# Remove unprintable/invalid characters
	$term	=~ s/[^[:print:]]//g;
	$term	=~ s/[\x{fdd0}-\x{fdef}]//g;
	$term	=~ s/[\p{Cs}\p{Cf}\p{Cn}]//g;
	
	chomp( $term );
	return $term;
}

# Convert all spaces to single character
sub unifySpaces {
	my ( $text, $rpl, $br ) = @_;
 	
 	$text	= pacify( $text );
  	
  	# Preserve line breaks?
  	$br	//= 0;
   	
   	# Replacement space, defaults to ' '
 	$rpl	//= ' ';
  	
  	if ( $br ) {
		$text	=~ s/[ \t\v\f]+/$rpl/;
 	} else {
  		$text	=~ s/[[:space:]]+/$rpl/;
  	}
  	
 	chomp( $text );
 	return $text;
}

# Decode URL encoded strings
sub utfDecode {
	my ( $term ) = @_;
	if ( $term eq '' ) {
		return '';
	}
	
	$term	= pacify( $term );
	$term	=~ s/\.{2,}/\./g;
	$term	=~ s/\+/ /;
	$term	=~ s/\%([\w]{2})/chr(hex($1))/ge;
	$term	= Encode::decode_utf8( $term );
	
	chomp( $term );
	return $term;
}

# Length of given string
sub strsize {
	my ( $str ) = @_;
	
	$str = pacify( $str );
	return length( Encode::encode( 'UTF-8', $str ) );
}

# Text starts with
sub textStartsWith {
	my ( $text, $needle ) = @_;
	my $nl	= length( $needle );
	my $tl	= length( $text );
	
	if ( !$nl || !$tl ) {
		return 0;
	}
	
	if ( $nl > $tl ) {
		return 0;
	}
	
	return substr( $text, 0, $nl ) eq $needle;
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

# Relative storage directory
sub storage {
	my ( $path ) = @_;
	
	# Remove leading spaces and trailing slashes, if any
	( my $dir = STORAGE_DIR ) =~ s/^[\s]+|[\s\/]+$//g;
	
	# Remove leading slashes and spaces, if any
	$path	=~ s/^[\s\/]+//g;
	
	# Double dots
	$path	=~ s/\.{2,}/\./g;
	
	return pacify( "$dir/$path" );
}

# File lock/unlock helper
sub fileLock {
	my ( $fname, $ltype ) = @_;
	my $fl		= "$fname.lock___";
	
	# Default to removing lock
	$ltype		//= 0;
	
	# Remove lock
	if ( $ltype eq 0 ) {
		# No lock
		if ( ! -f $fl ) {
			return 1;
		}
		unlink $fl;
		return 1;
	}
	
	my $tries	= LOCK_TRIES;
	while ( not sysopen ( $fl, $fname, O_WRONLY | O_EXCL | O_CREAT ) ) {
		if ( $tries == 0 ) {
			return 0;
		}
		
		$tries--;
		sleep 0.1;
	}
	
	return 1;
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
	state $data = '';
	if ( length ( $data ) ) {
		return $data;
	}
	
	my @raw;
	while ( my $line = <DATA> ) {
		push ( @raw, $line );
	}
	
	$data = join( '', @raw );
	return $data;
}

# Get allowed file extensions, content types, and file signatures ("magic numbers")
sub mimeList { 
	state %mime_list = ();
	if ( keys %mime_list ) {
		return %mime_list;
	}
	
	my $data = getRawData();
	
	# Mime data block
	while ( $data =~ /^(?<mime>--\s*MIME\s*data:\s*\n.*?\n--\s*End\s*mime\s*?data\s*)/msgi ) {
		my $find = $+{mime};
		chomp( $find );
		
		# Extension, type, and file signature(s)
		while ( $find =~ /^(?<ext>\S+)\s+(?<type>\S+)\s+(?<sig>.*?)\s*$/mg ) {
			my ( $ext, $type, $sig ) = ( $+{ext}, $+{type}, $+{sig} );
			if ( ! defined( $type ) ) {
				$type = 'application/octet-stream';
			}
			if ( ! defined( $sig ) ) {
				$sig = '';
			}
			my @sig = split( /\s+/, $sig );
			$mime_list{$ext} = { type => $type, sig => \@sig };
		}
	}
	
	return %mime_list;
}

# Timestamp helper
sub dateRfc {
	my ( $stamp ) = @_;
 	my $t = Time::Piece->strptime( $stamp, '%s' );
 	return $t->strftime();
}

# Limit the date given to a maximum value of today
sub verifyDate {
	my ( $stamp ) = @_;
	
	# Split stamp to components
	my ( $year, $month, $day ) 
	 	 	= $stamp =~ m{^(\d{4})/(\d{2})/(\d{2})$};
	
	$year	//= 0;
	$month	//= 0;
	$day	//= 0;
	
	# Day range
	if ( $day < 1 || $day > 31 ) {
		return 0;
	}
	
	# Month range
	if ( $month < 1 || $month > 12 ) {
		return 0;
	}
	
	# Year minimum
	if ( $year < 1900 ) {
		return 0;
	}
	
	# Prevent exceeding current date
	
	# Current date
 	my $now 	= localtime->strftime('%Y-%m-%d');
	my ( $year_, $month_, $day_ ) 
			= $now =~ m{^(\d{4})-(\d{2})-(\d{2})$};
	
	# Given year greater than current year?
	if ( $year > $year_ ) {
		return 0;
	
	# This year given?
	} elsif ( $year == $year_ ) {
		
		# Greater than current month?
		if ( $month > $month_ ) {
			return 0;
			
		# Greater than current day?
		} elsif ( $month == $month_ && $day > $day_ ) {
			return 0;
		}
	}
	
	# Leap year?
	my $is_leap = (
		( $year % 4 == 0 && $year % 100 != 0 ) || 
		( $year % 400 == 0 ) 
	) ? 1 : 0;
	
	# Days in February, adjusting for leap years
	my @dm 	 	= ( 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 );
	if ( $month == 2 && $is_leap ) {
		$dm[1]	= 29 
	}
	
	# Maximum day for given month
	my $m_day	= $dm[$month - 1];
	
  	if ( $day > $m_day ) {
		return 0;
	}
	
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
 	
  	$realm	//= $request{'realm'};
 	$root	//= '/';
	
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

# Sent binary data
sub formData {
	state %data	= ();
	
	if ( keys %data ) {
		return %data;
	}
	
	my %request_headers	= requestHeaders();
	my $ctype		= $request_headers{'content_type'} // '';
	
 	# Check multipart boundary
	my $boundary;
	if ( $ctype =~ /boundary=(.+)$/ ) {
		$boundary = $1;
	} else {
		return %data;
	}
	
	my %fields	= ();
	my @uploads	= [];
	
	my $pattern		= 
	qr/
		form-data;\s?					# Marker
		name="([^"]+)"(?:;\s?filename="([^"]+)")?	# Labeled names
	/ix;
	
	my $sent	= do { local $/; <STDIN> };
	my @segs	= split( /--\Q$boundary\E/, $sent );
	
	shift @segs;
	pop @segs;
	
	foreach my $part ( @segs ) {
		# Break by new lines
		my ( $headers, $content ) = split( /\r?\n\r?\n/, $part, 2 );
		
		# Parse headers
		my %parts;
		foreach my $line ( split( /\r?\n/, $headers ) ) {
			my ( $key, $value ) = split( /:\s*/, $line, 2 );
			$parts{lc( $key )} = $value;
		}
		
		if ( $parts{'content-disposition'} =~ /$pattern/ ) {
			my $name	= $1;
			my $fname	= $2;
			my $ptype	= 
				$parts{'content-type'} // 
				'application/octet-stream';
			
			# Intercept upload
			if ( defined $fname ) {
				my ( $tfh, $tname ) = tempfile();
				print $tfh $content;
				close $tfh;
				
				push( @uploads, {
					name		=> $name,
					filename	=> $fname,
					path		=> $tname,
					content_type	=> $ptype
				} );
				
				next;
			}
			
			$fields{$name} = $content;
		}
	}
	
	$data{'fields'} = %fields;
	$data{'files'}	= @uploads;
	
	return %data;
}
# Current host or server name/domain/ip address
sub siteRealm {
	my $realm = lc( $ENV{SERVER_NAME} // '' ) =~ s/[^a-zA-Z0-9\.]//gr;
	
	# Check for reqested realm, if it exists, and end early if invalid
	my $dir = storage( "sites/$realm" );
	
	if ( $realm eq '' || ! -d $dir ) {
		sendBadRequest();
	}
	
	return $realm;
}

# Get requested file range, return range error if range was invalid
sub requestRanges {
	my $fr = $ENV{HTTP_RANGE} //= '';
	if ( !$fr ) {
		return ();
	}
	
	# Range is too long
	if ( length( $fr ) > 100 ) {
		sendRangeError();
	}
	
	my @ranges;
	
	# Check range header
	my $pattern	= qr/
		bytes\s*=\s*				# Byte range heading
		(?<ranges>(?:\d+-\d+(?:,\s*\d+-\d+)*))	# Comma delimeted ranges
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
					defined $end	&& 
					$end >= $cs 
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
	return @ranges;
}

# Guess if current request is secure
sub isSecure {
	# Request protocol scheme HTTP/HTTPS etc..
	my $scheme	= lc( $ENV{REQUEST_SCHEME} // 'http' );
	
	# Forwarded protocol, if set
	my $frd		= 
		$ENV{HTTP_X_FORWARDED_PROTO}	//
		$ENV{HTTP_X_FORWARDED_PROTOCOL}	//
		$ENV{HTTP_X_URL_SCHEME}		// 'http';
	
	return ( $scheme eq 'https' || $frd  =~ /https/i ) ? 1 : 0;
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
			if ( ! defined $ld || $ld == 0 ) {
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
		if ( ! keys %dbh ) {
			return;
		}
		
		# Close every open connection
		foreach my $key ( keys %dbh ) {
			$dbh{$key}->disconnect();
		}
		%dbh = ();
		return;
	}
	
	
	# Database connection string format
	$db	= pacify( $db );
	$db	=~ s/\.{2,}/\./g;
	
	chomp( $db );
	
	if ( exists( $dbh{$db} ) ) {
		return $dbh{$db};
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
	} ) or exit 1;
	
	# Preemptive defense
	$dbh{$db}->do( 'PRAGMA quick_check;' );
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
		my $schema = databaseSchema( $db );
		if ( $schema ne '' ) {
			my @sql = split( /-- --/, $schema );
			for my $stmt ( @sql ) {
				$dbh{$db}->do( $stmt );
			}
		} else {
			httpCode( 500 );
			print "Database error";
			exit;
		}
		
		# Instalation check
		$dbh{$db}->do( 'PRAGMA integrity_check;' );
		$dbh{$db}->do( 'PRAGMA foreign_key_check;' );
	}
	
	$dbh{$db}->do( 'PRAGMA journal_mode = WAL;' );
	$dbh{$db}->do( 'PRAGMA foreign_keys = ON;' );
	
	return $dbh{$db};
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
	
	if ( keys %sent ) {
		return %sent;
	}
	
	my @items	= split( /;/, $ENV{'HTTP_COOKIE'} //= '' );
	foreach ( @items ) {
		my ( $k, $v )	= split( /=/, $_ );
		
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
	return 
	( COOKIE_PATH eq '/' && $request{'secure'} ) ? 
		'__Host-' : ( $request{'secure'} ? '__Secure-' : '' );
}

# Set a cookie with default parameters
sub setCookie {
	my ( $name, $value, $ttl ) = @_;
	my $prefix	= cookiePrefix();
	
	$ttl	//= COOKIE_EXP;
	$ttl	= ( $ttl > 0 ) ? $ttl : ( ( $ttl == -1 ) ? 1 : 0 );
	
	my @values	= ( 
		$prefix . "$name=$value",
		'Path=' . COOKIE_PATH,
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

sub deleteCookie {
	my ( $name ) = @_;
	setCookie( $name, "", -1 );
}




# Session management




# Generate or return session ID
sub sessionID {
	my ( $sent ) = @_;
	state $id = '';
	
	$sent //= '';
	if ( $sent ne '' ) {
		$id = ( $sent =~ /^([a-zA-Z0-9]{20,255})$/ ); 
	}
	
	if ( $id eq '' ) {
		# New pseudorandom ID
		$id = Digest::SHA::sha256_hex( 
			Time::HiRes::time() . rand( 2**32 ) 
		);
	}
	
	return $id;
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
	
	# Strip any non-cookie ID data
	my ( $find ) = $id =~ /^([a-zA-Z0-9]{20,255})$/;
	
	my $db	= getDb( 'sessions.db' );
	my $sth	= $db->prepare( qq(
		SELECT session_data FROM sessions 
			WHERE session_id = ? LIMIT 1;
	) );
	$sth->execute( $find );
	my $data = $sth->fetchrow_hashref and $sth->finish;
	
	# Load data to session, if it exists
	if ( $data ) {
		return $data->{session_data};
	}
	
	return '';
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
	$id	= pacify( $id );
	$id	=~ /^([a-zA-Z0-9]{20,255})$/;
	
	# Mark started
	$start	= 1;
	
	if ( $id eq '' ) {
		# New session data
		sessionNew();
		return;
	}
	
	my $data = sessionRead( $id );
	
	# Invalid existing cookie? Reset
	if ( $data eq '' ) {
		sessionNew();
		return;
	}
	
	# Restore session from cookie
	sessionID( $id );
	
	my $values = decode_json( "$data" );
	foreach my $key ( %{$values} ) {
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
	my $db		= getDb( 'sessions.db' );
	
	$db->do( 'DELETE FROM sessions WHERE session_id = ?;', undef, $id );
}

# Garbage collection
sub sessionGC {
	my $db		= getDb( 'sessions.db' );
	
	# Delete sessions exceeding garbage collection timeframe
	my $sth = 
	$db->prepare( qq(
		DELETE FROM sessions WHERE (
		strftime( '%s', 'now' ) - 
		strftime( '%s', updated ) ) > ? ;
	) );
	$sth->execute( SESSION_GC ) and $sth->finish;
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
	
	my $db		= getDb( 'sessions.db' );
	my $sth		= $db->prepare( qq(
		REPLACE INTO sessions ( session_id, session_data ) 
			VALUES( ?, ? );
	) );
	
	$sth->execute( 
		sessionID(),
		encode_json( \%data )
	) and $sth->finish;
	
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

# Generate a hash from given password and optional salt
sub hashPassword {
	my ( $pass, $salt, $csalt ) = @_;
	
	# Generate new salt, if empty
	$salt		//= genSalt( 16 );
	
	# Crypt-friendly blocks
	my @chunks	= 
		split( /(?=(?:.{8})+\z)/s, sha512_hex( $salt . $pass ) );
	
	my $cr		= ''; # Crypt result
	my $block	= ''; # Hash block
	
	for ( @chunks ) {
		# Use chunk's last 2 chars as salt for crypt and hash 1000 times
		$block = crypt( $_, substr( $_, 0, -2 ) );
		for ( 1..HASH_ROUNDS ) {
			$block = sha384_hex( $block );
		}
		
		$cr		.= $block;
	}
	
	return $salt . $cr;
}

# Match raw password against stored hash
sub verifyPassword {
	my ( $pass, $stored ) = @_;
	
	if ( $stored eq hashPassword( $pass, substr( $stored, 0, 16 ) ) ) {
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

# TODO: Process footnotes
sub footnote {
	my ( $ref, $note ) = @_;
	
	return '';
}

# TODO: Process uploaded media embeds
sub embeds {
	my ( $ref, $source, $title, $caption, $preview  ) = @_;
	for ( $ref ) {
		/audio/ and do {
			return 'audio';
		};
		
		/video/ and do {
			return 'video';
		};
		
		/figure/ and do {
			return 'figure';
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
				return '<a href="'. $dest . '" title="' . 
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
		'\n([#=]{1,6})\s?(.*?)\s?\1?\n'
		=> sub {
			my $i = strsize( $1 );
			return "<h$i>$2</h$i>";
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
	foreach my $match ( keys %patterns ) {
		my $html = $patterns{$match};
		$data =~ s/$match/$html->()/ge;
	}
	
	return $data;
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


