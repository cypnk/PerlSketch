#!"C:\xampp\perl\bin\perl.exe" -wT

# This is typicaly #!/usr/bin/perl, but I'm currently testing this on a Windows PC wih XAMPP

package PerlSketch;

# Basic security
use strict;
use warnings;

# Modules in use
use Template;
use File::Basename;
use Encode;
use DBI;

# Perl version
use 5.32.1;



# Writable content location
use constant STORAGE_DIR	=> "storage";

# Maximum number of posts per page
use constant POST_LIMIT		=> 10;

# File stream buffer size
use constant BUFFER_SIZE	=> 10240;


# Cookie defaults

# Base expiration
use constant COOKIE_EXP		=> 604800;

# Base domain path
use constant COOKIE_PATH	=> '/';



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

# Generally safe to send as-is
our @text_types	= qw(css js txt html vtt csv);
	

# Allowed file extensions and their content types
our %ext_list	= (
	'css'		=> "text/css",
	'js'		=> "text/javascript",
	'txt'		=> "text/plain",
	'html'		=> "text/html",
	'vtt'		=> "text/vtt",
	'csv'		=> "text/csv",
	
	'ico'		=> "image/vnd.microsoft.icon",
	'jpg'		=> "image/jpeg",
	'jpeg'		=> "image/jepg",
	'gif'		=> "image/gif",
	'bmp'		=> "image/bmp",
	'png'		=> "image/png",
	'tif'		=> "image/tiff",
	'tiff'		=> "image/tiff",
	'svg'		=> "image/svg+xml",
	'webp'		=> "image/webp",
	
	'ttf'		=> "font/ttf",
	'otf'		=> "font/otf",
	'woff'		=> "font/woff",
	'woff2'		=> "font/woff2",
	
	'oga'		=> "audio/oga",
	'mpa'		=> "audio/mpa",
	'mp3'		=> "audio/mp3",
	'm4a'		=> "audio/m4a",
	'wav'		=> "audio/wav",
	'wma'		=> "audio/wma",
	'flac'		=> "audio/flac",
	'weba'		=> "audio/webm",
	
	'avi'		=> "video/x-msvideo",
	'mp4'		=> "video/mp4",
	'mkv'		=> "video/x-matroska",
	'mov'		=> "video/quicktime",
	'ogg'		=> "video/ogg",
	'ogv'		=> "video/ogg",
	
	'doc'		=> "application/msword",
	'docx'		=> "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
	'ppt'		=> "application/vnd.ms-powerpoint",
	'pptx'		=> "application/vnd.openxmlformats-officedocument.presentationml.presentation",
	'pdf'		=> "application/pdf",
	'epub'		=> "application/epub+zip",
	'zip'		=> "application/zip",
	'7z'		=> "application/x-7z-compressed",
	'gz'		=> "application/gzip",
	'tar'		=> "application/x-tar"
);

# HTTP Response status codes
our %http_codes = (
	'200'	=> "200 OK",
	'201'	=> "201 Created",
	'202'	=> "202 Accepted",
	
	'204'	=> "204 No Content",
	'205'	=> "205 Reset Content",
	'206'	=> "206 Partial Content",
	
	'300'	=> "300 Multiple Choices",
	'301'	=> "301 Moved Permanently",
	'302'	=> "302 Found",
	'303'	=> "303 See Other",
	'304'	=> "304 Not Modified",
	
	'400'	=> "400 Bad Request",
	'401'	=> "401 Unauthorized",
	
	'403'	=> "403 Denied",
	'404'	=> "404 Not Found",
	'405'	=> "405 Method Not Allowed",
	'406'	=> "406 Not Acceptable",
	'407'	=> "407 Proxy Authentication Required",
	
	'409'	=> "409 Conflict",
	'410'	=> "410 Gone",
	'411'	=> "411 Length Required",
	'412'	=> "412 Precondition Failed",
	'413'	=> "413 Payload Too Large",
	'414'	=> "414 Request-URI Too Long",
	'415'	=> "415 Unsupported Media Type",
	'416'	=> "416 Range Not Satisfiable",
	
	'422'	=> "422 Unprocessable Entity",
	
	'425'	=> "425 Too Early",
	
	'429'	=> "429 Too Many Requests",
	
	'431'	=> "431 Request Header Fields Too Large",
	
	'500'	=> "500 Internal Server Error",
	'501'	=> "501 Not Implemented"
);



# Database variables



# Database connection handles
our %dbh;

# List of SQL database schema
our %table_schema;




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
	
	binmode STDOUT;
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

# Filter number within min and max range, inclusive
sub intRange {
	my ( $val, $min, $max ) = @_;
	my $out = sprintf( "%d", "$val" );
 	
	return 
	( $out > $max ) ? $max : ( ( $out < $min ) ? $min : $out );
}



# Response



# Send HTTP status code
sub httpCode {
	my ( $code ) = @_;
	
	# Check if status is currently present
	if ( !exists( $http_codes{$code} ) ) {
		print "Status: 501 Not Implemented\n";
		exit;
	}
	
	print "Status: $http_codes{$code}\n";
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

# Redirect to another path
sub redirect {
	my ( $path ) = @_;
	httpCode( '303' );
	print "Location: $path\n\n";
	exit;
}



# Request 



# Current host or server name/domain/ip address
sub siteRealm {
	my $realm = lc( $ENV{SERVER_NAME} //= '' ) =~ s/[^a-zA-Z0-9\.]//gr;
	
	$realm = pacify( $realm );
	
	# Check for reqested realm, if it exists, and end early if invalid
	my $dir = storage( "sites/$realm" );
	if ( $realm eq '' || ! -d $dir ) {
		sendBadRequest();
	}
	
	return $realm;
}

# Guess if current request is secure
sub isSecure {
	# Request protocol scheme HTTP/HTTPS etc..
	my $scheme	= lc( $ENV{REQUEST_SCHEME} //= 'http' );
	
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
	my ( $fail ) = @_;
	
	# Set fail to off by default
	$fail	//= 0;
	
	# Fail mode?, send 405 HTTP status code, default 200 OK
	httpCode( $fail ? '405' : '200' );
	
	print "Allow: GET, POST, HEAD, OPTIONS\n";
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
		print $http_codes{$code};
	}
	
	exit;
}

# File/directory not found page
sub sendNotFound {
	my ( $realm, $verb ) = @_;
	sendErrorResponse( $realm, $verb, 404 );
}

# Simple send file (for text types)
sub sendFile {
	my ( $rs ) = @_;
	
	open( my $fh, '<', $rs ) or exit 1;
	while ( my $r = <$fh> ) {
		print $r;
	}
	
	close( $fh );
	exit;
}

# Send file buffered
sub streamFile {
	my ( $rs ) = @_;
	
	# Binary output and file opened in raw mode
	binmode STDOUT;
	open( my $fh, '<:raw', $rs ) or exit 1;
	
	my $buf;
	while ( read( $fh, $buf, BUFFER_SIZE ) ) {
		print $buf;
	}
	
	close( $fh );
	exit;
}

# TODO: Send ranged content
sub streamRanged {
	my ( $ranges ) = @_;
 	
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
	
	# Not in whitelist?
	if ( !exists ( $ext_list{$ext} ) ) {
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
	
	
	# End here if sending is not necessary
	if ( $verb eq 'head' ) {
		httpCode( '200' );
		exit;
	}
	
	# TODO: Scan for file request ranges
	
	httpCode( '200' );
	preamble( 1, 1 );
	
	# Send the file content type header
	print "Content-type: $ext_list{$ext}\n\n";
	
	# Send simple mode if it's a text type
	if ( grep( /^$ext$/, @text_types ) ) {
		sendFile( $rs );
	}
	
	# Buffered stream for everything else
	streamFile( $rs );
}




# Database connectivity




# Read SQL table schema for each database in __DATA__ content
sub loadSchemaData {
	my @raw;
	while ( my $line = <DATA> ) {
		push ( @raw, $line );
	}
	
	my $find	= join( '', @raw );
	my $pattern	= qr/
	--\s*Database:\s*   		# Database delimeter prefix
		(?<base>[\w_]+\.db)	# Database name E.G. sessions.db
	\s*--
	
	(?<schema>.*?)			# Table and index schema
	
	--\s*End\s*database\s*--	# Database delimeter suffix
	/ixs;
	
	# Load schema list
	%table_schema = ();
	while ( $find =~ /$pattern/g ) {
		$table_schema{$+{base}} = $+{schema};
	}
}

# Collect database from schema list
sub tableSchema {
	my ( $label ) = @_;
	
	# Preload tables
	if ( ! keys %table_schema ) {
		loadSchemaData();
	}
	
	return $table_schema{$label} //= '';
}

# Get database connection
sub getDb {
	my ( $db ) = @_;
	
	# Database connection string format
	$db	= pacify( $db );
	$db	=~ s/\.{2,}/\./g;
	
	chomp( $db );
	
	if ( exists( $dbh{$db} ) ) {
		return $dbh{$db};
	}
	
	# Database file
	my $df		= storage( $db );
	my $first_run	= ( -f $df ) ? 0 : 1;
	my $dsn		= "dbi:SQLite;dbname=$df";
	
	$dbh{$db}->connect( $dsn, "", "", {
		AutoCommit		=> 0,
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
		$dbh{$db}->do( 'PRAGMA encoding = "UTF-8";' );
		$dbh{$db}->do( 'PRAGMA page_size = "16384";' );
		$dbh{$db}->do( 'PRAGMA auto_vacuum = "2";' );
		$dbh{$db}->do( 'PRAGMA temp_store = "2";' );
		$dbh{$db}->do( 'PRAGMA secure_delete = "1";' );
		
		# Install SQL, if available
		my $schema = tableSchema( $db );
		if ( $schema ne '' ) {
			$dbh{$db}->do( $schema );
		}
		
		# Instalation check
		$dbh{$db}->do( 'PRAGMA integrity_check;' );
		$dbh{$db}->do( 'PRAGMA foreign_key_check;' );
	}
	
	$dbh{$db}->do( 'PRAGMA journal_mode = WAL;' );
	$dbh{$db}->do( 'PRAGMA foreign_keys = ON;' );
	
	return $dbh{$db};
}

# Close every open connection
sub closeDb {
	foreach my $key ( keys %dbh ) {
		$dbh{$key}->disconnect();
	}
}

# Cleanup
END {
	closeDb();
}




# Cookie handling




# Get all cookie data from request
sub getCookies {
	my @items	= split( /;/, $ENV{'HTTP_COOKIE'} //= '' );
	my %sent;
	
	foreach ( @items ) {
		my ( $k, $v )	= split( /=/, $_ );
		
		# Clean prefixes, if any
		$k		=~ s/^__(Host|Secure)\-//gi;
		$sent{pacify( $k )} = pacify( $v );
	}
	
	return %sent;
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
	
	# Session cookie expiration only handled by the browser
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



# Site views ( Also exit after completing their tasks )

sub viewInstall {
	my ( $realm, $verb, $params ) = @_;
	
	httpCode( '200' );
	if ( $verb eq 'head' ) {
		exit;
	}
	preamble();
	print "TODO: Installation";
	exit;
}

# TODO: Main homepage
sub viewHome {
	my ( $realm, $verb, $params ) = @_;
	# Homepage template
	my $tpl = storage( "sites/$realm/index.html" );
	
	if ( !-f $tpl ) {
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
	
	my %data = (
		title	=> 'Your Homepage',
		body	=> "<p>Home requested with {$verb} on {$realm}</p>" . 
			$cval
	);
	
	setCookie( 'Test Cookie', 'Some Value expiring in 400 seconds (ttl 400)', 400 );
	setCookie( 'Session Cookie', 'Value should remain until browser decides to delete it (ttl 0)', 0 );
	
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
	
	my $year	= $params->{year}	//= 0;
	my $month	= $params->{month}	//= 0;
	my $day		= $params->{day}	//= 0;
	
	my $id		= $params->{id}		//= 0;
	
	httpCode( '200' );
	if ( $verb eq 'head' ) {
		exit;
	}
	
	my %data = (
		title		=> 'New post view',
		token		=> 'token',
		nonce		=> 'nonce',
		meta		=> 'meta',
		
		form_title	=> 'New post'
	);
	
	preamble();
	
	render( storage( "sites/$realm/newpost.html" ), \%data );
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
	
	httpCode( '200' );
	if ( $verb eq 'head' ) {
		exit;
	}
	
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
	
	httpCode( '200' );
	preamble();
	
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
	
	httpCode( '200' );
	preamble();
	
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
	
	httpCode( '200' );
	preamble();
	
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
	
	httpCode( '200' );
	preamble();
	
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
	
	# Send options, if asked
	# TODO: Limit options based on realm
	if ( $verb eq 'options' ) {
		sendOptions();
	}
	
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

