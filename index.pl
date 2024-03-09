#!"E:\xampp\perl\bin\perl.exe" -wT

# This is typicaly #!/usr/bin/perl, but I'm currently testing this on a Windows PC wih XAMPP

package PerlSketch;

# Basic security
use strict;
use warnings;

# Modules in use
use Template;
use File::Basename;
use Encode;

# Perl version
use 5.32.1;



# Writable content location
use constant STORAGE_DIR	=> "storage";

# Maximum number of posts per page
use constant POST_LIMIT		=> 10;

# File stream buffer size
use constant BUFFER_SIZE	=> 10240;


# Request methods and path handler map
our %path_map = (
	get	=> [
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
	
	# Request protocol scheme HTTP/HTTPS etc..
	'scheme'	=> lc( $ENV{REQUEST_SCHEME}	//= 'http' ),
	
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





# Site views ( Also exit after completing their tasks )

# TODO: Main homepage
sub viewHome {
	my ( $realm, $verb, $params ) = @_;
	# Homepage template
	my $tpl = storage( "sites/$realm/index.html" );
	
	if ( !-f $tpl ) {
		sendNotFound( $realm, $verb )
	}
	
	if ( $verb eq 'head' ) {
		httpCode( '200' );
		# Nothing else to send
		exit;
	}
	
	my %data = (
		title	=> 'Your Homepage',
		body	=> "<p>Home requested with {$verb} on {$realm}</p>"
	);
	
	httpCode( '200' );
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
	
	if ( $verb eq 'head' ) {
		httpCode( '200' );
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
	
	httpCode( '200' );
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
	
	if ( $verb eq 'head' ) {
		httpCode( '200' );
		exit;
	}
	
	my %data = (
		title	=> 'Blog index',
		body	=> 
		"<p>Blog index with <strong>$verb</strong> on <em>$realm</em></p>" . 
			"<p>Path - Year: $year, Month: $month, Day: $day, Slug: $slug</p>" . 
			"<p>Page $page</p>"
	);
	
	httpCode( '200' );
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
	
	if ( $verb eq 'head' ) {
		httpCode( '200' );
		exit;
	}
	
	my %data = (
		title		=> 'New post view',
		token		=> 'token',
		nonce		=> 'nonce',
		meta		=> 'meta',
		
		form_title	=> 'New post'
	);
	
	httpCode( '200' );
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
	
	if ( $verb eq 'head' ) {
		httpCode( '200' );
		exit;
	}
	
	my %data = (
		title		=> 'Edit existing post',
		token		=> 'token',
		nonce		=> 'nonce',
		meta		=> 'meta',
		
		form_title	=> 'Edit post'
	);
	
	httpCode( '200' );
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
	
	if ( $verb eq 'head' ) {
		httpCode( '200' );
		exit;
	}
	
	my %data = (
		title	=> 'Archive view',
		body	=> 
		"<p>Archive with {$verb} on {$realm}</p>" . 
			"<p>Page $page</p>"
	);
	
	httpCode( '200' );
	preamble();
	
	render( storage( "sites/$realm/index.html" ), \%data );
	exit;
}

# TODO: Searching index
sub viewSearch {
	my ( $realm, $verb, $params ) = @_;
	
	my $all		= $params->{all}	//= '';
	my $page	= $params->{page}	//= 1;
	
	if ( $verb eq 'head' ) {
		httpCode( '200' );
		exit;
	}
	
	httpCode( '200' );
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

