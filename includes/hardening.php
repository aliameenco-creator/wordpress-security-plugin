<?php
/**
 * The settings every site should have, and the files nobody should be able to read.
 *
 * Each item here is a WordPress setting or header, nothing invasive: no rewriting of core, no .htaccess surgery and
 * nothing that changes how a page looks. All of it is reversible by switching the setting off.
 *
 * @package wordpress-security-plugin
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Headers that tell the browser how to treat the page.
 *
 * In plain terms:
 *  - X-Frame-Options stops another website displaying this one inside a frame, which is how a convincing fake is
 *    built around a real site.
 *  - X-Content-Type-Options stops the browser guessing a file's type, a long-standing way of getting a browser to
 *    run something it should not.
 *  - Referrer-Policy keeps full addresses from leaking to other sites when a visitor clicks away.
 *  - Permissions-Policy says the pages do not need the camera, the microphone or the visitor's location.
 *  - HSTS tells the browser to only ever use the secure address. It is left off by default because it is remembered
 *    by the browser for a long time, so it is only safe once a site is reliably on HTTPS.
 *
 * None of this is visible to a visitor and none of it costs anything measurable: a handful of bytes per response.
 *
 * @return void
 */
function wpsp_security_headers() {
	if ( ! wpsp_on( 'security_headers' ) || headers_sent() ) {
		return;
	}

	header( 'X-Frame-Options: SAMEORIGIN' );
	header( 'X-Content-Type-Options: nosniff' );
	header( 'Referrer-Policy: strict-origin-when-cross-origin' );
	header( 'Cross-Origin-Opener-Policy: same-origin-allow-popups' );
	header( 'Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()' );

	if ( wpsp_on( 'hsts' ) && is_ssl() ) {
		header( 'Strict-Transport-Security: max-age=31536000; includeSubDomains' );
	}
}
add_action( 'send_headers', 'wpsp_security_headers' );
add_action( 'login_init', 'wpsp_security_headers' );
add_action( 'admin_init', 'wpsp_security_headers' );

/**
 * Turns off XML-RPC, the old remote interface. Nothing on these sites uses it, and it is a favourite of password
 * guessing tools because it can try many passwords in one request.
 *
 * @param bool $enabled Whether WordPress has it on.
 * @return bool
 */
function wpsp_xmlrpc( $enabled ) {
	return wpsp_on( 'disable_xmlrpc' ) ? false : $enabled;
}
add_filter( 'xmlrpc_enabled', 'wpsp_xmlrpc' );

/**
 * Removes the XML-RPC and Windows Live Writer hints from the page head when XML-RPC is off, so nothing advertises an
 * interface that is not there.
 *
 * @return void
 */
function wpsp_remove_xmlrpc_hints() {
	if ( ! wpsp_on( 'disable_xmlrpc' ) ) {
		return;
	}

	remove_action( 'wp_head', 'rsd_link' );
	remove_action( 'wp_head', 'wlwmanifest_link' );
	add_filter( 'wp_headers', static function ( $headers ) {
		unset( $headers['X-Pingback'] );

		return $headers;
	} );
}
add_action( 'init', 'wpsp_remove_xmlrpc_hints' );

/**
 * Hides the WordPress version number, which is what a scanner reads to decide which attacks to try.
 *
 * @return void
 */
function wpsp_hide_version() {
	if ( ! wpsp_on( 'hide_wp_version' ) ) {
		return;
	}

	remove_action( 'wp_head', 'wp_generator' );

	add_filter( 'the_generator', '__return_empty_string' );

	// The version is also appended to every stylesheet and script address.
	$strip = static function ( $src ) {
		if ( is_string( $src ) && false !== strpos( $src, 'ver=' . get_bloginfo( 'version' ) ) ) {
			$src = remove_query_arg( 'ver', $src );
		}

		return $src;
	};

	add_filter( 'style_loader_src', $strip, 20 );
	add_filter( 'script_loader_src', $strip, 20 );
}
add_action( 'init', 'wpsp_hide_version' );

/**
 * Turns off editing theme and plugin files from inside the admin.
 *
 * This is the single most useful hardening setting there is: with it on, an account that is taken over still cannot
 * put code on the server through the browser. Files are deployed through the theme updater instead.
 *
 * @return void
 */
function wpsp_disable_file_edit() {
	if ( wpsp_on( 'disable_file_edit' ) && ! defined( 'DISALLOW_FILE_EDIT' ) ) {
		define( 'DISALLOW_FILE_EDIT', true );
	}
}
add_action( 'plugins_loaded', 'wpsp_disable_file_edit', 1 );

/**
 * Application passwords are a real key to the site through the REST API. Only accounts that manage the site get to
 * have them, so a customer or subscriber account cannot mint one.
 *
 * @param bool    $available Whether WordPress allows it.
 * @param WP_User $user      The account.
 * @return bool
 */
function wpsp_limit_app_passwords( $available, $user = null ) {
	if ( ! wpsp_on( 'limit_app_passwords' ) ) {
		return $available;
	}

	if ( $user instanceof WP_User ) {
		return user_can( $user, 'manage_options' );
	}

	return $available;
}
add_filter( 'wp_is_application_passwords_available_for_user', 'wpsp_limit_app_passwords', 10, 2 );

/**
 * The file names a scanner asks for first, looking for a backup or a leaked configuration file.
 *
 * The server should already refuse these. Answering 404 here catches the cases where it does not, for instance a
 * stray copy inside the uploads folder that the web server happily serves.
 *
 * @return void
 */
function wpsp_block_sensitive_files() {
	if ( ! wpsp_on( 'block_sensitive' ) ) {
		return;
	}

	$path = strtolower( wpsp_request_path() );

	if ( '' === $path ) {
		return;
	}

	$exact = array(
		'readme.html',
		'license.txt',
		'wp-config.php.bak',
		'wp-config.bak',
		'wp-config.txt',
		'wp-config.old',
		'wp-config.php.save',
		'wp-config.php~',
		'.env',
		'.env.local',
		'.env.production',
		'.git/config',
		'.htpasswd',
		'composer.lock',
		'package-lock.json',
		'debug.log',
		'error_log',
		'phpinfo.php',
		'adminer.php',
		'wp-config-sample.php',
	);

	$blocked = in_array( $path, $exact, true )
		|| 0 === strpos( $path, '.git/' )
		|| 0 === strpos( $path, '.svn/' )
		|| preg_match( '/\.(sql|sql\.gz|sql\.zip|bak|old|save|swp|tar|tar\.gz|tgz)$/', $path )
		|| preg_match( '~^wp-content/(uploads|debug\.log)~', $path ) && preg_match( '/\.(php|phtml|php\d|phar)$/', $path );

	if ( ! $blocked ) {
		return;
	}

	wpsp_log_event( 'blocked_file', 'A request for a sensitive file was refused.', 'notice', substr( $path, 0, 120 ) );
	wpsp_deny( 404, 'Not Found' );
}
add_action( 'plugins_loaded', 'wpsp_block_sensitive_files', 3 );
