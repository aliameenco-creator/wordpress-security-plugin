<?php
/**
 * Settings, the request, and the visitor.
 *
 * Everything here is cheap on purpose: the settings are one autoloaded option, so reading them during a page render
 * costs no query, and the request helpers are string work only.
 *
 * @package wordpress-security-plugin
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * The defaults a fresh install starts with.
 *
 * Anything that could lock an administrator out, change what visitors see, or hide the login before the address has
 * been written down starts switched off.
 *
 * @return array<string, mixed>
 */
function wpsp_default_settings() {
	return array(
		// Login.
		'login_slug'          => '',
		'login_max_attempts'  => 5,
		'login_lockout'       => 900,
		'login_alert_email'   => '',
		'block_enumeration'   => true,

		// Two-step login.
		'twofactor_enabled'   => false,
		'twofactor_required'  => true,

		// Hardening.
		'security_headers'    => true,
		'hsts'                => false,
		'disable_xmlrpc'      => true,
		'disable_file_edit'   => true,
		'hide_wp_version'     => true,
		'limit_app_passwords' => true,
		'block_sensitive'     => true,

		// Bots and scraping.
		'bots_enabled'        => true,
		'block_ai_crawlers'   => true,
		'block_bad_agents'    => true,
		'honeypot'            => true,
		'rate_limit'          => true,
		'rate_limit_hits'     => 120,
		'behind_cloudflare'   => false,

		// Maintenance mode.
		'maintenance'         => false,
		'maintenance_code'    => '',
		'maintenance_heading' => '',
		'maintenance_message' => '',

		// Counters and reporting.
		'count_visits'        => true,
		'report_enabled'      => false,
		'report_key'          => '',
		'log_retention_days'  => 90,
	);
}

/**
 * All settings, with the defaults filled in.
 *
 * @return array<string, mixed>
 */
function wpsp_settings() {
	if ( isset( $GLOBALS['wpsp_settings'] ) && is_array( $GLOBALS['wpsp_settings'] ) ) {
		return $GLOBALS['wpsp_settings'];
	}

	$stored = get_option( 'wpsp_settings', array() );

	$GLOBALS['wpsp_settings'] = array_merge( wpsp_default_settings(), is_array( $stored ) ? $stored : array() );

	return $GLOBALS['wpsp_settings'];
}

/**
 * One setting.
 *
 * @param string $key     Setting name.
 * @param mixed  $default Fallback when the setting is unknown.
 * @return mixed
 */
function wpsp_option( $key, $default = null ) {
	$settings = wpsp_settings();

	return array_key_exists( $key, $settings ) ? $settings[ $key ] : $default;
}

/**
 * Whether a feature is on.
 *
 * @param string $key Setting name.
 * @return bool
 */
function wpsp_on( $key ) {
	return (bool) wpsp_option( $key, false );
}

/**
 * Saves settings, merged over what is stored, and clears the in-process cache.
 *
 * @param array<string, mixed> $changes Settings to change.
 * @return void
 */
function wpsp_save_settings( array $changes ) {
	$settings = array_merge( wpsp_settings(), $changes );

	update_option( 'wpsp_settings', $settings, true );

	$GLOBALS['wpsp_settings'] = $settings;
}

/**
 * The request path, without the site's subdirectory, leading or trailing slashes, or query string.
 *
 * @return string
 */
function wpsp_request_path() {
	static $path = null;

	if ( null !== $path ) {
		return $path;
	}

	$uri  = isset( $_SERVER['REQUEST_URI'] ) ? (string) wp_unslash( $_SERVER['REQUEST_URI'] ) : '';
	$path = (string) wp_parse_url( $uri, PHP_URL_PATH );
	$home = (string) wp_parse_url( home_url( '/' ), PHP_URL_PATH );

	if ( '' !== $home && '/' !== $home && 0 === strpos( $path, $home ) ) {
		$path = substr( $path, strlen( $home ) );
	}

	$path = trim( (string) $path, '/' );

	return $path;
}

/**
 * The visitor's IP address.
 *
 * REMOTE_ADDR is the only value that cannot be spoofed, so it is the default. Behind Cloudflare the real visitor is
 * in CF-Connecting-IP, but that header is only trusted when the setting says the site sits behind Cloudflare and the
 * connection really comes from a Cloudflare address, otherwise anyone could send the header and dodge a rate limit.
 *
 * @return string
 */
function wpsp_client_ip() {
	static $ip = null;

	if ( null !== $ip ) {
		return $ip;
	}

	$remote = isset( $_SERVER['REMOTE_ADDR'] ) ? (string) wp_unslash( $_SERVER['REMOTE_ADDR'] ) : '';
	$remote = filter_var( $remote, FILTER_VALIDATE_IP ) ? $remote : '';
	$ip     = $remote;

	if ( wpsp_on( 'behind_cloudflare' ) && isset( $_SERVER['HTTP_CF_CONNECTING_IP'] ) && wpsp_is_cloudflare_ip( $remote ) ) {
		$forwarded = (string) wp_unslash( $_SERVER['HTTP_CF_CONNECTING_IP'] );
		if ( filter_var( $forwarded, FILTER_VALIDATE_IP ) ) {
			$ip = $forwarded;
		}
	}

	return $ip;
}

/**
 * Whether an address belongs to Cloudflare's published ranges.
 *
 * The ranges are listed here rather than fetched, so no page load ever waits on a network call. They change rarely;
 * the nightly job refreshes a stored copy when the site is set as being behind Cloudflare.
 *
 * @param string $ip Address to test.
 * @return bool
 */
function wpsp_is_cloudflare_ip( $ip ) {
	if ( '' === $ip ) {
		return false;
	}

	$ranges = get_option( 'wpsp_cloudflare_ranges' );
	if ( ! is_array( $ranges ) || ! $ranges ) {
		$ranges = wpsp_cloudflare_default_ranges();
	}

	foreach ( $ranges as $range ) {
		if ( wpsp_ip_in_range( $ip, (string) $range ) ) {
			return true;
		}
	}

	return false;
}

/**
 * Cloudflare's own published ranges, as of 2026-11. Refreshed nightly from cloudflare.com/ips.
 *
 * @return string[]
 */
function wpsp_cloudflare_default_ranges() {
	return array(
		'173.245.48.0/20',
		'103.21.244.0/22',
		'103.22.200.0/22',
		'103.31.4.0/22',
		'141.101.64.0/18',
		'108.162.192.0/18',
		'190.93.240.0/20',
		'188.114.96.0/20',
		'197.234.240.0/22',
		'198.41.128.0/17',
		'162.158.0.0/15',
		'104.16.0.0/13',
		'104.24.0.0/14',
		'172.64.0.0/13',
		'131.0.72.0/22',
		'2400:cb00::/32',
		'2606:4700::/32',
		'2803:f800::/32',
		'2405:b500::/32',
		'2405:8100::/32',
		'2a06:98c0::/29',
		'2c0f:f248::/32',
	);
}

/**
 * Whether an address falls inside a CIDR range. Handles IPv4 and IPv6.
 *
 * @param string $ip    Address to test.
 * @param string $range CIDR range.
 * @return bool
 */
function wpsp_ip_in_range( $ip, $range ) {
	if ( false === strpos( $range, '/' ) ) {
		return $ip === $range;
	}

	list( $subnet, $bits ) = explode( '/', $range, 2 );

	$ip_bin     = inet_pton( $ip );
	$subnet_bin = inet_pton( $subnet );
	$bits       = (int) $bits;

	if ( false === $ip_bin || false === $subnet_bin || strlen( $ip_bin ) !== strlen( $subnet_bin ) || $bits < 0 ) {
		return false;
	}

	$whole = intdiv( $bits, 8 );
	$rest  = $bits % 8;

	if ( $whole > 0 && 0 !== substr_compare( $ip_bin, substr( $subnet_bin, 0, $whole ), 0, $whole ) ) {
		return false;
	}

	if ( 0 === $rest ) {
		return true;
	}

	if ( ! isset( $ip_bin[ $whole ], $subnet_bin[ $whole ] ) ) {
		return false;
	}

	$mask = ~( ( 1 << ( 8 - $rest ) ) - 1 ) & 0xFF;

	return ( ord( $ip_bin[ $whole ] ) & $mask ) === ( ord( $subnet_bin[ $whole ] ) & $mask );
}

/**
 * A short, one-way identifier for a visitor, used as a rate-limit key and in the log.
 *
 * The raw address is never stored. The daily salt means yesterday's identifiers cannot be matched against today's,
 * which keeps the log useful for spotting an attack without becoming a record of who visited.
 *
 * @param string $ip Optional address; the current visitor by default.
 * @return string
 */
function wpsp_ip_hash( $ip = '' ) {
	$ip   = '' !== $ip ? $ip : wpsp_client_ip();
	$salt = wpsp_daily_salt();

	return substr( hash_hmac( 'sha256', $ip, $salt ), 0, 16 );
}

/**
 * The rotating salt behind the visitor identifier.
 *
 * @return string
 */
function wpsp_daily_salt() {
	static $salt = null;

	if ( null !== $salt ) {
		return $salt;
	}

	$stored = get_option( 'wpsp_salt' );
	$today  = gmdate( 'Y-m-d' );

	if ( is_array( $stored ) && ( $stored['day'] ?? '' ) === $today && ! empty( $stored['value'] ) ) {
		$salt = (string) $stored['value'];

		return $salt;
	}

	$salt = wp_generate_password( 32, false, false );
	update_option( 'wpsp_salt', array( 'day' => $today, 'value' => $salt ), true );

	return $salt;
}

/**
 * The visitor's user agent, trimmed.
 *
 * @return string
 */
function wpsp_user_agent() {
	$agent = isset( $_SERVER['HTTP_USER_AGENT'] ) ? (string) wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) : '';

	return substr( trim( $agent ), 0, 255 );
}

/**
 * Whether this request is one of WordPress's own internal runs, which must never be interfered with.
 *
 * @return bool
 */
function wpsp_internal_request() {
	return wp_doing_cron()
		|| ( defined( 'WP_CLI' ) && WP_CLI )
		|| ( defined( 'WP_INSTALLING' ) && WP_INSTALLING )
		|| ( defined( 'DOING_AUTOSAVE' ) && DOING_AUTOSAVE );
}

/**
 * Sends a short plain response and stops. Used by the bot and rate-limit layers.
 *
 * Nothing about WordPress is revealed, and the response is marked as not cacheable so a block is never served on to
 * a real visitor by a page cache.
 *
 * @param int    $status  HTTP status code.
 * @param string $message One line of text.
 * @return void
 */
function wpsp_deny( $status, $message ) {
	if ( ! headers_sent() ) {
		status_header( $status );
		nocache_headers();
		header( 'Content-Type: text/plain; charset=utf-8' );
		if ( 429 === $status ) {
			header( 'Retry-After: 60' );
		}
	}

	echo esc_html( $message ) . "\n";
	exit;
}

/**
 * The site's own host, for comparing against a referer or a redirect target.
 *
 * @return string
 */
function wpsp_site_host() {
	static $host = null;

	if ( null === $host ) {
		$host = (string) wp_parse_url( home_url( '/' ), PHP_URL_HOST );
	}

	return $host;
}

/**
 * Purges full-page caches across known caching plugins and server caches.
 *
 * Useful when toggling maintenance mode or security settings so visitors immediately see the update.
 *
 * @return void
 */
function wpsp_purge_cache() {
	if ( function_exists( 'wp_cache_clear_cache' ) ) {
		wp_cache_clear_cache();
	}
	if ( function_exists( 'w3tc_flush_all' ) ) {
		w3tc_flush_all();
	}
	if ( function_exists( 'rocket_clean_domain' ) ) {
		rocket_clean_domain();
	}
	do_action( 'litespeed_purge_all' );
	do_action( 'wphb_clear_page_cache' );
}
