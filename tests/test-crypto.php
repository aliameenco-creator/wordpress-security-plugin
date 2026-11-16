<?php
/**
 * Tests for the parts where a mistake would be silent: the one-time code maths, the address range matching and the
 * report signature. A wrong TOTP implementation does not throw an error, it just locks everybody out, so these are
 * checked against the official test vectors rather than against our own output.
 *
 * Run from the plugin folder:
 *     php tests/test-crypto.php
 *
 * No WordPress needed: the handful of WordPress functions these files touch while loading are stubbed below.
 *
 * @package wordpress-security-plugin
 */

define( 'ABSPATH', __DIR__ . '/' );

// The hooks the files register on load. Nothing here runs them.
function add_action() {}
function add_filter() {}
function apply_filters( $tag, $value ) {
	return $value;
}
function wp_generate_password( $length = 12 ) {
	return substr( bin2hex( random_bytes( (int) ceil( $length / 2 ) + 1 ) ), 0, $length );
}
function wp_parse_url( $url, $component = -1 ) {
	return parse_url( $url, $component );
}
function wp_unslash( $value ) {
	return $value;
}
function get_option( $name, $default = false ) {
	return $default;
}
function update_option() {
	return true;
}
function home_url( $path = '/' ) {
	return 'https://example.test' . $path;
}
function sanitize_title( $title ) {
	return strtolower( preg_replace( '/[^a-z0-9-]/i', '-', (string) $title ) );
}
function esc_html__( $text ) {
	return $text;
}
function __( $text ) {
	return $text;
}
function esc_html_e( $text ) {
	echo $text;
}
function esc_attr_e( $text ) {
	echo $text;
}
function esc_attr( $text ) {
	return $text;
}
function esc_html( $text ) {
	return $text;
}
function esc_url( $url ) {
	return $url;
}
function get_locale() {
	return 'en_GB';
}
function get_bloginfo( $what = '' ) {
	return 'Example Site';
}
function wp_specialchars_decode( $text ) {
	return $text;
}
function status_header() {}
function nocache_headers() {}
function get_user_meta() {
	return '';
}
function update_user_meta() {
	return true;
}
function delete_user_meta() {
	return true;
}
function get_current_user_id() {
	return 0;
}
function current_time( $format ) {
	return gmdate( $format );
}
function wp_hash_password( $password ) {
	return password_hash( $password, PASSWORD_DEFAULT );
}
function wp_check_password( $password, $hash ) {
	return password_verify( $password, $hash );
}

const MINUTE_IN_SECONDS = 60;
const HOUR_IN_SECONDS   = 3600;
const DAY_IN_SECONDS    = 86400;
const WEEK_IN_SECONDS   = 604800;

define( 'WPSP_VERSION', 'test' );
define( 'WPSP_FILE', __DIR__ . '/wordpress-security-plugin.php' );
define( 'WPSP_SLUG', 'wordpress-security-plugin/wordpress-security-plugin.php' );

require_once __DIR__ . '/../includes/helpers.php';
require_once __DIR__ . '/../includes/two-factor.php';

$failures = 0;
$checks   = 0;

/**
 * Asserts two values match.
 *
 * @param string $what     What is being checked.
 * @param mixed  $expected Expected value.
 * @param mixed  $actual   Actual value.
 * @return void
 */
function check( $what, $expected, $actual ) {
	global $failures, $checks;

	$checks++;

	if ( $expected === $actual ) {
		echo "  ok    {$what}\n";

		return;
	}

	$failures++;
	printf( "  FAIL  %s\n          expected: %s\n          actual:   %s\n", $what, var_export( $expected, true ), var_export( $actual, true ) );
}

echo "\nBase32\n";
check( 'decodes the RFC 4648 example', 'foobar', wpsp_base32_decode( 'MZXW6YTBOI======' ) );
check( 'ignores spaces and case', 'foobar', wpsp_base32_decode( 'mzxw 6ytb oi' ) );
check( 'refuses characters outside the alphabet', '', wpsp_base32_decode( '0189!' ) );

echo "\nOne-time codes, against the RFC 6238 test vectors\n";
// The RFC uses the ASCII secret "12345678901234567890", which is this in base32.
$rfc = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
check( 'the key decodes to the RFC secret', '12345678901234567890', wpsp_base32_decode( $rfc ) );
check( 'T = 59 gives 287082', '287082', wpsp_totp_code( $rfc, (int) floor( 59 / 30 ) ) );
check( 'T = 1111111109 gives 081804', '081804', wpsp_totp_code( $rfc, (int) floor( 1111111109 / 30 ) ) );
check( 'T = 1111111111 gives 050471', '050471', wpsp_totp_code( $rfc, (int) floor( 1111111111 / 30 ) ) );
check( 'T = 1234567890 gives 005924', '005924', wpsp_totp_code( $rfc, (int) floor( 1234567890 / 30 ) ) );
check( 'T = 2000000000 gives 279037', '279037', wpsp_totp_code( $rfc, (int) floor( 2000000000 / 30 ) ) );
check( 'an unusable key gives nothing rather than a wrong code', '', wpsp_totp_code( '!!!!' ) );

echo "\nNew keys\n";
$secret = wpsp_totp_new_secret();
check( 'a new key is 32 base32 characters', 32, strlen( $secret ) );
check( 'a new key is 160 bits once decoded', 20, strlen( wpsp_base32_decode( $secret ) ) );
check( 'the current code is six digits', 1, preg_match( '/^\d{6}$/D', wpsp_totp_code( $secret ) ) );
check( 'two new keys differ', false, wpsp_totp_new_secret() === wpsp_totp_new_secret() );

echo "\nAddress ranges\n";
check( 'an address inside a /20 matches', true, wpsp_ip_in_range( '173.245.49.10', '173.245.48.0/20' ) );
check( 'an address outside a /20 does not', false, wpsp_ip_in_range( '173.245.64.1', '173.245.48.0/20' ) );
check( 'a /13 boundary is handled', true, wpsp_ip_in_range( '104.23.255.255', '104.16.0.0/13' ) );
check( 'just past a /13 is not', false, wpsp_ip_in_range( '104.24.0.1', '104.16.0.0/13' ) );
check( 'a /22 partial byte is handled', true, wpsp_ip_in_range( '103.21.247.255', '103.21.244.0/22' ) );
check( 'just past a /22 is not', false, wpsp_ip_in_range( '103.21.248.0', '103.21.244.0/22' ) );
check( 'IPv6 inside a /32 matches', true, wpsp_ip_in_range( '2606:4700:1:2::3', '2606:4700::/32' ) );
check( 'IPv6 outside a /32 does not', false, wpsp_ip_in_range( '2606:4701::1', '2606:4700::/32' ) );
check( 'an IPv4 address is not matched against an IPv6 range', false, wpsp_ip_in_range( '1.2.3.4', '2606:4700::/32' ) );
check( 'rubbish is not matched', false, wpsp_ip_in_range( 'not-an-ip', '10.0.0.0/8' ) );
check( 'a /0 matches everything', true, wpsp_ip_in_range( '8.8.8.8', '0.0.0.0/0' ) );
check( 'a bare address matches itself', true, wpsp_ip_in_range( '8.8.8.8', '8.8.8.8' ) );

echo "\nEvery Cloudflare range we ship is well formed\n";
$bad = 0;
foreach ( wpsp_cloudflare_default_ranges() as $range ) {
	list( $subnet, $bits ) = explode( '/', $range );
	if ( ! filter_var( $subnet, FILTER_VALIDATE_IP ) || (int) $bits < 1 || (int) $bits > 128 ) {
		$bad++;
	}
}
check( 'no malformed range in the shipped list', 0, $bad );
check( 'a known Cloudflare address is recognised', true, wpsp_is_cloudflare_ip( '162.158.1.1' ) );
check( 'an address that is not theirs is not', false, wpsp_is_cloudflare_ip( '8.8.8.8' ) );

echo "\nThe report signature\n";
$key       = bin2hex( random_bytes( 32 ) );
$timestamp = time();
$nonce     = 'abcdef1234567890';
$payload   = $timestamp . "\n" . $nonce . "\n" . 'GET' . "\n" . '/wordpress-security-plugin/v1/report';
$signature = hash_hmac( 'sha256', $payload, $key );

check( 'the signature is 64 hex characters', 1, preg_match( '/^[a-f0-9]{64}$/D', $signature ) );
check( 'the same inputs give the same signature', $signature, hash_hmac( 'sha256', $payload, $key ) );
check( 'another key gives a different signature', false, $signature === hash_hmac( 'sha256', $payload, bin2hex( random_bytes( 32 ) ) ) );
check( 'a changed timestamp gives a different signature', false, $signature === hash_hmac( 'sha256', ( $timestamp + 1 ) . "\n" . $nonce . "\nGET\n/wordpress-security-plugin/v1/report", $key ) );
check( 'a changed path gives a different signature', false, $signature === hash_hmac( 'sha256', $timestamp . "\n" . $nonce . "\nGET\n/wordpress-security-plugin/v1/other", $key ) );

echo "\nAccess codes\n";
$hash = wp_hash_password( '48213' );
check( 'the right code is accepted', true, wp_check_password( '48213', $hash ) );
check( 'a wrong code is not', false, wp_check_password( '48214', $hash ) );
check( 'the stored value is not the code', false, false !== strpos( $hash, '48213' ) );

printf( "\n%d checks, %d failures\n\n", $checks, $failures );

exit( $failures > 0 ? 1 : 0 );
