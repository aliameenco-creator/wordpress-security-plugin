<?php
/**
 * Maintenance mode with a numeric access code.
 *
 * While a site is being built or redesigned, visitors see a holding page and nothing else. Anyone who has been given
 * the code types it once and then browses the real site normally, with no account, no email and no sign-up.
 *
 * How the code is kept: only a hash of it is stored, the same way a password is, so the stored value is no use to
 * anyone who reads the database. A visitor who types it correctly gets a cookie holding a signed token, not the code
 * itself, so the code never travels again after the first submission.
 *
 * Search engines are told this is temporary: the holding page answers 503 with Retry-After, which is what Google
 * asks for and what keeps a page from being dropped from the index while a site is being worked on.
 *
 * Signed-in editors and administrators always see the real site, so maintenance mode cannot get in the way of the
 * work it exists for.
 *
 * @package wordpress-security-plugin
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/** How long a visitor stays let in after typing the code. */
const WPSP_MAINTENANCE_DAYS = 14;

/** How many wrong codes from one visitor before they are made to wait, and for how long. */
const WPSP_CODE_ATTEMPTS = 8;
const WPSP_CODE_LOCKOUT  = 900;

/**
 * The cookie name, tied to the site so two sites on one browser do not share a pass.
 *
 * @return string
 */
function wpsp_maintenance_cookie() {
	return 'wpsp_pass_' . substr( md5( (string) home_url( '/' ) ), 0, 8 );
}

/**
 * Stores a new access code, or clears it when the code is empty.
 *
 * @param string $code Digits only, 4 to 12 of them.
 * @return bool|WP_Error True on success.
 */
function wpsp_set_maintenance_code( $code ) {
	$code = preg_replace( '/\D/', '', (string) $code );

	if ( '' === $code ) {
		wpsp_save_settings( array( 'maintenance_code' => '' ) );
		delete_option( 'wpsp_maintenance_secret' );

		return true;
	}

	if ( strlen( $code ) < 4 || strlen( $code ) > 12 ) {
		return new WP_Error( 'length', __( 'Use between 4 and 12 numbers.', 'wordpress-security-plugin' ) );
	}

	if ( preg_match( '/^(\d)\1*$/D', $code ) || in_array( $code, array( '1234', '12345', '123456', '1234567890', '0000' ), true ) ) {
		return new WP_Error( 'weak', __( 'That code is too easy to guess. Mix the numbers up.', 'wordpress-security-plugin' ) );
	}

	// A per-site secret signs the cookie, so a token from one site is worthless on another and changing the code
	// does not invalidate everyone already let in unless the secret is rotated with it.
	if ( ! get_option( 'wpsp_maintenance_secret' ) ) {
		update_option( 'wpsp_maintenance_secret', wp_generate_password( 48, false, false ), false );
	}

	wpsp_save_settings( array( 'maintenance_code' => wp_hash_password( $code ) ) );

	return true;
}

/**
 * Whether a code has been set.
 *
 * @return bool
 */
function wpsp_has_maintenance_code() {
	return '' !== (string) wpsp_option( 'maintenance_code', '' );
}

/**
 * The signed value the cookie carries.
 *
 * @return string
 */
function wpsp_maintenance_token() {
	$secret = (string) get_option( 'wpsp_maintenance_secret', '' );
	$stamp  = (string) wpsp_option( 'maintenance_code', '' );

	// The hash of the code is part of what is signed, so clearing or changing the code ends every existing pass.
	return hash_hmac( 'sha256', 'wordpress-security-plugin-maintenance|' . $stamp, $secret );
}

/**
 * Whether this visitor has already typed the code.
 *
 * @return bool
 */
function wpsp_maintenance_passed() {
	$cookie = wpsp_maintenance_cookie();

	if ( empty( $_COOKIE[ $cookie ] ) ) {
		return false;
	}

	$given = (string) wp_unslash( $_COOKIE[ $cookie ] );

	return hash_equals( wpsp_maintenance_token(), $given );
}

/**
 * Whether the person looking is allowed past regardless of the code.
 *
 * @return bool
 */
function wpsp_maintenance_bypass() {
	if ( defined( 'WPSP_MAINTENANCE_OFF' ) && WPSP_MAINTENANCE_OFF ) {
		return true;
	}

	return is_user_logged_in() && current_user_can( 'edit_posts' );
}

/**
 * The paths that must stay reachable while the holding page is up.
 *
 * @return bool
 */
function wpsp_maintenance_allowed_path() {
	$path = wpsp_request_path();

	if ( '' === $path ) {
		return false;
	}

	// Signing in, the REST API, cron, the site icon and the robots file all keep working: the first so the owner can
	// get in, the rest so WordPress, the report and search engines are not broken by a holding page.
	$allowed = array( 'wp-login.php', 'wp-cron.php', 'robots.txt', 'favicon.ico', 'wp-json' );

	if ( in_array( $path, $allowed, true ) ) {
		return true;
	}

	foreach ( array( 'wp-admin', 'wp-includes', 'wp-content', 'wp-json' ) as $prefix ) {
		if ( 0 === strpos( $path, $prefix . '/' ) ) {
			return true;
		}
	}

	$slug = (string) wpsp_option( 'login_slug', '' );
	if ( '' !== $slug && $slug === $path ) {
		return true;
	}

	return false;
}

/**
 * Checks the submitted code and sets the cookie.
 *
 * Runs before the holding page is drawn, on the holding page's own POST.
 *
 * @return string An error message to show, or an empty string.
 */
function wpsp_maintenance_check_submission() {
	if ( 'POST' !== ( $_SERVER['REQUEST_METHOD'] ?? '' ) || ! isset( $_POST['wpsp_code'] ) ) {
		return '';
	}

	$key      = 'wpsp_code_' . wpsp_ip_hash();
	$attempts = (int) get_transient( $key );

	if ( $attempts >= WPSP_CODE_ATTEMPTS ) {
		return __( 'Too many attempts. Please wait fifteen minutes and try again.', 'wordpress-security-plugin' );
	}

	$given = preg_replace( '/\D/', '', (string) wp_unslash( $_POST['wpsp_code'] ) ); // phpcs:ignore WordPress.Security.ValidationSanitization.InputNotSanitized -- Reduced to digits.
	$hash  = (string) wpsp_option( 'maintenance_code', '' );

	if ( '' !== $given && '' !== $hash && wp_check_password( $given, $hash ) ) {
		setcookie(
			wpsp_maintenance_cookie(),
			wpsp_maintenance_token(),
			array(
				'expires'  => time() + ( WPSP_MAINTENANCE_DAYS * DAY_IN_SECONDS ),
				'path'     => (string) ( wp_parse_url( home_url( '/' ), PHP_URL_PATH ) ?: '/' ),
				'domain'   => '',
				'secure'   => is_ssl(),
				'httponly' => true,
				'samesite' => 'Lax',
			)
		);

		delete_transient( $key );
		wpsp_log_event( 'maintenance_pass', 'A visitor entered the access code.', 'notice' );

		// Back to the same page, so the visitor lands where they were heading. REQUEST_URI is a path on this
		// site, and wp_safe_redirect refuses anything that points elsewhere.
		$target = isset( $_SERVER['REQUEST_URI'] ) ? (string) wp_unslash( $_SERVER['REQUEST_URI'] ) : '/';
		wp_safe_redirect( $target );
		exit;
	}

	set_transient( $key, $attempts + 1, WPSP_CODE_LOCKOUT );
	wpsp_log_event( 'maintenance_fail', 'Wrong access code.', 'notice' );

	return __( 'That code is not right.', 'wordpress-security-plugin' );
}

/**
 * Shows the holding page when maintenance mode is on.
 *
 * Hooked very early so the theme, the page builder and the database work of rendering a real page never happen for a
 * visitor who is not being let through.
 *
 * @return void
 */
function wpsp_maintenance_gate() {
	if ( ! wpsp_on( 'maintenance' ) || wpsp_internal_request() ) {
		return;
	}

	if ( wpsp_maintenance_allowed_path() || wpsp_maintenance_bypass() || wpsp_maintenance_passed() ) {
		return;
	}

	$error = wpsp_has_maintenance_code() ? wpsp_maintenance_check_submission() : '';

	wpsp_render_maintenance_page( $error );
}
// init rather than plugins_loaded: by here the current user is established the normal way, so checking whether an
// editor is signed in cannot upset another plugin, and it is still long before the theme renders anything.
add_action( 'init', 'wpsp_maintenance_gate', 0 );

/**
 * Warns signed-in administrators on the admin bar that maintenance mode is currently active.
 *
 * @param WP_Admin_Bar $wp_admin_bar Admin bar instance.
 * @return void
 */
function wpsp_maintenance_admin_bar( $wp_admin_bar ) {
	if ( ! wpsp_on( 'maintenance' ) || ! current_user_can( 'edit_posts' ) ) {
		return;
	}

	$wp_admin_bar->add_node(
		array(
			'id'    => 'wpsp_maintenance_status',
			'title' => '<span style="background:#d63638;color:#fff;padding:2px 8px;border-radius:3px;font-weight:600;font-size:12px;">' . esc_html__( '⚠️ Maintenance Mode Active', 'wordpress-security-plugin' ) . '</span>',
			'href'  => admin_url( 'admin.php?page=wordpress-security-plugin&tab=maintenance' ),
			'meta'  => array(
				'title' => __( 'Maintenance mode is ON. Visitors see the holding page. Test in an Incognito / private browsing window.', 'wordpress-security-plugin' ),
			),
		)
	);
}
add_action( 'admin_bar_menu', 'wpsp_maintenance_admin_bar', 100 );

/**
 * Draws the holding page and stops.
 *
 * Self-contained: no theme, no stylesheet, no script and no external font, so it loads instantly and looks the same
 * on every site. 503 with Retry-After tells search engines the site is temporarily unavailable rather than gone.
 *
 * @param string $error Message from a failed code attempt.
 * @return void
 */
function wpsp_render_maintenance_page( $error = '' ) {
	$heading = (string) wpsp_option( 'maintenance_heading', '' );
	$message = (string) wpsp_option( 'maintenance_message', '' );
	$heading = '' !== $heading ? $heading : __( 'We are working on this website', 'wordpress-security-plugin' );
	$message = '' !== $message ? $message : __( 'It will be back shortly. Thank you for your patience.', 'wordpress-security-plugin' );
	$name    = get_bloginfo( 'name' );

	if ( ! headers_sent() ) {
		status_header( 503 );
		nocache_headers();
		header( 'Retry-After: 3600' );
		header( 'Content-Type: text/html; charset=utf-8' );
		header( 'X-Robots-Tag: noindex' );
	}

	?>
<!doctype html>
<html lang="<?php echo esc_attr( str_replace( '_', '-', get_locale() ) ); ?>">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title><?php echo esc_html( $name ); ?></title>
<style>
:root { color-scheme: dark; }
* { box-sizing: border-box; }
body {
	margin: 0; min-height: 100vh; display: flex; align-items: center; justify-content: center;
	padding: 24px; background: #0e1116; color: #e8eaed;
	font: 400 16px/1.6 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
}
main { width: 100%; max-width: 30rem; text-align: center; }
.brand { font-size: 0.75rem; letter-spacing: 0.18em; text-transform: uppercase; color: #8b93a1; margin: 0 0 1.75rem; }
h1 { font-size: clamp(1.5rem, 5vw, 2rem); line-height: 1.25; margin: 0 0 0.75rem; font-weight: 600; }
p.msg { color: #b6bcc7; margin: 0 0 2.5rem; }
form { display: flex; gap: 0.5rem; justify-content: center; flex-wrap: wrap; }
label { display: block; width: 100%; font-size: 0.8rem; color: #8b93a1; margin-bottom: 0.5rem; }
input {
	width: 10rem; padding: 0.7rem 0.9rem; border-radius: 10px; border: 1px solid #2a313c;
	background: #151a21; color: #e8eaed; font-size: 1.1rem; letter-spacing: 0.25em; text-align: center;
}
input:focus { outline: 2px solid #4b7bec; outline-offset: 1px; }
button {
	padding: 0.7rem 1.2rem; border-radius: 10px; border: 0; background: #e8eaed; color: #0e1116;
	font-size: 0.95rem; font-weight: 600; cursor: pointer;
}
button:hover { background: #fff; }
.error { color: #ff8f8f; font-size: 0.9rem; margin: 0.9rem 0 0; }
</style>
</head>
<body>
<main>
	<?php if ( $name ) : ?>
		<p class="brand"><?php echo esc_html( $name ); ?></p>
	<?php endif; ?>
	<h1><?php echo esc_html( $heading ); ?></h1>
	<p class="msg"><?php echo esc_html( $message ); ?></p>

	<?php if ( wpsp_has_maintenance_code() ) : ?>
		<form method="post" action="">
			<label for="wpsp_code"><?php esc_html_e( 'Have an access code?', 'wordpress-security-plugin' ); ?></label>
			<input id="wpsp_code" name="wpsp_code" type="text" inputmode="numeric" pattern="[0-9]*"
				autocomplete="off" maxlength="12" aria-label="<?php esc_attr_e( 'Access code', 'wordpress-security-plugin' ); ?>">
			<button type="submit"><?php esc_html_e( 'Enter', 'wordpress-security-plugin' ); ?></button>
			<?php if ( '' !== $error ) : ?>
				<p class="error" role="alert"><?php echo esc_html( $error ); ?></p>
			<?php endif; ?>
		</form>
	<?php endif; ?>
</main>
</body>
</html>
	<?php
	exit;
}
