<?php
/**
 * The private sign-in address, attempt limits, and closing the ways usernames leak.
 *
 * The sign-in page moves off /wp-login.php and /wp-admin to an address only the owners know, and the old addresses
 * stop existing for anyone not already signed in: they answer 404 rather than redirecting, so a scanner learns
 * nothing at all about the site. Password resets, logout and the front end's own admin-ajax calls keep working.
 *
 * This is noise reduction, not the main defence. It stops the thousands of automated attempts a day that every
 * public WordPress site receives. Two-step login (see two-factor.php) is what actually protects an account whose
 * password has leaked.
 *
 * Never locked out. Either line in wp-config.php gets an owner back in:
 *     define( 'WPSP_LOGIN_SLUG', 'some-address' );   // use this address instead of the stored one
 *     define( 'WPSP_LOGIN_OFF', true );              // put /wp-login.php back exactly as WordPress ships it
 *
 * @package wordpress-security-plugin
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * The actions on wp-login.php that must stay reachable at the core address, because they are reached from a link in
 * an email or a form a visitor already has.
 *
 * @return string[]
 */
function wpsp_public_login_actions() {
	return array( 'postpass', 'logout', 'lostpassword', 'rp', 'resetpass', 'confirmaction' );
}

/**
 * The files under wp-admin that must keep working for visitors who are not signed in: the first two are used by the
 * front end, the last two serve the login screen's own stylesheets and scripts.
 *
 * @return string[]
 */
function wpsp_public_admin_files() {
	return array( 'admin-ajax.php', 'admin-post.php', 'load-scripts.php', 'load-styles.php' );
}

/**
 * Whether something else on this site is already hiding the sign-in page.
 *
 * Two plugins moving the sign-in page at once would mean two private addresses and two sets of login URL filters
 * fighting each other, which is a good way to be locked out. A theme or plugin that already moves it returns true
 * from this filter, and this plugin steps aside and says so in the admin.
 *
 * @return bool
 */
function wpsp_core_owns_login() {
	return (bool) apply_filters( 'wpsp_login_handled_elsewhere', false );
}

/**
 * Warns that the sign-in settings here are doing nothing while something else holds the address.
 *
 * @return void
 */
function wpsp_core_conflict_notice() {
	if ( ! wpsp_core_owns_login() || ! current_user_can( 'manage_options' ) ) {
		return;
	}

	printf(
		'<div class="notice notice-warning"><p><strong>%s</strong> %s</p></div>',
		esc_html__( 'Another theme or plugin is already using a private sign-in address on this site.', 'wordpress-security-plugin' ),
		esc_html__( 'WordPress Security Plugin has left the sign-in page alone so the two cannot fight over it. Everything else works normally. To move sign-in here instead, switch off the other one first.', 'wordpress-security-plugin' )
	);
}
add_action( 'admin_notices', 'wpsp_core_conflict_notice' );

/**
 * The private sign-in address, or an empty string when the feature is off.
 *
 * @return string
 */
function wpsp_login_slug() {
	if ( defined( 'WPSP_LOGIN_OFF' ) && WPSP_LOGIN_OFF ) {
		return '';
	}

	if ( wpsp_core_owns_login() ) {
		return '';
	}

	if ( defined( 'WPSP_LOGIN_SLUG' ) && is_string( WPSP_LOGIN_SLUG ) && '' !== WPSP_LOGIN_SLUG ) {
		return sanitize_title( WPSP_LOGIN_SLUG );
	}

	return sanitize_title( (string) wpsp_option( 'login_slug', '' ) );
}

/**
 * Whether the private address is in force.
 *
 * @return bool
 */
function wpsp_login_hidden() {
	return '' !== wpsp_login_slug();
}

/**
 * The full sign-in URL.
 *
 * @return string
 */
function wpsp_login_url() {
	$slug = wpsp_login_slug();

	return $slug ? home_url( '/' . $slug . '/' ) : wp_login_url();
}

/**
 * A readable address nobody would guess, offered on the settings screen.
 *
 * @return string
 */
function wpsp_suggest_login_slug() {
	return 'secure-' . strtolower( wp_generate_password( 8, false, false ) );
}

/**
 * Addresses that must not be used, because WordPress or the site already owns them.
 *
 * @return string[]
 */
function wpsp_reserved_slugs() {
	return array(
		'wp-admin', 'wp-login', 'wp-content', 'wp-includes', 'wp-json', 'admin', 'login', 'dashboard',
		'shop', 'cart', 'checkout', 'account', 'my-account', 'blog', 'feed', 'sitemap', 'robots',
		'contact', 'about', 'home', 'search', 'page', 'wp-cron',
	);
}

/**
 * Serves the private address and makes the standard ones disappear.
 *
 * Runs before WordPress works out what the request is, so nothing of wp-login.php is exposed on the way past.
 *
 * @return void
 */
function wpsp_guard_login() {
	if ( ! wpsp_login_hidden() || wpsp_internal_request() ) {
		return;
	}

	$path = wpsp_request_path();
	$slug = wpsp_login_slug();

	if ( $slug === $path ) {
		// Served from wp_loaded: wp-login.php needs constants WordPress only defines later in the boot, and nothing
		// has been sent to the browser by then either.
		add_action( 'wp_loaded', 'wpsp_serve_login_page', 1 );

		return;
	}

	$action = isset( $_GET['action'] ) ? sanitize_key( wp_unslash( $_GET['action'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Reading which login screen was asked for, not acting on it.

	if ( 'wp-login.php' === $path ) {
		if ( in_array( $action, wpsp_public_login_actions(), true ) ) {
			return;
		}
		wpsp_login_not_found();

		return;
	}

	if ( 'wp-admin' === $path || 0 === strpos( $path, 'wp-admin/' ) ) {
		if ( in_array( basename( $path ), wpsp_public_admin_files(), true ) ) {
			return;
		}
		if ( ! is_user_logged_in() ) {
			wpsp_login_not_found();
		}
	}
}
add_action( 'plugins_loaded', 'wpsp_guard_login', 1 );

/**
 * Loads the real login page at the private address.
 *
 * @return void
 */
function wpsp_serve_login_page() {
	global $pagenow, $error, $interim_login, $action, $errors, $redirect_to, $user_login;

	$pagenow = 'wp-login.php'; // phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited -- Serving the login screen from another address.

	if ( ! defined( 'WP_USE_THEMES' ) ) {
		define( 'WP_USE_THEMES', false );
	}

	nocache_headers();

	// wp-login.php includes wp-load.php itself, which is already loaded, so this simply runs the login screen.
	require_once ABSPATH . 'wp-login.php';
	exit;
}

/**
 * Answers a plain 404 and stops.
 *
 * This runs before the theme exists and while the executing script is wp-login.php or a file in wp-admin, so the
 * request cannot be handed to the theme's 404 template. A short unbranded page is what a scanner sees, and it says
 * nothing about what software the site runs.
 *
 * @return void
 */
function wpsp_login_not_found() {
	if ( ! headers_sent() ) {
		status_header( 404 );
		nocache_headers();
		header( 'Content-Type: text/html; charset=utf-8' );
		header( 'X-Robots-Tag: noindex' );
	}

	echo "<!doctype html>\n<html><head><meta charset=\"utf-8\"><title>404 Not Found</title></head><body><h1>Not Found</h1><p>The requested URL was not found on this server.</p></body></html>\n";
	exit;
}

/**
 * Rewrites every sign-in URL WordPress generates so it points at the private address.
 *
 * @param string $url Generated URL.
 * @return string
 */
function wpsp_filter_login_url( $url ) {
	if ( ! wpsp_login_hidden() || ! is_string( $url ) || false === strpos( $url, 'wp-login.php' ) ) {
		return $url;
	}

	$query = (string) wp_parse_url( $url, PHP_URL_QUERY );
	$args  = array();
	if ( $query ) {
		wp_parse_str( $query, $args );
	}

	if ( isset( $args['action'] ) && in_array( $args['action'], wpsp_public_login_actions(), true ) ) {
		return $url;
	}

	$new = home_url( '/' . wpsp_login_slug() . '/' );

	return $args ? add_query_arg( $args, $new ) : $new;
}
add_filter( 'login_url', 'wpsp_filter_login_url', 20 );
add_filter( 'lostpassword_url', 'wpsp_filter_login_url', 20 );
add_filter( 'register_url', 'wpsp_filter_login_url', 20 );
add_filter( 'wp_redirect', 'wpsp_filter_login_url', 20 );

/**
 * The site_url() calls that build the login form's own action attribute.
 *
 * @param string $url    Full URL.
 * @param string $path   Requested path.
 * @param string $scheme Scheme WordPress asked for.
 * @return string
 */
function wpsp_filter_site_url( $url, $path, $scheme ) {
	if ( ! wpsp_login_hidden() || ( 'login' !== $scheme && 'login_post' !== $scheme ) ) {
		return $url;
	}

	return wpsp_filter_login_url( $url );
}
add_filter( 'site_url', 'wpsp_filter_site_url', 20, 3 );
add_filter( 'network_site_url', 'wpsp_filter_site_url', 20, 3 );

/**
 * The rate-limit key for this visitor.
 *
 * @return string
 */
function wpsp_login_key() {
	return 'wpsp_login_' . wpsp_ip_hash();
}

/**
 * Stops a visitor who has already failed too many times, before the password is even checked.
 *
 * @param WP_User|WP_Error|null $user     Result so far.
 * @param string                $username Submitted username.
 * @return WP_User|WP_Error|null
 */
function wpsp_throttle_login( $user, $username ) {
	if ( '' === (string) $username ) {
		return $user;
	}

	$max      = max( 3, (int) wpsp_option( 'login_max_attempts', 5 ) );
	$lockout  = max( 60, (int) wpsp_option( 'login_lockout', 900 ) );
	$attempts = (int) get_transient( wpsp_login_key() );

	if ( $attempts >= $max ) {
		return new WP_Error(
			'wpsp_locked_out',
			sprintf(
				/* translators: %d: number of minutes to wait. */
				esc_html__( 'Too many sign-in attempts. Please wait %d minutes and try again.', 'wordpress-security-plugin' ),
				(int) ceil( $lockout / 60 )
			)
		);
	}

	return $user;
}
add_filter( 'authenticate', 'wpsp_throttle_login', 30, 2 );

/**
 * Counts a failure, and raises the alarm once the limit is reached.
 *
 * @param string $username Username that was tried.
 * @return void
 */
function wpsp_count_login_failure( $username ) {
	$max      = max( 3, (int) wpsp_option( 'login_max_attempts', 5 ) );
	$lockout  = max( 60, (int) wpsp_option( 'login_lockout', 900 ) );
	$attempts = (int) get_transient( wpsp_login_key() ) + 1;

	set_transient( wpsp_login_key(), $attempts, $lockout );

	wpsp_log_event(
		'login_failed',
		'A sign-in attempt failed.',
		$attempts >= $max ? 'warning' : 'notice',
		substr( (string) $username, 0, 60 )
	);

	if ( $attempts === $max ) {
		wpsp_log_event( 'login_lockout', 'A visitor was locked out after repeated failures.', 'warning' );
	}
}
add_action( 'wp_login_failed', 'wpsp_count_login_failure' );

/**
 * Clears the count on a successful sign-in, and emails the owner when an administrator signs in from somewhere new.
 *
 * @param string  $user_login Username.
 * @param WP_User $user       The user.
 * @return void
 */
function wpsp_after_login( $user_login, $user = null ) {
	delete_transient( wpsp_login_key() );

	if ( ! $user instanceof WP_User ) {
		return;
	}

	$privileged = user_can( $user, 'manage_options' ) || user_can( $user, 'manage_woocommerce' );

	wpsp_log_event(
		'login_ok',
		sprintf( '%s signed in.', $user->user_login ),
		'notice',
		$privileged ? 'administrator' : 'user'
	);

	if ( ! $privileged ) {
		return;
	}

	// One stored list of the places an admin has signed in from before. Only the one-way identifier is kept, and the
	// identifier changes daily, so this is a "have we seen this today" check rather than a record of movements.
	$seen    = get_user_meta( $user->ID, 'wpsp_seen', true );
	$seen    = is_array( $seen ) ? $seen : array();
	$current = wpsp_ip_hash();
	$cutoff  = time() - ( 30 * DAY_IN_SECONDS );

	foreach ( $seen as $hash => $time ) {
		if ( (int) $time < $cutoff ) {
			unset( $seen[ $hash ] );
		}
	}

	$known = isset( $seen[ $current ] );

	$seen[ $current ] = time();
	update_user_meta( $user->ID, 'wpsp_seen', array_slice( $seen, -20, 20, true ) );

	if ( $known ) {
		return;
	}

	wpsp_log_event( 'login_new_device', sprintf( '%s signed in from a new device or network.', $user->user_login ), 'warning' );
	wpsp_send_login_alert( $user );
}
add_action( 'wp_login', 'wpsp_after_login', 10, 2 );

/**
 * Emails the owner about an administrator sign-in from somewhere new.
 *
 * Sent in the background on the next cron run rather than during the sign-in, so a slow mail server never delays
 * getting into the admin.
 *
 * @param WP_User $user The user who signed in.
 * @return void
 */
function wpsp_send_login_alert( WP_User $user ) {
	$to = (string) wpsp_option( 'login_alert_email', '' );
	$to = is_email( $to ) ? $to : (string) get_option( 'admin_email' );

	if ( ! is_email( $to ) ) {
		return;
	}

	wp_schedule_single_event(
		time() + 30,
		'wpsp_send_alert',
		array(
			$to,
			sprintf(
				/* translators: %s: site name. */
				__( '[%s] An administrator signed in from a new device', 'wordpress-security-plugin' ),
				get_bloginfo( 'name' )
			),
			sprintf(
				/* translators: 1: username, 2: site URL, 3: date and time. */
				__( "%1\$s signed in to %2\$s on %3\$s from a device or network not seen in the last 30 days.\n\nIf that was you, nothing needs doing. If it was not, change that account's password straight away and check the users list in the admin.", 'wordpress-security-plugin' ),
				$user->user_login,
				home_url( '/' ),
				wp_date( 'j F Y, H:i' )
			),
		)
	);
}

/**
 * Sends a queued alert.
 *
 * @param string $to      Recipient.
 * @param string $subject Subject.
 * @param string $body    Message.
 * @return void
 */
function wpsp_deliver_alert( $to, $subject, $body ) {
	if ( is_email( $to ) ) {
		wp_mail( $to, $subject, $body );
	}
}
add_action( 'wpsp_send_alert', 'wpsp_deliver_alert', 10, 3 );

/**
 * Keeps a failed sign-in from saying which half was wrong, so a wrong username cannot be told from a wrong password.
 *
 * @param WP_Error $errors Login errors.
 * @return WP_Error
 */
function wpsp_vague_login_errors( $errors ) {
	if ( ! is_wp_error( $errors ) || ! $errors->has_errors() ) {
		return $errors;
	}

	$telling = array( 'invalid_username', 'invalid_email', 'incorrect_password', 'empty_password', 'empty_username' );

	foreach ( $errors->get_error_codes() as $code ) {
		if ( in_array( $code, $telling, true ) ) {
			return new WP_Error( 'wpsp_failed', __( '<strong>Error:</strong> Those details are not right.', 'wordpress-security-plugin' ) );
		}
	}

	return $errors;
}
add_filter( 'wp_login_errors', 'wpsp_vague_login_errors', 20 );
add_filter( 'shake_error_codes', static function ( $codes ) {
	$codes[] = 'wpsp_failed';
	$codes[] = 'wpsp_locked_out';

	return $codes;
} );

// The same for the messages WordPress prints straight on the login screen, including password reset attempts for an
// address that has no account.
add_filter( 'login_errors', static function ( $message ) {
	if ( is_string( $message ) && ( false !== strpos( $message, 'is not registered' ) || false !== strpos( $message, 'Invalid username' ) ) ) {
		return __( '<strong>Error:</strong> Those details are not right.', 'wordpress-security-plugin' );
	}

	return $message;
}, 20 );

/**
 * Closes the author archives, the usual way a username is harvested from a WordPress site.
 *
 * @return void
 */
function wpsp_block_author_enumeration() {
	if ( ! wpsp_on( 'block_enumeration' ) || is_admin() || ! isset( $_GET['author'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Reading a public query argument.
		return;
	}

	if ( is_numeric( wp_unslash( $_GET['author'] ) ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		wp_safe_redirect( home_url( '/' ), 301 );
		exit;
	}
}
add_action( 'template_redirect', 'wpsp_block_author_enumeration', 0 );

/**
 * The users REST route is for people who may already list users.
 *
 * @param mixed           $result  Result so far.
 * @param WP_REST_Server  $server  Server.
 * @param WP_REST_Request $request Request.
 * @return mixed
 */
function wpsp_restrict_users_route( $result, $server, $request ) {
	if ( null !== $result || ! wpsp_on( 'block_enumeration' ) ) {
		return $result;
	}

	if ( 0 !== strpos( (string) $request->get_route(), '/wp/v2/users' ) || current_user_can( 'list_users' ) ) {
		return $result;
	}

	return new WP_Error( 'wpsp_rest_forbidden', __( 'You cannot list users.', 'wordpress-security-plugin' ), array( 'status' => 401 ) );
}
add_filter( 'rest_pre_dispatch', 'wpsp_restrict_users_route', 10, 3 );
