<?php
/**
 * Two-step login with a code from an authenticator app.
 *
 * After the password is accepted, the account is asked for the six-digit number showing in Google Authenticator,
 * Microsoft Authenticator, 1Password, Bitwarden or any other app that supports standard one-time codes. The code
 * changes every 30 seconds and is worked out from a shared key, so nothing is sent by email or text and the site
 * makes no outside calls.
 *
 * Standards used: the key is a base32 secret, the code is TOTP (RFC 6238) over HMAC-SHA1 with a 30 second step and
 * six digits, which is what every authenticator app expects. One step either side of now is accepted, so a phone
 * whose clock is slightly out still works. A code that has been used once cannot be used again, which closes the
 * window where someone watching the screen could replay it.
 *
 * Getting back in without the phone: ten single-use backup codes are shown at setup, each usable once. Failing that,
 * an owner with file access adds this to wp-config.php:
 *     define( 'WPSP_2FA_OFF', true );
 *
 * @package wordpress-security-plugin
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/** The shape of the codes, matching what authenticator apps produce. */
const WPSP_TOTP_DIGITS = 6;
const WPSP_TOTP_STEP   = 30;
const WPSP_TOTP_DRIFT  = 1;

/** How long the half-finished sign-in stays open while the code is typed. */
const WPSP_2FA_WINDOW = 600;

/**
 * Whether two-step login is switched on for this site.
 *
 * @return bool
 */
function wpsp_2fa_active() {
	if ( defined( 'WPSP_2FA_OFF' ) && WPSP_2FA_OFF ) {
		return false;
	}

	return wpsp_on( 'twofactor_enabled' );
}

/**
 * Whether an account has finished setting up two-step login.
 *
 * @param int $user_id User.
 * @return bool
 */
function wpsp_2fa_enabled_for( $user_id ) {
	return '' !== (string) get_user_meta( (int) $user_id, 'wpsp_totp_secret', true );
}

/**
 * Whether an account must use two-step login.
 *
 * @param WP_User $user The user.
 * @return bool
 */
function wpsp_2fa_required_for( WP_User $user ) {
	if ( ! wpsp_2fa_active() ) {
		return false;
	}

	if ( ! wpsp_on( 'twofactor_required' ) ) {
		return wpsp_2fa_enabled_for( $user->ID );
	}

	return user_can( $user, 'manage_options' ) || user_can( $user, 'edit_others_posts' ) || wpsp_2fa_enabled_for( $user->ID );
}

/* -------------------------------------------------------------------------
 * The maths
 * ---------------------------------------------------------------------- */

/**
 * A new random key, in the base32 form authenticator apps accept.
 *
 * @return string
 */
function wpsp_totp_new_secret() {
	$alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
	$secret   = '';

	// 160 bits, the length RFC 4226 recommends, as 32 base32 characters.
	$bytes = random_bytes( 20 );
	$bits  = '';
	for ( $i = 0, $len = strlen( $bytes ); $i < $len; $i++ ) {
		$bits .= str_pad( decbin( ord( $bytes[ $i ] ) ), 8, '0', STR_PAD_LEFT );
	}

	foreach ( str_split( $bits, 5 ) as $chunk ) {
		if ( 5 === strlen( $chunk ) ) {
			$secret .= $alphabet[ bindec( $chunk ) ];
		}
	}

	return $secret;
}

/**
 * Turns a base32 key back into raw bytes.
 *
 * @param string $secret Base32 key.
 * @return string Raw bytes, or an empty string when the key is not valid base32.
 */
function wpsp_base32_decode( $secret ) {
	$alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
	$secret   = strtoupper( preg_replace( '/[^A-Za-z2-7]/', '', (string) $secret ) );

	if ( '' === $secret ) {
		return '';
	}

	$bits = '';
	for ( $i = 0, $len = strlen( $secret ); $i < $len; $i++ ) {
		$index = strpos( $alphabet, $secret[ $i ] );
		if ( false === $index ) {
			return '';
		}
		$bits .= str_pad( decbin( $index ), 5, '0', STR_PAD_LEFT );
	}

	$bytes = '';
	foreach ( str_split( $bits, 8 ) as $chunk ) {
		if ( 8 === strlen( $chunk ) ) {
			$bytes .= chr( bindec( $chunk ) );
		}
	}

	return $bytes;
}

/**
 * The code for one 30-second step, as an authenticator app would show it.
 *
 * @param string $secret Base32 key.
 * @param int    $step   Which step; the current one when omitted.
 * @return string Six digits, or an empty string when the key is unusable.
 */
function wpsp_totp_code( $secret, $step = null ) {
	$key = wpsp_base32_decode( $secret );

	if ( '' === $key ) {
		return '';
	}

	$step = null === $step ? (int) floor( time() / WPSP_TOTP_STEP ) : (int) $step;

	// The counter, as eight bytes, most significant first.
	$counter = '';
	for ( $i = 7; $i >= 0; $i-- ) {
		$counter = chr( $step & 0xFF ) . $counter;
		$step   >>= 8;
	}

	$hash   = hash_hmac( 'sha1', $counter, $key, true );
	$offset = ord( $hash[19] ) & 0x0F;

	$value = ( ( ord( $hash[ $offset ] ) & 0x7F ) << 24 )
		| ( ( ord( $hash[ $offset + 1 ] ) & 0xFF ) << 16 )
		| ( ( ord( $hash[ $offset + 2 ] ) & 0xFF ) << 8 )
		| ( ord( $hash[ $offset + 3 ] ) & 0xFF );

	return str_pad( (string) ( $value % ( 10 ** WPSP_TOTP_DIGITS ) ), WPSP_TOTP_DIGITS, '0', STR_PAD_LEFT );
}

/**
 * Checks a typed code against the key, allowing one step of clock drift either way, and refuses a code that has
 * already been used.
 *
 * @param int    $user_id User.
 * @param string $secret  Base32 key.
 * @param string $given   What was typed.
 * @return bool
 */
function wpsp_totp_verify( $user_id, $secret, $given ) {
	$given = preg_replace( '/\D/', '', (string) $given );

	if ( strlen( $given ) !== WPSP_TOTP_DIGITS ) {
		return false;
	}

	$now = (int) floor( time() / WPSP_TOTP_STEP );

	for ( $drift = -WPSP_TOTP_DRIFT; $drift <= WPSP_TOTP_DRIFT; $drift++ ) {
		$step = $now + $drift;
		if ( hash_equals( wpsp_totp_code( $secret, $step ), $given ) ) {
			// One code, one use.
			$last = (int) get_user_meta( (int) $user_id, 'wpsp_totp_last', true );
			if ( $step <= $last ) {
				return false;
			}
			update_user_meta( (int) $user_id, 'wpsp_totp_last', $step );

			return true;
		}
	}

	return false;
}

/**
 * The otpauth:// address an authenticator app reads, whether from a QR code or pasted by hand.
 *
 * @param WP_User $user   The account.
 * @param string  $secret Base32 key.
 * @return string
 */
function wpsp_totp_uri( WP_User $user, $secret ) {
	$issuer  = wp_specialchars_decode( (string) get_bloginfo( 'name' ), ENT_QUOTES );
	$issuer  = '' !== trim( $issuer ) ? trim( $issuer ) : wpsp_site_host();
	$label   = $issuer . ':' . $user->user_login;

	return 'otpauth://totp/' . rawurlencode( $label ) . '?' . http_build_query(
		array(
			'secret'    => $secret,
			'issuer'    => $issuer,
			'algorithm' => 'SHA1',
			'digits'    => WPSP_TOTP_DIGITS,
			'period'    => WPSP_TOTP_STEP,
		),
		'',
		'&',
		PHP_QUERY_RFC3986
	);
}

/* -------------------------------------------------------------------------
 * Backup codes
 * ---------------------------------------------------------------------- */

/**
 * Makes ten fresh single-use backup codes, stores only their hashes, and returns the codes to show once.
 *
 * @param int $user_id User.
 * @return string[] The codes in plain text, to be shown now and never again.
 */
function wpsp_new_backup_codes( $user_id ) {
	$codes  = array();
	$hashes = array();

	for ( $i = 0; $i < 10; $i++ ) {
		$code     = strtolower( wp_generate_password( 10, false, false ) );
		$codes[]  = $code;
		$hashes[] = wp_hash_password( $code );
	}

	update_user_meta( (int) $user_id, 'wpsp_backup_codes', $hashes );

	return $codes;
}

/**
 * How many backup codes are left unused.
 *
 * @param int $user_id User.
 * @return int
 */
function wpsp_backup_codes_left( $user_id ) {
	$hashes = get_user_meta( (int) $user_id, 'wpsp_backup_codes', true );

	return is_array( $hashes ) ? count( $hashes ) : 0;
}

/**
 * Spends a backup code if it matches one that has not been used.
 *
 * @param int    $user_id User.
 * @param string $given   What was typed.
 * @return bool
 */
function wpsp_use_backup_code( $user_id, $given ) {
	$given  = strtolower( trim( preg_replace( '/[^A-Za-z0-9]/', '', (string) $given ) ) );
	$hashes = get_user_meta( (int) $user_id, 'wpsp_backup_codes', true );

	if ( '' === $given || ! is_array( $hashes ) ) {
		return false;
	}

	foreach ( $hashes as $index => $hash ) {
		if ( wp_check_password( $given, (string) $hash ) ) {
			unset( $hashes[ $index ] );
			update_user_meta( (int) $user_id, 'wpsp_backup_codes', array_values( $hashes ) );
			wpsp_log_event( 'twofactor_backup', 'A backup code was used to sign in.', 'warning' );

			return true;
		}
	}

	return false;
}

/* -------------------------------------------------------------------------
 * The second step of signing in
 * ---------------------------------------------------------------------- */

/**
 * After the password is accepted, holds the sign-in and asks for the code.
 *
 * Done by catching the authenticated user before WordPress sets the login cookie: a short-lived, signed token stands
 * in for the half-finished sign-in, so no session exists until the code is right.
 *
 * @param string  $user_login Username.
 * @param WP_User $user       The user.
 * @return void
 */
function wpsp_2fa_interrupt( $user_login, $user ) {
	if ( ! $user instanceof WP_User || ! wpsp_2fa_required_for( $user ) ) {
		return;
	}

	// An account that must use two-step login but has not set it up yet is let in and nagged in the admin, rather
	// than locked out of its own site.
	if ( ! wpsp_2fa_enabled_for( $user->ID ) ) {
		update_user_meta( $user->ID, 'wpsp_2fa_nag', 1 );

		return;
	}

	$redirect = isset( $_REQUEST['redirect_to'] ) ? (string) wp_unslash( $_REQUEST['redirect_to'] ) : admin_url(); // phpcs:ignore WordPress.Security.NonceVerification.Missing -- WordPress has already authenticated this request.

	// Undo the session WordPress has just started: nothing is signed in until the code is accepted.
	wp_clear_auth_cookie();
	wp_set_current_user( 0 );

	$token = wp_generate_password( 32, false, false );
	set_transient( 'wpsp_2fa_' . hash( 'sha256', $token ), (int) $user->ID, WPSP_2FA_WINDOW );

	wpsp_render_2fa_form( $token, $redirect, '' );
}
add_action( 'wp_login', 'wpsp_2fa_interrupt', 5, 2 );

/**
 * Handles the submitted code and finishes the sign-in.
 *
 * @return void
 */
function wpsp_2fa_submission() {
	if ( empty( $_POST['wpsp_2fa_token'] ) || empty( $_POST['wpsp_2fa'] ) ) {
		return;
	}

	$token = (string) wp_unslash( $_POST['wpsp_2fa_token'] ); // phpcs:ignore WordPress.Security.ValidationSanitization.InputNotSanitized -- Used only as a lookup key.
	$key   = 'wpsp_2fa_' . hash( 'sha256', $token );
	$id    = (int) get_transient( $key );

	$redirect = isset( $_POST['redirect_to'] ) ? (string) wp_unslash( $_POST['redirect_to'] ) : admin_url(); // phpcs:ignore WordPress.Security.ValidationSanitization.InputNotSanitized -- Passed through wp_safe_redirect.

	if ( ! $id ) {
		wpsp_render_2fa_form( '', $redirect, __( 'That took too long. Please sign in again.', 'wordpress-security-plugin' ) );
	}

	$attempt_key = 'wpsp_2fa_tries_' . $id;
	$attempts    = (int) get_transient( $attempt_key );

	if ( $attempts >= 5 ) {
		delete_transient( $key );
		wpsp_log_event( 'twofactor_lockout', 'Too many wrong codes at the second step.', 'warning' );
		wpsp_render_2fa_form( '', $redirect, __( 'Too many wrong codes. Please sign in again in a few minutes.', 'wordpress-security-plugin' ) );
	}

	$user = get_userdata( $id );
	if ( ! $user instanceof WP_User ) {
		delete_transient( $key );
		wpsp_render_2fa_form( '', $redirect, __( 'Please sign in again.', 'wordpress-security-plugin' ) );
	}

	$given  = (string) wp_unslash( $_POST['wpsp_2fa'] ); // phpcs:ignore WordPress.Security.ValidationSanitization.InputNotSanitized -- Reduced to digits or letters inside the verifiers.
	$secret = (string) get_user_meta( $user->ID, 'wpsp_totp_secret', true );

	$ok = wpsp_totp_verify( $user->ID, $secret, $given ) || wpsp_use_backup_code( $user->ID, $given );

	if ( ! $ok ) {
		set_transient( $attempt_key, $attempts + 1, 15 * MINUTE_IN_SECONDS );
		wpsp_log_event( 'twofactor_failed', sprintf( 'A wrong second-step code for %s.', $user->user_login ), 'warning' );
		wpsp_render_2fa_form( $token, $redirect, __( 'That code is not right. Check the app and try the next one.', 'wordpress-security-plugin' ) );
	}

	delete_transient( $key );
	delete_transient( $attempt_key );

	$remember = ! empty( $_POST['rememberme'] );
	wp_set_auth_cookie( $user->ID, $remember );
	wp_set_current_user( $user->ID );

	wpsp_log_event( 'twofactor_ok', sprintf( '%s completed two-step sign-in.', $user->user_login ), 'notice' );

	$target = wp_validate_redirect( $redirect, admin_url() );
	wp_safe_redirect( $target );
	exit;
}
add_action( 'login_init', 'wpsp_2fa_submission', 5 );

/**
 * Draws the "enter your code" screen and stops.
 *
 * Uses WordPress's own login layout, so it looks like part of signing in rather than something bolted on.
 *
 * @param string $token    The half-finished sign-in's token, or empty when it has expired.
 * @param string $redirect Where to go afterwards.
 * @param string $error    Message to show.
 * @return void
 */
function wpsp_render_2fa_form( $token, $redirect, $error ) {
	nocache_headers();

	$action = wpsp_login_hidden() ? wpsp_login_url() : wp_login_url();

	// login_header() and login_footer() live in wp-login.php, which is already running whenever this screen is
	// reached through signing in. If some other flow ever lands here, a plain page is shown instead of loading
	// wp-login.php a second time, which would run the whole login script again.
	if ( ! function_exists( 'login_header' ) ) {
		wpsp_render_plain_2fa_form( $token, $redirect, $error, $action );
	}

	login_header(
		__( 'Two-step sign-in', 'wordpress-security-plugin' ),
		'' !== $error ? '<div id="login_error">' . esc_html( $error ) . '</div>' : '<p class="message">' . esc_html__( 'Enter the six-digit code from your authenticator app.', 'wordpress-security-plugin' ) . '</p>'
	);
	?>
	<form name="wpsp_2fa_form" method="post" action="<?php echo esc_url( $action ); ?>">
		<p>
			<label for="wpsp_2fa"><?php esc_html_e( 'Code', 'wordpress-security-plugin' ); ?></label>
			<input type="text" name="wpsp_2fa" id="wpsp_2fa" class="input" value="" size="20"
				inputmode="numeric" autocomplete="one-time-code" autocapitalize="off" autocorrect="off" autofocus
				<?php echo '' === $token ? 'disabled' : ''; ?>>
		</p>
		<p class="description" style="margin-bottom:1em">
			<?php esc_html_e( 'No phone to hand? Type one of your backup codes instead.', 'wordpress-security-plugin' ); ?>
		</p>
		<input type="hidden" name="wpsp_2fa_token" value="<?php echo esc_attr( $token ); ?>">
		<input type="hidden" name="redirect_to" value="<?php echo esc_attr( $redirect ); ?>">
		<?php if ( ! empty( $_POST['rememberme'] ) ) : // phpcs:ignore WordPress.Security.NonceVerification.Missing -- Carrying the earlier choice forward. ?>
			<input type="hidden" name="rememberme" value="forever">
		<?php endif; ?>
		<p class="submit">
			<input type="submit" class="button button-primary button-large" value="<?php esc_attr_e( 'Continue', 'wordpress-security-plugin' ); ?>"
				<?php echo '' === $token ? 'disabled' : ''; ?>>
		</p>
		<?php if ( '' === $token ) : ?>
			<p><a href="<?php echo esc_url( $action ); ?>"><?php esc_html_e( 'Start again', 'wordpress-security-plugin' ); ?></a></p>
		<?php endif; ?>
	</form>
	<?php
	login_footer( 'wpsp_2fa' );
	exit;
}

/**
 * The same screen without WordPress's login layout, for the rare flow that reaches it outside wp-login.php.
 *
 * @param string $token    Half-finished sign-in token.
 * @param string $redirect Where to go afterwards.
 * @param string $error    Message to show.
 * @param string $action   Where the form posts.
 * @return void
 */
function wpsp_render_plain_2fa_form( $token, $redirect, $error, $action ) {
	if ( ! headers_sent() ) {
		status_header( 200 );
		header( 'Content-Type: text/html; charset=utf-8' );
		header( 'X-Robots-Tag: noindex' );
	}
	?>
<!doctype html>
<html lang="<?php echo esc_attr( str_replace( '_', '-', get_locale() ) ); ?>">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex"><title><?php esc_html_e( 'Two-step sign-in', 'wordpress-security-plugin' ); ?></title>
<style>body{font:16px/1.6 system-ui,sans-serif;max-width:22rem;margin:4rem auto;padding:0 1rem}
input{width:100%;padding:.6rem;font-size:1.1rem;margin:.4rem 0 1rem}button{padding:.6rem 1.2rem;font-size:1rem}
.e{color:#b32d2e}</style></head>
<body>
<h1 style="font-size:1.25rem"><?php esc_html_e( 'Two-step sign-in', 'wordpress-security-plugin' ); ?></h1>
<?php if ( '' !== $error ) : ?><p class="e"><?php echo esc_html( $error ); ?></p><?php endif; ?>
<form method="post" action="<?php echo esc_url( $action ); ?>">
	<label for="wpsp_2fa"><?php esc_html_e( 'Code from your authenticator app', 'wordpress-security-plugin' ); ?></label>
	<input type="text" id="wpsp_2fa" name="wpsp_2fa" inputmode="numeric" autocomplete="one-time-code" autofocus>
	<input type="hidden" name="wpsp_2fa_token" value="<?php echo esc_attr( $token ); ?>">
	<input type="hidden" name="redirect_to" value="<?php echo esc_attr( $redirect ); ?>">
	<button type="submit"><?php esc_html_e( 'Continue', 'wordpress-security-plugin' ); ?></button>
</form>
</body></html>
	<?php
	exit;
}

/**
 * The "set up two-step login" section on an account's own profile screen.
 *
 * @param WP_User $user The account being edited.
 * @return void
 */
function wpsp_2fa_profile_section( $user ) {
	// Setting up someone else's authenticator app is not possible, and should not look possible.
	if ( ! wpsp_2fa_active() || get_current_user_id() !== $user->ID ) {
		return;
	}

	$enabled = wpsp_2fa_enabled_for( $user->ID );
	$pending = (string) get_user_meta( $user->ID, 'wpsp_totp_pending', true );

	if ( ! $enabled && '' === $pending ) {
		$pending = wpsp_totp_new_secret();
		update_user_meta( $user->ID, 'wpsp_totp_pending', $pending );
	}

	$secret = $enabled ? '' : $pending;
	$codes  = get_user_meta( $user->ID, 'wpsp_backup_codes_plain', true );

	if ( is_array( $codes ) && $codes ) {
		// Shown once, immediately after they are made, then removed from the database.
		delete_user_meta( $user->ID, 'wpsp_backup_codes_plain' );
	}
	?>
	<h2 id="wordpress-security-plugin-2fa"><?php esc_html_e( 'Two-step sign-in', 'wordpress-security-plugin' ); ?></h2>
	<table class="form-table" role="presentation">
		<tr>
			<th scope="row"><?php esc_html_e( 'Status', 'wordpress-security-plugin' ); ?></th>
			<td>
				<?php if ( $enabled ) : ?>
					<p>
						<strong><?php esc_html_e( 'On.', 'wordpress-security-plugin' ); ?></strong>
						<?php
						printf(
							/* translators: %d: number of unused backup codes. */
							esc_html__( 'Signing in asks for a code from your app. You have %d backup codes left.', 'wordpress-security-plugin' ),
							(int) wpsp_backup_codes_left( $user->ID )
						);
						?>
					</p>
					<p>
						<button type="submit" name="wpsp_2fa_action" value="codes" class="button"><?php esc_html_e( 'Make new backup codes', 'wordpress-security-plugin' ); ?></button>
						<button type="submit" name="wpsp_2fa_action" value="off" class="button button-link-delete"><?php esc_html_e( 'Turn two-step sign-in off', 'wordpress-security-plugin' ); ?></button>
					</p>
				<?php else : ?>
					<p><?php esc_html_e( 'Off. Three steps to set it up:', 'wordpress-security-plugin' ); ?></p>
					<ol style="max-width:40em">
						<li><?php esc_html_e( 'Install an authenticator app on your phone: Google Authenticator, Microsoft Authenticator, 1Password or Bitwarden all work.', 'wordpress-security-plugin' ); ?></li>
						<li>
							<p style="margin:0.5em 0 0.8em;font-weight:600;">
								<?php esc_html_e( 'Scan this QR code with your authenticator app:', 'wordpress-security-plugin' ); ?>
							</p>
							<div style="background:#fff;padding:12px;display:inline-block;border:1px solid #ccd0d4;border-radius:4px;box-shadow:0 1px 3px rgba(0,0,0,0.05);margin-bottom:0.8em;">
								<?php echo wpsp_qr_svg( wpsp_totp_uri( $user, $secret ), 4 ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- SVG generated internally. ?>
							</div>
							<p style="margin:0 0 0.8em;">
								<a href="<?php echo esc_url( wpsp_totp_uri( $user, $secret ) ); ?>" class="button button-secondary" style="vertical-align:middle;">
									<?php esc_html_e( 'Open directly in an app on this device', 'wordpress-security-plugin' ); ?>
								</a>
							</p>
							<details style="margin:0.8em 0 1.2em;background:#f6f7f7;padding:12px 14px;border-radius:4px;border:1px solid #dcdcde;">
								<summary style="cursor:pointer;font-weight:600;color:#2271b1;">
									<?php esc_html_e( 'Cannot scan? Enter setup key manually', 'wordpress-security-plugin' ); ?>
								</summary>
								<div style="margin-top:10px;">
									<p style="margin:0 0 6px;">
										<?php esc_html_e( 'Key (no spaces):', 'wordpress-security-plugin' ); ?>
									</p>
									<div style="display:flex;align-items:center;gap:8px;max-width:32em;">
										<input type="text" id="wordpress-security-plugin-secret-key" readonly value="<?php echo esc_attr( $secret ); ?>"
											style="font-family:monospace;font-size:1.1em;letter-spacing:0.08em;padding:6px 10px;background:#fff;width:100%;cursor:text;"
											onclick="this.select();">
										<button type="button" class="button" id="wordpress-security-plugin-copy-key" onclick="navigator.clipboard.writeText('<?php echo esc_js( $secret ); ?>');this.innerText='Copied!';setTimeout(()=>this.innerText='Copy',2000);">
											<?php esc_html_e( 'Copy', 'wordpress-security-plugin' ); ?>
										</button>
									</div>
									<p class="description" style="margin-top:6px;">
										<?php esc_html_e( 'Account name: your username. Key type: time-based. Do not include spaces if entering manually.', 'wordpress-security-plugin' ); ?>
									</p>
								</div>
							</details>
						</li>
						<li>
							<label for="wpsp_2fa_confirm"><?php esc_html_e( 'Type the six-digit code the app now shows, then save this profile:', 'wordpress-security-plugin' ); ?></label><br>
							<input type="text" id="wpsp_2fa_confirm" name="wpsp_2fa_confirm" class="regular-text" style="max-width:10em"
								inputmode="numeric" autocomplete="off" value="">
						</li>
					</ol>
				<?php endif; ?>

				<?php if ( is_array( $codes ) && $codes ) : ?>
					<div class="notice notice-warning inline" style="margin-top:1em">
						<p><strong><?php esc_html_e( 'Your backup codes. Save them now: they are not shown again.', 'wordpress-security-plugin' ); ?></strong></p>
						<p style="font-family:monospace;line-height:2"><?php echo esc_html( implode( '   ', $codes ) ); ?></p>
						<p><?php esc_html_e( 'Each one works once, in place of a code from the app, if you ever lose the phone.', 'wordpress-security-plugin' ); ?></p>
					</div>
				<?php endif; ?>
			</td>
		</tr>
	</table>
	<?php
}
add_action( 'show_user_profile', 'wpsp_2fa_profile_section' );

/**
 * Saves what the profile screen submitted.
 *
 * @param int $user_id The account being saved.
 * @return void
 */
function wpsp_2fa_profile_save( $user_id ) {
	$user_id = (int) $user_id;

	if ( get_current_user_id() !== $user_id || ! current_user_can( 'edit_user', $user_id ) ) {
		return;
	}

	$action = isset( $_POST['wpsp_2fa_action'] ) ? sanitize_key( wp_unslash( $_POST['wpsp_2fa_action'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Missing -- WordPress checks the profile nonce before this hook.

	if ( 'off' === $action ) {
		delete_user_meta( $user_id, 'wpsp_totp_secret' );
		delete_user_meta( $user_id, 'wpsp_backup_codes' );
		delete_user_meta( $user_id, 'wpsp_totp_last' );
		wpsp_log_event( 'twofactor_off', 'Two-step sign-in was switched off for an account.', 'warning' );

		return;
	}

	if ( 'codes' === $action && wpsp_2fa_enabled_for( $user_id ) ) {
		update_user_meta( $user_id, 'wpsp_backup_codes_plain', wpsp_new_backup_codes( $user_id ) );

		return;
	}

	$confirm = isset( $_POST['wpsp_2fa_confirm'] ) ? (string) wp_unslash( $_POST['wpsp_2fa_confirm'] ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Missing, WordPress.Security.ValidationSanitization.InputNotSanitized -- Reduced to digits in the verifier.
	$confirm = preg_replace( '/\D/', '', $confirm );

	if ( '' === $confirm || wpsp_2fa_enabled_for( $user_id ) ) {
		return;
	}

	$pending = (string) get_user_meta( $user_id, 'wpsp_totp_pending', true );

	if ( '' === $pending || ! wpsp_totp_verify( $user_id, $pending, $confirm ) ) {
		// The profile screen says what went wrong through the nag notice, so nothing is stored here.
		update_user_meta( $user_id, 'wpsp_2fa_error', 1 );

		return;
	}

	update_user_meta( $user_id, 'wpsp_totp_secret', $pending );
	delete_user_meta( $user_id, 'wpsp_totp_pending' );
	delete_user_meta( $user_id, 'wpsp_2fa_nag' );
	delete_user_meta( $user_id, 'wpsp_2fa_error' );
	update_user_meta( $user_id, 'wpsp_backup_codes_plain', wpsp_new_backup_codes( $user_id ) );

	wpsp_log_event( 'twofactor_on', 'Two-step sign-in was set up for an account.', 'notice' );
}
add_action( 'personal_options_update', 'wpsp_2fa_profile_save' );

/**
 * Reminds an account that has to use two-step login but has not set it up, and says when a code did not match.
 *
 * @return void
 */
function wpsp_2fa_notices() {
	if ( ! wpsp_2fa_active() ) {
		return;
	}

	$user_id = get_current_user_id();

	if ( get_user_meta( $user_id, 'wpsp_2fa_error', true ) ) {
		delete_user_meta( $user_id, 'wpsp_2fa_error' );
		echo '<div class="notice notice-error"><p>' . esc_html__( 'That code did not match, so two-step sign-in was not switched on. Codes change every 30 seconds, so try again with the one showing now.', 'wordpress-security-plugin' ) . '</p></div>';
	}

	if ( wpsp_2fa_enabled_for( $user_id ) ) {
		return;
	}

	$user = wp_get_current_user();

	if ( ! $user instanceof WP_User || ! wpsp_2fa_required_for( $user ) ) {
		return;
	}

	printf(
		'<div class="notice notice-warning"><p><strong>%s</strong> %s <a href="%s">%s</a></p></div>',
		esc_html__( 'Two-step sign-in is not set up on your account.', 'wordpress-security-plugin' ),
		esc_html__( 'It takes two minutes and is the single best protection for an administrator account.', 'wordpress-security-plugin' ),
		esc_url( admin_url( 'profile.php#wordpress-security-plugin-2fa' ) ),
		esc_html__( 'Set it up now', 'wordpress-security-plugin' )
	);
}
add_action( 'admin_notices', 'wpsp_2fa_notices' );
