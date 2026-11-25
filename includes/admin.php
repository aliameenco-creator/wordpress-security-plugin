<?php
/**
 * The admin screens.
 *
 * Four tabs under a top-level "WordPress Security Plugin" menu: an overview of what is on and what happened, the login settings,
 * the bot settings, and the reporting key. Plain language throughout: these screens are read by the site's owner,
 * not by a developer, so each setting says what it does and what the cost of switching it off is.
 *
 * @package wordpress-security-plugin
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Adds the menu.
 *
 * @return void
 */
function wpsp_admin_menu() {
	add_menu_page(
		__( 'WordPress Security Plugin', 'wordpress-security-plugin' ),
		__( 'WordPress Security Plugin', 'wordpress-security-plugin' ),
		'manage_options',
		'wordpress-security-plugin',
		'wpsp_admin_page',
		'dashicons-shield-alt',
		// A string just past Settings (80), so landing on the same position cannot displace another plugin's menu.
		'80.7'
	);
}
add_action( 'admin_menu', 'wpsp_admin_menu' );

/**
 * The tabs.
 *
 * @return array<string, string>
 */
function wpsp_admin_tabs() {
	return array(
		'overview'    => __( 'Overview', 'wordpress-security-plugin' ),
		'login'       => __( 'Sign-in', 'wordpress-security-plugin' ),
		'bots'        => __( 'Bots and scraping', 'wordpress-security-plugin' ),
		'maintenance' => __( 'Maintenance mode', 'wordpress-security-plugin' ),
		'reporting'   => __( 'Daily report', 'wordpress-security-plugin' ),
	);
}

/**
 * Draws the page.
 *
 * @return void
 */
function wpsp_admin_page() {
	if ( ! current_user_can( 'manage_options' ) ) {
		wp_die( esc_html__( 'You cannot change these settings.', 'wordpress-security-plugin' ) );
	}

	$tabs    = wpsp_admin_tabs();
	$current = isset( $_GET['tab'] ) ? sanitize_key( wp_unslash( $_GET['tab'] ) ) : 'overview'; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Choosing which tab to draw.
	$current = isset( $tabs[ $current ] ) ? $current : 'overview';

	$notices = wpsp_handle_admin_post( $current );
	?>
	<div class="wrap">
		<h1><?php esc_html_e( 'WordPress Security Plugin', 'wordpress-security-plugin' ); ?></h1>

		<nav class="nav-tab-wrapper" style="margin-bottom:1.5em">
			<?php foreach ( $tabs as $slug => $label ) : ?>
				<a class="nav-tab <?php echo $slug === $current ? 'nav-tab-active' : ''; ?>"
					href="<?php echo esc_url( admin_url( 'admin.php?page=wordpress-security-plugin&tab=' . $slug ) ); ?>">
					<?php echo esc_html( $label ); ?>
				</a>
			<?php endforeach; ?>
		</nav>

		<?php foreach ( $notices as $notice ) : ?>
			<div class="notice notice-<?php echo esc_attr( $notice['type'] ); ?>">
				<p><?php echo wp_kses_post( $notice['text'] ); ?></p>
			</div>
		<?php endforeach; ?>

		<?php
		switch ( $current ) {
			case 'login':
				wpsp_tab_login();
				break;
			case 'bots':
				wpsp_tab_bots();
				break;
			case 'maintenance':
				wpsp_tab_maintenance();
				break;
			case 'reporting':
				wpsp_tab_reporting();
				break;
			default:
				wpsp_tab_overview();
		}
		?>
	</div>
	<?php
}

/**
 * Saves whichever tab was submitted.
 *
 * @param string $tab The tab being shown.
 * @return array<int, array{type: string, text: string}>
 */
function wpsp_handle_admin_post( $tab ) {
	$notices = array();

	if ( 'POST' !== ( $_SERVER['REQUEST_METHOD'] ?? '' ) || ! isset( $_POST['wpsp_tab'] ) ) {
		return $notices;
	}

	$submitted = sanitize_key( wp_unslash( $_POST['wpsp_tab'] ) );
	check_admin_referer( 'wpsp_save_' . $submitted );

	$post = wp_unslash( $_POST ); // phpcs:ignore WordPress.Security.ValidationSanitization.InputNotSanitized -- Each field is sanitized where it is read below.
	$flag = static function ( $key ) use ( $post ) {
		return ! empty( $post[ $key ] );
	};

	switch ( $submitted ) {
		case 'login':
			$slug     = sanitize_title( (string) ( $post['login_slug'] ?? '' ) );
			$changes  = array(
				'login_max_attempts' => max( 3, min( 20, (int) ( $post['login_max_attempts'] ?? 5 ) ) ),
				'login_lockout'      => max( 60, min( 86400, (int) ( $post['login_lockout'] ?? 900 ) ) ),
				'login_alert_email'  => is_email( (string) ( $post['login_alert_email'] ?? '' ) ) ? sanitize_email( (string) $post['login_alert_email'] ) : '',
				'block_enumeration'  => $flag( 'block_enumeration' ),
				'twofactor_enabled'  => $flag( 'twofactor_enabled' ),
				'twofactor_required' => $flag( 'twofactor_required' ),
				'security_headers'   => $flag( 'security_headers' ),
				'hsts'               => $flag( 'hsts' ),
				'disable_xmlrpc'     => $flag( 'disable_xmlrpc' ),
				'disable_file_edit'  => $flag( 'disable_file_edit' ),
				'hide_wp_version'    => $flag( 'hide_wp_version' ),
				'limit_app_passwords' => $flag( 'limit_app_passwords' ),
				'block_sensitive'    => $flag( 'block_sensitive' ),
			);

			if ( '' === $slug ) {
				$changes['login_slug'] = '';
				$notices[]             = array(
					'type' => 'info',
					'text' => esc_html__( 'The private sign-in address is off. WordPress is back to /wp-login.php.', 'wordpress-security-plugin' ),
				);
			} elseif ( in_array( $slug, wpsp_reserved_slugs(), true ) ) {
				$notices[] = array( 'type' => 'error', 'text' => esc_html__( 'That address is already used by WordPress or the site. Choose another.', 'wordpress-security-plugin' ) );
			} elseif ( strlen( $slug ) < 5 ) {
				$notices[] = array( 'type' => 'error', 'text' => esc_html__( 'Use at least five characters, and something nobody would guess.', 'wordpress-security-plugin' ) );
			} else {
				$changes['login_slug'] = $slug;
				$notices[]             = array(
					'type' => 'warning',
					'text' => sprintf(
						/* translators: %s: the new sign-in address. */
						wp_kses_post( __( 'Saved. From now on you sign in at <code>%s</code>. Write it down before you sign out.', 'wordpress-security-plugin' ) ),
						esc_html( home_url( '/' . $slug . '/' ) )
					),
				);
			}

			wpsp_save_settings( $changes );
			flush_rewrite_rules();
			wpsp_log_event( 'settings', 'The sign-in settings were changed.', 'warning' );
			break;

		case 'bots':
			wpsp_save_settings(
				array(
					'bots_enabled'      => $flag( 'bots_enabled' ),
					'block_ai_crawlers' => $flag( 'block_ai_crawlers' ),
					'block_bad_agents'  => $flag( 'block_bad_agents' ),
					'honeypot'          => $flag( 'honeypot' ),
					'rate_limit'        => $flag( 'rate_limit' ),
					'rate_limit_hits'   => max( 20, min( 2000, (int) ( $post['rate_limit_hits'] ?? 120 ) ) ),
					'behind_cloudflare' => $flag( 'behind_cloudflare' ),
					'count_visits'      => $flag( 'count_visits' ),
				)
			);
			$notices[] = array( 'type' => 'success', 'text' => esc_html__( 'Saved.', 'wordpress-security-plugin' ) );
			break;

		case 'maintenance':
			$code   = (string) ( $post['maintenance_code'] ?? '' );
			$result = true;

			if ( '' !== $code ) {
				$result = wpsp_set_maintenance_code( $code );
			}

			if ( is_wp_error( $result ) ) {
				$notices[] = array( 'type' => 'error', 'text' => esc_html( $result->get_error_message() ) );
				break;
			}

			if ( ! empty( $post['clear_code'] ) ) {
				wpsp_set_maintenance_code( '' );
			}

			$on = $flag( 'maintenance' );

			wpsp_save_settings(
				array(
					'maintenance'         => $on,
					'maintenance_heading' => sanitize_text_field( (string) ( $post['maintenance_heading'] ?? '' ) ),
					'maintenance_message' => sanitize_textarea_field( (string) ( $post['maintenance_message'] ?? '' ) ),
				)
			);

			wpsp_purge_cache();
			wpsp_log_event( 'maintenance', $on ? 'Maintenance mode was switched on.' : 'Maintenance mode was switched off.', 'warning' );

			$notices[] = array(
				'type' => $on ? 'warning' : 'success',
				'text' => $on
					? esc_html__( 'Maintenance mode is on and page caches have been cleared. Visitors see the holding page; you and any editor still see the real site (test in an Incognito window).', 'wordpress-security-plugin' )
					: esc_html__( 'Maintenance mode is off and page caches have been cleared. The site is open to everybody.', 'wordpress-security-plugin' ),
			);
			break;

		case 'reporting':
			if ( ! empty( $post['new_key'] ) ) {
				$key                           = wpsp_new_report_key();
				set_transient( 'wpsp_show_key', $key, 5 * MINUTE_IN_SECONDS );
				$notices[]                     = array( 'type' => 'warning', 'text' => esc_html__( 'A new key was made. Copy it into the tracker now: it is only shown on this screen for the next five minutes.', 'wordpress-security-plugin' ) );
			} elseif ( ! empty( $post['stop_reporting'] ) ) {
				wpsp_save_settings( array( 'report_enabled' => false, 'report_key' => '' ) );
				$notices[] = array( 'type' => 'info', 'text' => esc_html__( 'Reporting is off and the key has been removed.', 'wordpress-security-plugin' ) );
			} elseif ( ! empty( $post['save_scan'] ) ) {
				wpsp_save_settings( array( 'nightly_scan' => $flag( 'nightly_scan' ) ) );
				$notices[] = array( 'type' => 'success', 'text' => esc_html__( 'Saved.', 'wordpress-security-plugin' ) );
			} elseif ( ! empty( $post['run_scan'] ) ) {
				wpsp_run_scan();
				$notices[] = array( 'type' => 'success', 'text' => esc_html__( 'The check has run. The results are on the overview.', 'wordpress-security-plugin' ) );
			}
			break;
	}

	return $notices;
}

/**
 * A checkbox row with an explanation underneath.
 *
 * @param string $name  Field name.
 * @param string $label What it does.
 * @param string $help  Why it matters.
 * @return void
 */
function wpsp_checkbox( $name, $label, $help = '' ) {
	?>
	<tr>
		<th scope="row"><?php echo esc_html( $label ); ?></th>
		<td>
			<label>
				<input type="checkbox" name="<?php echo esc_attr( $name ); ?>" value="1" <?php checked( wpsp_on( $name ) ); ?>>
				<?php esc_html_e( 'On', 'wordpress-security-plugin' ); ?>
			</label>
			<?php if ( '' !== $help ) : ?>
				<p class="description" style="max-width:46em"><?php echo esc_html( $help ); ?></p>
			<?php endif; ?>
		</td>
	</tr>
	<?php
}

/**
 * The overview.
 *
 * @return void
 */
function wpsp_tab_overview() {
	$day    = wpsp_count_events( 24 );
	$scan   = wpsp_last_scan();
	$visits = wpsp_visits_for();
	$week   = wpsp_visits_total( 7 );

	$problems = array();

	if ( ! wpsp_login_hidden() ) {
		$problems[] = __( 'The sign-in page is still at the standard /wp-admin address.', 'wordpress-security-plugin' );
	}
	if ( ! wpsp_2fa_active() ) {
		$problems[] = __( 'Two-step sign-in is off.', 'wordpress-security-plugin' );
	}
	foreach ( (array) ( $scan['vulnerabilities'] ?? array() ) as $vuln ) {
		$problems[] = sprintf(
			/* translators: 1: plugin or theme name, 2: the issue. */
			__( '%1$s has a known security issue: %2$s', 'wordpress-security-plugin' ),
			(string) ( $vuln['name'] ?? '' ),
			(string) ( $vuln['title'] ?? '' )
		);
	}
	foreach ( (array) ( $scan['core_files']['modified'] ?? array() ) as $file ) {
		$problems[] = sprintf(
			/* translators: %s: file path. */
			__( 'A WordPress file has been changed: %s', 'wordpress-security-plugin' ),
			(string) $file
		);
	}
	foreach ( (array) ( $scan['unexpected_php'] ?? array() ) as $file ) {
		$problems[] = sprintf(
			/* translators: %s: file path. */
			__( 'There is program code in the uploads folder, which should only hold images and documents: %s', 'wordpress-security-plugin' ),
			(string) $file
		);
	}
	?>
	<h2><?php esc_html_e( 'Yesterday and today', 'wordpress-security-plugin' ); ?></h2>
	<table class="widefat striped" style="max-width:40em">
		<tbody>
			<tr><td><?php esc_html_e( 'Page views today', 'wordpress-security-plugin' ); ?></td><td><strong><?php echo esc_html( number_format_i18n( $visits['hits'] ) ); ?></strong></td></tr>
			<tr><td><?php esc_html_e( 'Visitors today', 'wordpress-security-plugin' ); ?></td><td><strong><?php echo esc_html( number_format_i18n( $visits['visitors'] ) ); ?></strong></td></tr>
			<tr><td><?php esc_html_e( 'Visitors this week', 'wordpress-security-plugin' ); ?></td><td><strong><?php echo esc_html( number_format_i18n( $week['visitors'] ) ); ?></strong></td></tr>
			<tr><td><?php esc_html_e( 'Failed sign-in attempts (24 hours)', 'wordpress-security-plugin' ); ?></td><td><strong><?php echo esc_html( number_format_i18n( (int) ( $day['login_failed'] ?? 0 ) ) ); ?></strong></td></tr>
			<tr><td><?php esc_html_e( 'Bots and scrapers turned away (24 hours)', 'wordpress-security-plugin' ); ?></td><td><strong><?php echo esc_html( number_format_i18n( (int) ( $day['bot_blocked'] ?? 0 ) + (int) ( $day['bot_fake'] ?? 0 ) + (int) ( $day['bot_trapped'] ?? 0 ) ) ); ?></strong></td></tr>
			<tr><td><?php esc_html_e( 'AI crawlers turned away (24 hours)', 'wordpress-security-plugin' ); ?></td><td><strong><?php echo esc_html( number_format_i18n( (int) ( $day['ai_blocked'] ?? 0 ) ) ); ?></strong></td></tr>
		</tbody>
	</table>

	<h2><?php esc_html_e( 'Worth looking at', 'wordpress-security-plugin' ); ?></h2>
	<?php if ( $problems ) : ?>
		<ul style="list-style:disc;margin-left:1.5em;max-width:46em">
			<?php foreach ( array_slice( $problems, 0, 15 ) as $problem ) : ?>
				<li><?php echo esc_html( $problem ); ?></li>
			<?php endforeach; ?>
		</ul>
	<?php else : ?>
		<p><?php esc_html_e( 'Nothing. The sign-in page is private, two-step sign-in is on, and the last check found no changed files or known security issues.', 'wordpress-security-plugin' ); ?></p>
	<?php endif; ?>

	<h2><?php esc_html_e( 'The last check', 'wordpress-security-plugin' ); ?></h2>
	<?php if ( ! empty( $scan['ran_at'] ) ) : ?>
		<p>
			<?php
			printf(
				/* translators: %s: date and time. */
				esc_html__( 'Ran %s. It runs itself every night at about 3am.', 'wordpress-security-plugin' ),
				esc_html( wp_date( 'j F Y, H:i', (int) strtotime( (string) $scan['ran_at'] ) ) )
			);
			?>
		</p>
	<?php else : ?>
		<p><?php esc_html_e( 'It has not run yet. It runs itself every night, or you can run it now from the Daily report tab.', 'wordpress-security-plugin' ); ?></p>
	<?php endif; ?>

	<h2><?php esc_html_e( 'Recent activity', 'wordpress-security-plugin' ); ?></h2>
	<table class="widefat striped">
		<thead>
			<tr>
				<th><?php esc_html_e( 'When', 'wordpress-security-plugin' ); ?></th>
				<th><?php esc_html_e( 'What', 'wordpress-security-plugin' ); ?></th>
				<th><?php esc_html_e( 'Detail', 'wordpress-security-plugin' ); ?></th>
			</tr>
		</thead>
		<tbody>
			<?php
			$events = wpsp_recent_events( 25 );
			if ( ! $events ) :
				?>
				<tr><td colspan="3"><?php esc_html_e( 'Nothing logged yet.', 'wordpress-security-plugin' ); ?></td></tr>
				<?php
			endif;
			foreach ( $events as $event ) :
				?>
				<tr>
					<td><?php echo esc_html( wp_date( 'j M, H:i', (int) strtotime( (string) $event['created_at'] ) ) ); ?></td>
					<td>
						<?php if ( 'notice' !== $event['severity'] ) : ?>
							<strong><?php echo esc_html( $event['message'] ); ?></strong>
						<?php else : ?>
							<?php echo esc_html( $event['message'] ); ?>
						<?php endif; ?>
					</td>
					<td><code><?php echo esc_html( $event['context'] ); ?></code></td>
				</tr>
			<?php endforeach; ?>
		</tbody>
	</table>
	<?php
}

/**
 * The sign-in tab.
 *
 * @return void
 */
function wpsp_tab_login() {
	$slug      = wpsp_login_slug();
	$suggested = $slug ? $slug : wpsp_suggest_login_slug();
	$forced    = defined( 'WPSP_LOGIN_SLUG' ) && WPSP_LOGIN_SLUG;
	$off       = defined( 'WPSP_LOGIN_OFF' ) && WPSP_LOGIN_OFF;
	?>
	<form method="post">
		<?php wp_nonce_field( 'wpsp_save_login' ); ?>
		<input type="hidden" name="wpsp_tab" value="login">

		<h2><?php esc_html_e( 'A private sign-in address', 'wordpress-security-plugin' ); ?></h2>
		<p style="max-width:46em">
			<?php esc_html_e( 'With an address set, /wp-admin and /wp-login.php answer "page not found" to anyone who is not signed in, so the automated attempts every WordPress site receives find nothing to attack. Password reset and logout links keep working, and so does everything the front of the site needs.', 'wordpress-security-plugin' ); ?>
		</p>

		<?php if ( $off ) : ?>
			<div class="notice notice-info inline"><p><?php esc_html_e( 'WPSP_LOGIN_OFF is set in wp-config.php, so the standard WordPress address is in use. Remove that line to use a private address again.', 'wordpress-security-plugin' ); ?></p></div>
		<?php elseif ( $forced ) : ?>
			<div class="notice notice-info inline"><p><?php printf( esc_html__( 'The address is set in wp-config.php and cannot be changed here: %s', 'wordpress-security-plugin' ), '<code>' . esc_html( wpsp_login_url() ) . '</code>' ); ?></p></div>
		<?php else : ?>
			<table class="form-table" role="presentation">
				<tr>
					<th scope="row"><label for="login_slug"><?php esc_html_e( 'Sign in at', 'wordpress-security-plugin' ); ?></label></th>
					<td>
						<code><?php echo esc_html( trailingslashit( home_url( '/' ) ) ); ?></code>
						<input type="text" id="login_slug" name="login_slug" class="regular-text" value="<?php echo esc_attr( $slug ); ?>" placeholder="<?php echo esc_attr( $suggested ); ?>">
						<code>/</code>
						<p class="description">
							<?php esc_html_e( 'Leave it empty for the standard WordPress address. A suggestion:', 'wordpress-security-plugin' ); ?>
							<code><?php echo esc_html( $suggested ); ?></code>
						</p>
					</td>
				</tr>
			</table>
		<?php endif; ?>

		<?php if ( $slug ) : ?>
			<div class="notice notice-warning inline">
				<p><strong><?php esc_html_e( 'Write this down now:', 'wordpress-security-plugin' ); ?></strong> <code><?php echo esc_html( wpsp_login_url() ); ?></code></p>
				<p>
					<?php esc_html_e( 'If it is ever lost, add either line to wp-config.php using the host file manager to get back in:', 'wordpress-security-plugin' ); ?><br>
					<code>define( 'WPSP_LOGIN_OFF', true );</code><br>
					<code>define( 'WPSP_LOGIN_SLUG', 'a-new-address' );</code>
				</p>
			</div>
		<?php endif; ?>

		<h2><?php esc_html_e( 'Attempt limits', 'wordpress-security-plugin' ); ?></h2>
		<table class="form-table" role="presentation">
			<tr>
				<th scope="row"><label for="login_max_attempts"><?php esc_html_e( 'Wrong passwords allowed', 'wordpress-security-plugin' ); ?></label></th>
				<td><input type="number" id="login_max_attempts" name="login_max_attempts" min="3" max="20" value="<?php echo esc_attr( (string) wpsp_option( 'login_max_attempts', 5 ) ); ?>" class="small-text"></td>
			</tr>
			<tr>
				<th scope="row"><label for="login_lockout"><?php esc_html_e( 'Then wait this long (seconds)', 'wordpress-security-plugin' ); ?></label></th>
				<td><input type="number" id="login_lockout" name="login_lockout" min="60" max="86400" step="60" value="<?php echo esc_attr( (string) wpsp_option( 'login_lockout', 900 ) ); ?>" class="small-text"></td>
			</tr>
			<tr>
				<th scope="row"><label for="login_alert_email"><?php esc_html_e( 'Email alerts to', 'wordpress-security-plugin' ); ?></label></th>
				<td>
					<input type="email" id="login_alert_email" name="login_alert_email" class="regular-text" value="<?php echo esc_attr( (string) wpsp_option( 'login_alert_email', '' ) ); ?>" placeholder="<?php echo esc_attr( (string) get_option( 'admin_email' ) ); ?>">
					<p class="description"><?php esc_html_e( 'Used when an administrator signs in from a device or network not seen in the last 30 days. Left empty, the site admin address is used.', 'wordpress-security-plugin' ); ?></p>
				</td>
			</tr>
			<?php wpsp_checkbox( 'block_enumeration', __( 'Hide the list of usernames', 'wordpress-security-plugin' ), __( 'Author pages and the users part of the REST API hand out usernames to anyone who asks. Half of guessing a password is knowing the username, so this closes both.', 'wordpress-security-plugin' ) ); ?>
		</table>

		<h2><?php esc_html_e( 'Two-step sign-in', 'wordpress-security-plugin' ); ?></h2>
		<p style="max-width:46em">
			<?php esc_html_e( 'After the password, the site asks for the six-digit number showing in an authenticator app on your phone: Google Authenticator, Microsoft Authenticator, 1Password and Bitwarden all work. The number changes every 30 seconds. It means a stolen password on its own is not enough to get in, which is the single biggest improvement you can make to a WordPress login.', 'wordpress-security-plugin' ); ?>
		</p>
		<p style="max-width:46em">
			<?php esc_html_e( 'Each person sets it up on their own profile screen, and gets ten backup codes in case the phone is lost. If everything is lost, adding WPSP_2FA_OFF to wp-config.php switches it off.', 'wordpress-security-plugin' ); ?>
			<?php if ( wpsp_2fa_active() ) : ?>
				<a href="<?php echo esc_url( admin_url( 'profile.php#wordpress-security-plugin-2fa' ) ); ?>"><?php esc_html_e( 'Set up your own now.', 'wordpress-security-plugin' ); ?></a>
			<?php endif; ?>
		</p>
		<table class="form-table" role="presentation">
			<?php
			wpsp_checkbox( 'twofactor_enabled', __( 'Use two-step sign-in', 'wordpress-security-plugin' ) );
			wpsp_checkbox( 'twofactor_required', __( 'Expect it of administrators and editors', 'wordpress-security-plugin' ), __( 'Anyone who can change the site is reminded to set it up every time they open the admin. Nobody is locked out for not having it yet.', 'wordpress-security-plugin' ) );
			?>
		</table>

		<h2><?php esc_html_e( 'The settings every site should have', 'wordpress-security-plugin' ); ?></h2>
		<table class="form-table" role="presentation">
			<?php
			wpsp_checkbox( 'disable_file_edit', __( 'No editing theme or plugin files in the admin', 'wordpress-security-plugin' ), __( 'The most useful of these. With it on, an account that is taken over still cannot put program code on the server through the browser. Files are deployed through the theme updater instead.', 'wordpress-security-plugin' ) );
			wpsp_checkbox( 'disable_xmlrpc', __( 'Turn off XML-RPC', 'wordpress-security-plugin' ), __( 'An old remote interface none of these sites use. Password guessing tools like it because it allows many attempts in a single request.', 'wordpress-security-plugin' ) );
			wpsp_checkbox( 'security_headers', __( 'Send security headers', 'wordpress-security-plugin' ), __( 'Invisible instructions to the visitor\'s browser: no other website may display this one inside a frame, do not guess file types, do not leak full addresses to other sites, and the pages do not need the camera, microphone or location.', 'wordpress-security-plugin' ) );
			wpsp_checkbox( 'hsts', __( 'Insist on the secure address (HSTS)', 'wordpress-security-plugin' ), __( 'Browsers remember to only ever use https for this domain, for a year. Only switch it on once the site and every subdomain is reliably on https, because browsers honour it for a long time.', 'wordpress-security-plugin' ) );
			wpsp_checkbox( 'hide_wp_version', __( 'Hide the WordPress version number', 'wordpress-security-plugin' ), __( 'A scanner reads the version to decide which attacks to try. Hiding it is not protection by itself, but it costs nothing.', 'wordpress-security-plugin' ) );
			wpsp_checkbox( 'limit_app_passwords', __( 'Only administrators may create application passwords', 'wordpress-security-plugin' ), __( 'An application password is a real key to the site through the REST API. A customer or subscriber account has no reason to be able to make one.', 'wordpress-security-plugin' ) );
			wpsp_checkbox( 'block_sensitive', __( 'Refuse requests for backups and configuration files', 'wordpress-security-plugin' ), __( 'Answers "page not found" for database dumps, .env files, old copies of wp-config and program code inside the uploads folder, which are the first things a scanner asks for.', 'wordpress-security-plugin' ) );
			?>
		</table>

		<?php submit_button( __( 'Save sign-in settings', 'wordpress-security-plugin' ) ); ?>
	</form>
	<?php
}

/**
 * The bots tab.
 *
 * @return void
 */
function wpsp_tab_bots() {
	?>
	<form method="post">
		<?php wp_nonce_field( 'wpsp_save_bots' ); ?>
		<input type="hidden" name="wpsp_tab" value="bots">

		<h2><?php esc_html_e( 'What this can and cannot do', 'wordpress-security-plugin' ); ?></h2>
		<p style="max-width:46em">
			<?php esc_html_e( 'A public page can be copied by anybody willing to use an ordinary browser, and no plugin can prevent that. What these settings stop is automated copying: scraping tools, whole-site downloaders and the crawlers that collect pages for AI training. Search engines are never blocked, because the sites depend on being found.', 'wordpress-security-plugin' ); ?>
		</p>
		<p style="max-width:46em">
			<strong><?php esc_html_e( 'One limit to know about:', 'wordpress-security-plugin' ); ?></strong>
			<?php esc_html_e( 'the host serves most pages from its own cache without running WordPress at all, so this plugin never sees those requests. Putting the site behind Cloudflare, which is free, checks every visitor before the cache does. There is a step-by-step guide in the plugin folder under docs.', 'wordpress-security-plugin' ); ?>
		</p>

		<table class="form-table" role="presentation">
			<?php
			wpsp_checkbox( 'bots_enabled', __( 'Watch for bots', 'wordpress-security-plugin' ), __( 'The switch for everything below.', 'wordpress-security-plugin' ) );
			wpsp_checkbox( 'block_ai_crawlers', __( 'Keep AI crawlers out', 'wordpress-security-plugin' ), __( 'Adds the published AI crawler names to robots.txt and turns them away if they come anyway: GPTBot, ClaudeBot, CCBot, Bytespider, PerplexityBot and the rest. Google and Bing search are not affected, so rankings are not either.', 'wordpress-security-plugin' ) );
			wpsp_checkbox( 'block_bad_agents', __( 'Turn away scraping tools', 'wordpress-security-plugin' ), __( 'Site downloaders and scripted fetchers name themselves, so refusing those names removes most automated copying. A request that sends no browser name at all is refused too, because no real browser does that.', 'wordpress-security-plugin' ) );
			wpsp_checkbox( 'honeypot', __( 'Use a trap link', 'wordpress-security-plugin' ), __( 'A link no person can see and no polite crawler will follow, because robots.txt says not to. Anything that follows it is not reading the page, and is blocked for a day.', 'wordpress-security-plugin' ) );
			wpsp_checkbox( 'rate_limit', __( 'Slow down whoever asks for too much', 'wordpress-security-plugin' ), __( 'Only counts the expensive requests: searches, the REST API and feeds. Ordinary page views are never counted, so browsing the site normally is never affected.', 'wordpress-security-plugin' ) );
			?>
			<tr>
				<th scope="row"><label for="rate_limit_hits"><?php esc_html_e( 'Requests a minute before slowing down', 'wordpress-security-plugin' ); ?></label></th>
				<td><input type="number" id="rate_limit_hits" name="rate_limit_hits" min="20" max="2000" value="<?php echo esc_attr( (string) wpsp_option( 'rate_limit_hits', 120 ) ); ?>" class="small-text"></td>
			</tr>
			<?php
			wpsp_checkbox( 'behind_cloudflare', __( 'This site is behind Cloudflare', 'wordpress-security-plugin' ), __( 'Switch this on only once the domain really is on Cloudflare, so the plugin reads the visitor\'s own address from Cloudflare rather than treating everybody as one visitor.', 'wordpress-security-plugin' ) );
			wpsp_checkbox( 'count_visits', __( 'Count visits', 'wordpress-security-plugin' ), __( 'Two numbers a day, page views and roughly how many separate visitors, for the daily report. No cookie, no address stored, nothing traceable to a person, so no consent banner is needed.', 'wordpress-security-plugin' ) );
			?>
		</table>

		<?php submit_button( __( 'Save bot settings', 'wordpress-security-plugin' ) ); ?>
	</form>
	<?php
}

/**
 * The maintenance tab.
 *
 * @return void
 */
function wpsp_tab_maintenance() {
	$on = wpsp_on( 'maintenance' );
	?>
	<form method="post">
		<?php wp_nonce_field( 'wpsp_save_maintenance' ); ?>
		<input type="hidden" name="wpsp_tab" value="maintenance">

		<h2><?php esc_html_e( 'Maintenance mode', 'wordpress-security-plugin' ); ?></h2>
		<p style="max-width:46em">
			<?php esc_html_e( 'While a site is being built or redesigned, visitors see a holding page instead of the website. You and anyone who can edit the site still see the real thing, because you are signed in. Anybody else you want to show it to types the access code once, and then browses normally for a fortnight: no account, no email address, nothing to sign up for.', 'wordpress-security-plugin' ); ?>
		</p>
		<p style="max-width:46em">
			<?php esc_html_e( 'The holding page tells search engines the site is temporarily unavailable rather than gone, which is what keeps an existing site from dropping out of Google while it is being worked on.', 'wordpress-security-plugin' ); ?>
		</p>

		<?php if ( $on ) : ?>
			<div class="notice notice-warning inline">
				<p><strong><?php esc_html_e( 'Maintenance mode is on right now. Visitors cannot see this website.', 'wordpress-security-plugin' ); ?></strong></p>
				<p><?php esc_html_e( 'Note: Because you are logged in as an administrator, you will continue to see the live site normally so you can keep working. To test the visitor holding page, open the website in an Incognito / private browsing window.', 'wordpress-security-plugin' ); ?></p>
			</div>
		<?php endif; ?>

		<table class="form-table" role="presentation">
			<?php wpsp_checkbox( 'maintenance', __( 'Show the holding page', 'wordpress-security-plugin' ) ); ?>
			<tr>
				<th scope="row"><label for="maintenance_code"><?php esc_html_e( 'Access code', 'wordpress-security-plugin' ); ?></label></th>
				<td>
					<input type="text" id="maintenance_code" name="maintenance_code" class="regular-text" style="max-width:12em"
						inputmode="numeric" autocomplete="off" value="" placeholder="<?php echo esc_attr( wpsp_has_maintenance_code() ? __( 'a code is set', 'wordpress-security-plugin' ) : __( 'e.g. 48213', 'wordpress-security-plugin' ) ); ?>">
					<p class="description" style="max-width:40em">
						<?php esc_html_e( 'Numbers only, 4 to 12 of them. Only a scrambled version is stored, the same way a password is, so nobody can read it back out of the site, including you: to change it, type a new one. Give it to whoever needs to see the work in progress.', 'wordpress-security-plugin' ); ?>
					</p>
					<?php if ( wpsp_has_maintenance_code() ) : ?>
						<p><label><input type="checkbox" name="clear_code" value="1"> <?php esc_html_e( 'Remove the code, so nobody can get past the holding page', 'wordpress-security-plugin' ); ?></label></p>
					<?php endif; ?>
				</td>
			</tr>
			<tr>
				<th scope="row"><label for="maintenance_heading"><?php esc_html_e( 'Heading on the holding page', 'wordpress-security-plugin' ); ?></label></th>
				<td>
					<input type="text" id="maintenance_heading" name="maintenance_heading" class="large-text" value="<?php echo esc_attr( (string) wpsp_option( 'maintenance_heading', '' ) ); ?>" placeholder="<?php esc_attr_e( 'We are working on this website', 'wordpress-security-plugin' ); ?>">
				</td>
			</tr>
			<tr>
				<th scope="row"><label for="maintenance_message"><?php esc_html_e( 'Message underneath', 'wordpress-security-plugin' ); ?></label></th>
				<td>
					<textarea id="maintenance_message" name="maintenance_message" class="large-text" rows="3" placeholder="<?php esc_attr_e( 'It will be back shortly. Thank you for your patience.', 'wordpress-security-plugin' ); ?>"><?php echo esc_textarea( (string) wpsp_option( 'maintenance_message', '' ) ); ?></textarea>
				</td>
			</tr>
		</table>

		<p class="description" style="max-width:46em">
			<?php esc_html_e( 'Locked out by mistake? Add this to wp-config.php through the host file manager and the holding page stops for everybody:', 'wordpress-security-plugin' ); ?>
			<code>define( 'WPSP_MAINTENANCE_OFF', true );</code>
		</p>

		<?php submit_button( __( 'Save maintenance settings', 'wordpress-security-plugin' ) ); ?>
	</form>
	<?php
}

/**
 * The reporting tab.
 *
 * @return void
 */
function wpsp_tab_reporting() {
	$key      = get_transient( 'wpsp_show_key' );
	$enabled  = wpsp_on( 'report_enabled' ) && '' !== wpsp_report_key();
	$last     = (int) get_option( 'wpsp_last_report', 0 );
	$endpoint = rest_url( 'wordpress-security-plugin/v1/report' );
	?>
	<h2><?php esc_html_e( 'The daily report', 'wordpress-security-plugin' ); ?></h2>
	<p style="max-width:46em">
		<?php esc_html_e( 'Once this is switched on, your tracker can ask this site each morning how it is doing, and show every site side by side. What it sends: whether the site answered and how quickly, visitors, enquiries, shop orders and customers, failed sign-ins and bots blocked, what needs updating, and anything the nightly check found.', 'wordpress-security-plugin' ); ?>
	</p>
	<p style="max-width:46em">
		<strong><?php esc_html_e( 'What it never sends:', 'wordpress-security-plugin' ); ?></strong>
		<?php esc_html_e( 'counts only. No name, no email address, no message anybody submitted, no order detail, no password and no setting. The endpoint can only be read, never written to, so nothing about this site can be changed through it.', 'wordpress-security-plugin' ); ?>
	</p>

	<table class="widefat striped" style="max-width:46em;margin-bottom:1.5em">
		<tbody>
			<tr>
				<td><?php esc_html_e( 'Status', 'wordpress-security-plugin' ); ?></td>
				<td><strong><?php echo $enabled ? esc_html__( 'On', 'wordpress-security-plugin' ) : esc_html__( 'Off', 'wordpress-security-plugin' ); ?></strong></td>
			</tr>
			<tr>
				<td><?php esc_html_e( 'Address for the tracker', 'wordpress-security-plugin' ); ?></td>
				<td><code><?php echo esc_html( $endpoint ); ?></code></td>
			</tr>
			<tr>
				<td><?php esc_html_e( 'Last pulled', 'wordpress-security-plugin' ); ?></td>
				<td><?php echo $last ? esc_html( wp_date( 'j F Y, H:i', $last ) ) : esc_html__( 'never', 'wordpress-security-plugin' ); ?></td>
			</tr>
		</tbody>
	</table>

	<?php if ( is_string( $key ) && '' !== $key ) : ?>
		<div class="notice notice-warning inline">
			<p><strong><?php esc_html_e( 'The key for this site. Copy it into the tracker now: it will not be shown again.', 'wordpress-security-plugin' ); ?></strong></p>
			<p><code style="user-select:all;word-break:break-all"><?php echo esc_html( $key ); ?></code></p>
		</div>
		<?php delete_transient( 'wpsp_show_key' ); ?>
	<?php endif; ?>

	<form method="post">
		<?php wp_nonce_field( 'wpsp_save_reporting' ); ?>
		<input type="hidden" name="wpsp_tab" value="reporting">
		<p>
			<button type="submit" name="new_key" value="1" class="button button-primary">
				<?php echo $enabled ? esc_html__( 'Replace the key', 'wordpress-security-plugin' ) : esc_html__( 'Switch reporting on and make a key', 'wordpress-security-plugin' ); ?>
			</button>
			<?php if ( $enabled ) : ?>
				<button type="submit" name="stop_reporting" value="1" class="button"><?php esc_html_e( 'Switch reporting off', 'wordpress-security-plugin' ); ?></button>
			<?php endif; ?>
			<button type="submit" name="run_scan" value="1" class="button"><?php esc_html_e( 'Run the nightly check now', 'wordpress-security-plugin' ); ?></button>
		</p>
		<p class="description" style="max-width:46em">
			<?php esc_html_e( 'Replacing the key stops the old one working straight away, so the tracker needs the new one pasted in. You can also read the report yourself right now, signed in as an administrator:', 'wordpress-security-plugin' ); ?>
			<a href="<?php echo esc_url( $endpoint ); ?>" target="_blank" rel="noreferrer"><?php esc_html_e( 'open the report', 'wordpress-security-plugin' ); ?></a>.
		</p>
	</form>

	<form method="post">
		<?php wp_nonce_field( 'wpsp_save_reporting' ); ?>
		<input type="hidden" name="wpsp_tab" value="reporting">
		<h2><?php esc_html_e( 'The nightly check', 'wordpress-security-plugin' ); ?></h2>
		<table class="form-table" role="presentation">
			<?php wpsp_checkbox( 'nightly_scan', __( 'Run the check every night', 'wordpress-security-plugin' ), __( 'A little after 3am the plugin compares the WordPress files with the official copies, looks for program code in the uploads folder, and lists what needs updating. Off, the button above still runs it whenever you ask.', 'wordpress-security-plugin' ) ); ?>
		</table>
		<p><button type="submit" name="save_scan" value="1" class="button button-primary"><?php esc_html_e( 'Save', 'wordpress-security-plugin' ); ?></button></p>
	</form>
	<?php
}
