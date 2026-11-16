<?php
/**
 * The daily report a tracker pulls.
 *
 * One endpoint, one format, every site:
 *     GET /wp-json/wordpress-security-plugin/v1/report
 *
 * How it is protected. Each site makes its own 64-character key, shown once in the admin and pasted into the
 * tracker. The tracker does not send the key: it sends the current time, a random string and a signature worked out
 * from the key, the time, the random string and the path. The site works the signature out again and compares the
 * two. So the key never travels, a recorded request cannot be replayed (the time has to be within five minutes and
 * each random string is only accepted once), and a site with no key set simply refuses.
 *
 * What it is allowed to do: read. There is no write side, no settings change, no user data, no password, no email
 * address and no form content. It reports counts and versions, nothing a person said or submitted. If the key leaks,
 * the worst outcome is somebody learning how many enquiries came in, and the key can be replaced in one click.
 *
 * Cost: nothing on a page load. The endpoint only exists when it is called, and the expensive answers come from what
 * the nightly job already worked out.
 *
 * @package wordpress-security-plugin
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/** How far out the tracker's clock may be. */
const WPSP_REPORT_WINDOW = 300;

/**
 * The site's report key, or an empty string when reporting is not set up.
 *
 * @return string
 */
function wpsp_report_key() {
	if ( defined( 'WPSP_REPORT_KEY' ) && is_string( WPSP_REPORT_KEY ) && '' !== WPSP_REPORT_KEY ) {
		return WPSP_REPORT_KEY;
	}

	return (string) wpsp_option( 'report_key', '' );
}

/**
 * Makes a fresh key and switches reporting on.
 *
 * @return string The new key, to be shown once and copied into the tracker.
 */
function wpsp_new_report_key() {
	$key = bin2hex( random_bytes( 32 ) );

	wpsp_save_settings(
		array(
			'report_key'     => $key,
			'report_enabled' => true,
		)
	);

	wpsp_log_event( 'report_key', 'A new reporting key was made.', 'warning' );

	return $key;
}

/**
 * Registers the endpoint.
 *
 * @return void
 */
function wpsp_register_report_route() {
	register_rest_route(
		'wordpress-security-plugin/v1',
		'/report',
		array(
			'methods'             => 'GET',
			'callback'            => 'wpsp_report_endpoint',
			'permission_callback' => 'wpsp_report_permission',
			'args'                => array(
				'days' => array(
					'type'              => 'integer',
					'default'           => 7,
					'sanitize_callback' => 'absint',
				),
			),
		)
	);
}
add_action( 'rest_api_init', 'wpsp_register_report_route' );

/**
 * Checks the signature on a report request.
 *
 * @param WP_REST_Request $request The request.
 * @return bool|WP_Error
 */
function wpsp_report_permission( $request ) {
	// An administrator reading it from their own browser is allowed, which makes checking the output easy.
	if ( current_user_can( 'manage_options' ) ) {
		return true;
	}

	$key = wpsp_report_key();

	if ( ! wpsp_on( 'report_enabled' ) || '' === $key ) {
		return new WP_Error( 'wpsp_report_off', __( 'Reporting is not switched on for this site.', 'wordpress-security-plugin' ), array( 'status' => 404 ) );
	}

	$timestamp = (int) $request->get_header( 'x-wpsp-timestamp' );
	$nonce     = (string) $request->get_header( 'x-wpsp-nonce' );
	$signature = (string) $request->get_header( 'x-wpsp-signature' );

	if ( ! $timestamp || '' === $nonce || '' === $signature ) {
		return wpsp_report_refused( 'The request was not signed.' );
	}

	if ( abs( time() - $timestamp ) > WPSP_REPORT_WINDOW ) {
		return wpsp_report_refused( 'The signature was out of date.' );
	}

	if ( strlen( $nonce ) < 16 || strlen( $nonce ) > 64 || ! ctype_alnum( $nonce ) ) {
		return wpsp_report_refused( 'The request was not signed properly.' );
	}

	// Each random string is accepted once, so a recorded request cannot be sent again inside the time window.
	$seen = 'wpsp_rnonce_' . hash( 'sha256', $nonce );
	if ( get_transient( $seen ) ) {
		return wpsp_report_refused( 'The same signed request arrived twice.' );
	}

	$expected = hash_hmac( 'sha256', $timestamp . "\n" . $nonce . "\n" . 'GET' . "\n" . '/wordpress-security-plugin/v1/report', $key );

	if ( ! hash_equals( $expected, $signature ) ) {
		return wpsp_report_refused( 'The signature did not match.' );
	}

	set_transient( $seen, 1, 2 * WPSP_REPORT_WINDOW );

	return true;
}

/**
 * Logs and refuses, without saying which part was wrong.
 *
 * @param string $reason What went wrong, for the site's own log only.
 * @return WP_Error
 */
function wpsp_report_refused( $reason ) {
	wpsp_log_event( 'report_refused', 'A report request was refused.', 'warning', $reason );

	return new WP_Error( 'wpsp_report_denied', __( 'Not allowed.', 'wordpress-security-plugin' ), array( 'status' => 401 ) );
}

/**
 * Builds the report.
 *
 * @param WP_REST_Request $request The request.
 * @return WP_REST_Response
 */
function wpsp_report_endpoint( $request ) {
	$days = max( 1, min( 90, (int) $request->get_param( 'days' ) ) );

	$report = array(
		'format'       => 'wordpress-security-plugin-report',
		'version'      => 1,
		'generated_at' => gmdate( 'c' ),
		'site'         => wpsp_report_site(),
		'security'     => wpsp_report_security(),
		'health'       => wpsp_report_health(),
		'traffic'      => wpsp_report_traffic( $days ),
		'business'     => wpsp_report_business( $days ),
		'content'      => wpsp_report_content(),
	);

	update_option( 'wpsp_last_report', time(), false );

	return new WP_REST_Response( $report, 200 );
}

/**
 * Which site this is, and what it is running.
 *
 * @return array<string, mixed>
 */
function wpsp_report_site() {
	$theme = wp_get_theme();

	return array(
		'name'            => get_bloginfo( 'name' ),
		'url'             => home_url( '/' ),
		'timezone'        => wp_timezone_string(),
		'locale'          => get_locale(),
		'wordpress'       => get_bloginfo( 'version' ),
		'php'             => PHP_VERSION,
		'https'           => is_ssl(),
		'theme'           => array(
			'name'    => $theme->get( 'Name' ),
			'slug'    => $theme->get_stylesheet(),
			'version' => $theme->get( 'Version' ),
		),
		'guard_version'   => WPSP_VERSION,
		'search_engines'  => (bool) get_option( 'blog_public' ),
		'maintenance'     => wpsp_on( 'maintenance' ),
		'woocommerce'     => class_exists( 'WooCommerce' ),
		'behind_cloudflare' => wpsp_on( 'behind_cloudflare' ),
	);
}

/**
 * What the defences did, and what is still open.
 *
 * @return array<string, mixed>
 */
function wpsp_report_security() {
	$day  = wpsp_count_events( 24 );
	$week = wpsp_count_events( 24 * 7 );
	$scan = wpsp_last_scan();

	$admins     = isset( $scan['admins'] ) && is_array( $scan['admins'] ) ? $scan['admins'] : array();
	$no_2fa     = 0;
	foreach ( $admins as $admin ) {
		if ( empty( $admin['two_factor'] ) ) {
			$no_2fa++;
		}
	}

	return array(
		'login_hidden'        => wpsp_login_hidden(),
		'two_factor_on'       => wpsp_2fa_active(),
		'admins'              => count( $admins ),
		'admins_without_2fa'  => $no_2fa,
		'last_24h'            => array(
			'failed_logins'  => (int) ( $day['login_failed'] ?? 0 ),
			'lockouts'       => (int) ( $day['login_lockout'] ?? 0 ),
			'bots_blocked'   => (int) ( $day['bot_blocked'] ?? 0 ) + (int) ( $day['bot_fake'] ?? 0 ) + (int) ( $day['bot_trapped'] ?? 0 ),
			'ai_blocked'     => (int) ( $day['ai_blocked'] ?? 0 ),
			'rate_limited'   => (int) ( $day['rate_limited'] ?? 0 ),
			'blocked_files'  => (int) ( $day['blocked_file'] ?? 0 ),
			'new_devices'    => (int) ( $day['login_new_device'] ?? 0 ),
		),
		'last_7d'             => array(
			'failed_logins' => (int) ( $week['login_failed'] ?? 0 ),
			'lockouts'      => (int) ( $week['login_lockout'] ?? 0 ),
			'bots_blocked'  => (int) ( $week['bot_blocked'] ?? 0 ) + (int) ( $week['bot_fake'] ?? 0 ) + (int) ( $week['bot_trapped'] ?? 0 ),
			'ai_blocked'    => (int) ( $week['ai_blocked'] ?? 0 ),
		),
		'core_files_modified' => isset( $scan['core_files']['modified'] ) ? array_values( (array) $scan['core_files']['modified'] ) : array(),
		'core_files_missing'  => isset( $scan['core_files']['missing'] ) ? array_values( (array) $scan['core_files']['missing'] ) : array(),
		'unexpected_php'      => isset( $scan['unexpected_php'] ) ? array_values( (array) $scan['unexpected_php'] ) : array(),
		'vulnerabilities'     => isset( $scan['vulnerabilities'] ) ? array_values( (array) $scan['vulnerabilities'] ) : array(),
		'alerts'              => wpsp_report_alerts(),
	);
}

/**
 * The warnings worth a person's attention, newest first, with no detail that identifies anybody.
 *
 * @return array<int, array<string, string>>
 */
function wpsp_report_alerts() {
	$alerts = array();

	foreach ( wpsp_recent_events( 25, 'warning' ) as $event ) {
		$alerts[] = array(
			'at'       => (string) $event['created_at'],
			'type'     => (string) $event['type'],
			'severity' => (string) $event['severity'],
			'message'  => (string) $event['message'],
		);
	}

	return $alerts;
}

/**
 * Whether the site is looked after: updates, backups, when the nightly check last ran.
 *
 * Whether the site is up is not answered here. A site that is down cannot answer anything, so the tracker decides
 * that from whether this request succeeded and how long it took.
 *
 * @return array<string, mixed>
 */
function wpsp_report_health() {
	$scan    = wpsp_last_scan();
	$updates = isset( $scan['updates'] ) && is_array( $scan['updates'] ) ? $scan['updates'] : array();

	return array(
		'last_scan'        => (string) ( $scan['ran_at'] ?? '' ),
		'core_update'      => (string) ( $updates['core'] ?? '' ),
		'plugin_updates'   => isset( $updates['plugins'] ) ? array_values( (array) $updates['plugins'] ) : array(),
		'theme_updates'    => isset( $updates['themes'] ) ? array_values( (array) $updates['themes'] ) : array(),
		'debug_mode'       => defined( 'WP_DEBUG' ) && WP_DEBUG,
		'file_edit_off'    => defined( 'DISALLOW_FILE_EDIT' ) && DISALLOW_FILE_EDIT,
		'cron_working'     => (bool) wp_next_scheduled( 'wpsp_nightly' ),
		'notes'            => isset( $scan['notes'] ) ? array_values( (array) $scan['notes'] ) : array(),
	);
}

/**
 * How many people came.
 *
 * @param int $days How far back.
 * @return array<string, mixed>
 */
function wpsp_report_traffic( $days ) {
	if ( ! wpsp_on( 'count_visits' ) ) {
		return array( 'counting' => false );
	}

	$today     = wpsp_visits_for( current_time( 'Y-m-d' ) );
	$yesterday = wpsp_visits_for( gmdate( 'Y-m-d', (int) strtotime( current_time( 'Y-m-d' ) ) - DAY_IN_SECONDS ) );
	$span      = wpsp_visits_total( $days );

	$daily = array();
	foreach ( wpsp_visit_rows( $days ) as $row ) {
		$daily[] = array(
			'day'      => (string) $row['day'],
			'views'    => (int) $row['hits'],
			'visitors' => (int) $row['visitors'],
		);
	}

	return array(
		'counting'  => true,
		'today'     => array( 'views' => $today['hits'], 'visitors' => $today['visitors'] ),
		'yesterday' => array( 'views' => $yesterday['hits'], 'visitors' => $yesterday['visitors'] ),
		'span_days' => (int) $days,
		'span'      => array( 'views' => $span['hits'], 'visitors' => $span['visitors'] ),
		'daily'     => $daily,
	);
}

/**
 * Enquiries, sign-ups and, where there is a shop, orders and customers.
 *
 * Counts only. No name, no email address, no message and no order detail leaves the site, so the report can be
 * stored and shown in the tracker without holding anybody's personal data.
 *
 * Which post types count as an enquiry differs between the sites, because each theme named its own. Any registered
 * post type ending in _enquiry counts, and the filter below lets a theme add others.
 *
 * @param int $days How far back.
 * @return array<string, mixed>
 */
function wpsp_report_business( $days ) {
	$since = gmdate( 'Y-m-d H:i:s', time() - ( (int) $days * DAY_IN_SECONDS ) );

	$enquiry_types = apply_filters(
		'wpsp_enquiry_post_types',
		array_merge(
			array( 'enquiry', 'contact_message', 'wpcf7_contact_form', 'flamingo_inbound' ),
			preg_grep( '/_enquiry$/D', get_post_types() )
		)
	);
	$enquiry_types = array_unique( (array) $enquiry_types );

	$enquiries = array(
		'total'      => 0,
		'recent'     => 0,
		'unanswered' => 0,
		'by_type'    => array(),
	);

	foreach ( (array) $enquiry_types as $type ) {
		if ( ! post_type_exists( $type ) ) {
			continue;
		}

		$counts = (array) wp_count_posts( $type );
		$total  = 0;
		foreach ( $counts as $status => $count ) {
			if ( 'auto-draft' !== $status && 'trash' !== $status ) {
				$total += (int) $count;
			}
		}

		$recent = wpsp_count_posts_since( $type, $since );

		$enquiries['total']          += $total;
		$enquiries['recent']         += $recent;
		$enquiries['by_type'][ $type ] = array( 'total' => $total, 'recent' => $recent );

		// A theme that marks an enquiry as dealt with uses a status or a term; both patterns are checked cheaply.
		$enquiries['unanswered'] += wpsp_count_unanswered( $type );
	}

	$shop = array( 'present' => false );

	if ( class_exists( 'WooCommerce' ) && function_exists( 'wc_get_orders' ) ) {
		$orders = wc_get_orders(
			array(
				'limit'        => -1,
				'return'       => 'ids',
				'date_created' => '>' . ( time() - ( (int) $days * DAY_IN_SECONDS ) ),
			)
		);

		$revenue = 0.0;
		foreach ( (array) $orders as $order_id ) {
			$order = wc_get_order( $order_id );
			if ( $order && in_array( $order->get_status(), array( 'completed', 'processing', 'on-hold' ), true ) ) {
				$revenue += (float) $order->get_total();
			}
		}

		$roles     = (array) ( count_users()['avail_roles'] ?? array() );
		$products  = (array) wp_count_posts( 'product' );

		$shop = array(
			'present'   => true,
			'currency'  => get_woocommerce_currency(),
			'orders'    => count( (array) $orders ),
			'revenue'   => round( $revenue, 2 ),
			'customers' => (int) ( $roles['customer'] ?? 0 ),
			'products'  => (int) ( $products['publish'] ?? 0 ),
			'span_days' => (int) $days,
		);
	}

	$comments = wp_count_comments();

	return array(
		'enquiries'  => $enquiries,
		'newsletter' => wpsp_count_newsletter( $since ),
		'shop'       => $shop,
		'comments'   => array(
			'awaiting' => (int) ( $comments->moderated ?? 0 ),
			'spam'     => (int) ( $comments->spam ?? 0 ),
		),
	);
}

/**
 * How many posts of a type were created since a moment.
 *
 * @param string $type  Post type.
 * @param string $since MySQL datetime in UTC.
 * @return int
 */
function wpsp_count_posts_since( $type, $since ) {
	global $wpdb;

	// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- A count with no cached equivalent; run once a day.
	return (int) $wpdb->get_var(
		$wpdb->prepare(
			"SELECT COUNT(*) FROM {$wpdb->posts} WHERE post_type = %s AND post_status NOT IN ('auto-draft','trash') AND post_date_gmt >= %s",
			$type,
			$since
		)
	);
}

/**
 * How many enquiries of a type still look unanswered.
 *
 * The sites mark this in one of two ways, so both are counted: a post status whose name contains "new", or no term
 * in an enquiry status taxonomy. Where neither pattern is used, the answer is zero rather than a guess.
 *
 * @param string $type Post type.
 * @return int
 */
function wpsp_count_unanswered( $type ) {
	global $wpdb;

	$statuses = get_post_stati( array(), 'names' );
	$new      = array();

	foreach ( (array) $statuses as $status ) {
		if ( preg_match( '/(^|[-_])(new|unread|pending|open)([-_]|$)/', (string) $status ) ) {
			$new[] = (string) $status;
		}
	}

	if ( ! $new ) {
		return 0;
	}

	$placeholders = implode( ', ', array_fill( 0, count( $new ), '%s' ) );

	// phpcs:disable WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Placeholder list built here, values prepared.
	return (int) $wpdb->get_var(
		$wpdb->prepare(
			"SELECT COUNT(*) FROM {$wpdb->posts} WHERE post_type = %s AND post_status IN ({$placeholders})",
			array_merge( array( $type ), $new )
		)
	);
	// phpcs:enable
}

/**
 * Newsletter sign-ups, where a site keeps them.
 *
 * @param string $since MySQL datetime in UTC.
 * @return array<string, mixed>
 */
function wpsp_count_newsletter( $since ) {
	$types = apply_filters(
		'wpsp_newsletter_post_types',
		array_unique( array_merge( array( 'newsletter_signup', 'subscriber' ), preg_grep( '/_subscriber$/D', get_post_types() ) ) )
	);

	foreach ( (array) $types as $type ) {
		if ( post_type_exists( $type ) ) {
			$counts = (array) wp_count_posts( $type );

			return array(
				'present' => true,
				'total'   => (int) ( $counts['publish'] ?? 0 ),
				'recent'  => wpsp_count_posts_since( $type, $since ),
			);
		}
	}

	return array( 'present' => false );
}

/**
 * How much is on the site, and whether anything has gone stale.
 *
 * @return array<string, mixed>
 */
function wpsp_report_content() {
	$pages = (array) wp_count_posts( 'page' );
	$posts = (array) wp_count_posts( 'post' );

	$media = (array) wp_count_posts( 'attachment' );

	$latest = get_posts(
		array(
			'post_type'        => 'post',
			'posts_per_page'   => 1,
			'post_status'      => 'publish',
			'orderby'          => 'date',
			'order'            => 'DESC',
			'fields'           => 'ids',
			'suppress_filters' => true,
		)
	);

	$last_post = $latest ? get_post_field( 'post_date_gmt', $latest[0] ) : '';

	return array(
		'pages'      => array(
			'published' => (int) ( $pages['publish'] ?? 0 ),
			'drafts'    => (int) ( $pages['draft'] ?? 0 ),
		),
		'posts'      => array(
			'published' => (int) ( $posts['publish'] ?? 0 ),
			'drafts'    => (int) ( $posts['draft'] ?? 0 ),
			'last'      => $last_post ? gmdate( 'c', (int) strtotime( (string) $last_post ) ) : '',
		),
		'media'       => (int) ( $media['inherit'] ?? 0 ),
		'last_change' => get_lastpostmodified( 'gmt' ) ? gmdate( 'c', (int) strtotime( (string) get_lastpostmodified( 'gmt' ) ) ) : '',
	);
}
