<?php
/**
 * Counting visits, without tracking anybody.
 *
 * The daily report needs to say how many people came. Google Analytics answers that too, but it needs a consent
 * banner, it is blocked for a good share of visitors, and it cannot be read by the tracker without connecting an
 * account per site. So the plugin keeps its own count: two numbers a day, page views and roughly how many separate
 * visitors, and nothing else.
 *
 * What is stored: one row per day holding two totals. No addresses, no identifiers, no paths, no sessions, no
 * cookies, nothing that could be traced back to a person. Whether a visitor has been counted today is held in a
 * short-lived transient keyed by the rotating one-way identifier from helpers.php, which cannot be reversed and is
 * meaningless by tomorrow. There is nothing here to export under a data request and nothing that needs consent.
 *
 * Why a beacon rather than counting in PHP: the host serves most pages from its cache without running WordPress, so
 * counting during a page render would miss most of the traffic and undercount by a wide margin. A small script asks
 * the site to add one after the page has finished loading, which is accurate and costs the visitor nothing: it runs
 * after everything else, uses the browser's own background send, and is a few hundred bytes inline with no extra
 * file to fetch.
 *
 * @package wordpress-security-plugin
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Records one page view, and one visitor if this one has not been seen today.
 *
 * Two statements on one indexed row, so two visitors arriving at the same moment cannot overwrite each other's
 * count the way a stored option would.
 *
 * @return void
 */
function wpsp_record_visit() {
	global $wpdb;

	$table = wpsp_visits_table();
	$day   = current_time( 'Y-m-d' );
	$key   = 'wpsp_seen_' . wpsp_ip_hash();
	$fresh = ! get_transient( $key );

	if ( $fresh ) {
		set_transient( $key, 1, 12 * HOUR_IN_SECONDS );
	}

	// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- A counter has no cache, and the table name is built here.
	$wpdb->query(
		$wpdb->prepare(
			"INSERT INTO {$table} (day, hits, visitors) VALUES (%s, 1, %d)
			 ON DUPLICATE KEY UPDATE hits = hits + 1, visitors = visitors + %d",
			$day,
			$fresh ? 1 : 0,
			$fresh ? 1 : 0
		)
	);
	// phpcs:enable
}

/**
 * The totals for a span of days, newest first.
 *
 * @param int $days How many days back.
 * @return array<int, array<string, mixed>>
 */
function wpsp_visit_rows( $days = 30 ) {
	global $wpdb;

	$table = wpsp_visits_table();
	$since = gmdate( 'Y-m-d', time() - ( max( 1, (int) $days ) * DAY_IN_SECONDS ) );

	// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Table name only.
	$rows = $wpdb->get_results( $wpdb->prepare( "SELECT day, hits, visitors FROM {$table} WHERE day >= %s ORDER BY day DESC", $since ), ARRAY_A );

	return is_array( $rows ) ? $rows : array();
}

/**
 * The totals for one day.
 *
 * @param string $day A date as Y-m-d; today by default.
 * @return array{hits: int, visitors: int}
 */
function wpsp_visits_for( $day = '' ) {
	global $wpdb;

	$table = wpsp_visits_table();
	$day   = '' !== $day ? $day : current_time( 'Y-m-d' );

	// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Table name only.
	$row = $wpdb->get_row( $wpdb->prepare( "SELECT hits, visitors FROM {$table} WHERE day = %s", $day ), ARRAY_A );

	return array(
		'hits'     => (int) ( $row['hits'] ?? 0 ),
		'visitors' => (int) ( $row['visitors'] ?? 0 ),
	);
}

/**
 * The total across a span of days.
 *
 * @param int $days How many days back.
 * @return array{hits: int, visitors: int}
 */
function wpsp_visits_total( $days = 30 ) {
	$hits     = 0;
	$visitors = 0;

	foreach ( wpsp_visit_rows( $days ) as $row ) {
		$hits     += (int) $row['hits'];
		$visitors += (int) $row['visitors'];
	}

	return array(
		'hits'     => $hits,
		'visitors' => $visitors,
	);
}

/**
 * Registers the endpoint the beacon calls.
 *
 * Public by design: it accepts nothing and returns nothing but a 204, so there is no data to protect and nothing an
 * attacker gains beyond inflating a number on the owner's own dashboard. The per-visitor rate limit applies.
 *
 * @return void
 */
function wpsp_register_visit_route() {
	register_rest_route(
		'wordpress-security-plugin/v1',
		'/hit',
		array(
			'methods'             => 'POST',
			'callback'            => 'wpsp_visit_endpoint',
			'permission_callback' => '__return_true',
		)
	);
}
add_action( 'rest_api_init', 'wpsp_register_visit_route' );

/**
 * Counts the view and answers with nothing.
 *
 * @return WP_REST_Response
 */
function wpsp_visit_endpoint() {
	if ( wpsp_on( 'count_visits' ) ) {
		wpsp_record_visit();
	}

	return new WP_REST_Response( null, 204 );
}

/**
 * Puts the beacon on the page.
 *
 * Deliberately small and late: it is inline so there is no extra file to download, it waits for the page to finish
 * loading so it cannot delay anything a visitor sees, it uses the browser's background send so the request does not
 * hold the page open, and it skips anyone signed in, any admin screen, and any browser asking not to be tracked.
 *
 * @return void
 */
function wpsp_visit_beacon() {
	if ( ! wpsp_on( 'count_visits' ) || is_user_logged_in() || is_admin() || is_preview() || is_404() ) {
		return;
	}

	$url = esc_url_raw( rest_url( 'wordpress-security-plugin/v1/hit' ) );

	?>
<script id="wordpress-security-plugin-beacon">
(function () {
	if (navigator.webdriver || navigator.doNotTrack === "1") { return; }
	var send = function () {
		try {
			var u = <?php echo wp_json_encode( $url ); ?>;
			if (navigator.sendBeacon) { navigator.sendBeacon(u); }
			else { fetch(u, { method: "POST", keepalive: true, credentials: "omit" }); }
		} catch (e) {}
	};
	if (document.readyState === "complete") { setTimeout(send, 800); }
	else { window.addEventListener("load", function () { setTimeout(send, 800); }); }
})();
</script>
	<?php
}
add_action( 'wp_footer', 'wpsp_visit_beacon', 100 );
