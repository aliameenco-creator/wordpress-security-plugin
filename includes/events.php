<?php
/**
 * The event log and the visit counter's tables.
 *
 * Two small tables rather than options, so a write is one indexed statement and two visitors arriving at the same
 * moment cannot overwrite each other's count. Both tables are capped: the nightly job deletes anything older than
 * the retention setting, so neither can grow without limit on a site that runs for years.
 *
 * No raw IP address and no personal detail is ever written here. The visitor column holds the rotating one-way
 * identifier from helpers.php.
 *
 * @package wordpress-security-plugin
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * The event table's name.
 *
 * @return string
 */
function wpsp_events_table() {
	global $wpdb;

	return $wpdb->prefix . 'wpsp_events';
}

/**
 * The visit table's name.
 *
 * @return string
 */
function wpsp_visits_table() {
	global $wpdb;

	return $wpdb->prefix . 'wpsp_visits';
}

/**
 * Creates or updates both tables.
 *
 * @return void
 */
function wpsp_install_tables() {
	global $wpdb;

	require_once ABSPATH . 'wp-admin/includes/upgrade.php';

	$charset = $wpdb->get_charset_collate();
	$events  = wpsp_events_table();
	$visits  = wpsp_visits_table();

	dbDelta(
		"CREATE TABLE {$events} (
			id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
			created_at DATETIME NOT NULL,
			type VARCHAR(32) NOT NULL,
			severity VARCHAR(10) NOT NULL DEFAULT 'notice',
			visitor VARCHAR(16) NOT NULL DEFAULT '',
			user_id BIGINT UNSIGNED NOT NULL DEFAULT 0,
			message VARCHAR(255) NOT NULL DEFAULT '',
			context VARCHAR(255) NOT NULL DEFAULT '',
			PRIMARY KEY (id),
			KEY created_at (created_at),
			KEY type_created (type, created_at)
		) {$charset};"
	);

	dbDelta(
		"CREATE TABLE {$visits} (
			day DATE NOT NULL,
			hits BIGINT UNSIGNED NOT NULL DEFAULT 0,
			visitors BIGINT UNSIGNED NOT NULL DEFAULT 0,
			PRIMARY KEY (day)
		) {$charset};"
	);

	update_option( 'wpsp_db_version', WPSP_DB_VERSION, true );
}

/**
 * Records one event.
 *
 * Deliberately forgiving: if the table is missing or the write fails, the site carries on. A log that can break a
 * page is worse than a missing line in the log.
 *
 * @param string $type     Short machine name, e.g. login_failed, bot_blocked, setting_changed.
 * @param string $message  One readable line.
 * @param string $severity notice, warning or critical.
 * @param string $context  Optional extra detail, such as a path or a user agent.
 * @return void
 */
function wpsp_log_event( $type, $message, $severity = 'notice', $context = '' ) {
	global $wpdb;

	$table = wpsp_events_table();

	// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- A log write has no cache.
	$wpdb->insert(
		$table,
		array(
			'created_at' => current_time( 'mysql', true ),
			'type'       => substr( (string) $type, 0, 32 ),
			'severity'   => in_array( $severity, array( 'notice', 'warning', 'critical' ), true ) ? $severity : 'notice',
			'visitor'    => wpsp_ip_hash(),
			'user_id'    => (int) get_current_user_id(),
			'message'    => substr( (string) $message, 0, 255 ),
			'context'    => substr( (string) $context, 0, 255 ),
		),
		array( '%s', '%s', '%s', '%s', '%d', '%s', '%s' )
	);
}

/**
 * How many events of each type happened in the last so many hours.
 *
 * @param int           $hours How far back to count.
 * @param string[]|null $types Limit to these types, or all types.
 * @return array<string, int>
 */
function wpsp_count_events( $hours = 24, $types = null ) {
	global $wpdb;

	$table = wpsp_events_table();
	$since = gmdate( 'Y-m-d H:i:s', time() - ( (int) $hours * HOUR_IN_SECONDS ) );

	if ( is_array( $types ) && $types ) {
		$placeholders = implode( ', ', array_fill( 0, count( $types ), '%s' ) );
		// phpcs:disable WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Table name and placeholder list are built here, values are prepared.
		$sql = $wpdb->prepare(
			"SELECT type, COUNT(*) AS total FROM {$table} WHERE created_at >= %s AND type IN ({$placeholders}) GROUP BY type",
			array_merge( array( $since ), $types )
		);
		// phpcs:enable
	} else {
		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Table name only.
		$sql = $wpdb->prepare( "SELECT type, COUNT(*) AS total FROM {$table} WHERE created_at >= %s GROUP BY type", $since );
	}

	// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared -- Prepared above.
	$rows = $wpdb->get_results( $sql, ARRAY_A );

	$counts = array();
	foreach ( (array) $rows as $row ) {
		$counts[ (string) $row['type'] ] = (int) $row['total'];
	}

	return $counts;
}

/**
 * The most recent events, newest first.
 *
 * @param int    $limit    How many rows.
 * @param string $severity Optional: only this severity and above.
 * @return array<int, array<string, mixed>>
 */
function wpsp_recent_events( $limit = 50, $severity = '' ) {
	global $wpdb;

	$table = wpsp_events_table();
	$limit = max( 1, min( 500, (int) $limit ) );

	if ( 'warning' === $severity ) {
		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Table name only.
		$sql = $wpdb->prepare( "SELECT * FROM {$table} WHERE severity IN ('warning','critical') ORDER BY id DESC LIMIT %d", $limit );
	} elseif ( 'critical' === $severity ) {
		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Table name only.
		$sql = $wpdb->prepare( "SELECT * FROM {$table} WHERE severity = 'critical' ORDER BY id DESC LIMIT %d", $limit );
	} else {
		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Table name only.
		$sql = $wpdb->prepare( "SELECT * FROM {$table} ORDER BY id DESC LIMIT %d", $limit );
	}

	// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared -- Prepared above.
	$rows = $wpdb->get_results( $sql, ARRAY_A );

	return is_array( $rows ) ? $rows : array();
}

/**
 * Deletes events and visit rows past the retention period. Called by the nightly job only.
 *
 * @return int Rows removed from the event log.
 */
function wpsp_prune_events() {
	global $wpdb;

	$days   = max( 7, min( 365, (int) wpsp_option( 'log_retention_days', 90 ) ) );
	$cutoff = gmdate( 'Y-m-d H:i:s', time() - ( $days * DAY_IN_SECONDS ) );
	$events = wpsp_events_table();
	$visits = wpsp_visits_table();

	// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Table name only.
	$removed = (int) $wpdb->query( $wpdb->prepare( "DELETE FROM {$events} WHERE created_at < %s", $cutoff ) );

	// Visit totals are tiny, one row a day, so a longer window costs nothing and makes year-on-year useful.
	$visit_cutoff = gmdate( 'Y-m-d', time() - ( 400 * DAY_IN_SECONDS ) );

	// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Table name only.
	$wpdb->query( $wpdb->prepare( "DELETE FROM {$visits} WHERE day < %s", $visit_cutoff ) );

	return $removed;
}
