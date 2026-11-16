<?php
/**
 * Plugin Name:       WordPress Security Plugin
 * Plugin URI:        https://github.com/aliameenco-creator/wordpress-security-plugin
 * Description:       Security, bot protection, maintenance mode and daily reporting for WordPress sites. One plugin, one report format, nothing heavy on the front end.
 * Version:           0.2.0
 * Requires at least: 6.6
 * Requires PHP:      8.1
 * Author:            aliameenco-creator
 * License:           GPL-2.0-or-later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       wordpress-security-plugin
 * Update URI:        https://github.com/aliameenco-creator/wordpress-security-plugin
 *
 * Design rules this plugin keeps to:
 *
 * 1. A visitor's page load must cost nothing measurable. Everything on the front end is plain PHP string work against
 *    one already-loaded option. No HTTP calls, no file scans and no queries during a page render, except the single
 *    indexed insert the visit counter makes when it is switched on.
 * 2. Heavy work happens on WP-Cron, once a day, in one place: includes/scanner.php.
 * 3. Every feature has an off switch, and the stored settings are the only state.
 * 4. Nothing leaves the site except the report, which is read-only, signed, and never contains a credential.
 *
 * @package wordpress-security-plugin
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'WPSP_VERSION', '0.2.0' );
define( 'WPSP_FILE', __FILE__ );
define( 'WPSP_PATH', plugin_dir_path( __FILE__ ) );
define( 'WPSP_URL', plugin_dir_url( __FILE__ ) );
define( 'WPSP_SLUG', plugin_basename( __FILE__ ) );

/** The database layout version, bumped when a table changes. */
define( 'WPSP_DB_VERSION', 2 );

require_once WPSP_PATH . 'includes/helpers.php';
require_once WPSP_PATH . 'includes/events.php';
require_once WPSP_PATH . 'includes/maintenance.php';
require_once WPSP_PATH . 'includes/login.php';
require_once WPSP_PATH . 'includes/qr.php';
require_once WPSP_PATH . 'includes/two-factor.php';
require_once WPSP_PATH . 'includes/hardening.php';
require_once WPSP_PATH . 'includes/bots.php';
require_once WPSP_PATH . 'includes/visits.php';
require_once WPSP_PATH . 'includes/scanner.php';
require_once WPSP_PATH . 'includes/report.php';
require_once WPSP_PATH . 'includes/github-updater.php';

if ( is_admin() ) {
	require_once WPSP_PATH . 'includes/admin.php';
}

/**
 * First run: create the tables, pick safe defaults and schedule the nightly job.
 */
function wpsp_activate() {
	wpsp_install_tables();

	$settings = get_option( 'wpsp_settings' );
	if ( ! is_array( $settings ) ) {
		// A fresh install starts with the measures that cannot lock anyone out or change how the site looks. The
		// private sign-in address and maintenance mode are deliberately left off until an administrator sets them.
		add_option( 'wpsp_settings', wpsp_default_settings(), '', true );
	}

	wpsp_schedule_jobs();
	wpsp_log_event( 'plugin', 'WordPress Security Plugin activated.', 'notice' );
}
register_activation_hook( __FILE__, 'wpsp_activate' );

/**
 * Leaves the site in a working state: the nightly job stops, and the private sign-in address releases its rewrite
 * rules so /wp-login.php answers normally again. Settings, logs and counters are kept.
 */
function wpsp_deactivate() {
	wpsp_unschedule_jobs();
	flush_rewrite_rules();
}
register_deactivation_hook( __FILE__, 'wpsp_deactivate' );

/**
 * Keeps the tables and the nightly job in step after a plugin update, without a query on normal page loads.
 */
function wpsp_maybe_upgrade() {
	if ( (int) get_option( 'wpsp_db_version' ) !== WPSP_DB_VERSION ) {
		wpsp_install_tables();
	}
	wpsp_schedule_jobs();
}
add_action( 'admin_init', 'wpsp_maybe_upgrade' );
