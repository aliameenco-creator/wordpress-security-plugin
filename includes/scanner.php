<?php
/**
 * The nightly check.
 *
 * Everything expensive lives here, and here only: comparing WordPress's own files against the official checksums,
 * looking for PHP files where none should be, asking the vulnerability database about the installed plugins, and
 * tidying the log. It runs once a day on WP-Cron and the result is stored, so the report and the admin screen read
 * a stored answer rather than doing the work again.
 *
 * Only two outside addresses are ever contacted, both official and both read-only:
 *   api.wordpress.org  - the checksums for the installed WordPress version
 *   cloudflare.com     - the published list of Cloudflare addresses, and only when the site is set as being behind it
 *
 * @package wordpress-security-plugin
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Puts the nightly job on the schedule if it is not there.
 *
 * @return void
 */
function wpsp_schedule_jobs() {
	// The job also tidies the log, so it runs every night; the expensive checks inside it only run when the
	// nightly check is switched on. See wpsp_nightly_job().
	if ( ! wp_next_scheduled( 'wpsp_nightly' ) ) {
		// A little after 3am in the site's own timezone, when nobody is looking at the site.
		$offset = (int) ( (float) get_option( 'gmt_offset', 0 ) * HOUR_IN_SECONDS );
		$next   = strtotime( 'tomorrow 03:17' ) - $offset;
		wp_schedule_event( $next > time() ? $next : time() + HOUR_IN_SECONDS, 'daily', 'wpsp_nightly' );
	}
}

/**
 * Takes it off again.
 *
 * @return void
 */
function wpsp_unschedule_jobs() {
	$timestamp = wp_next_scheduled( 'wpsp_nightly' );

	while ( $timestamp ) {
		wp_unschedule_event( $timestamp, 'wpsp_nightly' );
		$timestamp = wp_next_scheduled( 'wpsp_nightly' );
	}
}

/**
 * The nightly run.
 *
 * Each step is wrapped so one failure cannot stop the rest, and the stored result always says when it ran, so the
 * tracker can tell a stale answer from a fresh one.
 *
 * @return array<string, mixed> What was found.
 */
function wpsp_run_scan() {
	$result = array(
		'ran_at'          => gmdate( 'c' ),
		'core_files'      => array( 'checked' => false, 'modified' => array(), 'missing' => array() ),
		'unexpected_php'  => array(),
		'vulnerabilities' => array(),
		'updates'         => array(),
		'admins'          => array(),
		'notes'           => array(),
	);

	foreach ( array( 'core_files' => 'wpsp_scan_core', 'unexpected_php' => 'wpsp_scan_uploads', 'updates' => 'wpsp_scan_updates', 'admins' => 'wpsp_scan_admins' ) as $slot => $callback ) {
		try {
			$result[ $slot ] = $callback();
		} catch ( Throwable $e ) {
			$result['notes'][] = $slot . ': ' . $e->getMessage();
		}
	}

	try {
		$result['vulnerabilities'] = wpsp_scan_vulnerabilities();
	} catch ( Throwable $e ) {
		$result['notes'][] = 'vulnerabilities: ' . $e->getMessage();
	}

	$removed = wpsp_prune_events();
	if ( $removed > 0 ) {
		$result['notes'][] = sprintf( '%d old log entries removed.', $removed );
	}

	if ( wpsp_on( 'behind_cloudflare' ) ) {
		wpsp_refresh_cloudflare_ranges();
	}

	update_option( 'wpsp_scan', $result, false );

	$problems = count( $result['core_files']['modified'] ) + count( $result['core_files']['missing'] )
		+ count( $result['unexpected_php'] ) + count( $result['vulnerabilities'] );

	wpsp_log_event(
		'scan',
		$problems > 0 ? sprintf( 'The nightly check found %d things to look at.', $problems ) : 'The nightly check found nothing wrong.',
		$problems > 0 ? 'warning' : 'notice'
	);

	return $result;
}

/**
 * What WP-Cron runs each night: the full check when it is switched on, otherwise only the log tidy-up, which is a
 * single delete query and contacts nobody.
 *
 * @return void
 */
function wpsp_nightly_job() {
	if ( wpsp_on( 'nightly_scan' ) ) {
		wpsp_run_scan();
		return;
	}

	wpsp_prune_events();
}
add_action( 'wpsp_nightly', 'wpsp_nightly_job' );

/**
 * The last stored result.
 *
 * @return array<string, mixed>
 */
function wpsp_last_scan() {
	$scan = get_option( 'wpsp_scan' );

	return is_array( $scan ) ? $scan : array();
}

/**
 * Compares WordPress's own files against the official checksums.
 *
 * A changed core file is the clearest sign a site has been broken into, because nothing legitimate edits them. The
 * two files WordPress itself expects owners to have changed are skipped.
 *
 * @return array<string, mixed>
 */
function wpsp_scan_core() {
	$out = array( 'checked' => false, 'modified' => array(), 'missing' => array() );

	if ( ! function_exists( 'get_core_checksums' ) ) {
		require_once ABSPATH . 'wp-admin/includes/update.php';
	}

	$version   = get_bloginfo( 'version' );
	$checksums = get_core_checksums( $version, get_locale() );

	if ( ! is_array( $checksums ) ) {
		$checksums = get_core_checksums( $version, 'en_US' );
	}

	if ( ! is_array( $checksums ) ) {
		$out['note'] = 'WordPress.org did not return checksums for this version.';

		return $out;
	}

	$out['checked'] = true;
	$skip           = array( 'wp-config-sample.php', 'wp-includes/version.php', 'readme.html', 'license.txt' );

	foreach ( $checksums as $file => $hash ) {
		if ( in_array( $file, $skip, true ) || 0 === strpos( $file, 'wp-content/' ) ) {
			continue;
		}

		$path = ABSPATH . $file;

		if ( ! file_exists( $path ) ) {
			$out['missing'][] = $file;
			continue;
		}

		if ( md5_file( $path ) !== $hash ) {
			$out['modified'][] = $file;
		}

		// A plain cap so a site with an odd install cannot produce a report thousands of lines long.
		if ( count( $out['modified'] ) > 50 ) {
			$out['note'] = 'More than fifty files differ. Compare the install against a fresh copy of WordPress.';
			break;
		}
	}

	return $out;
}

/**
 * Looks for PHP files inside the uploads folder.
 *
 * Nothing legitimate puts code there. A PHP file in uploads is either a mistake or a back door, and it is the first
 * thing to look for after a break-in.
 *
 * @return array<int, string>
 */
function wpsp_scan_uploads() {
	$found   = array();
	$uploads = wp_get_upload_dir();
	$base    = $uploads['basedir'] ?? '';

	if ( '' === $base || ! is_dir( $base ) ) {
		return $found;
	}

	$iterator = new RecursiveIteratorIterator(
		new RecursiveDirectoryIterator( $base, FilesystemIterator::SKIP_DOTS ),
		RecursiveIteratorIterator::LEAVES_ONLY
	);

	$checked = 0;

	foreach ( $iterator as $file ) {
		if ( ++$checked > 50000 ) {
			break;
		}

		$name = strtolower( $file->getFilename() );

		if ( preg_match( '/\.(php|phtml|php\d|phar|pht|shtml)$/', $name ) ) {
			$found[] = str_replace( $base, '', $file->getPathname() );
		}

		if ( count( $found ) >= 25 ) {
			break;
		}
	}

	return $found;
}

/**
 * What needs updating.
 *
 * @return array<string, mixed>
 */
function wpsp_scan_updates() {
	if ( ! function_exists( 'get_plugin_updates' ) ) {
		require_once ABSPATH . 'wp-admin/includes/update.php';
	}
	if ( ! function_exists( 'get_plugins' ) ) {
		require_once ABSPATH . 'wp-admin/includes/plugin.php';
	}

	wp_update_plugins();
	wp_update_themes();

	$core    = get_core_updates();
	$plugins = get_plugin_updates();
	$themes  = get_theme_updates();

	$core_version = '';
	if ( is_array( $core ) && isset( $core[0] ) && 'upgrade' === ( $core[0]->response ?? '' ) ) {
		$core_version = (string) ( $core[0]->current ?? '' );
	}

	$plugin_list = array();
	foreach ( (array) $plugins as $file => $data ) {
		$plugin_list[] = array(
			'name'      => (string) ( $data->Name ?? $file ), // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- WordPress's own property name.
			'installed' => (string) ( $data->Version ?? '' ), // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase
			'available' => (string) ( $data->update->new_version ?? '' ),
		);
	}

	$theme_list = array();
	foreach ( (array) $themes as $slug => $theme ) {
		$theme_list[] = array(
			'name'      => (string) $theme->get( 'Name' ),
			'installed' => (string) $theme->get( 'Version' ),
			'available' => (string) ( $theme->update['new_version'] ?? '' ),
		);
	}

	return array(
		'core'    => $core_version,
		'plugins' => $plugin_list,
		'themes'  => $theme_list,
	);
}

/**
 * The administrator accounts, and whether any appeared recently.
 *
 * A new administrator nobody created is the clearest sign of a compromised site, so the report names them and the
 * tracker can flag a count that has changed.
 *
 * @return array<int, array<string, mixed>>
 */
function wpsp_scan_admins() {
	$admins = array();

	foreach ( get_users( array( 'role' => 'administrator', 'number' => 50 ) ) as $user ) {
		$admins[] = array(
			'login'      => $user->user_login,
			'registered' => $user->user_registered,
			'two_factor' => wpsp_2fa_enabled_for( $user->ID ),
		);
	}

	return $admins;
}

/**
 * Asks the public vulnerability database whether any installed plugin or theme has a known security hole.
 *
 * Wordfence publish their intelligence feed openly, with no key and no account, under a licence that allows this
 * use. Only the installed slugs and versions are compared locally against the downloaded list: the site does not
 * tell anybody what it has installed.
 *
 * The list is large, so it is fetched at most once a week and the comparison is done on a stream rather than by
 * holding the whole thing in memory.
 *
 * @return array<int, array<string, mixed>>
 */
function wpsp_scan_vulnerabilities() {
	if ( ! function_exists( 'get_plugins' ) ) {
		require_once ABSPATH . 'wp-admin/includes/plugin.php';
	}

	$feed = get_option( 'wpsp_vuln_feed' );
	$age  = is_array( $feed ) ? ( time() - (int) ( $feed['fetched'] ?? 0 ) ) : PHP_INT_MAX;

	if ( $age > WEEK_IN_SECONDS ) {
		$response = wp_safe_remote_get(
			'https://www.wordfence.com/api/intelligence/v2/vulnerabilities/production/scanner',
			array(
				'timeout'             => 30,
				'redirection'         => 2,
				'limit_response_size' => 25000000,
				'headers'             => array( 'Accept' => 'application/json' ),
			)
		);

		if ( is_wp_error( $response ) || 200 !== wp_remote_retrieve_response_code( $response ) ) {
			return is_array( $feed ) && isset( $feed['matches'] ) ? (array) $feed['matches'] : array();
		}

		$data = json_decode( (string) wp_remote_retrieve_body( $response ), true );

		if ( ! is_array( $data ) ) {
			return array();
		}

		$feed = array( 'fetched' => time(), 'matches' => wpsp_match_vulnerabilities( $data ) );
		update_option( 'wpsp_vuln_feed', $feed, false );

		return (array) $feed['matches'];
	}

	return (array) ( $feed['matches'] ?? array() );
}

/**
 * Compares the feed against what is installed.
 *
 * @param array<string, mixed> $data The feed.
 * @return array<int, array<string, mixed>>
 */
function wpsp_match_vulnerabilities( array $data ) {
	$installed = array();

	foreach ( get_plugins() as $file => $plugin ) {
		$slug                = dirname( $file );
		$slug                = '.' === $slug ? basename( $file, '.php' ) : $slug;
		$installed[ $slug ]  = array(
			'name'    => (string) ( $plugin['Name'] ?? $slug ),
			'version' => (string) ( $plugin['Version'] ?? '0' ),
			'kind'    => 'plugin',
		);
	}

	foreach ( wp_get_themes() as $slug => $theme ) {
		$installed[ (string) $slug ] = array(
			'name'    => (string) $theme->get( 'Name' ),
			'version' => (string) $theme->get( 'Version' ),
			'kind'    => 'theme',
		);
	}

	$matches = array();

	foreach ( $data as $vuln ) {
		$software = isset( $vuln['software'] ) && is_array( $vuln['software'] ) ? $vuln['software'] : array();

		foreach ( $software as $item ) {
			$slug = (string) ( $item['slug'] ?? '' );

			if ( '' === $slug || ! isset( $installed[ $slug ] ) ) {
				continue;
			}

			$version   = $installed[ $slug ]['version'];
			$affected  = isset( $item['affected_versions'] ) && is_array( $item['affected_versions'] ) ? $item['affected_versions'] : array();
			$is_match  = false;

			foreach ( $affected as $range ) {
				$from     = (string) ( $range['from_version'] ?? '' );
				$to       = (string) ( $range['to_version'] ?? '' );
				$from_in  = ! empty( $range['from_inclusive'] );
				$to_in    = ! empty( $range['to_inclusive'] );
				$above    = '' === $from || '*' === $from || version_compare( $version, $from, $from_in ? '>=' : '>' );
				$below    = '' === $to || '*' === $to || version_compare( $version, $to, $to_in ? '<=' : '<' );

				if ( $above && $below ) {
					$is_match = true;
					break;
				}
			}

			if ( ! $is_match ) {
				continue;
			}

			$matches[] = array(
				'slug'     => $slug,
				'name'     => $installed[ $slug ]['name'],
				'kind'     => $installed[ $slug ]['kind'],
				'version'  => $version,
				'title'    => substr( (string) ( $vuln['title'] ?? 'Known security issue' ), 0, 160 ),
				'severity' => (string) ( $vuln['cvss']['rating'] ?? '' ),
				'patched'  => (string) ( $item['patched_versions'][0] ?? '' ),
			);

			if ( count( $matches ) >= 50 ) {
				return $matches;
			}
		}
	}

	return $matches;
}

/**
 * Refreshes the stored copy of Cloudflare's published addresses.
 *
 * @return void
 */
function wpsp_refresh_cloudflare_ranges() {
	$ranges = array();

	foreach ( array( 'https://www.cloudflare.com/ips-v4', 'https://www.cloudflare.com/ips-v6' ) as $url ) {
		$response = wp_safe_remote_get( $url, array( 'timeout' => 15, 'limit_response_size' => 20000 ) );

		if ( is_wp_error( $response ) || 200 !== wp_remote_retrieve_response_code( $response ) ) {
			continue;
		}

		foreach ( preg_split( '/\s+/', (string) wp_remote_retrieve_body( $response ) ) as $line ) {
			$line = trim( (string) $line );
			if ( '' !== $line && preg_match( '~^[0-9a-fA-F:.]+/\d{1,3}$~D', $line ) ) {
				$ranges[] = $line;
			}
		}
	}

	// Only replace the stored list when both files came back looking sane, so a bad fetch cannot leave the site
	// unable to recognise Cloudflare and therefore rate limiting every visitor as one address.
	if ( count( $ranges ) >= 10 ) {
		update_option( 'wpsp_cloudflare_ranges', $ranges, true );
	}
}
