<?php
/**
 * Updates from numbered GitHub releases, through WordPress's own plugin upgrader.
 *
 * One release updates the plugin on every site from inside WordPress. The repository is public, so no token or
 * other credential is needed, stored or sent.
 *
 * Updates are always manual. WordPress shows that a new version exists, and an administrator decides when to
 * install it, either with the update link or by uploading the ZIP. The plugin never updates itself, even if
 * automatic updates are switched on for plugins in general.
 *
 * Every package is checked before a single file is installed: the release must be a numbered stable release, the
 * download must match the size and SHA-256 digest GitHub published, and the ZIP must contain only paths inside
 * wordpress-security-plugin/ with no symbolic links and the version the release claims.
 *
 * @package wordpress-security-plugin
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/** The repository releases come from, and the file name inside each release. */
const WPSP_REPO    = 'aliameenco-creator/wordpress-security-plugin';
const WPSP_PACKAGE = 'wordpress-security-plugin.zip';

/**
 * The GitHub API address for the repository.
 *
 * @return string
 */
function wpsp_update_api() {
	return 'https://api.github.com/repos/' . WPSP_REPO;
}

/**
 * Headers for an API call.
 *
 * @return array<string, string>
 */
function wpsp_update_headers() {
	return array(
		'Accept'               => 'application/vnd.github+json',
		'X-GitHub-Api-Version' => '2022-11-28',
		'User-Agent'           => 'WordPress-Security-Plugin-Updater',
	);
}

/**
 * Checks a release is one we are willing to install, and pulls out what is needed to verify the download.
 *
 * @param mixed $data The decoded release.
 * @return array<string, mixed>|WP_Error
 */
function wpsp_release_validate( $data ) {
	if ( ! is_array( $data ) || ! empty( $data['draft'] ) || ! empty( $data['prerelease'] )
		|| ! isset( $data['tag_name'], $data['assets'] )
		|| ! preg_match( '/^v(\d+\.\d+\.\d+)$/D', (string) $data['tag_name'], $match ) ) {
		return new WP_Error( 'release', 'No stable numbered release is available.' );
	}

	foreach ( (array) $data['assets'] as $asset ) {
		if ( WPSP_PACKAGE !== ( $asset['name'] ?? '' ) ) {
			continue;
		}

		if ( empty( $asset['id'] ) || ! is_int( $asset['id'] )
			|| ! preg_match( '/^sha256:([a-f0-9]{64})$/D', (string) ( $asset['digest'] ?? '' ), $digest )
			|| empty( $asset['size'] ) || $asset['size'] > 20000000 ) {
			return new WP_Error( 'asset', 'The release package is missing a valid SHA-256 digest or is larger than expected.' );
		}

		return array(
			'version' => $match[1],
			'package' => wpsp_update_api() . '/releases/assets/' . $asset['id'],
			'sha256'  => $digest[1],
			'size'    => (int) $asset['size'],
			'notes'   => is_string( $data['body'] ?? null ) ? $data['body'] : '',
		);
	}

	return new WP_Error( 'package', 'The release must include an uploaded ' . WPSP_PACKAGE . ' asset.' );
}

/**
 * Asks GitHub about the latest release, at most once an hour.
 *
 * @param bool $force Ignore the stored answer.
 * @return array<string, mixed>|WP_Error
 */
function wpsp_release_check( $force = false ) {
	if ( ! $force ) {
		$cached = get_site_transient( 'wpsp_release' );
		if ( is_array( $cached ) || is_wp_error( $cached ) ) {
			return $cached;
		}
	}

	$response = wp_safe_remote_get(
		wpsp_update_api() . '/releases/latest',
		array(
			'headers'             => wpsp_update_headers(),
			'timeout'             => 20,
			'redirection'         => 0,
			'limit_response_size' => 1000000,
		)
	);

	if ( is_wp_error( $response ) ) {
		$error = new WP_Error( 'network', 'GitHub could not be reached. Try again later.' );
		set_site_transient( 'wpsp_release', $error, 5 * MINUTE_IN_SECONDS );

		return $error;
	}

	if ( 200 !== wp_remote_retrieve_response_code( $response ) ) {
		$error = new WP_Error( 'github', 'GitHub did not return a release. Check that a release exists. GitHub also rate limits, which can mean waiting before checking again.' );
		set_site_transient( 'wpsp_release', $error, 5 * MINUTE_IN_SECONDS );

		return $error;
	}

	$release = wpsp_release_validate( json_decode( (string) wp_remote_retrieve_body( $response ), true ) );

	set_site_transient( 'wpsp_release', $release, is_wp_error( $release ) ? 5 * MINUTE_IN_SECONDS : HOUR_IN_SECONDS );

	return $release;
}

/**
 * Tells WordPress when an update is available.
 *
 * @param mixed $transient The plugin update data.
 * @return mixed
 */
function wpsp_release_updates( $transient ) {
	if ( ! is_object( $transient ) ) {
		return $transient;
	}

	// Never contact GitHub while a visitor's page is being built. Only wp-admin, cron and the upgrader ask.
	if ( ! is_admin() && ! wp_doing_cron() && ! is_array( get_site_transient( 'wpsp_release' ) ) ) {
		return $transient;
	}

	$release = wpsp_release_check();

	if ( is_wp_error( $release ) ) {
		unset( $transient->response[ WPSP_SLUG ] );

		return $transient;
	}

	$item = (object) array(
		'id'          => WPSP_REPO,
		'slug'        => 'wordpress-security-plugin',
		'plugin'      => WPSP_SLUG,
		'new_version' => $release['version'],
		'url'         => 'https://github.com/' . WPSP_REPO . '/releases',
		'package'     => $release['package'],
		'tested'      => get_bloginfo( 'version' ),
	);

	if ( version_compare( $release['version'], WPSP_VERSION, '>' ) ) {
		$transient->response[ WPSP_SLUG ] = $item;
		unset( $transient->no_update[ WPSP_SLUG ] );
	} else {
		unset( $transient->response[ WPSP_SLUG ] );
		$transient->no_update[ WPSP_SLUG ] = $item;
	}

	return $transient;
}
add_filter( 'site_transient_update_plugins', 'wpsp_release_updates' );

/**
 * Checks the downloaded ZIP before anything is installed.
 *
 * @param string $file    The downloaded file.
 * @param string $version The version the release claims.
 * @return true|WP_Error
 */
function wpsp_release_zip_validate( $file, $version ) {
	if ( ! class_exists( 'ZipArchive' ) ) {
		return new WP_Error( 'zip', 'The server needs the PHP ZIP extension to verify this update.' );
	}

	$zip = new ZipArchive();

	if ( true !== $zip->open( $file ) ) {
		return new WP_Error( 'zip', 'The downloaded package is not a valid ZIP.' );
	}

	$error = null;
	$total = 0;

	if ( $zip->numFiles > 500 ) {
		$error = 'Too many files in the plugin ZIP.';
	}

	for ( $i = 0; ! $error && $i < $zip->numFiles; ++$i ) {
		$entry  = $zip->statIndex( $i );
		$name   = (string) $entry['name'];
		$total += (int) $entry['size'];

		if ( ! str_starts_with( $name, 'wordpress-security-plugin/' ) || str_contains( $name, '\\' )
			|| preg_match( '~(^|/)(\.{1,2}|\.[^/]+)(/|$)~', $name ) || $total > 60000000 ) {
			$error = 'The plugin ZIP contains an unsafe path or exceeds the expanded size limit.';
			break;
		}

		$opsys      = 0;
		$attributes = 0;
		if ( $zip->getExternalAttributesIndex( $i, $opsys, $attributes ) && 0120000 === ( ( $attributes >> 16 ) & 0170000 ) ) {
			$error = 'Symbolic links are not allowed in update packages.';
		}
	}

	$main = $zip->getFromName( 'wordpress-security-plugin/wordpress-security-plugin.php' );

	if ( ! $error && ( ! is_string( $main ) || ! preg_match( '/^\s*\*\s*Version:\s*' . preg_quote( $version, '/' ) . '\s*$/m', $main ) ) ) {
		$error = 'The package version does not match the release.';
	}

	$zip->close();

	return $error ? new WP_Error( 'package', $error ) : true;
}

/**
 * Downloads the release asset, verifying it before handing it to the upgrader.
 *
 * Needed because GitHub serves release assets as octet-stream from a redirect host: without this the
 * standard download fails with a ZIP format error.
 *
 * @param mixed  $reply      Short-circuit value.
 * @param string $package    The package address WordPress was given.
 * @param object $upgrader   The upgrader.
 * @param array  $hook_extra Context.
 * @return mixed
 */
function wpsp_release_download( $reply, $package, $upgrader, $hook_extra = array() ) {
	if ( ! str_starts_with( (string) $package, wpsp_update_api() . '/releases/assets/' ) ) {
		return $reply;
	}

	$release = wpsp_release_check();

	if ( is_wp_error( $release ) || $package !== $release['package'] ) {
		return new WP_Error( 'package', 'The requested update does not match the checked release.' );
	}

	require_once ABSPATH . 'wp-admin/includes/file.php';

	$file = wp_tempnam( WPSP_PACKAGE );

	if ( ! $file ) {
		return new WP_Error( 'file', 'Cannot create the update temporary file.' );
	}

	$headers           = wpsp_update_headers();
	$headers['Accept'] = 'application/octet-stream';

	$args = array(
		'headers'             => $headers,
		'timeout'             => 120,
		'redirection'         => 0,
		'stream'              => true,
		'filename'            => $file,
		'limit_response_size' => 20000001,
	);

	$response = wp_safe_remote_get( $package, $args );

	if ( ! is_wp_error( $response ) && in_array( wp_remote_retrieve_response_code( $response ), array( 301, 302, 303, 307, 308 ), true ) ) {
		$url  = (string) wp_remote_retrieve_header( $response, 'location' );
		$host = (string) wp_parse_url( $url, PHP_URL_HOST );

		if ( 'https' !== wp_parse_url( $url, PHP_URL_SCHEME )
			|| ! in_array( $host, array( 'release-assets.githubusercontent.com', 'objects.githubusercontent.com' ), true )
			|| wp_parse_url( $url, PHP_URL_USER ) || wp_parse_url( $url, PHP_URL_PASS ) ) {
			wp_delete_file( $file );

			return new WP_Error( 'redirect', 'GitHub returned an unexpected download host.' );
		}

		// Only a plain User-Agent goes to the download host.
		$args['headers']     = array( 'User-Agent' => 'WordPress-Security-Plugin-Updater' );
		$args['redirection'] = 3;
		$response            = wp_safe_remote_get( $url, $args );
	}

	if ( is_wp_error( $response ) || 200 !== wp_remote_retrieve_response_code( $response )
		|| filesize( $file ) !== $release['size']
		|| ! hash_equals( $release['sha256'], (string) hash_file( 'sha256', $file ) ) ) {
		wp_delete_file( $file );

		return new WP_Error( 'download', 'The update download failed size or SHA-256 verification. No files were installed.' );
	}

	$valid = wpsp_release_zip_validate( $file, $release['version'] );

	if ( is_wp_error( $valid ) ) {
		wp_delete_file( $file );

		return $valid;
	}

	return $file;
}
add_filter( 'upgrader_pre_download', 'wpsp_release_download', 10, 4 );

/**
 * Never lets WordPress install an update of this plugin on its own.
 *
 * @param bool|null $update Whether to update automatically.
 * @param object    $item   The plugin being considered.
 * @return bool|null
 */
function wpsp_no_auto_update( $update, $item ) {
	if ( isset( $item->plugin ) && WPSP_SLUG === $item->plugin ) {
		return false;
	}

	return $update;
}
add_filter( 'auto_update_plugin', 'wpsp_no_auto_update', 99, 2 );

/**
 * Replaces the "Enable auto-updates" link on the Plugins screen with a plain note, so nobody switches on something
 * that would not happen anyway.
 *
 * @param string $html        The link WordPress would show.
 * @param string $plugin_file The plugin on this row.
 * @return string
 */
function wpsp_auto_update_note( $html, $plugin_file ) {
	if ( WPSP_SLUG !== $plugin_file ) {
		return $html;
	}

	return esc_html__( 'Updated by hand only', 'wordpress-security-plugin' );
}
add_filter( 'plugin_auto_update_setting_html', 'wpsp_auto_update_note', 10, 2 );

add_action(
	'upgrader_process_complete',
	static function ( $upgrader, $options ) {
		if ( 'plugin' === ( $options['type'] ?? '' ) ) {
			delete_site_transient( 'wpsp_release' );
		}
	},
	10,
	2
);

/**
 * The updates screen, under the plugin's own menu.
 *
 * @return void
 */
function wpsp_updates_menu() {
	add_submenu_page(
		'wordpress-security-plugin',
		__( 'Updates', 'wordpress-security-plugin' ),
		__( 'Updates', 'wordpress-security-plugin' ),
		'update_plugins',
		'wordpress-security-plugin-updates',
		'wpsp_updates_screen'
	);
}
// Priority 20, after the parent menu is registered in admin.php at the default priority. A submenu added before its
// parent exists still appears, but WordPress cannot work out its address and falls back to a raw path that 404s.
add_action( 'admin_menu', 'wpsp_updates_menu', 20 );

/**
 * Draws the updates screen.
 *
 * @return void
 */
function wpsp_updates_screen() {
	if ( ! current_user_can( 'update_plugins' ) ) {
		return;
	}

	$force = 'POST' === ( $_SERVER['REQUEST_METHOD'] ?? '' ) && isset( $_POST['wpsp_check'] );

	if ( $force ) {
		check_admin_referer( 'wpsp_check_updates' );
		delete_site_transient( 'wpsp_release' );
	}

	$release = wpsp_release_check( $force );

	echo '<div class="wrap"><h1>' . esc_html__( 'WordPress Security Plugin updates', 'wordpress-security-plugin' ) . '</h1>';
	echo '<p>' . esc_html__( 'Installed version:', 'wordpress-security-plugin' ) . ' <strong>' . esc_html( WPSP_VERSION ) . '</strong></p>';
	echo '<form method="post">';
	wp_nonce_field( 'wpsp_check_updates' );
	echo '<button class="button" type="submit" name="wpsp_check" value="1">' . esc_html__( 'Check for updates', 'wordpress-security-plugin' ) . '</button></form>';

	if ( is_wp_error( $release ) ) {
		echo '<div class="notice notice-warning inline"><p>' . esc_html( $release->get_error_message() ) . '</p></div>';
	} else {
		echo '<p>' . esc_html__( 'Latest release:', 'wordpress-security-plugin' ) . ' <strong>' . esc_html( $release['version'] ) . '</strong></p>';

		if ( version_compare( $release['version'], WPSP_VERSION, '>' ) ) {
			$url = wp_nonce_url( self_admin_url( 'update.php?action=upgrade-plugin&plugin=' . urlencode( WPSP_SLUG ) ), 'upgrade-plugin_' . WPSP_SLUG );
			echo '<p><a class="button button-primary" href="' . esc_url( $url ) . '">' . esc_html__( 'Update now', 'wordpress-security-plugin' ) . '</a></p>';
		} else {
			echo '<p>' . esc_html__( 'This plugin is up to date.', 'wordpress-security-plugin' ) . '</p>';
		}

		if ( '' !== (string) $release['notes'] ) {
			echo '<h2>' . esc_html__( 'Release notes', 'wordpress-security-plugin' ) . '</h2><div style="white-space:pre-wrap;max-width:46em">' . esc_html( $release['notes'] ) . '</div>';
		}
	}

	echo '</div>';
}
