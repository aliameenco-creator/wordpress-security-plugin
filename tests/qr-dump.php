<?php
/**
 * Prints a QR grid as rows of 0 and 1, so tests/test-qr.py can compare it against a reference encoder.
 *
 *     php tests/qr-dump.php "<text>" [version] [mask]
 *
 * A QR code that is subtly wrong still looks like a QR code, so this comparison is the only way to know the
 * encoder in includes/qr.php is right.
 *
 * @package wordpress-security-plugin
 */

define( 'ABSPATH', __DIR__ . '/' );

function esc_attr__( $text ) {
	return $text;
}

require_once __DIR__ . '/../includes/qr.php';

$text    = $argv[1] ?? '';
$version = isset( $argv[2] ) && '' !== $argv[2] ? (int) $argv[2] : null;
$mask    = isset( $argv[3] ) && '' !== $argv[3] ? (int) $argv[3] : null;

$matrix = wpsp_qr_matrix( $text, $version, $mask );

if ( ! $matrix ) {
	fwrite( STDERR, "too long\n" );
	exit( 1 );
}

foreach ( $matrix as $row ) {
	echo implode( '', $row ), "\n";
}
