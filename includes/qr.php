<?php
/**
 * A QR code, drawn as an SVG, with no library and no outside call.
 *
 * Setting up two-step login by typing a 32-character key is miserable and error-prone, and some authenticator apps
 * refuse a key that has spaces in it. A QR code removes the whole problem: point the phone at the screen.
 *
 * Why this is written here rather than pulled in: the only thing being encoded is the account's own secret key, and
 * sending that to an outside QR service would hand somebody else the key to the account. A QR image service is the
 * one dependency this feature must not have. So the code is generated on the site, offline, every time.
 *
 * Scope: byte mode, error correction level M, versions 1 to 10, which covers any otpauth:// address comfortably.
 * The implementation follows ISO/IEC 18004 and is checked against a reference encoder in tests/test-qr.php, module
 * for module, across every version and all eight masks — a QR code that is subtly wrong still looks like a QR code,
 * so eyeballing it proves nothing.
 *
 * @package wordpress-security-plugin
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * How much fits, and how the error correction is laid out, for error correction level M.
 *
 * Per version: total data codewords, error correction codewords per block, and the blocks as [count, data each].
 *
 * @return array<int, array{0: int, 1: int, 2: array<int, array{0: int, 1: int}>}>
 */
function wpsp_qr_levels() {
	return array(
		1  => array( 16, 10, array( array( 1, 16 ) ) ),
		2  => array( 28, 16, array( array( 1, 28 ) ) ),
		3  => array( 44, 26, array( array( 1, 44 ) ) ),
		4  => array( 64, 18, array( array( 2, 32 ) ) ),
		5  => array( 86, 24, array( array( 2, 43 ) ) ),
		6  => array( 108, 16, array( array( 4, 27 ) ) ),
		7  => array( 124, 18, array( array( 4, 31 ) ) ),
		8  => array( 154, 22, array( array( 2, 38 ), array( 2, 39 ) ) ),
		9  => array( 182, 22, array( array( 3, 36 ), array( 2, 37 ) ) ),
		10 => array( 216, 26, array( array( 4, 43 ), array( 1, 44 ) ) ),
	);
}

/**
 * Where the small alignment squares go, per version.
 *
 * @return array<int, int[]>
 */
function wpsp_qr_alignment() {
	return array(
		1  => array(),
		2  => array( 6, 18 ),
		3  => array( 6, 22 ),
		4  => array( 6, 26 ),
		5  => array( 6, 30 ),
		6  => array( 6, 34 ),
		7  => array( 6, 22, 38 ),
		8  => array( 6, 24, 42 ),
		9  => array( 6, 26, 46 ),
		10 => array( 6, 28, 50 ),
	);
}

/* -------------------------------------------------------------------------
 * Arithmetic in GF(256), which is what the error correction is built on
 * ---------------------------------------------------------------------- */

/**
 * The exponent and logarithm tables for GF(256).
 *
 * @return array{0: int[], 1: int[]}
 */
function wpsp_qr_tables() {
	static $tables = null;

	if ( null !== $tables ) {
		return $tables;
	}

	$exp = array_fill( 0, 512, 0 );
	$log = array_fill( 0, 256, 0 );
	$x   = 1;

	for ( $i = 0; $i < 255; $i++ ) {
		$exp[ $i ] = $x;
		$log[ $x ] = $i;
		$x <<= 1;
		if ( $x & 0x100 ) {
			$x ^= 0x11D; // The field's defining polynomial.
		}
	}

	for ( $i = 255; $i < 512; $i++ ) {
		$exp[ $i ] = $exp[ $i - 255 ];
	}

	$tables = array( $exp, $log );

	return $tables;
}

/**
 * Multiplies two values in GF(256).
 *
 * @param int $a First value.
 * @param int $b Second value.
 * @return int
 */
function wpsp_qr_multiply( $a, $b ) {
	if ( 0 === $a || 0 === $b ) {
		return 0;
	}

	list( $exp, $log ) = wpsp_qr_tables();

	return $exp[ $log[ $a ] + $log[ $b ] ];
}

/**
 * The generator polynomial for a given number of error correction codewords.
 *
 * @param int $degree How many error correction codewords.
 * @return int[]
 */
function wpsp_qr_generator( $degree ) {
	$poly = array( 1 );

	list( $exp ) = wpsp_qr_tables();

	for ( $i = 0; $i < $degree; $i++ ) {
		$next = array_fill( 0, count( $poly ) + 1, 0 );

		// Multiplying by (x + a^i), with the highest power first: the x term keeps its place and the constant
		// term moves one along. The leading coefficient has to stay 1, which is the quick way to spot these two
		// being the wrong way round.
		foreach ( $poly as $index => $coefficient ) {
			$next[ $index ]     ^= $coefficient;
			$next[ $index + 1 ] ^= wpsp_qr_multiply( $coefficient, $exp[ $i ] );
		}

		$poly = $next;
	}

	return $poly;
}

/**
 * The error correction codewords for one block.
 *
 * @param int[] $data   The block's data codewords.
 * @param int   $degree How many error correction codewords to produce.
 * @return int[]
 */
function wpsp_qr_remainder( array $data, $degree ) {
	$generator = wpsp_qr_generator( $degree );
	$remainder = array_fill( 0, $degree, 0 );

	foreach ( $data as $byte ) {
		$factor = $byte ^ array_shift( $remainder );
		$remainder[] = 0;

		foreach ( $generator as $index => $coefficient ) {
			if ( $index > 0 ) {
				$remainder[ $index - 1 ] ^= wpsp_qr_multiply( $coefficient, $factor );
			}
		}
	}

	return $remainder;
}

/* -------------------------------------------------------------------------
 * Turning the text into codewords
 * ---------------------------------------------------------------------- */

/**
 * The smallest version that holds this much text at error correction level M.
 *
 * @param int $length How many bytes.
 * @return int|false
 */
function wpsp_qr_version_for( $length ) {
	foreach ( wpsp_qr_levels() as $version => $spec ) {
		$count_bits = $version < 10 ? 8 : 16;
		$capacity   = ( $spec[0] * 8 ) - 4 - $count_bits;

		if ( $length * 8 <= $capacity ) {
			return $version;
		}
	}

	return false;
}

/**
 * The full codeword stream: the text, padded, with error correction interleaved as the standard requires.
 *
 * @param string $text    What to encode.
 * @param int    $version Which version.
 * @return int[]
 */
function wpsp_qr_codewords( $text, $version ) {
	$levels = wpsp_qr_levels();
	list( $total_data, $ec_per_block, $groups ) = $levels[ $version ];

	$count_bits = $version < 10 ? 8 : 16;
	$length     = strlen( $text );

	// Mode indicator 0100 (bytes), then the length, then the bytes themselves.
	$bits = '0100' . str_pad( decbin( $length ), $count_bits, '0', STR_PAD_LEFT );

	for ( $i = 0; $i < $length; $i++ ) {
		$bits .= str_pad( decbin( ord( $text[ $i ] ) ), 8, '0', STR_PAD_LEFT );
	}

	// Up to four zero bits to mark the end, then zeros to the next whole codeword.
	$capacity = $total_data * 8;
	$bits    .= str_repeat( '0', min( 4, $capacity - strlen( $bits ) ) );
	$bits    .= str_repeat( '0', ( 8 - ( strlen( $bits ) % 8 ) ) % 8 );

	// Then the two alternating filler bytes the standard specifies, until full.
	$fillers = array( '11101100', '00010001' );
	$index   = 0;

	while ( strlen( $bits ) < $capacity ) {
		$bits .= $fillers[ $index % 2 ];
		$index++;
	}

	$codewords = array();
	foreach ( str_split( $bits, 8 ) as $byte ) {
		$codewords[] = bindec( $byte );
	}

	// Split into blocks, work out each block's error correction, then interleave both.
	$data_blocks = array();
	$ec_blocks   = array();
	$offset      = 0;

	foreach ( $groups as $group ) {
		list( $block_count, $block_size ) = $group;

		for ( $i = 0; $i < $block_count; $i++ ) {
			$block         = array_slice( $codewords, $offset, $block_size );
			$offset       += $block_size;
			$data_blocks[] = $block;
			$ec_blocks[]   = wpsp_qr_remainder( $block, $ec_per_block );
		}
	}

	$stream  = array();
	$longest = 0;
	foreach ( $data_blocks as $block ) {
		$longest = max( $longest, count( $block ) );
	}

	for ( $i = 0; $i < $longest; $i++ ) {
		foreach ( $data_blocks as $block ) {
			if ( isset( $block[ $i ] ) ) {
				$stream[] = $block[ $i ];
			}
		}
	}

	for ( $i = 0; $i < $ec_per_block; $i++ ) {
		foreach ( $ec_blocks as $block ) {
			$stream[] = $block[ $i ];
		}
	}

	return $stream;
}

/* -------------------------------------------------------------------------
 * Drawing the grid
 * ---------------------------------------------------------------------- */

/**
 * Lays down the fixed patterns every QR code has: the three big corner squares, the timing lines, the alignment
 * squares and the one module that is always dark.
 *
 * @param array<int, array<int, int|null>> $matrix   Grid, by reference.
 * @param array<int, array<int, bool>>     $reserved Which modules the data must not touch, by reference.
 * @param int                              $version  Which version.
 * @param int                              $size     Grid width.
 * @return void
 */
function wpsp_qr_place_patterns( array &$matrix, array &$reserved, $version, $size ) {
	$finder = static function ( $top, $left ) use ( &$matrix, &$reserved, $size ) {
		for ( $row = -1; $row <= 7; $row++ ) {
			for ( $column = -1; $column <= 7; $column++ ) {
				$y = $top + $row;
				$x = $left + $column;

				if ( $y < 0 || $y >= $size || $x < 0 || $x >= $size ) {
					continue;
				}

				$inside = $row >= 0 && $row <= 6 && $column >= 0 && $column <= 6;
				$ring   = $inside && ( 0 === $row || 6 === $row || 0 === $column || 6 === $column );
				$centre = $inside && $row >= 2 && $row <= 4 && $column >= 2 && $column <= 4;

				$matrix[ $y ][ $x ]   = ( $ring || $centre ) ? 1 : 0;
				$reserved[ $y ][ $x ] = true;
			}
		}
	};

	$finder( 0, 0 );
	$finder( 0, $size - 7 );
	$finder( $size - 7, 0 );

	// The dotted lines that run between the corner squares.
	for ( $i = 8; $i < $size - 8; $i++ ) {
		$value                = ( 0 === $i % 2 ) ? 1 : 0;
		$matrix[6][ $i ]      = $value;
		$reserved[6][ $i ]    = true;
		$matrix[ $i ][6]      = $value;
		$reserved[ $i ][6]    = true;
	}

	// The smaller squares, except where they would sit on a corner square.
	$centres = wpsp_qr_alignment()[ $version ];

	foreach ( $centres as $row_centre ) {
		foreach ( $centres as $column_centre ) {
			$on_finder = ( 6 === $row_centre && 6 === $column_centre )
				|| ( 6 === $row_centre && $column_centre === $size - 7 )
				|| ( $row_centre === $size - 7 && 6 === $column_centre );

			if ( $on_finder ) {
				continue;
			}

			for ( $row = -2; $row <= 2; $row++ ) {
				for ( $column = -2; $column <= 2; $column++ ) {
					$y = $row_centre + $row;
					$x = $column_centre + $column;

					$edge                 = 2 === max( abs( $row ), abs( $column ) );
					$matrix[ $y ][ $x ]   = ( $edge || ( 0 === $row && 0 === $column ) ) ? 1 : 0;
					$reserved[ $y ][ $x ] = true;
				}
			}
		}
	}

	// The module that is always dark.
	$matrix[ $size - 8 ][8]   = 1;
	$reserved[ $size - 8 ][8] = true;

	// Keep the data out of where the format information goes. Nine modules beside the top-left corner square in
	// each direction, and eight at the far end of each: the far side is one shorter, and reserving a ninth there
	// would leave a module nothing ever writes to, which silently shifts every data bit that follows it.
	for ( $i = 0; $i < 9; $i++ ) {
		$reserved[8][ $i ] = true;
		$reserved[ $i ][8] = true;
	}

	for ( $i = 0; $i < 8; $i++ ) {
		$reserved[8][ $size - 1 - $i ] = true;
		$reserved[ $size - 1 - $i ][8] = true;
	}

	if ( $version >= 7 ) {
		for ( $i = 0; $i < 6; $i++ ) {
			for ( $j = 0; $j < 3; $j++ ) {
				$reserved[ $i ][ $size - 11 + $j ] = true;
				$reserved[ $size - 11 + $j ][ $i ] = true;
			}
		}
	}
}

/**
 * Writes the codewords into the grid, in the zigzag the standard describes, skipping the fixed patterns.
 *
 * @param array<int, array<int, int|null>> $matrix    Grid, by reference.
 * @param array<int, array<int, bool>>     $reserved  Reserved modules.
 * @param int[]                            $codewords The stream.
 * @param int                              $size      Grid width.
 * @return void
 */
function wpsp_qr_place_data( array &$matrix, array $reserved, array $codewords, $size ) {
	$bits = '';
	foreach ( $codewords as $codeword ) {
		$bits .= str_pad( decbin( $codeword ), 8, '0', STR_PAD_LEFT );
	}

	$position = 0;
	$total    = strlen( $bits );
	$upward   = true;

	for ( $x = $size - 1; $x > 0; $x -= 2 ) {
		$right = ( $x <= 6 ) ? $x - 1 : $x;

		for ( $step = 0; $step < $size; $step++ ) {
			$row = $upward ? $size - 1 - $step : $step;

			foreach ( array( $right, $right - 1 ) as $column ) {
				if ( ! empty( $reserved[ $row ][ $column ] ) ) {
					continue;
				}

				$matrix[ $row ][ $column ] = $position < $total ? (int) $bits[ $position ] : 0;
				$position++;
			}
		}

		$upward = ! $upward;
	}
}

/**
 * Whether a module is flipped by a given mask.
 *
 * @param int $mask   Which mask, 0 to 7.
 * @param int $row    Row.
 * @param int $column Column.
 * @return bool
 */
function wpsp_qr_mask_at( $mask, $row, $column ) {
	switch ( $mask ) {
		case 0:
			return 0 === ( $row + $column ) % 2;
		case 1:
			return 0 === $row % 2;
		case 2:
			return 0 === $column % 3;
		case 3:
			return 0 === ( $row + $column ) % 3;
		case 4:
			return 0 === ( intdiv( $row, 2 ) + intdiv( $column, 3 ) ) % 2;
		case 5:
			return 0 === ( ( $row * $column ) % 2 ) + ( ( $row * $column ) % 3 );
		case 6:
			return 0 === ( ( ( $row * $column ) % 2 ) + ( ( $row * $column ) % 3 ) ) % 2;
		case 7:
			return 0 === ( ( ( $row + $column ) % 2 ) + ( ( $row * $column ) % 3 ) ) % 2;
	}

	return false;
}

/**
 * The fifteen bits that say which error correction level and mask were used.
 *
 * @param int $mask Which mask.
 * @return int
 */
function wpsp_qr_format_bits( $mask ) {
	// 00 is error correction level M.
	$value     = ( 0 << 3 ) | $mask;
	$remainder = $value << 10;

	for ( $i = 4; $i >= 0; $i-- ) {
		if ( $remainder & ( 1 << ( $i + 10 ) ) ) {
			$remainder ^= 0x537 << $i;
		}
	}

	return ( ( $value << 10 ) | $remainder ) ^ 0x5412;
}

/**
 * The eighteen bits that say which version this is, for version 7 and up.
 *
 * @param int $version Which version.
 * @return int
 */
function wpsp_qr_version_bits( $version ) {
	$remainder = $version << 12;

	for ( $i = 5; $i >= 0; $i-- ) {
		if ( $remainder & ( 1 << ( $i + 12 ) ) ) {
			$remainder ^= 0x1F25 << $i;
		}
	}

	return ( $version << 12 ) | $remainder;
}

/**
 * Writes the format and version information into their reserved places.
 *
 * @param array<int, array<int, int|null>> $matrix  Grid, by reference.
 * @param int                              $version Which version.
 * @param int                              $mask    Which mask.
 * @param int                              $size    Grid width.
 * @return void
 */
function wpsp_qr_place_info( array &$matrix, $version, $mask, $size ) {
	$format  = wpsp_qr_format_bits( $mask );
	$voffset = 0;
	$hoffset = 0;

	for ( $i = 0; $i < 8; $i++ ) {
		$vbit = ( $format >> $i ) & 1;
		$hbit = ( $format >> ( 14 - $i ) ) & 1;

		if ( 6 === $i ) {
			$voffset = 1;
			$hoffset = 1;
		}

		// Vertical row, upper left corner.
		$matrix[ $i + $voffset ][8] = $vbit;
		// Horizontal row, upper left corner.
		$matrix[8][ $i + $hoffset ] = $hbit;
		// Horizontal row, upper right corner.
		$matrix[8][ $size - 1 - $i ] = $vbit;
		// Vertical row, bottom left corner.
		$matrix[ $size - 1 - $i ][8] = $hbit;
	}

	// Dark module.
	$matrix[ $size - 8 ][8] = 1;

	if ( $version < 7 ) {
		return;
	}

	$bits = wpsp_qr_version_bits( $version );

	for ( $i = 0; $i < 6; $i++ ) {
		$bit1 = ( $bits >> ( $i * 3 ) ) & 1;
		$bit2 = ( $bits >> ( ( $i * 3 ) + 1 ) ) & 1;
		$bit3 = ( $bits >> ( ( $i * 3 ) + 2 ) ) & 1;

		// Lower left.
		$matrix[ $size - 11 ][ $i ] = $bit1;
		$matrix[ $size - 10 ][ $i ] = $bit2;
		$matrix[ $size - 9 ][ $i ]  = $bit3;

		// Upper right.
		$matrix[ $i ][ $size - 11 ] = $bit1;
		$matrix[ $i ][ $size - 10 ] = $bit2;
		$matrix[ $i ][ $size - 9 ]  = $bit3;
	}
}

/**
 * How ugly a finished grid is, by the standard's four rules. The lowest score wins.
 *
 * @param array<int, array<int, int>> $matrix The grid.
 * @param int                         $size   Grid width.
 * @return int
 */
function wpsp_qr_penalty( array $matrix, $size ) {
	$score = 0;

	// Rule one: runs of five or more of the same colour, in rows and in columns.
	for ( $pass = 0; $pass < 2; $pass++ ) {
		for ( $a = 0; $a < $size; $a++ ) {
			$run_value = -1;
			$run       = 0;

			for ( $b = 0; $b < $size; $b++ ) {
				$value = 0 === $pass ? $matrix[ $a ][ $b ] : $matrix[ $b ][ $a ];

				if ( $value === $run_value ) {
					$run++;
					if ( 5 === $run ) {
						$score += 3;
					} elseif ( $run > 5 ) {
						$score++;
					}
				} else {
					$run_value = $value;
					$run       = 1;
				}
			}
		}
	}

	// Rule two: every two by two block of one colour.
	for ( $row = 0; $row < $size - 1; $row++ ) {
		for ( $column = 0; $column < $size - 1; $column++ ) {
			$value = $matrix[ $row ][ $column ];
			if ( $value === $matrix[ $row ][ $column + 1 ]
				&& $value === $matrix[ $row + 1 ][ $column ]
				&& $value === $matrix[ $row + 1 ][ $column + 1 ] ) {
				$score += 3;
			}
		}
	}

	// Rule three: the pattern that looks like part of a corner square, which would confuse a reader.
	$patterns = array(
		array( 1, 0, 1, 1, 1, 0, 1, 0, 0, 0, 0 ),
		array( 0, 0, 0, 0, 1, 0, 1, 1, 1, 0, 1 ),
	);

	for ( $pass = 0; $pass < 2; $pass++ ) {
		for ( $a = 0; $a < $size; $a++ ) {
			for ( $b = 0; $b <= $size - 11; $b++ ) {
				foreach ( $patterns as $pattern ) {
					$found = true;

					for ( $k = 0; $k < 11; $k++ ) {
						$value = 0 === $pass ? $matrix[ $a ][ $b + $k ] : $matrix[ $b + $k ][ $a ];
						if ( $value !== $pattern[ $k ] ) {
							$found = false;
							break;
						}
					}

					if ( $found ) {
						$score += 40;
					}
				}
			}
		}
	}

	// Rule four: how far the balance of dark and light is from half and half.
	$dark = 0;
	foreach ( $matrix as $row ) {
		$dark += array_sum( $row );
	}

	$percent = ( $dark * 100 ) / ( $size * $size );
	$score  += ( (int) ( abs( $percent - 50 ) / 5 ) ) * 10;

	return $score;
}

/**
 * Builds the grid for a piece of text.
 *
 * @param string   $text    What to encode.
 * @param int|null $version Force a version, for testing.
 * @param int|null $mask    Force a mask, for testing.
 * @return array<int, array<int, int>>|false The grid, or false when the text is too long.
 */
function wpsp_qr_matrix( $text, $version = null, $mask = null ) {
	$text = (string) $text;

	if ( null === $version ) {
		$version = wpsp_qr_version_for( strlen( $text ) );
	}

	if ( ! $version || $version < 1 || $version > 10 ) {
		return false;
	}

	$size      = 17 + ( 4 * $version );
	$codewords = wpsp_qr_codewords( $text, $version );

	$base     = array_fill( 0, $size, array_fill( 0, $size, null ) );
	$reserved = array_fill( 0, $size, array_fill( 0, $size, false ) );

	wpsp_qr_place_patterns( $base, $reserved, $version, $size );
	wpsp_qr_place_data( $base, $reserved, $codewords, $size );

	$best       = null;
	$best_score = PHP_INT_MAX;
	$candidates = null === $mask ? range( 0, 7 ) : array( (int) $mask );

	foreach ( $candidates as $candidate ) {
		$matrix = $base;

		for ( $row = 0; $row < $size; $row++ ) {
			for ( $column = 0; $column < $size; $column++ ) {
				if ( empty( $reserved[ $row ][ $column ] ) && wpsp_qr_mask_at( $candidate, $row, $column ) ) {
					$matrix[ $row ][ $column ] ^= 1;
				}
			}
		}

		wpsp_qr_place_info( $matrix, $version, $candidate, $size );

		$score = wpsp_qr_penalty( $matrix, $size );

		if ( $score < $best_score ) {
			$best_score = $score;
			$best       = $matrix;
		}
	}

	return $best;
}

/**
 * The QR code as an SVG, ready to put straight into a page.
 *
 * Drawn as one path of squares rather than an image file, so it is sharp at any size, needs no upload and works
 * with a strict content security policy.
 *
 * @param string $text  What to encode.
 * @param int    $scale Pixels per module.
 * @return string The SVG, or an empty string when the text will not fit.
 */
function wpsp_qr_svg( $text, $scale = 5 ) {
	$matrix = wpsp_qr_matrix( $text );

	if ( ! $matrix ) {
		return '';
	}

	$size   = count( $matrix );
	$quiet  = 4;
	$width  = ( $size + ( $quiet * 2 ) ) * $scale;
	$path   = '';

	foreach ( $matrix as $row => $columns ) {
		foreach ( $columns as $column => $value ) {
			if ( 1 === $value ) {
				$path .= sprintf(
					'M%d %dh%dv%dh-%dz',
					( $column + $quiet ) * $scale,
					( $row + $quiet ) * $scale,
					$scale,
					$scale,
					$scale
				);
			}
		}
	}

	return sprintf(
		'<svg xmlns="http://www.w3.org/2000/svg" width="%1$d" height="%1$d" viewBox="0 0 %1$d %1$d" role="img" aria-label="%2$s"><rect width="%1$d" height="%1$d" fill="#fff"/><path d="%3$s" fill="#000"/></svg>',
		$width,
		esc_attr__( 'QR code for setting up two-step sign-in', 'wordpress-security-plugin' ),
		$path
	);
}
