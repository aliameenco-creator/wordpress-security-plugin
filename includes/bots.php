<?php
/**
 * Bots, scrapers and AI crawlers.
 *
 * Four layers, from politest to firmest:
 *
 *  1. robots.txt asks the AI crawlers not to copy the site. The well-behaved ones obey; the rest are why layers
 *     two to four exist.
 *  2. A user-agent list. Scraper tools and whole-site downloaders mostly name themselves, so refusing those names
 *     removes a large share of automated copying for no effort. Search engines are never on this list, and a request
 *     claiming to be Googlebot or Bingbot is checked against the address it really came from before being trusted.
 *  3. A rate limit. A person reads a page every few seconds; a scraper asks for dozens a second. Requests from one
 *     visitor are counted and anything far past a sane limit is slowed down with a 429. Only applied to the paths
 *     that are expensive and never cached (search, the REST API, feeds, 404 storms), so ordinary browsing is never
 *     counted and never queried for.
 *  4. A trap. A link no person can see, which robots.txt tells crawlers not to follow. Anything that follows it has
 *     ignored the rules and is not reading the page, so it is banned for a day.
 *
 * What this cannot do, said plainly: a public page can be copied by anyone willing to use a real browser. This stops
 * automated and bulk copying. Determined copying by hand is not something any plugin can prevent.
 *
 * Why Cloudflare still matters: a cached page is served by the host before WordPress runs, so this file never sees
 * that request. Cloudflare sits in front of the cache and does. See docs/cloudflare-setup.md.
 *
 * Cost on a normal page load: a few string comparisons against one already-loaded option. No queries, no files.
 *
 * @package wordpress-security-plugin
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/** How long a trapped bot stays blocked. */
const WPSP_TRAP_BAN = DAY_IN_SECONDS;

/** The path the trap link points at. */
const WPSP_TRAP_PATH = 'do-not-follow-this-link';

/**
 * Whether the browser is carrying a WordPress sign-in cookie.
 *
 * Used instead of is_user_logged_in() because this runs before WordPress has worked out who the visitor is. Reading
 * the cookie costs nothing, while asking for the current user this early means a database query on every page and
 * can upset plugins that expect to decide the user themselves. The cookie only has to be good enough to step aside
 * for someone who is probably signed in: a forged one gets a visitor past the bot gate and nothing more.
 *
 * @return bool
 */
function wpsp_has_login_cookie() {
	foreach ( array_keys( (array) $_COOKIE ) as $name ) {
		if ( 0 === strpos( (string) $name, 'wordpress_logged_in_' ) ) {
			return true;
		}
	}

	return false;
}

/**
 * The AI and dataset crawlers robots.txt asks to stay away.
 *
 * These are the published names of the crawlers that collect pages for training and for answer engines. Blocking
 * them keeps the sites' photography and writing out of those datasets. It has no effect on Google or Bing search
 * rankings: Google's search crawler is Googlebot, and Google-Extended only controls training use.
 *
 * @return string[]
 */
function wpsp_ai_crawlers() {
	return array(
		'GPTBot',
		'OAI-SearchBot',
		'ChatGPT-User',
		'ClaudeBot',
		'Claude-User',
		'Claude-SearchBot',
		'anthropic-ai',
		'CCBot',
		'Google-Extended',
		'Applebot-Extended',
		'Bytespider',
		'PerplexityBot',
		'Perplexity-User',
		'meta-externalagent',
		'FacebookBot',
		'Amazonbot',
		'cohere-ai',
		'Diffbot',
		'omgili',
		'Timpibot',
		'ImagesiftBot',
		'AI2Bot',
		'DataForSeoBot',
	);
}

/**
 * Names that belong to scraping tools and site downloaders rather than to browsers or search engines.
 *
 * Matched case-insensitively against any part of the user agent. Kept deliberately short and specific: a wide net
 * here would eventually block something real, and a blocked customer is worse than a copied page.
 *
 * @return string[]
 */
function wpsp_bad_agents() {
	return array(
		'httrack',
		'webcopier',
		'webzip',
		'wget',
		'curl/',
		'python-requests',
		'python-urllib',
		'aiohttp',
		'go-http-client',
		'java/',
		'okhttp',
		'libwww-perl',
		'scrapy',
		'nutch',
		'puppeteer',
		'playwright',
		'headlesschrome',
		'phantomjs',
		'selenium',
		'zgrab',
		'masscan',
		'nikto',
		'sqlmap',
		'nmap',
		'wpscan',
		'acunetix',
		'nessus',
		'dirbuster',
		'gobuster',
		'semrushbot',
		'ahrefsbot',
		'mj12bot',
		'dotbot',
		'blexbot',
		'serpstatbot',
		'megaindex',
		'seokicks',
		'petalbot',
		'zoominfobot',
	);
}

/**
 * The search engines that must always get through, with the host names their addresses resolve to.
 *
 * A request claiming one of these names is only believed when a reverse lookup of its address ends in the matching
 * domain and a forward lookup of that name comes back to the same address. This is the method Google and Bing
 * document, and it is the reason a scraper cannot simply call itself Googlebot.
 *
 * @return array<string, string[]>
 */
function wpsp_verified_crawlers() {
	return array(
		'googlebot'            => array( '.googlebot.com', '.google.com' ),
		'google-inspectiontool' => array( '.googlebot.com', '.google.com' ),
		'adsbot-google'        => array( '.googlebot.com', '.google.com' ),
		'mediapartners-google' => array( '.googlebot.com', '.google.com' ),
		'bingbot'              => array( '.search.msn.com' ),
		'adidxbot'             => array( '.search.msn.com' ),
		'duckduckbot'          => array( '.duckduckgo.com' ),
		'yandexbot'            => array( '.yandex.ru', '.yandex.net', '.yandex.com' ),
		'applebot'             => array( '.applebot.apple.com' ),
		'baiduspider'          => array( '.baidu.com', '.baidu.jp' ),
	);
}

/**
 * The names that are always welcome without a lookup, because they only ever fetch one small thing and blocking them
 * breaks something the owner wants: link previews when a page is shared, and the host's own monitoring.
 *
 * @return string[]
 */
function wpsp_always_allowed() {
	return array(
		'facebookexternalhit',
		'twitterbot',
		'linkedinbot',
		'whatsapp',
		'telegrambot',
		'slackbot',
		'discordbot',
		'pinterest',
		'embedly',
		'redditbot',
		'skypeuripreview',
		'google pagespeed',
		'chrome-lighthouse',
		'gtmetrix',
		'pingdom',
		'uptimerobot',
		'betteruptime',
		'wordpress/',
		'jetpack',
		'wpsp-tracker',
	);
}

/**
 * Whether this request claims to be a verified search engine, and really is one.
 *
 * The result is remembered for a day per address, so the reverse lookup happens once rather than on every page a
 * crawler visits. Without that, letting Google in would cost a DNS round trip per request.
 *
 * @param string $agent Lower-case user agent.
 * @return bool
 */
function wpsp_is_verified_crawler( $agent ) {
	$suffixes = array();

	foreach ( wpsp_verified_crawlers() as $name => $domains ) {
		if ( false !== strpos( $agent, $name ) ) {
			$suffixes = $domains;
			break;
		}
	}

	if ( ! $suffixes ) {
		return false;
	}

	$ip = wpsp_client_ip();

	if ( '' === $ip ) {
		return false;
	}

	$key    = 'wpsp_crawler_' . md5( $ip );
	$cached = get_transient( $key );

	if ( 'yes' === $cached ) {
		return true;
	}
	if ( 'no' === $cached ) {
		return false;
	}

	$host     = gethostbyaddr( $ip );
	$verified = false;

	if ( is_string( $host ) && $host !== $ip ) {
		$host = strtolower( rtrim( $host, '.' ) );
		foreach ( $suffixes as $suffix ) {
			if ( substr( $host, -strlen( $suffix ) ) === $suffix ) {
				// Forward lookup back to the same address, so a made-up reverse record is not enough.
				$verified = in_array( $ip, (array) gethostbynamel( $host ), true ) || gethostbyname( $host ) === $ip;
				break;
			}
		}
	}

	set_transient( $key, $verified ? 'yes' : 'no', DAY_IN_SECONDS );

	return $verified;
}

/**
 * The gate every front-end request passes through.
 *
 * @return void
 */
function wpsp_bot_gate() {
	if ( ! wpsp_on( 'bots_enabled' ) || wpsp_internal_request() || wpsp_has_login_cookie() ) {
		return;
	}

	$path = wpsp_request_path();

	// The trap, checked first: following it is proof enough on its own.
	if ( wpsp_on( 'honeypot' ) && WPSP_TRAP_PATH === $path ) {
		set_transient( 'wpsp_ban_' . wpsp_ip_hash(), 1, WPSP_TRAP_BAN );
		wpsp_log_event( 'bot_trapped', 'A bot followed the hidden trap link and was blocked for a day.', 'warning', wpsp_user_agent() );
		wpsp_deny( 403, 'Forbidden' );
	}

	if ( get_transient( 'wpsp_ban_' . wpsp_ip_hash() ) ) {
		wpsp_deny( 403, 'Forbidden' );
	}

	$agent = strtolower( wpsp_user_agent() );

	// Anything on the welcome list, or a search engine that checks out, goes straight through.
	foreach ( wpsp_always_allowed() as $allowed ) {
		if ( false !== strpos( $agent, $allowed ) ) {
			return;
		}
	}

	if ( wpsp_is_verified_crawler( $agent ) ) {
		return;
	}

	if ( wpsp_on( 'block_bad_agents' ) ) {
		// No user agent at all is not a browser. Real browsers always send one.
		if ( '' === trim( $agent ) ) {
			wpsp_log_event( 'bot_blocked', 'A request with no browser name was refused.', 'notice', substr( $path, 0, 100 ) );
			wpsp_deny( 403, 'Forbidden' );
		}

		foreach ( wpsp_bad_agents() as $bad ) {
			if ( false !== strpos( $agent, $bad ) ) {
				wpsp_log_event( 'bot_blocked', 'A scraping tool was refused.', 'notice', substr( $agent, 0, 120 ) );
				wpsp_deny( 403, 'Forbidden' );
			}
		}
	}

	// A crawler that only claims to be a search engine, and failed the check above, is turned away here.
	foreach ( array_keys( wpsp_verified_crawlers() ) as $name ) {
		if ( false !== strpos( $agent, $name ) ) {
			wpsp_log_event( 'bot_fake', 'A request pretending to be a search engine was refused.', 'warning', substr( $agent, 0, 120 ) );
			wpsp_deny( 403, 'Forbidden' );
		}
	}

	if ( wpsp_on( 'block_ai_crawlers' ) ) {
		foreach ( wpsp_ai_crawlers() as $crawler ) {
			if ( false !== strpos( $agent, strtolower( $crawler ) ) ) {
				wpsp_log_event( 'ai_blocked', 'An AI crawler was refused.', 'notice', $crawler );
				wpsp_deny( 403, 'Forbidden' );
			}
		}
	}

	wpsp_rate_limit( $path );
}
add_action( 'plugins_loaded', 'wpsp_bot_gate', 4 );

/**
 * Counts requests to the expensive paths and slows a visitor down past a sane limit.
 *
 * Normal page views are not counted. There is no point: those are cached, and counting them would mean a transient
 * read on every single page load, which is exactly the kind of weight this plugin is meant to avoid.
 *
 * @param string $path The request path.
 * @return void
 */
function wpsp_rate_limit( $path ) {
	if ( ! wpsp_on( 'rate_limit' ) ) {
		return;
	}

	$expensive = isset( $_GET['s'] )                            // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Looking at whether this is a search.
		|| 0 === strpos( $path, 'wp-json/' )
		|| 'wp-json' === $path
		|| 0 === strpos( $path, 'feed' )
		|| false !== strpos( $path, '/feed' )
		|| 0 === strpos( $path, 'xmlrpc.php' )
		|| isset( $_GET['orderby'], $_GET['filter'] );          // phpcs:ignore WordPress.Security.NonceVerification.Recommended

	if ( ! $expensive ) {
		return;
	}

	// The report endpoint has its own signed limit and must never be throttled out of a daily pull.
	if ( 0 === strpos( $path, 'wp-json/wordpress-security-plugin/' ) ) {
		return;
	}

	$limit = max( 20, (int) wpsp_option( 'rate_limit_hits', 120 ) );
	$key   = 'wpsp_rate_' . wpsp_ip_hash();
	$hits  = (int) get_transient( $key ) + 1;

	set_transient( $key, $hits, MINUTE_IN_SECONDS );

	if ( $hits > $limit ) {
		if ( $hits === $limit + 1 ) {
			wpsp_log_event( 'rate_limited', 'A visitor was asked to slow down.', 'warning', substr( $path, 0, 100 ) );
		}
		wpsp_deny( 429, 'Too many requests. Please slow down.' );
	}
}

/**
 * Adds the crawler rules to robots.txt.
 *
 * WordPress builds robots.txt itself when no file exists on disk, which is the case on all these sites, so adding to
 * it here is enough.
 *
 * @param string $rules  What WordPress has so far.
 * @param bool   $public Whether the site is set to be indexed.
 * @return string
 */
function wpsp_robots_txt( $rules, $public ) {
	if ( ! $public ) {
		return $rules;
	}

	$extra = "\n# Added by WordPress Security Plugin\n";

	if ( wpsp_on( 'honeypot' ) ) {
		$extra .= "User-agent: *\n";
		$extra .= 'Disallow: /' . WPSP_TRAP_PATH . "/\n";
	}

	if ( wpsp_on( 'block_ai_crawlers' ) ) {
		$extra .= "\n# These crawlers collect pages for AI training and answer engines. Search engines are not affected.\n";
		foreach ( wpsp_ai_crawlers() as $crawler ) {
			$extra .= 'User-agent: ' . $crawler . "\n";
			$extra .= "Disallow: /\n";
		}
	}

	return $rules . $extra;
}
add_filter( 'robots_txt', 'wpsp_robots_txt', 10, 2 );

/**
 * Puts the trap link in the footer.
 *
 * Hidden from sight and from screen readers, and marked nofollow so no search engine is tempted. A person cannot
 * click it; a crawler that reads the HTML and ignores robots.txt will.
 *
 * @return void
 */
function wpsp_trap_link() {
	if ( ! wpsp_on( 'bots_enabled' ) || ! wpsp_on( 'honeypot' ) || is_user_logged_in() ) {
		return;
	}

	printf(
		'<a href="%s" rel="nofollow noindex" aria-hidden="true" tabindex="-1" style="position:absolute;left:-9999px;width:1px;height:1px;overflow:hidden">.</a>',
		esc_url( home_url( '/' . WPSP_TRAP_PATH . '/' ) )
	);
}
add_action( 'wp_footer', 'wpsp_trap_link', 99 );

