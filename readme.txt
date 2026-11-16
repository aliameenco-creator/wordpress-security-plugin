=== WordPress Security Plugin ===
Contributors: aliameenco-creator
Requires at least: 6.6
Tested up to: 6.9
Requires PHP: 8.1
Stable tag: 0.2.0
License: GPL-2.0-or-later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Security, bot protection, maintenance mode and daily reporting for WordPress sites.

== Description ==

A private sign-in address, two-step sign-in with an authenticator app, attempt limits, the hardening settings every
site should have, a four-layer bot and AI-crawler defence, a maintenance holding page with a numeric access code,
a nightly integrity and vulnerability check, and one signed read-only report per site for your own tracker.

Built to stay light: nothing heavy runs while a visitor is looking at a page, and every feature has an off switch.

Full documentation is in README.md, docs/cloudflare-setup.md and docs/report-format.md in the plugin folder.

== Getting back in ==

Any of these lines in wp-config.php, added through the host file manager:

* define( 'WPSP_LOGIN_OFF', true );              - the standard WordPress sign-in address
* define( 'WPSP_LOGIN_SLUG', 'a-new-address' );  - a different private address
* define( 'WPSP_2FA_OFF', true );                - two-step sign-in off
* define( 'WPSP_MAINTENANCE_OFF', true );        - the holding page off

== Changelog ==

= 0.1.1 =
* Fixed the Updates submenu linking to a page that did not exist. It was registered before its parent menu, so
  WordPress could not work out its address and fell back to a raw path that answered 404.
* The top-level menu no longer sits on the same position number as Settings, where it could displace another
  plugin's menu.

= 0.1.0 =
* First release. Private sign-in address, attempt limits, vague errors, no username harvesting, new-device alerts.
* Two-step sign-in (TOTP, RFC 6238) with ten single-use backup codes, checked against the official test vectors.
* Hardening: no admin file editing, XML-RPC off, security headers, optional HSTS, version hidden, application
  passwords for administrators only, refusal of backup and configuration file requests.
* Bots: AI crawler rules in robots.txt plus enforcement, scraper name list, verified search-engine allowlist by
  reverse DNS, rate limiting on expensive paths only, and a trap link.
* Maintenance mode with a hashed numeric access code and a 503 holding page.
* Nightly check: core file checksums, program code in uploads, the public vulnerability feed, pending updates,
  administrator accounts, log retention.
* Cookie-free visit counting and the signed read-only report endpoint.
* Updates from public GitHub releases, no token needed, with SHA-256 and package verification.
