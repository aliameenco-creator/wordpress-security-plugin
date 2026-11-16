# WordPress Security Plugin

One security and reporting plugin for WordPress sites, built to run the same on every site you look after.

It does four things:

1. **Moves the sign-in page** off `/wp-admin`, and adds the protections that actually stop an account being taken over.
2. **Turns away bots, scrapers and AI crawlers**, without ever blocking Google or Bing.
3. **Maintenance mode** with a numeric access code, for sites being built or redesigned.
4. **Sends one daily report** to your own tracker, in the same format from every site.

Written to be light. Nothing heavy runs while a visitor is looking at a page; the expensive work happens once a night. Every feature has an off switch.

---

## What it protects, in plain words

### The sign-in page

With a private address set, `/wp-admin` and `/wp-login.php` answer **"page not found"** to anyone who is not already signed in. A scanner learns nothing — not even that WordPress is installed. Password resets, logout links and everything the front of the site needs keep working.

This stops the automated attempts every public WordPress site receives all day. It is noise reduction, not the main defence.

**You cannot be locked out.** Either line in `wp-config.php` gets you back in:

```php
define( 'WPSP_LOGIN_OFF', true );              // standard WordPress address again
define( 'WPSP_LOGIN_SLUG', 'a-new-address' );  // or a new private address
```

### Two-step sign-in

After the password, the site asks for the six-digit number showing in an authenticator app on your phone — Google Authenticator, Microsoft Authenticator, 1Password, Bitwarden. The number changes every 30 seconds.

This is the part that matters most. A stolen or guessed password on its own is no longer enough to get in.

Each person sets it up on their own profile screen and gets ten single-use backup codes. The code maths is the standard one (RFC 6238, SHA-1, 30 seconds, six digits) and is tested against the official test vectors, so any authenticator app works. Escape hatch: `define( 'WPSP_2FA_OFF', true );`

### Attempt limits and alerts

- Five wrong passwords, then a fifteen minute wait. Both numbers are settings.
- A failed sign-in never says which half was wrong, so a wrong username cannot be told from a wrong password.
- Author pages and the users part of the REST API stop handing out usernames.
- An email when an administrator signs in from a device or network not seen in the last 30 days.

### The settings every WordPress site should have

| Setting | What it does |
|---|---|
| No file editing in the admin | An account that is taken over still cannot put code on the server through the browser. The most useful single setting here. |
| XML-RPC off | An old remote interface none of these sites use, and a favourite of password-guessing tools because it allows many tries per request. |
| Security headers | Invisible instructions to the browser: no other site may show this one in a frame, do not guess file types, do not leak full addresses, no camera/microphone/location. |
| HSTS *(off by default)* | Browsers only ever use `https` for the domain, for a year. Switch on only once the site and every subdomain is reliably on https. |
| Hide the WordPress version | A scanner reads the version to choose which attacks to try. |
| Application passwords for administrators only | An application password is a real key to the site through the REST API. |
| Refuse backup and config files | `404` for database dumps, `.env`, old `wp-config` copies, and program code inside `uploads/`. |

### Bots, scrapers and AI crawlers

Four layers, politest first:

1. **`robots.txt`** asks the AI crawlers to stay away — GPTBot, ClaudeBot, CCBot, Google-Extended, Bytespider, PerplexityBot and the rest. The honest ones obey. Google and Bing *search* are untouched, so rankings are not affected.
2. **A name list.** Site downloaders and scripted fetchers name themselves (HTTrack, wget, curl, python-requests, Scrapy, headless browsers, vulnerability scanners), so refusing those names removes most automated copying. A request with no browser name at all is refused too.
3. **A rate limit** on the expensive paths only — search, the REST API, feeds. Ordinary page views are never counted, so normal browsing is never affected and no database lookup happens on a normal page load.
4. **A trap link** that no person can see and `robots.txt` tells crawlers not to follow. Anything that follows it is banned for a day.

Search engines that claim to be Googlebot or Bingbot are **verified** by reverse DNS before being trusted, the way Google and Bing document, and the answer is cached for a day. A scraper cannot simply call itself Googlebot.

**Said plainly:** a public page can be copied by anybody willing to use an ordinary browser, and no plugin can prevent that. This stops *automated* and *bulk* copying.

**And one real limitation:** the host serves most pages from its own cache without running WordPress, so this plugin never sees those requests. Cloudflare sits in front of the cache and does see them, free. See [docs/cloudflare-setup.md](docs/cloudflare-setup.md).

### Maintenance mode

Visitors see a holding page; you and anyone who can edit the site see the real thing because you are signed in. Anyone else types a **numeric access code** once and then browses normally for a fortnight — no account, no email address, nothing to sign up for.

- Only a scrambled version of the code is stored, the same way a password is. Nobody can read it back out of the database, including you.
- The cookie holds a signed token, not the code, so the code only ever travels once.
- The holding page answers `503` with `Retry-After`, which is what tells Google the site is *temporarily* unavailable rather than gone. This is what keeps a live site from dropping out of search while it is being worked on.
- Wrong codes are rate limited: eight tries, then a fifteen minute wait.
- Escape hatch: `define( 'WPSP_MAINTENANCE_OFF', true );`

### The nightly check

Once a day, at about 3am, and nowhere else:

- Every WordPress core file compared against the official checksums from wordpress.org. Nothing legitimate edits those, so a change is the clearest sign of a break-in.
- A look for PHP files inside `uploads/`, where only images and documents belong.
- The installed plugins and themes compared against the public Wordfence vulnerability feed (fetched weekly, compared locally — the site does not tell anybody what it has installed).
- What needs updating, and which administrator accounts exist.
- Old log entries deleted past the retention period.

---

## The daily report

```
GET /wp-json/wordpress-security-plugin/v1/report
```

One format, every site. Full details and a working client for the tracker: [docs/report-format.md](docs/report-format.md).

**How it is protected.** Each site makes its own 64-character key, shown once and pasted into the tracker. The tracker does not send the key: it sends the time, a random string and a signature worked out from all of it. So the key never travels, and a recorded request cannot be replayed.

**What it sends:** counts and versions. Visitors, enquiries, shop orders and revenue totals, failed sign-ins, bots blocked, what needs updating, what the nightly check found.

**What it never sends:** no name, no email address, no message anybody submitted, no order detail, no password, no setting. The endpoint is read-only — nothing about the site can be changed through it. If the key leaked, the worst outcome is somebody learning how many enquiries came in, and it is replaced in one click.

Whether the site is *up* is not in the report, because a site that is down cannot answer. The tracker decides that from whether the request succeeded and how long it took.

### Visit counting

Two numbers a day: page views, and roughly how many separate visitors. No cookie, no stored address, nothing traceable to a person, so no consent banner is needed. A small inline script asks the site to add one *after* the page has finished loading, because the host's cache means counting during a page render would miss most of the traffic.

---

## Weight

| When | What runs |
|---|---|
| A visitor opens a page | String comparisons against one already-loaded setting. No database query, no file read, no outside call. |
| An expensive path (search, REST, feed) | One short-lived counter read, only if rate limiting is on. |
| A page finishes loading | One tiny background request to add 1 to today's count, if counting is on. |
| 3am | The nightly check. |
| wp-admin | Settings reads, and a GitHub release check at most once an hour. |

Three external addresses are ever contacted, all official, all read-only: `api.wordpress.org` for the core checksums, `wordfence.com` for the vulnerability feed, `cloudflare.com` for its published address list (only when the site is marked as being behind it). Plus `api.github.com` for updates, from wp-admin only.

---

## Installing

1. Upload the plugin and activate it. **Nothing visible changes yet**: the private sign-in address, two-step login and maintenance mode all start switched off, deliberately.
2. **WordPress Security Plugin → Sign-in.** Set the private address. Write it down. Then switch on two-step sign-in and set it up on your own profile before anyone else's.
3. **WordPress Security Plugin → Bots and scraping.** Defaults are sensible. Only tick "behind Cloudflare" once the domain really is.
4. **WordPress Security Plugin → Daily report.** Make the key and paste it into the tracker.
5. Optional: **Maintenance mode**, while a rebuild is in progress.

If a theme or another plugin already moves the sign-in page, run one or the other, never both. A theme can tell this plugin to step aside with `add_filter( 'wpsp_login_handled_elsewhere', '__return_true' );` — the sign-in page is then left alone, everything else still works, and the admin says so.

## Updating

Releases come from the public `aliameenco-creator/wordpress-security-plugin` repository, through WordPress's normal Plugins → Updates screen or the plugin's own Updates page. No token or account is needed. Every package is verified against the size and SHA-256 GitHub published, and the ZIP is inspected, before a single file is installed.

## Development

```bash
php tests/test-crypto.php      # one-time code maths, address ranges, signatures
python scripts/package.py      # build dist/wordpress-security-plugin.zip and print its SHA-256
```

`tests/test-crypto.php` needs no WordPress. It checks the one-time code implementation against the official RFC 6238 test vectors, which is the only way to know an authenticator app will accept the codes.
