# The daily report

Written for: whoever builds the tracker's side of this.

```
GET https://<site>/wp-json/wordpress-security-plugin/v1/report?days=7
```

One format from every site. Read-only: there is no write side to this endpoint, so nothing about a site can be changed through it.

## Signing a request

Each site makes its own 64-character hex key (WordPress Security Plugin → Daily report), shown once. The key is **never sent**. Three headers are sent instead:

| Header | Value |
|---|---|
| `X-WPSP-Timestamp` | Unix seconds. Must be within 300 seconds of the site's clock. |
| `X-WPSP-Nonce` | 16–64 random alphanumeric characters, different every request. Each is accepted once. |
| `X-WPSP-Signature` | `HMAC-SHA256` hex of the payload below, keyed with the site's key. |

The payload, with real newlines:

```
<timestamp>\n<nonce>\nGET\n/wordpress-security-plugin/v1/report
```

The path is the route, not the full URL, so a site in a subdirectory signs the same string.

### Client (TypeScript — the tracker is Next.js)

```ts
import { createHmac, randomBytes } from "node:crypto";

export async function fetchSiteReport(siteUrl: string, key: string, days = 7) {
  const timestamp = Math.floor(Date.now() / 1000);
  const nonce = randomBytes(12).toString("hex");           // 24 alphanumeric characters
  const payload = `${timestamp}\n${nonce}\nGET\n/wordpress-security-plugin/v1/report`;
  const signature = createHmac("sha256", key).update(payload).digest("hex");

  const started = Date.now();
  const response = await fetch(`${siteUrl.replace(/\/$/, "")}/wp-json/wordpress-security-plugin/v1/report?days=${days}`, {
    headers: {
      "X-WPSP-Timestamp": String(timestamp),
      "X-WPSP-Nonce": nonce,
      "X-WPSP-Signature": signature,
      "User-Agent": "wpsp-tracker",
      Accept: "application/json",
    },
    signal: AbortSignal.timeout(20_000),
    cache: "no-store",
  });

  // Up or down, and how fast, are decided here: a site that is down cannot report on itself.
  const responseMs = Date.now() - started;

  if (!response.ok) {
    return { ok: false as const, status: response.status, responseMs };
  }

  return { ok: true as const, status: 200, responseMs, report: await response.json() };
}
```

`User-Agent: wpsp-tracker` is on the plugin's always-allowed list, so the tracker is never mistaken for a scraper.

### Refusals

| Status | Meaning |
|---|---|
| `401` | Signature missing, wrong, out of date, or the same nonce arrived twice. The site logs the reason; the response never says which, so a wrong key gives nothing away. |
| `404` | Reporting is not switched on, or no key is set. |
| `429` | Rate limited. Should not happen — the report path is exempt — but handle it. |

An administrator signed in to the site in their own browser can open the endpoint without a signature, which makes checking the output easy.

## Storing it

Keep each pull as a dated row per site. Everything in the report is a count or a version, so a year of history is small and makes trends possible: enquiries month on month, whether bot traffic is growing, how long a site has been running an out-of-date plugin.

Two fields the tracker adds itself, because the site cannot: **whether it answered** and **how long it took**.

---

## The shape

```jsonc
{
  "format": "wordpress-security-plugin-report",
  "version": 1,
  "generated_at": "2026-11-04T03:21:07+00:00",

  "site": {
    "name": "Example Studio",
    "url": "https://example.com/",
    "timezone": "Europe/London",
    "locale": "en_GB",
    "wordpress": "6.9.1",
    "php": "8.2.27",
    "https": true,
    "theme": { "name": "Example Theme", "slug": "example-theme", "version": "1.4.2" },
    "guard_version": "0.1.0",
    "search_engines": true,          // false means the site is hidden from search — flag this loudly
    "maintenance": false,            // true means visitors are seeing the holding page
    "woocommerce": false,
    "behind_cloudflare": false
  },

  "security": {
    "login_hidden": true,
    "two_factor_on": true,
    "admins": 2,
    "admins_without_2fa": 0,         // anything above 0 is worth chasing
    "last_24h": {
      "failed_logins": 14, "lockouts": 1, "bots_blocked": 203,
      "ai_blocked": 37, "rate_limited": 2, "blocked_files": 9, "new_devices": 0
    },
    "last_7d": { "failed_logins": 96, "lockouts": 4, "bots_blocked": 1488, "ai_blocked": 260 },
    "core_files_modified": [],       // anything here is serious: nothing legitimate edits core files
    "core_files_missing": [],
    "unexpected_php": [],            // program code in uploads/ — serious
    "vulnerabilities": [             // installed plugin/theme with a known security hole
      { "slug": "some-plugin", "name": "Some Plugin", "kind": "plugin",
        "version": "2.1.0", "title": "Stored XSS", "severity": "high", "patched": "2.1.3" }
    ],
    "alerts": [                      // last 25 warnings, newest first; no personal detail
      { "at": "2026-11-03 22:14:08", "type": "login_lockout", "severity": "warning",
        "message": "A visitor was locked out after repeated failures." }
    ]
  },

  "health": {
    "last_scan": "2026-11-04T03:17:02+00:00",   // stale means WP-Cron has stopped: flag it
    "core_update": "",                           // a version string means WordPress needs updating
    "plugin_updates": [ { "name": "Yoast SEO", "installed": "24.1", "available": "24.3" } ],
    "theme_updates": [],
    "debug_mode": false,                         // true on a live site is a mistake
    "file_edit_off": true,
    "cron_working": true,
    "notes": []
  },

  "traffic": {
    "counting": true,                            // false means visit counting is switched off
    "today":     { "views": 212, "visitors": 168 },
    "yesterday": { "views": 480, "visitors": 361 },
    "span_days": 7,
    "span":      { "views": 3104, "visitors": 2290 },
    "daily": [ { "day": "2026-11-03", "views": 480, "visitors": 361 } ]
  },

  "business": {
    "enquiries": {
      "total": 184, "recent": 6, "unanswered": 2,
      "by_type": { "contact_enquiry": { "total": 184, "recent": 6 } }
    },
    "newsletter": { "present": true, "total": 412, "recent": 9 },
    "shop": {                                    // { "present": false } where there is no shop
      "present": true, "currency": "GBP", "orders": 12,
      "revenue": 1480.5, "customers": 96, "products": 48, "span_days": 7
    },
    "comments": { "awaiting": 0, "spam": 3 }
  },

  "content": {
    "pages": { "published": 14, "drafts": 1 },
    "posts": { "published": 23, "drafts": 2, "last": "2026-10-28T09:12:00+00:00" },
    "media": 486,
    "last_change": "2026-11-01T16:40:11+00:00"
  }
}
```

### What is deliberately not in it

No name, no email address, no message anybody submitted, no order detail, no customer record, no password, no setting value, no IP address. Counts only. The tracker can store a year of these without holding anybody's personal data.

---

## Per-site differences the tracker should expect

**Enquiries.** Each theme named its own post type, so the plugin checks a list: `enquiry`, `contact_message`, `wpcf7_contact_form`, `flamingo_inbound`, plus any post type whose name ends in `_enquiry`. A theme adds its own:

```php
add_filter( 'wpsp_enquiry_post_types', fn( $types ) => [ ...$types, 'my_theme_enquiry' ] );
```

Same for newsletter sign-ups via `wpsp_newsletter_post_types`.

Until a theme is wired up, `enquiries.total` reads `0` — which means *not reporting*, not *no enquiries*. Worth showing as a dash rather than a zero in the tracker.

**Unanswered** is counted from post statuses whose name contains `new`, `unread`, `pending` or `open`. A theme that marks enquiries some other way reports `0`.

## Suggested tracker rules

| Show | When |
|---|---|
| 🔴 Red | request failed, `core_files_modified` or `unexpected_php` not empty, a `high`/`critical` vulnerability, `search_engines: false` on a live site |
| 🟠 Amber | `core_update` set, `admins_without_2fa > 0`, `last_scan` over 48 hours old, `login_hidden: false`, `maintenance: true` on a live site, unanswered enquiries over 3 days old |
| 🟢 Green | everything else |

One row per site: traffic light · visitors this week · enquiries this month · theme version against the GitHub release · response time.
