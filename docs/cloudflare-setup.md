# Putting a site behind Cloudflare

Written for: the site owner, working through one domain at a time.

## Why

The host serves most pages from its own cache, without running WordPress at all. That is why the sites are fast — and it means the WordPress Security Plugin plugin never sees those requests, so it cannot block a bot on a cached page. Cloudflare sits in front of the cache and checks every visitor before anything is served.

It also absorbs traffic floods, saves host bandwidth, and gives free SSL.

**Cost: nothing.** The free plan covers unlimited websites, is not a trial, and needs no card. Bot blocking, AI-bot blocking, the firewall, rate limiting and SSL are all included. The only way to be charged is to click Upgrade or buy an add-on. With no card on the account, nothing can be charged by accident.

**One rule to know:** the free plan is for websites — pages, images, normal files. It is not meant for serving large **video files** directly. Videos on YouTube or Vimeo are fine. If a site hosts big video files on the server itself, either move them to YouTube/Vimeo or leave that part of the site off Cloudflare (the grey cloud, step 3).

---

## Before you start

Write down the current nameservers from your domain registrar for the domain. They are probably:

```
ns1.dns-parking.com
ns2.dns-parking.com
```

Putting these back undoes everything in this guide, so keep them to hand.

---

## 1. Create the Cloudflare account — once, for all sites

Sign up at cloudflare.com. One account holds every website.

**Turn on two-step login for the Cloudflare account itself.** Whoever controls this account controls where all the sites point.

## 2. Add the domain

1. **Add a domain**, type it in (e.g. `example.com`).
2. Choose the **Free** plan.
3. Cloudflare scans the domain and copies its current DNS records — the address book that says where the website lives and where email goes.

## 3. Check the copied records — the step that matters

Compare Cloudflare's list against the DNS zone at your current host or registrar.

| Record | Must be there | Cloud colour |
|---|---|---|
| `A` or `CNAME` for the domain and `www` | yes | **Orange** (proxied — goes through Cloudflare) |
| `MX` records | yes, or email stops | **Grey** (DNS only) |
| `TXT` starting `v=spf1` | yes | Grey |
| DKIM `TXT` / `CNAME` | yes | Grey |
| `_dmarc` `TXT` | if it exists now | Grey |
| `mail`, `webmail`, `ftp`, `cpanel` | if they exist now | **Grey** |

**Anything to do with email stays grey.** An orange cloud on a mail record breaks email delivery, and that is the one mistake worth being careful about here.

If you are not sure, screenshot both lists and have them compared before moving on.

## 4. Switch the domain over

Cloudflare gives you two nameserver addresses, like `ana.ns.cloudflare.com` and `bob.ns.cloudflare.com`.

1. Log in to your **domain registrar**, open the domain, find **Nameservers**.
2. Replace the current ones with the two from Cloudflare.
3. Save.

It takes anywhere from a few minutes to 24 hours. **The site stays online throughout.** Cloudflare emails when the domain is active.

Do not do this on a domain that is about to expire. Renew first.

## 5. Cloudflare settings

| Where | Setting | Value |
|---|---|---|
| SSL/TLS → Overview | Encryption mode | **Full (strict)** |
| SSL/TLS → Edge Certificates | Always Use HTTPS | On |
| SSL/TLS → Edge Certificates | Minimum TLS Version | 1.2 |
| Security → Bots | Bot Fight Mode | On |
| Security → Bots | Block AI bots / AI Scrapers and Crawlers | On |
| Speed → Optimization | Rocket Loader | **Off** |
| Caching → Configuration | Caching Level | Standard |

**"Full (strict)" matters.** Any other encryption mode can put a WordPress site into a redirect loop.

Leave everything else at its default.

### The one firewall rule worth adding

Security → WAF → **Rate limiting rules** → Create rule:

- **Field:** URI Path · **Operator:** equals · **Value:** `/your-private-login-address/`
  (the address from WordPress Security Plugin → Sign-in)
- **Requests:** 10 · **Period:** 1 minute · **Action:** Block · **Duration:** 1 hour

This stops password guessing before it ever reaches WordPress.

### If the site has a members area, a shop checkout or a form that behaves oddly

Caching → **Cache Rules**, and bypass the cache for paths like `/checkout`, `/cart`, `/my-account`. WooCommerce sites need this; a plain brochure site does not.

## 6. The host side

- If the host has its own **CDN** switched on for this site, **turn it off**. Two content networks stacked on each other cause strange, hard-to-trace problems.
- Leave LiteSpeed Cache alone. It works alongside Cloudflare.

## 7. WordPress side

**WordPress Security Plugin → Bots and scraping → "This site is behind Cloudflare" → on.**

This matters: without it the plugin sees Cloudflare's own address as the visitor's, so every visitor looks like the same one and the rate limit misfires. With it on, the plugin reads the real visitor address from Cloudflare — and only trusts that header when the request genuinely arrives from a Cloudflare address, so it cannot be faked.

## 8. Test — all five

1. Open the site in a private browser window.
2. Open it on your phone, on mobile data.
3. Sign in to WordPress at the private address.
4. Submit the contact form, and confirm the email arrives.
5. Send an email **to** and **from** the domain's mailbox.

All five working means the site is done. Record it in the tracker as **DNS provider: Cloudflare**.

## If something goes wrong

Put the old nameservers back at your registrar. Everything returns to how it was within the hour. Nothing on the server was changed at any point.

| Symptom | Cause | Fix |
|---|---|---|
| "Too many redirects" | Encryption mode is not Full (strict) | Set it to Full (strict) |
| Email stopped | A mail record is orange, or `MX`/SPF did not copy across | Set mail records to grey and re-add anything missing |
| Site looks broken, scripts fail | Rocket Loader | Turn it off |
| Everyone rate limited at once | "Behind Cloudflare" not ticked in WordPress Security Plugin | Tick it |
| Logged-out visitors see a logged-in page | Cache serving a page it should not | Add a cache bypass rule for that path |

---

## Rolling it out across the sites

1. **One low-risk site first** — no shop, little email use. Confirm all five tests.
2. **Three to five per session** after that.
3. **Last:** sites with important email, and shops.
4. Domains with a renewal due: renew before moving.
