# Proposal: Lightweight JavaScript Challenge (Plesk + Nginx + Apache + Drupal) — Standalone PHP Implementation

---

## Executive Summary

Automated traffic (bad bots, scrapers, credential-stuffers) is degrading site performance and inflating origin load. We propose a **lightweight JavaScript (JS) challenge** that runs *before* Drupal and adds a minimal, user-transparent check for first-time requests. The solution is purpose-built for **Plesk** running **Nginx ➜ Apache ➜ Drupal**, using **two tiny standalone PHP endpoints** and a **micro gate** loaded via `auto_prepend_file`. This avoids bootstrapping Drupal on challenge hits and keeps latency overhead to a few milliseconds.

**Key benefits**

* Negligible overhead: Drupal never boots for first-time gated hits.
* CDN/cache-safe: Challenge routes are `no-store`.
* Accessible & low-friction: No CAPTCHA unless you later choose to add one.
* **Authenticated bypass:** Requests with a valid Drupal session cookie (`SSESS*`) skip the challenge entirely for a seamless logged-in experience.
* Simple rollback: A single PHP setting toggle.
* Extensible: Optional Nginx rate limiting; add PoW/CAPTCHA only if abuse spikes.

---

## Goals & Non-Goals

**Goals**

* Reduce commodity bot traffic at the edge/origin with minimal user impact.
* Ensure the check runs without Drupal bootstrap.
* Remain Plesk-friendly (no template hacking; use supported "Additional directives" and per-domain PHP settings).

**Non-Goals (for this phase)**

* Full device fingerprinting.
* Advanced bot management or behavioral ML (can be layered later via WAF/CDN).

---

## High-Level Architecture

1. **Gate (pre-app):** A tiny PHP file (`sec_js_gate.php`) runs for every PHP request via `auto_prepend_file`. It **immediately allows authenticated users** carrying a Drupal session cookie (`SSESS*`). If the JS token cookie is present and valid, it passes; otherwise it 302s to `/js-check.php?b=<original URL>` and exits. Drupal is not loaded on a miss.
2. **JS Check Page:** `/js-check.php` returns a minimal HTML page that performs ~100ms of WebCrypto work and calls `/__js_challenge.php`.
3. **Issuer:** `/__js_challenge.php` sets a short-lived, signed, HttpOnly cookie `sec_js` (10 minutes by default) and returns `ok`.
4. **Return:** Browser is redirected back to the original URL. Subsequent requests within TTL pass the gate instantly.
5. **Optional Nginx assist:** Per-domain directives can redirect missing-cookie requests even earlier and apply rate limits to hot paths.

---

## Request Flow (Text Diagram)

```
Client → Nginx → Apache (PHP-FPM) → auto_prepend_file (sec_js_gate.php) →
  ├─ if authenticated (Drupal session cookie SSESS*) → continue to Drupal (normal request)
  ├─ if valid sec_js cookie → continue to Drupal (normal request)
  └─ else → 302 to /js-check.php?b=<original>

/js-check.php → client runs tiny JS (~100ms) → fetch /__js_challenge.php (issuer)
→ issuer sets HttpOnly cookie → client navigates back to <original URL>
→ gate validates → Drupal serves page
```

---

## Components & Files

Assuming `example.com` docroot at `/var/www/vhosts/example.com/httpdocs`.

```
/var/www/vhosts/example.com/priv/SEC_JS_SECRET                 # HMAC key (outside webroot)
/var/www/vhosts/example.com/priv/sec_js_gate.php               # gate (auto_prepend_file)
/var/www/vhosts/example.com/priv/challenge/js-check.php        # check page (HTML + JS) — outside webroot
/var/www/vhosts/example.com/priv/challenge/__js_challenge.php  # cookie issuer — outside webroot
```

> We intentionally keep the challenge scripts **outside** the app repo (httpdocs) to separate sysadmin‑owned security controls from developer code. They are mapped into public URLs via web server configuration below.

> Replace `example.com` with the actual domain path in Plesk. Ensure `/priv/` is **outside** webroot to keep secrets non-public.

---

## Security Model

**Objectives:** prevent trivial non-JS scraping and scripted abuse while keeping friction near-zero for humans and legitimate crawlers.

**Mechanisms**

* **One-time JS proof:** On first visit per short window, the browser performs a ~100ms WebCrypto digest loop. This is enough to filter basic bots that don’t execute JS.
* **Short‑lived signed token:** Server issues `sec_js` (HttpOnly, Secure, SameSite=Lax) containing a JSON payload `{ v, exp, ua }`, where `exp` is a 5–10 minute TTL and `ua` is an optional 12‑hex SHA‑256 prefix of the User‑Agent. Payload is protected with HMAC‑SHA256 using a secret stored **outside** webroot.
* **Pre‑app enforcement:** A tiny PHP gate (`auto_prepend_file`) validates the cookie *before* Drupal boots. On failure, it 302s to the check page and exits.
* **Bypasses:** Static assets, admin/login, cron, the challenge endpoints, and **authenticated Drupal sessions (cookies starting with `SSESS`)** are always allowed to avoid breaking admin or logged-in UX.
* **Good bot allowlist:** Built into the gate. Googlebot/Bingbot are verified via forward‑confirmed reverse DNS; several reputable crawlers and social preview bots are allowed by UA policy. (Details in Implementation Step 4.)

**Threat model snapshot**

* **Stops/Slows:** trivial curl/scrapy, many headless fetchers that ignore JS or cookies, low‑effort credential spray.
* **Not a silver bullet against:** high‑end headless browsers with cookie handling and human‑like behavior; pair with WAF/rate limiting for those.
* **Privacy:** no persistent fingerprinting; token contains no PII; TTL keeps identifiers short‑lived.

---

## SEO Impact & Search Crawler Access

### Summary

* The JS challenge is **transparent to real users** and runs once per 10 minutes (configurable). It returns a **302 (temporary)** redirect to a `noindex` page, then immediately back to the original URL.
* Major search engines often **do not execute JS** for discovery. To avoid crawl/indexing issues, we **allowlist known good crawlers** so they bypass the challenge entirely.
* The challenge endpoints are explicitly **`no-store`** and marked with **`<meta name=\"robots\" content=\"noindex\">`**, and we recommend disallowing these paths in `robots.txt`.

### Recommended robots.txt entries

```
User-agent: *
Disallow: /js-check.php
Disallow: /__js_challenge.php
```

### Why SEO impact is minimal

* Human visitors and SERP clickers are unaffected beyond a ~100ms check once per session window.
* Search bots (Googlebot/Bingbot/etc.) are **bypassed** using UA + reverse DNS verification (see below), so they see the site normally.
* We use **302**, not 301, so there is no lasting redirect signal.

---

## Good Bot Allowlist (Search & Link Preview Crawlers)

We support two layers:

1. **Edge hint (nginx):** Skip the challenge early for requests whose **User-Agent** matches known crawlers. (Fast, but headers are spoofable.)
2. **Authoritative check (PHP gate):** For high-value bots (Googlebot/Bingbot), perform **reverse DNS verification** before bypassing, per their published guidance. This happens in the tiny gate file before Drupal.

### 1) Optional nginx hint (per-domain Additional nginx directives)

> Keep this as a *hint*; the PHP gate below does the real verification.

```nginx
# Allowlisted crawlers (UA header check only; pair with PHP RDNS for safety)
if ($http_user_agent ~* "(Googlebot|Google-InspectionTool|AdsBot-Google|Bingbot|BingPreview|DuckDuckBot|Applebot|Twitterbot|facebookexternalhit|LinkedInBot|Slackbot|Discordbot)") {
  set $rp_bypass 1;
}
```

### 2) Authoritative verification (built into the gate)

The good‑bot allowlist is **implemented inside the PHP gate** (see Implementation Step 4). It uses UA matching plus forward‑confirmed reverse DNS for Googlebot/Bingbot. No additional configuration is required beyond deploying the gate.

### Operational notes

* Keep the UA pattern configurable; we can promote it to a small `.ini` or PHP array for easy edits.
* If you prefer a stricter stance, require RDNS for *all* allowlisted bots, not only Google/Bing.
* Challenge endpoints remain `noindex` and are excluded in `robots.txt`.

## Performance Impact

* **Gate path:** String checks + HMAC verify on already-signed token → microseconds. On a miss, 302 and exit (no Drupal).
* **Check page:** ~100ms JS workload once per TTL window (default 10 minutes).
* **Issuer:** Small PHP script doing HMAC; negligible server cost.

---

## Implementation Plan (Step-by-Step)

### 1) Create secret and directories

```bash
# Run as root or appropriate user
umask 077
mkdir -p /var/www/vhosts/example.com/priv
openssl rand -base64 48 > /var/www/vhosts/example.com/priv/SEC_JS_SECRET
```

### 2) Create `/priv/challenge/js-check.php`

````php
<?php
// /priv/challenge/js-check.php
header('Content-Type: text/html; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
$back = isset($_GET['b']) ? $_GET['b'] : '/';
?>
<!doctype html><meta charset="utf-8">
<title>Checking your browser…</title>
<meta name="robots" content="noindex">
<style>body{font-family:system-ui,Segoe UI,Arial,sans-serif;margin:4rem;max-width:42rem}</style>
<p>One moment while we verify your browser…</p>
<noscript><p>Please enable JavaScript or continue to <a href="/user/login">login</a>.</p></noscript>
<script>
(async () => {
  // ~100ms of trivial work
  const nonce = crypto.getRandomValues(new Uint8Array(32));
  for (let i=0;i<4000;i++) { await crypto.subtle.digest("SHA-256", nonce); }
  // Ask server to issue HttpOnly cookie, then go back
  await fetch("/__js_challenge.php", { credentials:"include" });
  location.replace(<?= json_encode($back, JSON_UNESCAPED_SLASHES) ?>);
})();
</script>
```php
<?php
// /httpdocs/js-check.php
header('Content-Type: text/html; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
$back = isset($_GET['b']) ? $_GET['b'] : '/';
?>
<!doctype html><meta charset="utf-8">
<title>Checking your browser…</title>
<meta name="robots" content="noindex">
<style>body{font-family:system-ui,Segoe UI,Arial,sans-serif;margin:4rem;max-width:42rem}</style>
<p>One moment while we verify your browser…</p>
<noscript><p>Please enable JavaScript or continue to <a href="/user/login">login</a>.</p></noscript>
<script>
(async () => {
  // ~100ms of trivial work
  const nonce = crypto.getRandomValues(new Uint8Array(32));
  for (let i=0;i<4000;i++) { await crypto.subtle.digest("SHA-256", nonce); }
  // Ask server to issue HttpOnly cookie, then go back
  await fetch("/__js_challenge.php", { credentials:"include" });
  location.replace(<?= json_encode($back, JSON_UNESCAPED_SLASHES) ?>);
})();
</script>
````

### 3) Create `/priv/challenge/__js_challenge.php`

````php
<?php
declare(strict_types=1);

// /priv/challenge/__js_challenge.php
header('Content-Type: text/plain; charset=utf-8');
header('Cache-Control: no-store');

$secret_path = dirname(__DIR__) . '/SEC_JS_SECRET';
$secret = @file_get_contents($secret_path);
if ($secret === false) { http_response_code(500); exit("secret missing"); }

function b64u(string $bin): string {
  return rtrim(strtr(base64_encode($bin), '+/', '-_'), '=');
}

$ttl   = 600;             // 10 minutes
$now   = time();
$exp   = $now + $ttl;
$ver   = 1;

// (Optional) bind loosely to UA to make blind re-use harder
$ua    = $_SERVER['HTTP_USER_AGENT'] ?? '';
$ua12  = substr(hash('sha256',$ua),0,12);
$payload = json_encode(['v'=>$ver,'exp'=>$exp,'ua'=>$ua12], JSON_UNESCAPED_SLASHES);
$sig     = hash_hmac('sha256', $payload, $secret, true);
$token   = b64u($payload) . '.' . b64u($sig);

// Secure cookie attrs
$cookie_name  = 'sec_js';
$cookie_value = $token;
$cookie_opts  = [
  'expires'  => $exp,
  'path'     => '/',
  'domain'   => '',         // default to current host
  'secure'   => true,
  'httponly' => true,
  'samesite' => 'Lax',
];

setcookie($cookie_name, $cookie_value, $cookie_opts);
echo "ok";
```php
<?php
declare(strict_types=1);

// /httpdocs/__js_challenge.php
header('Content-Type: text/plain; charset=utf-8');
header('Cache-Control: no-store');

$secret_path = dirname(__DIR__) . '/priv/SEC_JS_SECRET';
$secret = @file_get_contents($secret_path);
if ($secret === false) { http_response_code(500); exit("secret missing"); }

function b64u(string $bin): string {
  return rtrim(strtr(base64_encode($bin), '+/', '-_'), '=');
}

$ttl   = 600;             // 10 minutes
$now   = time();
$exp   = $now + $ttl;
$ver   = 1;

// (Optional) bind loosely to UA to make blind re-use harder
$ua    = $_SERVER['HTTP_USER_AGENT'] ?? '';
$ua12  = substr(hash('sha256',$ua),0,12);
$payload = json_encode(['v'=>$ver,'exp'=>$exp,'ua'=>$ua12], JSON_UNESCAPED_SLASHES);
$sig     = hash_hmac('sha256', $payload, $secret, true);
$token   = b64u($payload) . '.' . b64u($sig);

// Secure cookie attrs
$cookie_name  = 'sec_js';
$cookie_value = $token;
$cookie_opts  = [
  'expires'  => $exp,
  'path'     => '/',
  'domain'   => '',         // default to current host
  'secure'   => true,
  'httponly' => true,
  'samesite' => 'Lax',
];

setcookie($cookie_name, $cookie_value, $cookie_opts);
echo "ok";
````

### 4) Map the outside-webroot scripts to public URLs

Depending on your PHP handler in Plesk, use **one** of the following methods to map URLs to the private scripts.

#### A) PHP-FPM served by **Apache** (most common)

Add to **Domains → Apache & nginx Settings → Additional Apache directives (HTTPS)**:

```apache
# Map URLs to files outside httpdocs
Alias /js-check.php \
  	/var/www/vhosts/example.com/priv/challenge/js-check.php
Alias /__js_challenge.php \
  	/var/www/vhosts/example.com/priv/challenge/__js_challenge.php

<Directory "/var/www/vhosts/example.com/priv/challenge">
    Require all granted
    # In Plesk, PHP-FPM via Apache is already wired; no extra handler lines needed.
    # Ensure no caching of challenge endpoints
    <Files "js-check.php">
        Header set Cache-Control "no-store, no-cache, must-revalidate, max-age=0"
    </Files>
    <Files "__js_challenge.php">
        Header set Cache-Control "no-store"
    </Files>
</Directory>
```

> Replace `example.com` paths as appropriate.

#### B) PHP-FPM served by **nginx**

Add to **Domains → Apache & nginx Settings → Additional nginx directives (HTTPS)**:

```nginx
# Serve challenge scripts from outside webroot via nginx+PHP-FPM
location = /js-check.php {
    include proxy_fcgi.conf; # Plesk includes fastcgi params; otherwise include snippets/fastcgi-php.conf
    fastcgi_param SCRIPT_FILENAME /var/www/vhosts/example.com/priv/challenge/js-check.php;
    fastcgi_pass "unix:/var/www/vhosts/system/example.com/php-fpm.sock";
}
location = /__js_challenge.php {
    include proxy_fcgi.conf;
    fastcgi_param SCRIPT_FILENAME /var/www/vhosts/example.com/priv/challenge/__js_challenge.php;
    fastcgi_pass "unix:/var/www/vhosts/system/example.com/php-fpm.sock";
}
```

> The socket path varies; confirm under **PHP Settings** for the domain, or use the TCP form `127.0.0.1:9070` if configured that way.

---

### 5) Create `/priv/sec_js_gate.php`

```php
<?php
declare(strict_types=1);

// /priv/sec_js_gate.php — lightweight gate with crawler allowlist and Drupal SSESS bypass

// BYPASS: safety paths that should never be gated
$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);
if ($path === false) { $path = '/'; }
$skip_patterns = [
  '#^/(core|modules|themes|sites/.+/files/styles)/#',
  '#^/(robots\.txt|favicon\.ico|sitemap\.xml)$#',
  '#^/(cron\.php|update\.php|admin|user/login)#',
  '#^/(js-check\.php|__js_challenge\.php)(\?|$)#',
];
foreach ($skip_patterns as $re) {
  if (preg_match($re, $path)) { return; } // allow
}

// --- Authenticated Drupal user bypass (SSESS*) ---
foreach (array_keys($_COOKIE) as $ck) {
  if (strpos($ck, 'SSESS') === 0) { return; }
}

// --- Known-good crawlers allowlist ---
// We bypass the challenge for well-known bots. For Google/Bing we use
// forward-confirmed reverse DNS to prevent spoofing. Others are UA-based.
$ua = $_SERVER['HTTP_USER_AGENT'] ?? '';
$ip = $_SERVER['REMOTE_ADDR'] ?? '';
$allow_ua_re = '~(Googlebot|Google-InspectionTool|AdsBot-Google|Bingbot|BingPreview|DuckDuckBot|Applebot|Twitterbot|facebookexternalhit|LinkedInBot|Slackbot|Discordbot)~i';
if ($ua && preg_match($allow_ua_re, $ua)) {
  if (verify_known_crawler($ip, $ua)) {
    return; // allow crawl/link preview without challenge
  }
}

function ends_with(string $haystack, string $needle): bool {
  return $needle !== '' && substr($haystack, -strlen($needle)) === $needle;
}

function verify_known_crawler(string $ip, string $ua): bool {
  if (!filter_var($ip, FILTER_VALIDATE_IP)) return false;

  // Reverse DNS verify Googlebot
  if (stripos($ua, 'google') !== false) {
    $host = @gethostbyaddr($ip);
    if ($host && (ends_with($host, '.googlebot.com') || ends_with($host, '.google.com'))) {
      $ip2 = @gethostbyname($host);
      if ($ip2 === $ip) return true; // forward-confirmed reverse DNS
    }
  }

  // Reverse DNS verify Bingbot
  if (stripos($ua, 'bing') !== false) {
    $host = @gethostbyaddr($ip);
    if ($host && ends_with($host, '.search.msn.com')) {
      $ip2 = @gethostbyname($host);
      if ($ip2 === $ip) return true;
    }
  }

  // Lower-risk crawlers: allow by UA only (tune to policy)
  if (preg_match('~(DuckDuckBot|Applebot)~i', $ua)) return true;

  // Social/link preview bots (aid sharing)
  if (preg_match('~(Twitterbot|facebookexternalhit|LinkedInBot|Slackbot|Discordbot)~i', $ua)) return true;

  return false;
}

// If cookie exists and is valid, allow
$tok = $_COOKIE['sec_js'] ?? '';
if ($tok && strpos($tok, '.') !== false) {
  [$p, $s] = explode('.', $tok, 2);
  $payload = base64_decode(strtr($p, '-_', '+/'));
  $sig     = base64_decode(strtr($s, '-_', '+/'));
  if ($payload && $sig) {
    $data = json_decode($payload, true);
    if (is_array($data) && isset($data['exp']) && $data['exp'] >= time()) {
      $ua_hash = substr(hash('sha256', $ua), 0, 12);
      $ua_ok = !isset($data['ua']) || $data['ua'] === $ua_hash;
      if ($ua_ok) {
        $secret = @file_get_contents(dirname(__DIR__) . '/priv/SEC_JS_SECRET');
        if ($secret !== false) {
          $expect = hash_hmac('sha256', $payload, $secret, true);
          if (hash_equals($expect, $sig)) {
            return; // PASS
          }
        }
      }
    }
  }
}

// Otherwise: redirect once to js-check
http_response_code(302);
$back = $_SERVER['REQUEST_URI'] ?? '/';
header('Location: /js-check.php?b=' . rawurlencode($back));
exit;
```

### 5) Enable the gate in Plesk (per domain)

**Domains → example.com → PHP Settings → Additional configuration directives**:

```
auto_prepend_file = /var/www/vhosts/example.com/priv/sec_js_gate.php
```

Click **OK/Apply**.

> This activates the gate for all PHP‑handled requests without touching Plesk templates.

---

## Optional: Nginx Assist (Per Domain)

In **Domains → example.com → Apache & nginx Settings → Additional nginx directives (HTTPS)**

````nginx
# --- BYPASS: assets, health, admin, login, challenge endpoints, and authenticated users
set $rp_bypass 0;

if ($request_uri ~ ^/(core|modules|themes|sites/.+/files/styles)/) { set $rp_bypass 1; }
if ($request_uri ~ ^/(robots\.txt|favicon\.ico|sitemap\.xml)$)     { set $rp_bypass 1; }
if ($request_uri ~ ^/(cron\.php|update\.php|admin|user/login))     { set $rp_bypass 1; }
if ($request_uri ~ ^/(js-check\.php|__js_challenge\.php)(\?|$))    { set $rp_bypass 1; }

# Authenticated Drupal sessions carry cookies that start with SSESS
if ($http_cookie ~* "SSESS") { set $rp_bypass 1; }

# Only bounce if not bypassed and cookie absent
if ($rp_bypass = 0) {
  if ($http_cookie !~ "sec_js=") { return 302 /js-check.php?b=$request_uri; }
}

# (Optional) enable if you set a global limit_req_zone
# location ~ ^/(api|user/login|user/password) { limit_req zone=rl_api burst=30 nodelay; }
```nginx
# --- BYPASS: assets, health, admin, login, and the challenge endpoints
set $rp_bypass 0;

if ($request_uri ~ ^/(core|modules|themes|sites/.+/files/styles)/) { set $rp_bypass 1; }
if ($request_uri ~ ^/(robots\.txt|favicon\.ico|sitemap\.xml)$)     { set $rp_bypass 1; }
if ($request_uri ~ ^/(cron\.php|update\.php|admin|user/login))     { set $rp_bypass 1; }
if ($request_uri ~ ^/(js-check\.php|__js_challenge\.php)(\?|$))    { set $rp_bypass 1; }

# Only bounce if not bypassed and cookie absent
if ($rp_bypass = 0) {
  if ($http_cookie !~ "sec_js=") { return 302 /js-check.php?b=$request_uri; }
}

# (Optional) enable if you set a global limit_req_zone
# location ~ ^/(api|user/login|user/password) { limit_req zone=rl_api burst=30 nodelay; }
````

> This is optional because the PHP gate already handles misses, but edge bouncing reduces PHP invocations on obvious bots.

---

## Optional: Global Nginx Rate Limiting (Server-Wide)

Create once (root): `/etc/nginx/conf.d/rp-js-rl.conf`

```nginx
# HTTP-level context (included by Plesk's nginx.conf)
limit_req_zone $binary_remote_addr zone=rl_api:10m rate=10r/s;
```

Test & reload:

```bash
nginx -t && systemctl reload nginx
```

Then, in any protected domain’s **Additional nginx directives**, uncomment the `location` block:

```nginx
location ~ ^/(api|user/login|user/password) { limit_req zone=rl_api burst=30 nodelay; }
```

---

## Apache Headers for Challenge Routes (Per Domain)

In **Apache & nginx Settings → Additional Apache directives (HTTPS)**:

```apache
<Location "/js-check.php">
    Header set Cache-Control "no-store, no-cache, must-revalidate, max-age=0"
</Location>
<Location "/__js_challenge.php">
    Header set Cache-Control "no-store"
</Location>
```

> Ensures intermediaries/mod_cache never store the challenge assets.

---

## Configuration Matrix (Multi-Env)

| Setting               |  Staging |  Production |
| --------------------- | -------: | ----------: |
| Token TTL             |   10 min |      10 min |
| Optional UA binding   |       On |          On |
| Nginx redirect assist | Optional | Recommended |
| Rate limit (`rl_api`) |    5 r/s |      10 r/s |
| Bypass paths          |     Same |        Same |

---

## Testing Plan

1. **Cold visit test:** Private window → `/` → observe 302 to `/js-check.php`, then back to `/`.
2. **Cookie presence:** DevTools → Application → Cookies: `sec_js` exists; HttpOnly, Secure; expiry ~10 minutes.
3. **No re-challenge within TTL:** Reload page within 10 minutes; no redirect to `/js-check.php`.
4. **Bypass paths:** Navigate to `/user/login` and `/admin` → no redirect.
5. **Authenticated bypass:** Log in to Drupal so `SSESS*` is present; open a new tab → **no challenge**, even after TTL expiry.
6. **Expiry test:** Wait 10+ minutes or delete `sec_js` (while logged out) → next request re-challenges.
7. **Static assets unaffected:** CSS/JS/images load without being gated.
8. **Rate-limit smoke (if enabled):** Abnormally fast requests to `/user/login` → `429` as expected.

---

## Monitoring & Observability

* **Nginx logs:** Count 302 to `/js-check.php` to trend bot pressure.
* **Apache/PHP logs:** Watch for `secret missing` errors (misconfigured paths).
* **Browser metrics:** Optional RUM to measure first-hit overhead (<150ms typical).

---

## Rollback / Kill Switch

* **Immediate:** In Plesk → PHP Settings → remove the `auto_prepend_file` line. Apply.
* **Edge assist off:** Remove per-domain Nginx directives and reload.
* **Keep endpoints:** Leaving `/js-check.php` and `/__js_challenge.php` in place is harmless, or you can delete them after rollback.

---

## Security, Privacy & Accessibility Notes

* **Privacy:** No fingerprinting beyond a coarse UA hash in the token payload; no PII stored.
* **Accessibility:** No visual CAPTCHA. If JS disabled, the page suggests login as a fallback; you can add a manual CAPTCHA page if policy requires.
* **TLS only:** `Secure` cookie requires HTTPS; all production traffic should already be HTTPS.

---

## Risks & Mitigations

* **Sophisticated bots setting cookies manually:** Mitigate with optional Nginx rate limiting and/or add a short Proof‑of‑Work or Turnstile for abused endpoints only.
* **Mobile/proxy UA changes:** Very rare within minutes; UA hash binding is short (12 hex chars) and TTL is small. If false positives occur, disable UA binding (remove `ua` from payload).
* **Operational drift (paths/env):** Use exact Plesk domain paths; document in runbooks.

---

## Future Enhancements (Optional)

* **Adaptive PoW:** Add a tiny SHA‑256 nonce puzzle on specific hot endpoints.
* **Managed challenge at CDN/WAF:** Cloudflare Turnstile / Managed Challenge for higher accuracy.
* **Per-endpoint form hardening:** Hidden JS-populated fields and timing checks for login/signup/comment forms.

---

## Acceptance Criteria

* First visit in a private session redirects once to `/js-check.php` and returns to original page within ~150ms client-side overhead.
* Subsequent requests within TTL (10 minutes) do not redirect.
* Admin/login/cron and static assets are bypassed.
* No additional load on Drupal for the challenge flow (Drupal untouched on misses).

---

## Appendix A — Command & Path Cheatsheet

* Secret: `/var/www/vhosts/example.com/priv/SEC_JS_SECRET`
* Gate: `/var/www/vhosts/example.com/priv/sec_js_gate.php`
* Check page: `/var/www/vhosts/example.com/httpdocs/js-check.php`
* Issuer: `/var/www/vhosts/example.com/httpdocs/__js_challenge.php`
* Plesk PHP setting: `auto_prepend_file = /var/www/vhosts/example.com/priv/sec_js_gate.php`
* Nginx global (optional): `/etc/nginx/conf.d/rp-js-rl.conf`

---

## Appendix B — Threat Model Snapshot

* Stops: trivial scrapers/cURL, many headless fetchers without JS, replay without cookie, brute-force credential spray without patience.
* Slows: medium bots that execute JS but don’t persist cookies.
* Not a silver bullet against: targeted bots that mimic browsers and manage cookies; for those, pair with WAF and behavioral controls.

---

**End of Proposal**
