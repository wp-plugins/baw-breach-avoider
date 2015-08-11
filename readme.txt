=== BREACH Avoider ===
Contributors: juliobox
Tags: security, https, breach
Requires at least: 3.9
Tested up to: 4.3
Stable tag: trunk
Donate link: https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=RB7646G6NVPWU
License: GPLv2

Avoid to be easily the target of the HTTPS BREACH vulnerability.

== Description ==
In August 2013, a new Web Vulnerability has been released, in some words : "HTTPS can be hacked in 30 seconds".

If you're using the HTTPS (TSL or SSL) at any level (admin, front, event for 1 page) you HAVE to protect your site against this flaw now.

How ? Just install this free plugin!

== Installation ==

1. Extract the plugin folder from the downloaded ZIP file.
2. Upload Bthe folder to your /wp-content/plugins/ directory.
3. Activate the plugin from the "Plugins" page in your Dashboard.
4. Done!

You can (and i encourage you to do it) define 2 constant in wp-config.php file :

BBA_REPEATER : used by this plugin to add a new secret srting in each nonces (e number used once to create a secure token and avoid CSRF flaws), default is 2, min is 1, no max, just change it.

BBA_NONCE_LENGTH : From 4 to 32 with 10 for default value, you can modify the length the each nonces in WordPress, the longer, the better

Also, WordPress includes a "nonce_life" filter hook. Its default value is 1 day, i suggest you to low this value, like 12 hours or 6 hours (DAY_IN_SECONDS /2 or /4)

== Frequently Asked Questions ==

= What is BREACH? =
This means "Browser Reconnaissance & Exfiltration via Adaptive Compression of Hypertext"
Read this http://www.kb.cert.org/vuls/id/987798 and this http://breachattack.com/

= How to protect against BREACH? =
Some of these mitigations may protect entire applications, while others may only protect individual web pages.
1. Disable HTTP compression. (1)
2. Separate the secrets from the user input. (2)
3. Randomize the secrets in each client request. -> Done!
4. Mask secrets (effectively randomizing by XORing with a random secret per request). -> Done!
5. Protect web pages from CSRF attacks.
6. Obfuscate the length of web responses by adding random amounts of arbitrary bytes. -> Done!

(1) I do not recommand this because of lack of performance, at least, but you can do it yourself in you PHP.ini or .htaccess, google "how to disable http gzip compression"
(2) Can't do this in WordPress.

Install this plugin and be protected as much as we can do in WordPress.

== Upgrade Notice ==
1.0 -> 1.2 requires WP 2.5
1.3+ requires WP 3.9 minimum

== Changelog ==

= 1.3 =
* 11 aug 2015
* 4.3 support
* Security hardening using wp_get_session_token() + hash_equals()

= 1.2 =
* 29 aug 2013
* New problem with pack() now, use my own function.

= 1.1 =
* 29 aug 2013
* hex2bin() is not always available, use a pack() instead

= 1.0 =
* 29 aug 2013
* First release