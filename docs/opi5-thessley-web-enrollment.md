# OPI5 Thessley web account enrollment

This guide covers the root-only, command-line helper for creating Thessley device enrollment requests on the Orange Pi 5. It is not a web endpoint.

The source is [`scripts/opi5-thessley-enroll.php`](../scripts/opi5-thessley-enroll.php). On the OPI5 it is installed as `/usr/local/sbin/thessley-web-enroll.php`.

## Install or update

From the repository on the OPI5, install the script with root ownership and restricted permissions:

```sh
sudo install -o root -g root -m 0750 scripts/opi5-thessley-enroll.php /usr/local/sbin/thessley-web-enroll.php
```

Run it with `sudo php`:

```sh
sudo php /usr/local/sbin/thessley-web-enroll.php list
sudo php /usr/local/sbin/thessley-web-enroll.php wp admin
sudo php /usr/local/sbin/thessley-web-enroll.php wp admin --add-another
sudo php /usr/local/sbin/thessley-web-enroll.php drupal admin
sudo php /usr/local/sbin/thessley-web-enroll.php drupal admin --add-another
```

Replace `admin` with the exact account login. Usernames must be 1–100 characters and contain only ASCII letters, digits, `.`, `_`, `@`, or `-`.

## Supported sites

| Command | Site | Application path |
| --- | --- | --- |
| `wp` | `dashboard.eagleeye-intelligence.com` | `/var/www/wordpress` |
| `drupal` | `fruitandvegreports.com` | `/var/www/fruitnweg` |

This helper does not currently cover `wp-opsec` or `unwantedip`.

## Enrollment behavior

`list` prints the recorded device labels and whether each enrollment is active or revoked for the two supported sites. An enrollment belongs to a specific site and account; enroll each site/account separately.

By default, enrollment stops if the account already has an active device. Use `--add-another` only when you intend to register an additional device. The helper does not revoke existing devices. When replacing a phone, enroll and verify the new device first, then revoke the old one through that site's administration interface.

Successful enrollment prints JSON containing an app link and a fallback URL. The request expires after 120 seconds, so open the app link in Thessley promptly. Treat both links as temporary credentials: do not paste them into tickets, logs, or shared chat. The helper checks that the site origin uses HTTPS before returning a link.

The script requires root and invokes the site's local WP-CLI or Drush command. Keep it root-owned and executable only by root; do not expose it through a web server.
