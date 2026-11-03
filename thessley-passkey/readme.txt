=== Thessley Passkey ===
Contributors: martinlundstrom, thessleysecurity
Tags: passkey, passwordless, two-factor, login, qr
Requires at least: 6.0
Tested up to: 7.1
Requires PHP: 8.3
Stable tag: 1.0.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Passwordless WordPress sign-in with the Thessley Passkey Android app — scan a QR code or tap a link, confirmed with the phone's own biometric lock.

== Description ==

Thessley Passkey replaces the password on wp-login.php with a phone approval, BankID-style. The login page shows a QR code; scanning it with the Thessley Passkey app identifies *and* authenticates the user in one step. On the same phone, a tappable link does the same without a QR.

**Three site-wide modes**

* **Password or the app** — the password form and the QR are shown together; whichever the visitor reaches for first works.
* **Password, then the app** — the password step runs first and the app confirms it, so a stolen password alone is not enough.
* **App only** — the QR is the only way in, apart from accounts with no device enrolled.

**Also included**

* **Username prompt** (optional) — ask for the username before showing the QR, for sites that prefer the account to be known up front. Unknown usernames look exactly like real accounts without a device, so nothing reveals which accounts exist.
* **Per-user device list** on the profile screen — enrol a device, see its attestation status (TEE, StrongBox, TPM, software) and revoke it.
* **Device attestation** — Android Keystore attestation chains and TPM proofs are verified server-side where the device supplies them.
* **No external service** — QR codes are drawn locally; the plugin never calls a third-party API.

This is the server half of the protocol. The Android app is a separate project.

== Installation ==

1. Upload the `thessley-passkey` folder to `/wp-content/plugins/`.
2. Activate **Thessley Passkey** in the Plugins screen.
3. Open **Thessley Passkey** in the admin menu and pick a login method.
4. Log in on a phone with the Thessley Passkey app and add it from your profile screen.

**Upgrading from Thessley Security Hardening:** if you used the Passkey Login module there, install this plugin *before* updating the hardening plugin. It reuses the same tables (`wp_thessley_passkeys`, `wp_thessley_passkey_requests`) and options (`thessley_passkey_mode`, `thessley_passkey_identify`), so every enrolled device and the settings carry over with no re-enrolment. Deactivate the old module by updating Thessley Security Hardening, which no longer ships it.

== Frequently Asked Questions ==

= Does it need Thessley Security Hardening? =
No. The two plugins are independent. When both are active, passkey events are written to the hardening plugin's Event Log; on its own, this plugin simply does not log to that table.

= What happens to users without a device? =
They keep the normal password form. A site-wide "app only" mode only applies to accounts that have an enrolled device; there is nothing to approve with otherwise.

= What is removed when I delete the plugin? =
Deleting it (not just deactivating) drops the two passkey tables and their options, which removes every enrolled device. Deactivating keeps the data.

= Bundled third-party assets =

* QR code generation (rendered as inline SVG), [kazuhikoarase/qrcode-generator](https://github.com/kazuhikoarase/qrcode-generator), MIT License — see assets/vendor/qrcode-generator.LICENSE.txt.

== Changelog ==

= 1.0.0 =
* First release as a standalone plugin, split out of Thessley Security Hardening 1.0.23. Behaviour and database schema are unchanged.
