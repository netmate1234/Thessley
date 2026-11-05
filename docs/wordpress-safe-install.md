# Safe WordPress installation and lockout recovery

Use this checklist when installing or changing Thessley Security Hardening or Thessley Passkey for WordPress, including on a site referred to operationally as `wp-opsec`. Commands below are examples: confirm the actual plugin slug, site path, hosting stack, and recovery access before running them. Do not paste credentials into shell history or this guide.

## Before installation or a policy change

1. **Start on staging or a low-risk pilot.** Check the WordPress, PHP, theme, caching, security, and identity-plugin compatibility. Do not begin by enabling a site-wide enforcement setting.
2. **Make a backup you can restore.** Back up both the database and WordPress files, including `wp-content`; confirm where the backup is and who can restore it. A backup that has not been tested is not a proven rollback.
3. **Prove an independent recovery route.** Confirm hosting control panel or console access and, where available, SSH/SFTP and WP-CLI. Keep access independent of WordPress login, plugin QR approval, and the site's public IP. Verify the hosting provider's recovery procedure before production changes.
4. **Preserve administrator access.** Keep the current administrator session open while testing a second private/incognito session. Maintain a separate, named break-glass administrator with a strong unique password stored securely. Do not enroll only one device or make phone approval the only sign-in method until recovery has been tested.
5. **Record the baseline.** Note the active plugin versions, relevant settings, administrator accounts, login URL, and expected behavior. Schedule a quiet maintenance window and make one change at a time.

## Install and validate

Install on staging first. For example, using WP-CLI:

```sh
wp --path=/path/to/wordpress plugin install <trusted-plugin-zip-or-url>
wp --path=/path/to/wordpress plugin list
```

Activate only after confirming that the backup and recovery route are ready:

```sh
wp --path=/path/to/wordpress plugin activate <verified-plugin-slug>
```

Then validate all of the following before applying the same scoped change to production:

- Front page, `/wp-login.php`, `/wp-admin/`, password sign-in, and the intended Thessley sign-in flow.
- Administrator access from a second browser session and from the actual administrator network/device.
- Recovery using the separate break-glass account and the documented hosting/SSH route.
- Relevant forms, REST/API integrations, caching, scheduled tasks, and site-specific workflows.
- Logs and settings for unexpected denials. Do not test by deliberately triggering a live block or rate limit on a production site.

Enable enforcement gradually, only for the intended users/routes, and repeat the checks after each change. Keep an authorized operator available throughout the production change.

## If administrators are locked out

Use the least disruptive available path; preserve logs and note what changed and when.

1. Try the separate break-glass administrator and the verified hosting/console route. Do not repeatedly retry a blocked login or widen access rules blindly.
2. If WP-CLI works, deactivate only the suspected plugin:

   ```sh
   wp --path=/path/to/wordpress plugin deactivate <verified-plugin-slug>
   ```

   If WP-CLI is unavailable but filesystem access works, rename that plugin's directory under `wp-content/plugins/` to a temporary name. WordPress will treat it as unavailable. Restore the original directory name after diagnosis; do not delete plugin data or other plugins as a first response.
3. Retest `/wp-login.php` and administrator access. If access remains broken, inspect the web/PHP error logs and the change record, then use the host's documented restore procedure. Restore database and files from the same known-good point where possible; coordinate with the site owner because this can discard changes made after the backup.
4. Once service is restored, leave enforcement disabled until the cause is understood. Reproduce and fix the issue on staging, then retest recovery before another production attempt.

Deactivating or renaming a plugin is an **emergency containment step**, not a guarantee that every setting, mu-plugin, server rule, or side effect is reversed. Check the product's own uninstall/deactivation behavior and any separately installed components. Restore a backup only when needed and with the owner's approval; it may overwrite newer content or orders.

## Rollback plan to write down before production

Record these site-specific values in the operator's approved runbook (not in a public repository):

- Site owner, maintenance window, current plugin version, and exact change being made.
- Backup identifiers and tested restore owner/procedure.
- The verified plugin slug and exact WP-CLI deactivation command.
- The hosting/SSH/console route and authorized break-glass account custodian.
- Health checks and rollback trigger (for example, administrator login fails in the second session).
- Who approves a full restore and how new content/orders will be protected.

Do not enable a login gate, IP restriction, or other access-denial control on the only administrator or recovery route. Do not assume a Thessley plugin can restore host-level firewall rules, reverse-proxy configuration, or WordPress changes made outside that plugin.
