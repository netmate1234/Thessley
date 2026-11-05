# Thessley installation and lockout recovery standard

Applies across the Thessley project family. Product-specific installers and guides take precedence for exact commands and behavior; this checklist does not imply that every component changes system login policy.

## Before installing

1. Identify whether the component is an **approver/client app**, a **web login plugin/module**, or a **host access gate**. Only the last two categories can directly affect the login path they integrate with.
2. Use a disposable lab or staging system first. Confirm product and operating-system versions, the intended accounts/routes, and the behavior when the phone, network, or approval service is unavailable.
3. Create a backup appropriate to the system and verify the restore route. For WordPress/Drupal, capture database and site files. For host access policy, snapshot configuration and retain the installer-provided rollback timer when offered.
4. Keep an independent recovery route available: an existing authenticated session plus local console, hosting control panel, or a non-gated administrator route. Do not rely on the new gate itself as recovery.
5. Enroll and test at least two independent approvers where supported. Maintain a break-glass administrator. Keep passwords/PINs and recovery credentials out of source control and chat logs.

## Roll out cautiously

- Install the base service/client first; add login integrations separately and only when needed.
- Start with optional, log-only, password-fallback, or narrowly scoped modes where the product supports them. Do not enable app-only or fail-closed behavior for the sole administrator until recovery has been tested.
- Make one policy change at a time. Validate configuration before reload/restart, keep the current session open, then test a **new** login from a second terminal/browser/device.
- Confirm both success and recovery: normal user, administrator, unenrolled user, lost/unavailable phone, and any scoped exception. Do not trigger disruptive blocks on production to test them.
- Leave timed rollback armed until the new access path is proven. Only explicitly confirm/cancel it after testing a fresh login. Keep the resulting backup until the change window is closed.

## If access fails

1. Do not close surviving sessions or repeatedly retry a potentially rate-limited route.
2. Use the documented independent recovery path. For a web plugin/module, deactivate the specific integration with the framework's supported CLI or hosting file manager; prefer deactivation over uninstall/deletion so settings and enrolled devices are retained.
3. For SSH/PAM/Windows policy, allow the matching automatic rollback timer to restore its snapshot or use the documented rollback command from a local/admin console. Do not improvise broad firewall or authentication changes.
4. If rollback does not restore service, use the verified backup and product-specific recovery instructions. A full restore may overwrite content changed since the backup; get the site/system owner's approval and protect newer data.
5. Keep enforcement off until the failure is understood, reproduce the issue in staging, then repeat the pilot with a narrower scope.

## Project-specific notes

- [WordPress safe install and recovery](wordpress-safe-install.md)
- [Linux PAM SSH recovery](https://github.com/netmate1234/thessley-pam-linux/blob/main/docs/SSH.md)
- [Windows PAM SSH recovery](https://github.com/netmate1234/thessley-pam-windows/blob/main/docs/SSH.md)
- [Drupal Passkey install](https://github.com/netmate1234/thessley-passkey-drupal#quick-install)
- [Windows AD lab recovery notes](https://github.com/netmate1234/thessley-infra/blob/main/windows-ad-lab/README.md)
- Android and desktop approver apps do not themselves install a host login gate; still enroll a second approver and preserve account recovery before relying on them.

Never make a Thessley phone, service, network path, plugin, PAM module, SSH gate, or QR workflow the only way to administer or recover the system.
