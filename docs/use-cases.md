# Thessley use cases and service packages

Use this page to guide discovery calls and demos. Start by identifying the site, who administers it, how accounts are recovered, and what the customer needs to improve. Recommend only the components that fit.

## WordPress use cases

### 1. Agencies and freelance WordPress maintainers

**Need:** a consistent security baseline and an explainable record of important security events across client sites.

**Pilot:** choose one low-risk client site, document its current configuration, install Thessley Security Hardening, configure only the modules appropriate to that site, and review the resulting event log with the client. Use the [safe WordPress installation and recovery checklist](wordpress-safe-install.md) before changing enforcement or login settings.

**Potential paid work:** initial assessment and setup, a written handover, then recurring configuration reviews and maintenance. The agency can provide the service directly or refer the owner to a Thessley deployment partner.

**Demo proof:** a repeatable checklist, sample event entries, and a rollback plan. Do not imply the plugin replaces host-level controls, backups, updates, or incident response.

### 2. Small organizations with a small administrator team

**Need:** reduce avoidable risk around privileged WordPress logins and know how to revoke access when a staff member leaves or loses a device.

**Pilot:** review administrator accounts and recovery procedures; deploy hardening first; optionally enroll one or two administrators in Thessley Passkey for WordPress.

**Demo proof:** enrollment, a normal sign-in, device revocation, and a tested recovery route. Keep a separate working break-glass administrator until recovery has been proven; use the [safe installation and lockout recovery guide](wordpress-safe-install.md).

### 3. WooCommerce, membership, and content sites

**Need:** protect the staff's WordPress administration access without disrupting customer-facing activity.

**Pilot:** scope the work to administrators and editors using `wp-login.php`; test compatibility with the site's theme, plugins, caching, and identity workflow on staging before production.

**Important boundary:** the Thessley WordPress passkey plugin protects WordPress sign-in. Do not sell it as protecting payment processing, customer checkout, customer accounts, or the hosting environment unless those capabilities are separately implemented and tested.

### 4. Suspicious activity or a security review

**Need:** understand the current configuration and available evidence, then prioritize improvements.

**Pilot:** review the site's configuration and Thessley Security Hardening event log, record the time window and evidence sources, and produce a short findings report with severity, recommended action, and limitations.

**Important boundary:** this is a configuration and evidence review, not a guarantee that every attack is detected or a replacement for forensic incident response or an independent penetration test.

## Infrastructure use case

Organizations concerned about administrator access to Linux or Windows hosts may be a fit for Thessley PAM. Treat this as a separate, higher-trust engagement: first confirm supported operating systems, network paths, recovery access, and rollback; demonstrate in a lab; then agree on a limited production pilot. Never begin by gating the only administrator or recovery route.

## Service package outline

1. **Discovery:** confirm site count, hosting, administrator roles, current login and recovery process, maintenance ownership, and compatibility constraints.
2. **Assessment:** document the baseline and prioritize risks; distinguish verified findings from assumptions.
3. **Pilot setup:** deploy to staging or one agreed site, enable only suitable controls, and test normal use, recovery, and rollback.
4. **Handover:** provide a concise configuration record, event-log example, recovery steps, and a list of exclusions.
5. **Ongoing care (optional):** scheduled reviews, configuration drift checks, plugin compatibility checks, and an agreed response process.

Price discovery and setup separately from recurring work. Start with a fixed, narrow pilot; quote ongoing maintenance only after its scope and response expectations are explicit. Do not promise “unhackable,” guaranteed prevention, or compliance certification.

## Finding the first customers

- Ask WordPress agencies, freelancers, and managed hosts for a short discovery call; they already support sites that may need a repeatable security review.
- Offer a limited paid pilot with a written scope and clear exclusions rather than an open-ended free audit.
- Use a staging demo to show installation, administrator enrollment, revocation, recovery, and the event log.
- Request permission before publishing a case study; anonymize site details unless the customer explicitly approves attribution.
- Track outreach, replies, demos, paid pilots, referrals, and recurring conversions. Use objections to improve onboarding and compatibility documentation.
