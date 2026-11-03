# Source control

**GitHub is canonical.** `origin` points at `github.com/netmate1234/...` for
every project except the Android app, which stays on GitLab.

| Repository | Remote | Notes |
| --- | --- | --- |
| [`Thessley`](https://github.com/netmate1234/Thessley) | GitHub | umbrella: docs, presentations, scripts, site content, infra |
| [`thessley-security-hardening`](https://github.com/netmate1234/thessley-security-hardening) | GitHub | release `1.0.24` |
| [`thessley-passkey`](https://github.com/netmate1234/thessley-passkey) | GitHub | release `1.0.0` |
| [`thessley-pam-linux`](https://github.com/netmate1234/thessley-pam-linux) | GitHub + GitLab mirror | merged history |
| [`thessley-pam-windows`](https://github.com/netmate1234/thessley-pam-windows) | GitHub + GitLab mirror | merged history |
| [`thessley-passkey-linux`](https://github.com/netmate1234/thessley-passkey-linux) | GitHub + GitLab mirror | merged history |
| [`thessley-passkey-server`](https://github.com/netmate1234/thessley-passkey-server) | GitHub + GitLab mirror | merged history |
| [`thessley-infra`](https://github.com/netmate1234/thessley-infra) | GitHub | lab credentials stay local and ignored |
| [`thessley-site`](https://github.com/netmate1234/thessley-site) | GitHub | publishing scripts |
| `thessley-passkey-android` | GitLab only | intentionally not moved |

## Rules

- Commit to `origin` (GitHub). GitLab is a mirror; do not start a second line there.
- The Android app is built from `/home/ubuntu/wp_opsec/thessley-passkey-android`
  (0.1.40+). `/home/ubuntu/thessley-passkey-android` is the same repository and
  must be kept in sync — do not build from a stale copy.
- Binaries live in GitHub Releases, not in git (`dist/` is ignored).
- Old local copies of the split projects are archived at
  `/home/ubuntu/archive/wp_opsec-copies/`; they are not part of any repository.
- Never commit credentials; `windows-ad-lab/LOCAL-CREDENTIALS.txt` is ignored.
