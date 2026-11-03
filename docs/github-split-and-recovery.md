# Repository split and Thessley recovery

Status note written while waiting for GitHub's repository-creation rate limit.
Keep this file until the recovery is confirmed, then delete it.

## What happened

While giving the READMEs a consistent look, a `git add -A` in the `Thessley`
working tree swept untracked local files into commit `30bcb22` and pushed it to a
**public** repository. That commit contained `opencode_token` (a 42-character
token), scratch notes, screenshots, and the local copies of other projects as
embedded gitlinks.

Containment so far:

1. A clean commit replaced it on `main` (`75c0292`), then the stray paths were
   added to `.gitignore`.
2. `netmate1234/Thessley` was **deleted** — the repository and its objects are
   gone, and the cached raw blob now returns 404.
3. The token must still be treated as compromised and **rotated**.

## Current state

| Repository | Visibility | State |
| --- | --- | --- |
| `thessley-security-hardening` | public | clean, release `1.0.24` |
| `thessley-passkey` | public | clean, release `1.0.0` |
| `thessley-pam-linux` | public | clean, Pages deck |
| `thessley-pam-windows` | public | clean, Pages deck |
| `thessley-passkey-linux` | public | clean, Pages deck |
| `thessley-passkey-server` | public | clean, Pages deck |
| `thessley-infra` | public | clean (credentials stay local and ignored) |
| `thessley-site` | public | clean |
| `thessley-presentations` | public | hub for the decks |
| `Thessley` | **missing** | deleted after the leak; recreation blocked by GitHub's limit |

The clean history and all working files are in `/home/ubuntu/wp_opsec`
(`main` = `8c98318`, no token file in `HEAD`).

## Recovery procedure

GitHub rate-limits repository creation after a burst ("You have created too many
repositories, too quickly"). It is time-based; retry later.

```sh
# 1. create (private first)
gh repo create netmate1234/Thessley --private \
  --description "Thessley — passwordless authentication for WordPress, Linux, Windows and Active Directory, plus the security-hardening plugins and infrastructure."

# 2. push the clean history
cd /home/ubuntu/wp_opsec
git push -u origin main
git push origin --tags

# 3. restore the releases (assets live in /tmp/rel)
gh release create thessley-pam-linux-2026.10.22 \
  thessley-pam-linux-2026.10.22.tar.gz thessley-pam-linux-2026.10.22-SHA256SUMS.txt \
  -R netmate1234/Thessley --title "Thessley PAM for Linux 2026.10.22" \
  --notes "Distribution tarball for thessley-pam-linux."

gh release create windows-tools-2026.11.02 \
  windows-desktop-approval.zip windows-qr-signin-experimental.zip windows-ssh-webgui.zip \
  windows-tools-2026.11.02-SHA256SUMS.txt \
  -R netmate1234/Thessley --title "Windows tools 2026.11.02" \
  --notes "Windows desktop approval, QR sign-in (experimental) and the SSH web GUI, built 2026-11-02."

gh release create thessley-ad-service-2026.11.01 \
  thessley-ad-service-2026.11.01-b091ecb-windows.zip \
  thessley-ad-service-2026.11.01-SHA256SUMS.txt \
  -R netmate1234/Thessley --title "Thessley AD service 2026.11.01" \
  --notes "Windows AD service bundle, build b091ecb."

# 4. public + Pages
gh repo edit netmate1234/Thessley --visibility public --accept-visibility-change-consequences
gh api -X POST repos/netmate1234/Thessley/pages \
  -f "source[branch]=main" -f "source[path]=/docs"
```

A retry loop is running in the background (`/tmp/opencode/recreate.log`) and a
watcher (`/tmp/opencode/restore_thessley.sh`, log `/tmp/opencode/restore.log`)
performs steps 3–4 as soon as the repository exists.

## Verification checklist

- [ ] `git ls-remote origin refs/heads/main` equals local `main`
- [ ] `git ls-tree -r HEAD | grep opencode_token` → empty
- [ ] `https://raw.githubusercontent.com/netmate1234/Thessley/30bcb22/opencode_token` → 404
- [ ] three releases present with the right assets
- [ ] `https://netmate1234.github.io/Thessley/` → 200
- [ ] repository public, description without the retired name
- [ ] token rotated in the OpenCode account

## Conventions for these repositories

- README: badges, a plain `docs/preview/hero.png` banner, one real diagram
  (`architecture.png`), a link to the deck. **No slide screenshots.**
- Pages: `docs/index.html` (the entry file GitHub Pages looks for) plus
  `docs/.nojekyll`; enable with `gh api ... /pages` and `source[path]=/docs`.
- Releases: built assets and a per-release `SHA256SUMS.txt`; never commit
  binaries (`dist/` is ignored).
- Lab credentials are never committed; `windows-ad-lab/LOCAL-CREDENTIALS.txt`
  is ignored in `thessley-infra`.
