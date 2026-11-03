# QR approval workflow (phone approvals for SSH and web logins)

How to run a QR approval request for the user, in the shape that was agreed.
Follow this instead of inventing a new delivery mechanism each time.

## Rules

- **Never publish approval links or QR images on a public site.** No uploads to
  `wp-opsec` (or any other site) unless the user explicitly asks for that exact thing.
- **Do not change a host just to serve a QR.** No new files in web roots, no new
  routes, no extra services on the OPI5. It runs production-adjacent things.
- The only local surface allowed is loopback HTTPS (`127.0.0.1:8443`), or the PNG
  shown directly in chat.
- Show the PNG; a clickable link is a convenience, not a replacement.

## Applies to every gate, not just the OPI5

Same recipe for all of them: a pty session, read the `Link:` line, `qrencode`,
show the PNG. Only the ssh command differs.

| Target | Command | What the gate asks |
| --- | --- | --- |
| OPI5 (`orangepi5`) | `ssh -tt -p 50022 ubuntu@192.168.1.200` | `thessleypam://sudo?…&s=sshd` |
| OPI5 test account | `ssh -tt -p 50022 -i ~/.ssh/thessley_sshtest sshtest@192.168.1.200` | same, `u=sshtest` |
| Windows VM (AD-joined PC) | `ssh -tt -i ~/.ssh/thessley-vm-debug -F /dev/null -l Administrator@lab.thessley.test 192.168.122.127` | AD SSH gate, `thessleypam://…&ctx=ssh&api=ad` |
| Domain controller | `ssh -tt -i ~/.ssh/thessley-vm-debug -F /dev/null -l Administrator 192.168.122.98` | AD SSH gate, per-user |
| AD web admin / SSH service | any `thessleypam://login?…` printed by the service | `thessleypam://login?…` |
| WordPress passkey login | QR on `wp-login.php`, or `/?rest_route=/thessley/v1/passkey/login/start` | `thessleypasskey://auth?type=login&…` |

The gate prints the same shape everywhere:

```
Approve <service> for <user> on <host> with Thessley Passkey (scan within 90 s):
Link: thessleypam://…  (or thessleypasskey://auth?…)
[ASCII QR]
Approve on your phone, then press Enter:
```

The gate prints, on a pty:

```
Approve sshd for <user> on <host> with Thessley Passkey (scan within 90 s):
Link: thessleypam://sudo?h=...&id=...&n=...&...
[ASCII QR]
Approve on your phone, then press Enter:
```

The request is valid **90 seconds**; the waiting session can stay open a few minutes.

## Steps

1. Start the session with the auto-Enter helper (presses Enter while the gate waits).
   Substitute the ssh command for whichever target is being approved:

   ```sh
   rm -f /tmp/opencode/gate.log
   nohup timeout 420 python3 /tmp/opencode/ptyrun_enter.py /tmp/opencode/gate.log 410 \
     ssh -tt -p 50022 -o LogLevel=ERROR ubuntu@192.168.1.200 "echo PASS-GRANTED" >/dev/null 2>&1 &
   sleep 7
   ```

   The `echo PASS-GRANTED` is just a marker that the session got through; any harmless
   command works, and it must be a `-tt` session.

2. Take the link **from the terminal output**, do not rebuild it:

   ```sh
   sed -e 's/\x1b\[[0-9;?]*[a-zA-Z]//g' -e 's/\x1b\][^\x07]*\x07//g' /tmp/opencode/gate.log \
     | grep -o 'thessleypam://[^ ]*' | head -1 > /tmp/opencode/link.txt
   ```

3. Render it:

   ```sh
   qrencode -l M -s 8 -m 2 -o /tmp/opencode/qr.png < /tmp/opencode/link.txt
   ```

4. Show `/tmp/opencode/qr.png` in chat (the image is the primary delivery), and give
   the same `thessleypam://…` string as a clickable link plus a fenced copy for the
   app's “Paste a link” box. State the account/host and that it expires in 90 s.

5. Optional local surface, loopback only:

   ```sh
   # /tmp/opencode/qr-site/serve.py serves this directory on https://127.0.0.1:8443
   # self-signed cert for CN=127.0.0.1, never bound to a LAN address
   python3 /tmp/opencode/qr-site/serve.py
   ```

6. After the user approves, verify, then use the pass:

   ```sh
   ssh -tt -p 50022 ubuntu@192.168.1.200 "echo PASS-GRANTED"
   ssh -tt -p 50022 ubuntu@192.168.1.200 "sudo thessley-pam passes"
   ```

## WordPress login QR (real sign-in, verified)

This is the one that has actually been taken end to end on `wp-opsec`:

```sh
scripts/qr-https-serve.py &          # loopback HTTPS on 127.0.0.1:8443
scripts/qr-login.sh                  # mints the request, renders the QR, polls
# open https://127.0.0.1:8443/qr.png (or /link.txt), scan, approve
```

What it does, and why each step matters:

1. `POST /?rest_route=/thessley/v1/passkey/login/start` with `username=<user>` and a
   cookie jar. With `mode=required` / `identify=1`, the username is mandatory.
2. `app_link` from the JSON is the QR payload (`thessleypasskey://auth?…`), valid 120 s.
3. `qrencode` it into the loopback directory; show `https://127.0.0.1:8443/qr.png`.
4. Poll `/login/<id>/status` with **both** `-b jar` and `-c jar`. Reading with `-b`
   alone does not save the `wordpress_logged_in` cookie the approval issues, so the
   next `/wp-admin/` request bounces to the login screen and it looks broken.
5. On `approved` the response carries `redirect_to`; the same jar can then load
   `/wp-admin/` (200) — that is the proof of a real session.

Approvals are single-use: a consumed request reports `expired` and needs a new QR.

Observed success on `wp-opsec` (admin, 2026-11-03):

```
status=approved  redirect_to=https://wp-opsec.eagleeye-intelligence.com/wp-admin/
wp-admin: 200    <title>Dashboard ‹ Thessley Security Projects — WordPress</title>
```

That second line is the point: with the cookie jar written as well as read, the
approved request turns into a real signed-in session, not just an approved row.

## Gotchas learned the hard way

- **Non-tty is refused** on the OPI5 even with a valid pass (`Permission denied
  (keyboard-interactive)`), so every command goes through `ssh -tt` / the pty helper.
  The VM gate does allow non-tty with a pass.
- **A pass suppresses new QRs** for the same user+service+client IP. To produce a
  fresh QR while holding a pass, bind the client to the host's second address:
  `ssh -b 192.168.1.249 …` — the gate sees a new IP and asks again.
- **`wp media delete` does not exist** in the OPI5's WP-CLI; attachments are posts:
  `wp post delete <id> --force`.
- The OPI5 gate advertises `h=192.168.1.200:47810`, which is LAN/VPN-only. If the
  phone is on mobile data, the approval cannot arrive — check that first when
  approvals “do nothing”.
- `sshtest@orangepi5` authenticates with `~/.ssh/thessley_sshtest` (not `id_ed25519`)
  and is a good account for testing without touching `ubuntu`.
- The Windows VM and the domain controller take their own passes: a pass approved
  on the Pi does not open them, and vice versa. Approve per target.
- Web logins (`thessleypasskey://auth?…`) go through the same rendering step; there
  is no terminal session to keep alive, only the request's 120 s window.
