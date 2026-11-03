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

## Hosts and gates

| Host | SSH | Gate |
| --- | --- | --- |
| OPI5 (`orangepi5`) | `ssh -p 50022 ubuntu@192.168.1.200` | Thessley PAM on sshd, QR per login, 4 h pass per user+service+client IP |
| Windows VM | `ssh -i ~/.ssh/thessley-vm-debug ... Administrator@lab.thessley.test 192.168.122.127` | AD SSH gate, QR + pass |

The gate prints, on a pty:

```
Approve sshd for <user> on <host> with Thessley Passkey (scan within 90 s):
Link: thessleypam://sudo?h=...&id=...&n=...&...
[ASCII QR]
Approve on your phone, then press Enter:
```

The request is valid **90 seconds**; the waiting session can stay open a few minutes.

## Steps

1. Start the session with the auto-Enter helper (presses Enter while the gate waits):

   ```sh
   rm -f /tmp/opencode/gate.log
   nohup timeout 420 python3 /tmp/opencode/ptyrun_enter.py /tmp/opencode/gate.log 410 \
     ssh -tt -p 50022 -o LogLevel=ERROR ubuntu@192.168.1.200 "echo PASS-GRANTED" >/dev/null 2>&1 &
   sleep 7
   ```

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
