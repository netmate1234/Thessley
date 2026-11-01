Thessley Windows distribution files

windows-ssh-webgui.zip: Windows OpenSSH QR approval service and HTTPS admin web GUI. Includes installer,
setup guides, and the two companion bundles below.

windows-desktop-approval.zip: standalone approval/enrollment helper. Requires the Thessley Windows service.

windows-qr-signin-experimental.zip: experimental Windows credential provider. Read its included rollback
instructions before use; keep built-in PIN/password sign-in available. It can be staged over SSH, but
complete QR setup at the Windows sign-in screen and confirm only after a real sign-in succeeds. No ADB
or USB debugging is required.

thessley-ad-service-2026.11.01-b091ecb-windows.zip: Thessley AD service for a Windows domain controller
(ADWS + pinned Python, installer, INSTALL.txt). Serves the API on 47810, phone AD-key
enrollment on 47811 and the administrator site on 47820.

The packages are unsigned. Windows may show a security prompt when opening them.
Rebuild with: python3 thessley-pam-windows-update/scripts/build_downloads.py
