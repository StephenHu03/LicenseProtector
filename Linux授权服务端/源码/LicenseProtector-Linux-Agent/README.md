# Linux Agent deployment

Project-specific deployment ZIPs are created by the Windows Native build. They
contain this Agent, the PHP Loader source, the vendor public key, and that
project's runtime key. The ZIP therefore contains a secret and must be sent to
the Linux server only over a trusted channel; never put it in a public web root
or source repository. It never contains the vendor private key.

Keep the PHP application at its existing path. First copy the contents of the
Windows PHP delivery directory over that application, then extract the Linux
deployment ZIP and run:

```sh
sudo bash ./install.sh --project-root /existing/path/to/php-project
```

Optional flags select the PHP CLI/FPM used by the application and provide the
public server address for IP-bound licenses. The installer refuses to run if
the delivery files are absent, if an existing Agent key differs, or if the PHP
development ABI does not match. It does not move or replace the PHP project.

Fixed service paths:

```text
/opt/license-protector-agent  Agent source and isolated Python environment
/etc/license-protector        Runtime key, public key, and Agent config
/run/license-protector        Local PHP-to-Agent socket
```

The PHP extension is built on the target Linux server for its exact PHP ABI.
Install matching PHP development headers and libsodium development files before
running the installer. Check `journalctl -u license-agent` if systemd reports a
startup failure.
