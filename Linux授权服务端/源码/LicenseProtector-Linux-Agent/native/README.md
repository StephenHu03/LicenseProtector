# Native Loader build

The native boundary is intentionally a PHP extension, not a PHP `eval()`
loader. Build it on the target Linux PHP ABI:

```sh
sudo apt-get install php8.3-dev libsodium-dev build-essential pkg-config autoconf
cd native/loader
phpize
PUBLIC_KEY_B64="$(openssl pkey -pubin -in /path/to/vendor_public.pem -pubout -outform DER | tail -c 32 | base64 -w0)"
./configure --enable-license_loader --with-license-loader-public-key="$PUBLIC_KEY_B64"
make -j"$(nproc)"
sudo make install
```

启用扩展并重启 PHP-FPM/CLI：

```sh
echo 'extension=license_loader.so' | sudo tee /etc/php/8.3/mods-available/license_loader.ini
sudo phpenmod license_loader
sudo systemctl restart php8.3-fpm
php -m | grep license_loader
```

On distributions where the PHP package is not named `php8.3-dev`, install the
development package matching `php -v` (for example `php8.2-dev`). Do not mix a
PHP 8.2 extension with PHP 8.3 or a different architecture.

The Loader verifies the signed manifest and LPBC envelope, requests the
currently authorized plaintext payload from the Unix-socket Agent, removes only
the outer PHP tags, and invokes the target PHP ABI's Zend compiler without writing
plaintext to disk. This supports normal
PHP classes and Hyperf code, but plaintext exists briefly in the PHP process
memory and can be recovered by a privileged debugger. PHP minor versions and
architectures must be built separately because Zend ABI is not portable.

The extension source is included in this repository, but this Windows-only
development environment has no PHP development headers or Linux compiler.
Build and exercise it on the target Linux/PHP ABI before production use; a
`.so` built for one PHP minor version must not be reused for another.

For a reproducible build, copy the vendor public key to the Linux build host
and run:

```sh
./native/build-linux.sh /etc/license-protector/vendor_public.pem
php --extension=./native/loader/modules/license_loader.so native/selfcheck.php
```

The resulting `license_loader.so` is a deployment dependency. It must be
installed for the same PHP minor version used by PHP-FPM and CLI, and its
configuration must point `LP_AGENT_SOCKET` at the Agent socket. The release
directory intentionally contains no runtime key or private signing key.
