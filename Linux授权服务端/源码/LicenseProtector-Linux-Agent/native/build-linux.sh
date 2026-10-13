#!/usr/bin/env bash
set -euo pipefail

# Build the Loader against the exact PHP binary that will run the customer
# application.  A Loader built for another PHP minor version is not portable.
if [[ $# -ne 1 ]]; then
  echo "usage: $0 <vendor-public-key.pem>" >&2
  exit 2
fi

PUBLIC_KEY_FILE=$1
if [[ ! -f "$PUBLIC_KEY_FILE" ]]; then
  echo "public key does not exist: $PUBLIC_KEY_FILE" >&2
  exit 2
fi
PHPIZE=${PHPIZE:-$(command -v phpize || true)}
PHP_CONFIG=${PHP_CONFIG:-$(command -v php-config || true)}
[[ -x "$PHPIZE" ]] || { echo "matching phpize is required" >&2; exit 1; }
[[ -x "$PHP_CONFIG" ]] || { echo "matching php-config is required" >&2; exit 1; }
command -v openssl >/dev/null || { echo "openssl is required" >&2; exit 1; }

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
LOADER_DIR="$SCRIPT_DIR/loader"
KEY_B64=$(openssl pkey -pubin -in "$PUBLIC_KEY_FILE" -pubout -outform DER | tail -c 32 | base64 | tr -d '\n')
[[ ${#KEY_B64} -gt 40 ]] || { echo "could not extract a raw Ed25519 public key" >&2; exit 1; }

cd "$LOADER_DIR"
if [[ ! -f configure ]]; then
  "$PHPIZE"
fi
./configure --with-php-config="$PHP_CONFIG" --enable-license_loader --with-license-loader-public-key="$KEY_B64"
make -j"$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 2)"
echo "Built: $LOADER_DIR/modules/license_loader.so"
echo "PHP build tools: $PHPIZE / $PHP_CONFIG ($("$PHP_CONFIG" --version))"
