PHP_ARG_ENABLE([license_loader], [whether to enable LicenseProtector Loader],
  [AS_HELP_STRING([--enable-license_loader], [Enable LicenseProtector Loader])], [no])
PHP_ARG_WITH([license_loader_public_key], [vendor public key for LicenseProtector Loader],
  [AS_HELP_STRING([--with-license-loader-public-key=BASE64], [Raw Ed25519 public key, base64 encoded])], [no])

if test "$PHP_LICENSE_LOADER" != "no"; then
  if test "$PHP_LICENSE_LOADER_PUBLIC_KEY" = "no"; then
    AC_MSG_ERROR([--with-license-loader-public-key is required])
  fi
  PKG_CHECK_MODULES([SODIUM], [libsodium])
  AC_CHECK_HEADERS([sodium.h], [], [AC_MSG_ERROR([libsodium headers are required])])
  AC_DEFINE_UNQUOTED([LP_VENDOR_PUBLIC_KEY_B64], ["$PHP_LICENSE_LOADER_PUBLIC_KEY"], [Vendor Ed25519 public key])
  PHP_EVAL_INCLINE([$SODIUM_CFLAGS])
  PHP_EVAL_LIBLINE([$SODIUM_LIBS], [LICENSE_LOADER_SHARED_LIBADD])
  PHP_NEW_EXTENSION([license_loader], [license_loader.c], [$ext_shared])
  PHP_ADD_EXTENSION_DEP([license_loader], [json])
fi
