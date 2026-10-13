cmake_minimum_required(VERSION 3.16)
project(license_loader C)

find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED libsodium)
find_path(PHP_INCLUDE_DIR php.h PATH_SUFFIXES php)
set(LP_VENDOR_PUBLIC_KEY_B64 "" CACHE STRING "Vendor Ed25519 public key (base64 raw 32-byte key)")
if(NOT PHP_INCLUDE_DIR)
  message(FATAL_ERROR "PHP development headers not found; install php-dev/php-devel")
endif()
if(NOT LP_VENDOR_PUBLIC_KEY_B64)
  message(FATAL_ERROR "Set LP_VENDOR_PUBLIC_KEY_B64 to the vendor raw Ed25519 public key")
endif()

add_library(license_loader MODULE license_loader.c)
target_include_directories(license_loader PRIVATE ${PHP_INCLUDE_DIR} ${SODIUM_INCLUDE_DIRS})
target_link_libraries(license_loader PRIVATE ${SODIUM_LIBRARIES})
target_compile_definitions(license_loader PRIVATE
  LP_LOADER_VERSION=\"1.0.0\"
  LP_VENDOR_PUBLIC_KEY_B64=\"${LP_VENDOR_PUBLIC_KEY_B64}\")
set_target_properties(license_loader PROPERTIES PREFIX "" SUFFIX ".so")
