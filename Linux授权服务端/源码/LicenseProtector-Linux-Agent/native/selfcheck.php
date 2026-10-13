<?php
/**
 * Runtime smoke check for a deployed Loader.  This deliberately does not
 * decrypt anything itself; it verifies that PHP loaded the native boundary
 * and that the exported entry point has the expected signature.
 */
if (!extension_loaded('license_loader')) {
    fwrite(STDERR, "license_loader extension is not loaded\n");
    exit(1);
}
if (!function_exists('lpbc_execute')) {
    fwrite(STDERR, "lpbc_execute() is missing\n");
    exit(1);
}
$reflection = new ReflectionFunction('lpbc_execute');
if ($reflection->getNumberOfRequiredParameters() !== 3) {
    fwrite(STDERR, "lpbc_execute() must accept artifact, socket and host\n");
    exit(1);
}
fwrite(STDOUT, "license_loader loaded; lpbc_execute() is available\n");
