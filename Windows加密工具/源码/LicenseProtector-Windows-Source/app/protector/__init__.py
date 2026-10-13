"""Load protection components only when requested by the encoder or Agent."""

from importlib import import_module

_EXPORT_MODULES = {
    "WatchdogBuilder": "watchdog_builder",
    "build_manifest": "integrity_builder", "verify_manifest": "integrity_builder",
    "SourceHardeningError": "php_hardener", "harden_php_sources": "php_hardener",
    "normalize_source_paths": "php_hardener",
    "LPBCError": "lpbc", "LPBCHeader": "lpbc", "create_runtime_key": "lpbc",
    "decode_container": "lpbc", "derive_file_key": "lpbc", "encode_source": "lpbc",
    "build_native_delivery": "native_backend", "encode_selected_files": "native_backend",
    "write_native_license": "native_backend",
    "NATIVE_PROTOCOL": "native_manifest", "write_native_manifest": "native_manifest",
}


def __getattr__(name: str):
    module = _EXPORT_MODULES.get(name)
    if module is None:
        raise AttributeError(name)
    value = getattr(import_module(f".{module}", __name__), name)
    globals()[name] = value
    return value

__all__ = [
    "WatchdogBuilder", "build_manifest", "verify_manifest", "SourceHardeningError",
    "harden_php_sources", "normalize_source_paths",
    "LPBCError", "LPBCHeader", "create_runtime_key", "decode_container", "derive_file_key", "encode_source", "encode_selected_files", "build_native_delivery", "write_native_license",
    "NATIVE_PROTOCOL", "write_native_manifest",
]
