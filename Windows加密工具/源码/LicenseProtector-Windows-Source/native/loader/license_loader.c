/*
 * LPBC v1 PHP extension Loader.
 * Decrypts signed PHP source in memory and invokes the target Zend ABI. It
 * never writes plaintext to disk or calls userland eval(). Build separately
 * for each PHP ABI.
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <php.h>
#include <ext/standard/info.h>
#include <Zend/zend_exceptions.h>
#include <ext/json/php_json.h>
#include <Zend/zend_compile.h>
#include <Zend/zend_execute.h>
#include <sodium.h>
#include <ctype.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/time.h>
#include <unistd.h>

#ifndef LP_LOADER_VERSION
#define LP_LOADER_VERSION "dev"
#endif
#ifndef LP_VENDOR_PUBLIC_KEY_B64
#define LP_VENDOR_PUBLIC_KEY_B64 ""
#endif

#define LP_MAX_FILE (64U * 1024U * 1024U)
#define LP_MAX_HEADER (64U * 1024U)
#define LP_MAX_RESPONSE (90U * 1024U * 1024U)
static const unsigned char lp_magic[] = {'L','P','B','C',1};

static int lp_read_file(const char *path, unsigned char **out, size_t *out_len) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return 0;
    off_t end = lseek(fd, 0, SEEK_END);
    if (end <= 0 || (uint64_t)end > LP_MAX_FILE || lseek(fd, 0, SEEK_SET) < 0) { close(fd); return 0; }
    unsigned char *buf = emalloc((size_t)end);
    size_t got = 0;
    while (got < (size_t)end) {
        ssize_t n = read(fd, buf + got, (size_t)end - got);
        if (n <= 0) { efree(buf); close(fd); return 0; }
        got += (size_t)n;
    }
    close(fd); *out = buf; *out_len = got; return 1;
}

static uint32_t lp_u32be(const unsigned char *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

static zval *lp_field(zval *object, const char *name) {
    if (Z_TYPE_P(object) == IS_ARRAY) return zend_hash_str_find(Z_ARRVAL_P(object), name, strlen(name));
    if (Z_TYPE_P(object) == IS_OBJECT) return zend_hash_str_find(Z_OBJPROP_P(object), name, strlen(name));
    return NULL;
}

static int lp_json(const unsigned char *bytes, size_t len, zval *result) {
    /* The JSON scanner needs a trailing NUL, like a PHP string. File buffers
     * have no sentinel, and LPBC header slices are followed by binary data.
     * Copy exactly len bytes so parsing never depends on the next byte. */
    zend_string *json = zend_string_init((const char *)bytes, len, 0);
    ZVAL_NULL(result);
    php_json_decode_ex(result, ZSTR_VAL(json), ZSTR_LEN(json), PHP_JSON_OBJECT_AS_ARRAY, 64);
    sodium_memzero(ZSTR_VAL(json), ZSTR_LEN(json));
    zend_string_release(json);
    if (JSON_G(error_code) != PHP_JSON_ERROR_NONE
        || (Z_TYPE_P(result) != IS_ARRAY && Z_TYPE_P(result) != IS_OBJECT)) {
        zval_ptr_dtor(result);
        ZVAL_NULL(result);
        return 0;
    }
    return 1;
}

static int lp_text_eq(zval *value, const char *expected) {
    return value && Z_TYPE_P(value) == IS_STRING
        && Z_STRLEN_P(value) == strlen(expected)
        && memcmp(Z_STRVAL_P(value), expected, strlen(expected)) == 0;
}

static int lp_valid_relative_path(const char *path, size_t len) {
    if (!len || path[0] == '/' || (len >= 2 && path[1] == ':')) return 0;
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)path[i];
        if (!(isalnum(c) || c == '_' || c == '-' || c == '.' || c == '/')) return 0;
        if (c == '.' && i + 1 < len && path[i + 1] == '.') {
            if ((i == 0 || path[i - 1] == '/') && (i + 2 == len || path[i + 2] == '/')) return 0;
        }
    }
    return 1;
}

static int lp_json_escape(const char *input, char *output, size_t capacity) {
    size_t used = 0;
    for (const unsigned char *p = (const unsigned char *)input; *p; p++) {
        if (*p < 0x20 || *p == '"' || *p == '\\') {
            if (capacity - used < 7) return 0;
            static const char hex[] = "0123456789abcdef";
            output[used++] = '\\'; output[used++] = 'u'; output[used++] = '0'; output[used++] = '0';
            output[used++] = hex[*p >> 4]; output[used++] = hex[*p & 15];
        } else {
            if (capacity - used < 2) return 0;
            output[used++] = (char)*p;
        }
    }
    if (used >= capacity) return 0;
    output[used] = '\0'; return 1;
}

static int lp_write_all(int fd, const char *buffer, size_t length) {
    size_t sent = 0;
    while (sent < length) {
        ssize_t n = write(fd, buffer + sent, length - sent);
        if (n <= 0) return 0;
        sent += (size_t)n;
    }
    return 1;
}

static int lp_agent_payload(const char *socket_path, const char *host, const char *artifact_rel,
                            const char *source_path, const char *expected_payload_type,
                            const char *manifest_sha, unsigned char **payload_out, size_t *payload_len_out) {
    if (strlen(socket_path) >= sizeof(((struct sockaddr_un *)0)->sun_path)) return 0;
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return 0;
    struct sockaddr_un addr; memset(&addr, 0, sizeof(addr)); addr.sun_family = AF_UNIX;
    memcpy(addr.sun_path, socket_path, strlen(socket_path) + 1);
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) { close(fd); return 0; }
    struct timeval timeout = {5, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    char escaped_host[1024], escaped_path[4096];
    if (!lp_json_escape(host, escaped_host, sizeof(escaped_host)) || !lp_json_escape(artifact_rel, escaped_path, sizeof(escaped_path))) { close(fd); return 0; }
    char request[8192];
    int request_len = snprintf(request, sizeof(request),
        "{\"protocol\":\"LP-AGENT-1\",\"op\":\"authorize\",\"host\":\"%s\",\"path\":\"%s\",\"manifest_sha256\":\"%s\"}\n",
        escaped_host, escaped_path, manifest_sha);
    if (request_len <= 0 || (size_t)request_len >= sizeof(request) || !lp_write_all(fd, request, (size_t)request_len)) { close(fd); return 0; }
    size_t capacity = 4096, used = 0;
    unsigned char *response = emalloc(capacity);
    while (used < LP_MAX_RESPONSE - 1) {
        if (used + 1 == capacity) {
            size_t next = capacity > LP_MAX_RESPONSE / 2 ? LP_MAX_RESPONSE : capacity * 2;
            response = erealloc(response, next);
            capacity = next;
        }
        ssize_t n = read(fd, response + used, capacity - used - 1);
        if (n <= 0) break;
        used += (size_t)n;
        if (memchr(response, '\n', used)) break;
    }
    close(fd);
    if (!used || used >= LP_MAX_RESPONSE - 1) { efree(response); return 0; }
    response[used] = 0;
    zval response_json;
    if (!lp_json(response, used, &response_json)) { efree(response); return 0; }
    efree(response);
    zval *ok = lp_field(&response_json, "ok"), *protocol = lp_field(&response_json, "protocol");
    zval *returned_path = lp_field(&response_json, "path"), *returned_source = lp_field(&response_json, "source_path");
    zval *returned_type = lp_field(&response_json, "payload_type"), *payload_value = lp_field(&response_json, "payload_b64");
    if (!ok || Z_TYPE_P(ok) != IS_TRUE || !lp_text_eq(protocol, "LP-AGENT-1")
        || !returned_path || Z_TYPE_P(returned_path) != IS_STRING || strcmp(Z_STRVAL_P(returned_path), artifact_rel) != 0
        || !returned_source || Z_TYPE_P(returned_source) != IS_STRING || strcmp(Z_STRVAL_P(returned_source), source_path) != 0
        || !lp_text_eq(returned_type, expected_payload_type)
        || !payload_value || Z_TYPE_P(payload_value) != IS_STRING) {
        zval_ptr_dtor(&response_json); return 0;
    }
    size_t encoded_len = Z_STRLEN_P(payload_value);
    size_t decoded_capacity = (encoded_len / 4) * 3 + 3;
    if (decoded_capacity > LP_MAX_FILE) { zval_ptr_dtor(&response_json); return 0; }
    unsigned char *decoded_payload = emalloc(decoded_capacity ? decoded_capacity : 1);
    size_t decoded_len = 0;
    int valid = sodium_base642bin(decoded_payload, decoded_capacity, Z_STRVAL_P(payload_value), encoded_len,
                                  NULL, &decoded_len, NULL, sodium_base64_VARIANT_ORIGINAL) == 0
        && decoded_len <= LP_MAX_FILE;
    if (valid) { *payload_out = decoded_payload; *payload_len_out = decoded_len; }
    else { sodium_memzero(decoded_payload, decoded_capacity); efree(decoded_payload); }
    zval_ptr_dtor(&response_json);
    return valid;
}

static int lp_manifest(const char *artifact_path, const unsigned char public_key[crypto_sign_PUBLICKEYBYTES],
                       char **artifact_rel_out, char manifest_sha[crypto_hash_sha256_BYTES * 2 + 1],
                       char artifact_sha[crypto_hash_sha256_BYTES * 2 + 1],
                       char *error_stage, size_t error_stage_size) {
#define LP_MANIFEST_STAGE(name) do { if (error_stage && error_stage_size) snprintf(error_stage, error_stage_size, "%s", name); } while (0)
    LP_MANIFEST_STAGE("unknown");
    const char *marker = strstr(artifact_path, "/protected/lpbc/");
    if (!marker || strstr(marker + strlen("/protected/lpbc/"), "/protected/lpbc/")) {
        LP_MANIFEST_STAGE("artifact path");
        return 0;
    }
    size_t root_len = (size_t)(marker - artifact_path);
    char *manifest_path = emalloc(root_len + sizeof("/protected/lpbc/manifest.json"));
    memcpy(manifest_path, artifact_path, root_len);
    strcpy(manifest_path + root_len, "/protected/lpbc/manifest.json");
    unsigned char *manifest = NULL, *signature_text = NULL; size_t manifest_len = 0, signature_len = 0;
    if (!lp_read_file(manifest_path, &manifest, &manifest_len)) { LP_MANIFEST_STAGE("manifest read"); efree(manifest_path); return 0; }
    strcpy(manifest_path + root_len, "/protected/lpbc/manifest.sig");
    if (!lp_read_file(manifest_path, &signature_text, &signature_len)) { LP_MANIFEST_STAGE("signature read"); efree(manifest_path); efree(manifest); return 0; }
    efree(manifest_path);
    unsigned char signature[crypto_sign_BYTES]; size_t signature_len_raw = 0;
    if (sodium_base642bin(signature, sizeof(signature), (const char *)signature_text, signature_len,
                          "\r\n \t", &signature_len_raw, NULL, sodium_base64_VARIANT_ORIGINAL) != 0
        || signature_len_raw != crypto_sign_BYTES) {
        LP_MANIFEST_STAGE("signature encoding");
        efree(manifest); efree(signature_text); return 0;
    }
    if (crypto_sign_verify_detached(signature, manifest, (unsigned long long)manifest_len, public_key) != 0) {
        LP_MANIFEST_STAGE("signature verification");
        efree(manifest); efree(signature_text); return 0;
    }
    const char *relative = marker + strlen("/protected/lpbc/");
    size_t relative_len = strlen(relative);
    if (!relative_len || relative_len >= 4096 || !lp_valid_relative_path(relative, relative_len)) { LP_MANIFEST_STAGE("artifact relative path"); efree(manifest); efree(signature_text); return 0; }
    char artifact_rel[4200];
    int artifact_rel_len = snprintf(artifact_rel, sizeof(artifact_rel), "protected/lpbc/%s", relative);
    if (artifact_rel_len <= 0 || (size_t)artifact_rel_len >= sizeof(artifact_rel)) { LP_MANIFEST_STAGE("artifact relative path length"); efree(manifest); efree(signature_text); return 0; }
    zval manifest_json;
    if (!lp_json(manifest, manifest_len, &manifest_json)) {
        char stage[64];
        snprintf(stage, sizeof(stage), "manifest JSON type=%d error=%d", Z_TYPE(manifest_json), (int)JSON_G(error_code));
        LP_MANIFEST_STAGE(stage);
        efree(manifest); efree(signature_text); return 0;
    }
    zval *manifest_protocol = lp_field(&manifest_json, "protocol"), *files = lp_field(&manifest_json, "files");
    if (!lp_text_eq(manifest_protocol, "LP-NATIVE-1") || !files || Z_TYPE_P(files) != IS_ARRAY) {
        LP_MANIFEST_STAGE("manifest protocol");
        zval_ptr_dtor(&manifest_json); efree(manifest); efree(signature_text); return 0;
    }
    unsigned char *artifact_data = NULL; size_t artifact_len = 0;
    if (!lp_read_file(artifact_path, &artifact_data, &artifact_len)) {
        LP_MANIFEST_STAGE("artifact read");
        zval_ptr_dtor(&manifest_json); efree(manifest); efree(signature_text); return 0;
    }
    unsigned char file_digest[crypto_hash_sha256_BYTES]; char file_hex[crypto_hash_sha256_BYTES * 2 + 1];
    crypto_hash_sha256(file_digest, artifact_data, (unsigned long long)artifact_len);
    sodium_bin2hex(file_hex, sizeof(file_hex), file_digest, sizeof(file_digest));
    sodium_memzero(artifact_data, artifact_len); efree(artifact_data);
    zend_bool listed = 0; zval *entry;
    ZEND_HASH_FOREACH_VAL(Z_ARRVAL_P(files), entry) {
        zval *entry_path = lp_field(entry, "path"), *entry_hash = lp_field(entry, "sha256");
        if (entry_path && Z_TYPE_P(entry_path) == IS_STRING && strcmp(Z_STRVAL_P(entry_path), artifact_rel) == 0
            && entry_hash && Z_TYPE_P(entry_hash) == IS_STRING && strcmp(Z_STRVAL_P(entry_hash), file_hex) == 0) {
            listed = 1; break;
        }
    } ZEND_HASH_FOREACH_END();
    zval_ptr_dtor(&manifest_json);
    if (!listed) { LP_MANIFEST_STAGE("artifact manifest hash"); efree(manifest); efree(signature_text); return 0; }
    memcpy(artifact_sha, file_hex, sizeof(file_hex));
    unsigned char digest[crypto_hash_sha256_BYTES]; crypto_hash_sha256(digest, manifest, (unsigned long long)manifest_len);
    sodium_bin2hex(manifest_sha, crypto_hash_sha256_BYTES * 2 + 1, digest, sizeof(digest));
    *artifact_rel_out = estrdup(artifact_rel);
    efree(manifest); efree(signature_text);
#undef LP_MANIFEST_STAGE
    return 1;
}

static int lp_allowed_native(const char *name) {
    static const char *allowed[] = {"strlen", "strtolower", "strtoupper", "trim", "hash", "json_encode", NULL};
    for (size_t i = 0; allowed[i]; i++) if (strcasecmp(name, allowed[i]) == 0) return 1;
    return 0;
}

static int lp_run_ir(const unsigned char *payload, size_t payload_len, zval *return_value) {
    zval ir; if (!lp_json(payload, payload_len, &ir)) return 0;
    zval *ir_name = lp_field(&ir, "ir"), *instructions = lp_field(&ir, "instructions");
    if (!lp_text_eq(ir_name, "LP-IR-1") || !instructions || Z_TYPE_P(instructions) != IS_ARRAY
        || zend_hash_num_elements(Z_ARRVAL_P(instructions)) == 0 || zend_hash_num_elements(Z_ARRVAL_P(instructions)) > 128) {
        zval_ptr_dtor(&ir); return 0;
    }
    zval stack[64]; uint32_t stack_len = 0; zval *instruction; zend_ulong index; zend_string *key;
    ZEND_HASH_FOREACH_KEY_VAL(Z_ARRVAL_P(instructions), index, key, instruction) {
        zval *op = lp_field(instruction, "op");
        if (lp_text_eq(op, "PUSH_CONST")) {
            zval *value = lp_field(instruction, "value");
            if (!value || stack_len == 64 || Z_TYPE_P(value) == IS_ARRAY || Z_TYPE_P(value) == IS_OBJECT) { zval_ptr_dtor(&ir); return 0; }
            ZVAL_COPY(&stack[stack_len++], value);
        } else if (lp_text_eq(op, "CALL_NATIVE")) {
            zval *name = lp_field(instruction, "name"), *argc_zv = lp_field(instruction, "argc");
            if (!name || Z_TYPE_P(name) != IS_STRING || !lp_allowed_native(Z_STRVAL_P(name)) || !argc_zv || Z_TYPE_P(argc_zv) != IS_LONG
                || Z_LVAL_P(argc_zv) < 0 || (uint32_t)Z_LVAL_P(argc_zv) > stack_len) { zval_ptr_dtor(&ir); return 0; }
            uint32_t argc = (uint32_t)Z_LVAL_P(argc_zv); zval retval, function;
            ZVAL_STRINGL(&function, Z_STRVAL_P(name), Z_STRLEN_P(name));
            if (call_user_function(EG(function_table), NULL, &function, &retval, argc, argc ? &stack[stack_len - argc] : NULL) != SUCCESS) {
                zval_ptr_dtor(&function); zval_ptr_dtor(&ir); return 0;
            }
            zval_ptr_dtor(&function);
            while (argc--) zval_ptr_dtor(&stack[--stack_len]);
            stack[stack_len++] = retval;
        } else if (lp_text_eq(op, "RETURN")) {
            if (stack_len != 1) { zval_ptr_dtor(&ir); return 0; }
            ZVAL_COPY(return_value, &stack[0]); zval_ptr_dtor(&stack[0]); zval_ptr_dtor(&ir); return 1;
        } else { zval_ptr_dtor(&ir); return 0; }
    } ZEND_HASH_FOREACH_END();
    zval_ptr_dtor(&ir); return 0;
}

static int lp_execute_php_source(const unsigned char *source, size_t source_len, const char *virtual_filename, zval *return_value) {
    const unsigned char *code_start = source;
    size_t code_len = source_len;
    if (code_len >= 3 && code_start[0] == 0xef && code_start[1] == 0xbb && code_start[2] == 0xbf) {
        code_start += 3; code_len -= 3;
    }
    if (code_len >= 5 && strncasecmp((const char *)code_start, "<?php", 5) == 0) {
        code_start += 5; code_len -= 5;
    }
    while (code_len >= 2 && code_start[code_len - 2] == '?' && code_start[code_len - 1] == '>') {
        code_len -= 2;
    }
    zend_string *code = zend_string_init((const char *)code_start, code_len, 0);
    /* PHP 8.2+ requires the lexer position explicitly. PHP 8.1 uses the
     * older two-argument ABI, so keep one source compatible with both. */
#if PHP_VERSION_ID >= 80200
    zend_op_array *op_array = zend_compile_string(code, virtual_filename, ZEND_COMPILE_POSITION_AFTER_OPEN_TAG);
#else
    zend_op_array *op_array = zend_compile_string(code, virtual_filename);
#endif
    zend_string_release(code);
    if (!op_array) return 0;
    zval result; ZVAL_UNDEF(&result);
    zend_execute(op_array, &result);
    if (EG(exception)) {
        if (Z_TYPE(result) != IS_UNDEF) zval_ptr_dtor(&result);
        destroy_op_array(op_array); efree(op_array);
        return -1;
    }
    destroy_op_array(op_array); efree(op_array);
    if (Z_TYPE(result) != IS_UNDEF) ZVAL_COPY_VALUE(return_value, &result);
    else ZVAL_NULL(return_value);
    return 1;
}

ZEND_BEGIN_ARG_INFO_EX(arginfo_lpbc_execute, 0, 0, 3)
    ZEND_ARG_TYPE_INFO(0, artifact, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, socket, IS_STRING, 0)
    ZEND_ARG_TYPE_INFO(0, host, IS_STRING, 0)
ZEND_END_ARG_INFO()

PHP_FUNCTION(lpbc_execute) {
    zend_string *artifact, *socket_path, *host;
    ZEND_PARSE_PARAMETERS_START(3, 3)
        Z_PARAM_STR(artifact) Z_PARAM_STR(socket_path) Z_PARAM_STR(host)
    ZEND_PARSE_PARAMETERS_END();

    unsigned char public_key[crypto_sign_PUBLICKEYBYTES]; size_t public_key_len = 0;
    if (sodium_base642bin(public_key, sizeof(public_key), LP_VENDOR_PUBLIC_KEY_B64, strlen(LP_VENDOR_PUBLIC_KEY_B64),
                          NULL, &public_key_len, NULL, sodium_base64_VARIANT_ORIGINAL) != 0 || public_key_len != sizeof(public_key)) {
        zend_throw_exception(NULL, "License Loader: vendor public key is not configured", 0); RETURN_NULL();
    }
    char *artifact_rel = NULL, manifest_sha[crypto_hash_sha256_BYTES * 2 + 1];
    char artifact_sha[crypto_hash_sha256_BYTES * 2 + 1];
    char manifest_error_stage[64];
    if (!lp_manifest(ZSTR_VAL(artifact), public_key, &artifact_rel, manifest_sha, artifact_sha,
                     manifest_error_stage, sizeof(manifest_error_stage))) {
        zend_throw_exception_ex(NULL, 0, "License Loader: signed manifest verification failed (%s)", manifest_error_stage); RETURN_NULL();
    }
    unsigned char *data = NULL; size_t len = 0;
    if (!lp_read_file(ZSTR_VAL(artifact), &data, &len)) { efree(artifact_rel); zend_throw_exception(NULL, "License Loader: cannot read artifact", 0); RETURN_NULL(); }
    unsigned char actual_digest[crypto_hash_sha256_BYTES]; char actual_hex[crypto_hash_sha256_BYTES * 2 + 1];
    crypto_hash_sha256(actual_digest, data, (unsigned long long)len);
    sodium_bin2hex(actual_hex, sizeof(actual_hex), actual_digest, sizeof(actual_digest));
    if (sodium_memcmp(actual_hex, artifact_sha, sizeof(actual_hex) - 1) != 0) {
        efree(data); efree(artifact_rel); zend_throw_exception(NULL, "License Loader: artifact differs from signed manifest", 0); RETURN_NULL();
    }
    if (len < sizeof(lp_magic) + 4 + 12 + crypto_aead_aes256gcm_ABYTES + crypto_sign_BYTES || memcmp(data, lp_magic, sizeof(lp_magic)) != 0) {
        efree(data); efree(artifact_rel); zend_throw_exception(NULL, "License Loader: malformed LPBC", 0); RETURN_NULL();
    }
    uint32_t header_len = lp_u32be(data + sizeof(lp_magic)); size_t header_start = sizeof(lp_magic) + 4, header_end = header_start + header_len;
    if (header_len == 0 || header_len > LP_MAX_HEADER || header_end + 12 + crypto_aead_aes256gcm_ABYTES + crypto_sign_BYTES > len
        || crypto_sign_verify_detached(data + len - crypto_sign_BYTES, data, (unsigned long long)(len - crypto_sign_BYTES), public_key) != 0) {
        efree(data); efree(artifact_rel); zend_throw_exception(NULL, "License Loader: signature or header invalid", 0); RETURN_NULL();
    }
    zval header; if (!lp_json(data + header_start, header_len, &header)) {
        efree(data); efree(artifact_rel); zend_throw_exception(NULL, "License Loader: invalid metadata", 0); RETURN_NULL();
    }
    zval *payload_type = lp_field(&header, "payload_type"), *source_path = lp_field(&header, "path");
    zval *format_version = lp_field(&header, "format_version"), *algorithm = lp_field(&header, "algorithm"), *payload_sha = lp_field(&header, "payload_sha256");
    int is_ir = lp_text_eq(payload_type, "ir-v1");
    if ((!is_ir && !lp_text_eq(payload_type, "php-source-v1")) || !source_path || Z_TYPE_P(source_path) != IS_STRING
        || !lp_valid_relative_path(Z_STRVAL_P(source_path), Z_STRLEN_P(source_path))
        || Z_STRLEN_P(source_path) < 4
        || !format_version || Z_TYPE_P(format_version) != IS_LONG || Z_LVAL_P(format_version) != 1
        || !lp_text_eq(algorithm, "AES-256-GCM") || !payload_sha || Z_TYPE_P(payload_sha) != IS_STRING || Z_STRLEN_P(payload_sha) != 64) {
        zval_ptr_dtor(&header); efree(data); efree(artifact_rel); zend_throw_exception(NULL, "License Loader: unsupported LPBC payload type", 0); RETURN_NULL();
    }
    size_t artifact_rel_len = strlen(artifact_rel);
    if (artifact_rel_len < 5 || strcmp(artifact_rel + artifact_rel_len - 5, ".lpbc") != 0
        || Z_STRLEN_P(source_path) != artifact_rel_len - sizeof("protected/lpbc/")
        || memcmp(Z_STRVAL_P(source_path), artifact_rel + sizeof("protected/lpbc/") - 1,
                  Z_STRLEN_P(source_path) - 4) != 0
        || memcmp(Z_STRVAL_P(source_path) + Z_STRLEN_P(source_path) - 4, ".php", 4) != 0) {
        zval_ptr_dtor(&header); efree(data); efree(artifact_rel); zend_throw_exception(NULL, "License Loader: LPBC path does not match signed metadata", 0); RETURN_NULL();
    }
    char signed_payload_sha[65]; memcpy(signed_payload_sha, Z_STRVAL_P(payload_sha), 64); signed_payload_sha[64] = '\0';
    char source_path_copy[4096];
    if (Z_STRLEN_P(source_path) >= sizeof(source_path_copy)) {
        zval_ptr_dtor(&header); efree(data); efree(artifact_rel); zend_throw_exception(NULL, "License Loader: source path too long", 0); RETURN_NULL();
    }
    memcpy(source_path_copy, Z_STRVAL_P(source_path), Z_STRLEN_P(source_path));
    source_path_copy[Z_STRLEN_P(source_path)] = '\0';
    zval_ptr_dtor(&header);
    unsigned char *plain = NULL; size_t plain_len = 0;
    if (!lp_agent_payload(ZSTR_VAL(socket_path), ZSTR_VAL(host), artifact_rel, source_path_copy,
                          is_ir ? "ir-v1" : "php-source-v1", manifest_sha, &plain, &plain_len)) {
        efree(data); efree(artifact_rel); zend_throw_exception(NULL, "License Loader: Agent authorization or decryption failed", 0); RETURN_NULL();
    }
    efree(artifact_rel);
    unsigned char expected_digest[crypto_hash_sha256_BYTES]; char expected_hex[crypto_hash_sha256_BYTES * 2 + 1];
    crypto_hash_sha256(expected_digest, plain, (unsigned long long)plain_len);
    sodium_bin2hex(expected_hex, sizeof(expected_hex), expected_digest, sizeof(expected_digest));
    efree(data);
    if (memcmp(expected_hex, signed_payload_sha, sizeof(expected_hex) - 1) != 0) {
        sodium_memzero(plain, plain_len); efree(plain); zend_throw_exception(NULL, "License Loader: payload digest mismatch", 0); RETURN_NULL();
    }
    ZVAL_NULL(return_value);
    char virtual_filename[4096];
    /* Preserve PHP's file semantics for __FILE__, __DIR__, and relative
     * require/include calls. The artifact lives below <root>/protected/lpbc,
     * while the original source path is relative to <root>. */
    const char *artifact_marker = strstr(ZSTR_VAL(artifact), "/protected/lpbc/");
    int virtual_len;
    if (artifact_marker) {
        size_t root_len = (size_t)(artifact_marker - ZSTR_VAL(artifact));
        virtual_len = (root_len > 0 && root_len + 1 + strlen(source_path_copy) < sizeof(virtual_filename))
            ? snprintf(virtual_filename, sizeof(virtual_filename), "%.*s/%s", (int)root_len, ZSTR_VAL(artifact), source_path_copy)
            : -1;
    } else {
        virtual_len = snprintf(virtual_filename, sizeof(virtual_filename), "%s", source_path_copy);
    }
    int executed = is_ir ? lp_run_ir(plain, plain_len, return_value)
                         : lp_execute_php_source(plain, plain_len,
                                                   virtual_len > 0 ? virtual_filename : "LicenseProtector LPBC",
                                                   return_value);
    sodium_memzero(plain, (size_t)plain_len); efree(plain);
    if (executed < 0) RETURN_NULL();
    if (!executed) { zend_throw_exception(NULL, "License Loader: payload execution failed", 0); RETURN_NULL(); }
}

PHP_MINIT_FUNCTION(license_loader) {
    if (sodium_init() < 0) return FAILURE;
    return SUCCESS;
}
PHP_MINFO_FUNCTION(license_loader) {
    php_info_print_table_start(); php_info_print_table_row(2, "LicenseProtector Loader", LP_LOADER_VERSION);
    php_info_print_table_row(2, "LPBC payloads", "php-source-v1 in-memory Zend compile; ir-v1 optional"); php_info_print_table_end();
}
static const zend_function_entry lp_functions[] = { PHP_FE(lpbc_execute, arginfo_lpbc_execute) PHP_FE_END };
zend_module_entry license_loader_module_entry = {
    STANDARD_MODULE_HEADER, "license_loader", lp_functions, PHP_MINIT(license_loader), NULL, NULL, NULL,
    PHP_MINFO(license_loader), LP_LOADER_VERSION, STANDARD_MODULE_PROPERTIES
};
ZEND_GET_MODULE(license_loader)
