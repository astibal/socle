#pragma once

#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <optional>
#include <string_view>
#include <arpa/inet.h>
#include <array>
#include <ctime>
#include <climits>
#include <limits>
#include <vars.hpp>
#include <string>
#include <vector>

// Borrowed OpenSSL inputs; these helpers never take ownership of certificates.
// No JSON or proxy dependencies: presentation schemas belong to callers.
namespace socle::ossl {

// Formatting alone never consumes the thread-local OpenSSL error queue.
inline std::string error_text(unsigned long code, size_t buffer_size = 256) {
    if(buffer_size == 0) return {};
    std::vector<char> text(buffer_size, 0);
    ERR_error_string_n(code, text.data(), text.size());
    return text.data();
}

// Consume exactly one entry, retaining OpenSSL's textual representation of 0.
inline std::string take_error_text(size_t buffer_size = 256) {
    return error_text(ERR_get_error(), buffer_size);
}

// Explicitly drain the entire queue, oldest error first.
inline std::string drain_error_text() {
    std::string result;
    while(auto code = ERR_get_error()) {
        if(!result.empty()) result += "; ";
        result += error_text(code);
    }
    return result;
}

// Read on the SSL object's owning thread. Returned values own their storage.
// No handshake/policy decisions: callers decide when these fields are valid.
struct session_info {
    std::string transport_version; // SSL_get_version: can describe QUIC, not TLS.
    int protocol_version = 0;       // SSL_SESSION_get_protocol_version: TLS version.
    std::string cipher;
    bool has_ticket = false;
    unsigned long ticket_lifetime_hint = 0;
};

inline std::optional<session_info> session_details(SSL const* ssl) {
    auto const* session = ssl ? SSL_get_session(ssl) : nullptr;
    if(!session) return std::nullopt;
    session_info result;
    result.transport_version = SSL_get_version(ssl);
    result.protocol_version = SSL_SESSION_get_protocol_version(session);
    result.cipher = SSL_CIPHER_get_name(SSL_SESSION_get0_cipher(session));
    result.has_ticket = SSL_SESSION_has_ticket(session) != 0;
    if(result.has_ticket)
        result.ticket_lifetime_hint = SSL_SESSION_get_ticket_lifetime_hint(session);
    return result;
}

inline std::optional<std::string> server_name(SSL const* ssl) {
    auto const* name = ssl ? SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name) : nullptr;
    return name ? std::optional<std::string>(name) : std::nullopt;
}

inline std::string selected_alpn(SSL const* ssl) {
    if(!ssl) return {};
    unsigned char const* bytes = nullptr;
    unsigned int size = 0;
    SSL_get0_alpn_selected(ssl, &bytes, &size);
    return bytes && size ? std::string(reinterpret_cast<char const*>(bytes), size) : std::string{};
}

using bio_ptr = socle::raw::var<BIO*>;

inline std::string bio_text(BIO* bio) {
    if(!bio) return {};
    char* bytes = nullptr;
    auto size = BIO_get_mem_data(bio, &bytes);
    return size > 0 ? std::string(bytes, static_cast<size_t>(size)) : std::string{};
}

// Public certificate only; the returned PEM never includes a private key.
inline std::string certificate_pem(X509 const* certificate) {
    if(!certificate) return {};
    bio_ptr output(BIO_new(BIO_s_mem()), BIO_free);
    if(!output.value || PEM_write_bio_X509(output.value, certificate) != 1) return {};
    return bio_text(output.value);
}

// Unbounded diagnostic rendering, unlike the legacy fixed-buffer overloads.
inline std::string time_text_full(ASN1_TIME const* value) {
    if(!value) return {};
    bio_ptr output(BIO_new(BIO_s_mem()), BIO_free);
    if(!output.value || ASN1_TIME_print(output.value, value) != 1) return {};
    return bio_text(output.value);
}

// The buffer size is explicit so legacy callers retain their truncation policy.
inline std::string common_name(X509_NAME const* name, size_t buffer_size = 512) {
    if(!name || buffer_size < 2 || buffer_size > static_cast<size_t>(INT_MAX)) return {};
    std::vector<char> value(buffer_size, 0);
    return X509_NAME_get_text_by_NID(name, NID_commonName, value.data(),
                                    static_cast<int>(buffer_size - 1)) < 0
           ? std::string{} : std::string(value.data());
}

inline std::string name_oneline(X509_NAME const* name, size_t buffer_size = 512) {
    if(!name || buffer_size < 2 || buffer_size > static_cast<size_t>(INT_MAX)) return {};
    std::vector<char> value(buffer_size, 0);
    return X509_NAME_oneline(name, value.data(), static_cast<int>(buffer_size - 1))
           ? std::string(value.data()) : std::string{};
}

inline std::string distinguished_name(X509_NAME const* name) {
    if(!name) return {};
    bio_ptr output(BIO_new(BIO_s_mem()), BIO_free);
    if(!output.value || X509_NAME_print_ex(output.value, name, 0, XN_FLAG_RFC2253) < 0) return {};
    return bio_text(output.value);
}

inline bool time_text(ASN1_TIME const* value, char* output, size_t size) {
    if(!value || !output || size == 0 || size > static_cast<size_t>(INT_MAX)) return false;
    output[0] = '\0';
    bio_ptr bio(BIO_new(BIO_s_mem()), BIO_free);
    return bio.value && ASN1_TIME_print(bio.value, value) > 0 &&
           BIO_gets(bio.value, output, static_cast<int>(size)) > 0;
}

inline std::string time_text(ASN1_TIME const* value, size_t buffer_size = 512) {
    if(buffer_size < 2 || buffer_size > static_cast<size_t>(INT_MAX)) return {};
    std::vector<char> output(buffer_size, 0);
    return time_text(value, output.data(), buffer_size - 1) ? std::string(output.data()) : std::string{};
}

inline std::string time_iso8601(ASN1_TIME const* value) {
    std::tm utc{};
    if(!value || ASN1_TIME_to_tm(value, &utc) != 1) return {};
    std::array<char, 32> text{};
    if(std::strftime(text.data(), text.size(), "%Y-%m-%dT%H:%M:%SZ", &utc) == 0) return {};
    return text.data();
}

enum class hex_case { lower, upper };

inline std::string hex_encode(unsigned char const* bytes, size_t size,
                              hex_case casing = hex_case::lower) {
    auto const* hex = casing == hex_case::upper ? "0123456789ABCDEF" : "0123456789abcdef";
    std::string result;
    result.reserve(size * 2);
    for(size_t i = 0; i < size; ++i) {
        result += hex[bytes[i] >> 4];
        result += hex[bytes[i] & 15];
    }
    return result;
}

// Empty input is valid. The caller decides whether its domain allows it.
inline std::optional<std::string> sha256(std::string_view input) {
    socle::raw::var<EVP_MD_CTX*> context(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    if(!context.value) return std::nullopt;
    std::array<unsigned char, EVP_MAX_MD_SIZE> digest{};
    unsigned size = 0;
    if(EVP_DigestInit_ex(context.value, EVP_sha256(), nullptr) != 1 ||
       EVP_DigestUpdate(context.value, input.data(), input.size()) != 1 ||
       EVP_DigestFinal_ex(context.value, digest.data(), &size) != 1) return std::nullopt;
    return hex_encode(digest.data(), size);
}

inline std::optional<std::string> random_hex(size_t bytes) {
    if(bytes == 0 || bytes > static_cast<size_t>(INT_MAX)) return std::nullopt;
    std::vector<unsigned char> random(bytes);
    if(RAND_bytes(random.data(), static_cast<int>(random.size())) != 1) return std::nullopt;
    return hex_encode(random.data(), random.size());
}

inline std::string fingerprint(X509 const* certificate, EVP_MD const* algorithm,
                               hex_case casing = hex_case::lower) {
    if(!certificate || !algorithm) return {};
    std::array<unsigned char, EVP_MAX_MD_SIZE> digest{};
    unsigned size = 0;
    if(X509_digest(certificate, algorithm, digest.data(), &size) != 1) return {};
    return hex_encode(digest.data(), size, casing);
}

inline std::string serial_hex(X509 const* certificate) {
    if(!certificate) return {};
    socle::raw::var<BIGNUM*> serial(
        ASN1_INTEGER_to_BN(X509_get0_serialNumber(certificate), nullptr), BN_free);
    if(!serial.value) return {};
    auto free_hex = [](char* value) { OPENSSL_free(value); };
    socle::raw::var<char*> hex(BN_bn2hex(serial.value), free_hex);
    return hex.value ? std::string(hex.value) : std::string{};
}

struct public_key_info {
    std::string algorithm;
    int bits = 0;
    bool present = false;
};

inline public_key_info public_key(X509 const* certificate) {
    auto* key = certificate ? X509_get0_pubkey(certificate) : nullptr;
    if(!key) return {};
    auto const* algorithm = OBJ_nid2sn(EVP_PKEY_base_id(key));
    return {algorithm ? algorithm : "unknown", EVP_PKEY_bits(key), true};
}

enum class alternative_name_type { dns, ip };
struct alternative_name {
    alternative_name_type type;
    std::string value;
};
struct alternative_names_result {
    std::vector<alternative_name> names;
    bool present = false;
    bool truncated = false;
};
struct alternative_names_options {
    size_t maximum_names = std::numeric_limits<size_t>::max();
    bool ascii_dns_only = false;
    bool reject_duplicate_extensions = false;
};

// Preserve certificate order. Limits apply to inspected GENERAL_NAME entries,
// including unsupported types, not just the number of exported DNS/IP names.
inline alternative_names_result alternative_names(
        X509 const* certificate, alternative_names_options options = {}) {
    alternative_names_result result;
    if(!certificate) return result;
    if(options.reject_duplicate_extensions) {
        auto first = X509_get_ext_by_NID(certificate, NID_subject_alt_name, -1);
        if(first >= 0 && X509_get_ext_by_NID(certificate, NID_subject_alt_name, first) >= 0)
            return result;
    }
    auto const* extensions = X509_get0_extensions(certificate);
    size_t inspected = 0;
    for(int e = 0; e < sk_X509_EXTENSION_num(extensions); ++e) {
        auto* extension = sk_X509_EXTENSION_value(extensions, e);
        if(!extension || OBJ_obj2nid(X509_EXTENSION_get_object(extension)) != NID_subject_alt_name) continue;
        socle::raw::var<GENERAL_NAMES*> names(
            static_cast<GENERAL_NAMES*>(X509V3_EXT_d2i(extension)), GENERAL_NAMES_free);
        if(!names.value) continue;
        result.present = true;
        for(int i = 0; i < sk_GENERAL_NAME_num(names.value); ++i) {
            if(inspected++ >= options.maximum_names) {
                result.truncated = true;
                return result;
            }
            auto const* name = sk_GENERAL_NAME_value(names.value, i);
            if(!name) continue;
            if(name->type == GEN_DNS) {
                auto const* value = name->d.dNSName;
                if(!value) continue;
                auto size = ASN1_STRING_length(value);
                auto const* bytes = ASN1_STRING_get0_data(value);
                bool valid = bytes && size > 0;
                for(int j = 0; valid && j < size; ++j)
                    valid = bytes[j] != 0 && (!options.ascii_dns_only || bytes[j] < 128);
                if(valid) result.names.push_back({alternative_name_type::dns,
                    std::string(reinterpret_cast<char const*>(bytes), size)});
            } else if(name->type == GEN_IPADD) {
                auto const* value = name->d.iPAddress;
                if(!value) continue;
                auto size = ASN1_STRING_length(value);
                auto const* bytes = ASN1_STRING_get0_data(value);
                if(!bytes || (size != 4 && size != 16)) continue;
                std::array<char, INET6_ADDRSTRLEN> address{};
                if(inet_ntop(size == 4 ? AF_INET : AF_INET6, bytes, address.data(), address.size()))
                    result.names.push_back({alternative_name_type::ip, address.data()});
            }
        }
    }
    return result;
}

inline std::string signature_algorithm(X509 const* certificate) {
    if(!certificate) return {};
    auto const* algorithm = OBJ_nid2ln(X509_get_signature_type(certificate));
    return algorithm ? algorithm : "";
}

// Report allocation failure separately for legacy diagnostic callers.
inline bool extensions_text(X509 const* certificate, std::string& text, int indent = 0) {
    text.clear();
    if(!certificate) return false;
    bio_ptr output(BIO_new(BIO_s_mem()), BIO_free);
    if(!output.value) return false;
    X509V3_extensions_print(output.value, nullptr, X509_get0_extensions(certificate), 0, indent);
    text = bio_text(output.value);
    return true;
}

inline std::string extensions_text(X509 const* certificate) {
    std::string text;
    extensions_text(certificate, text);
    return text;
}

} // namespace socle::ossl
