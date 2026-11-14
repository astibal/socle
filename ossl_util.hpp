#pragma once

#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <arpa/inet.h>
#include <array>
#include <ctime>
#include <climits>
#include <limits>
#include <memory>
#include <string>
#include <vector>

// Borrowed OpenSSL inputs; these helpers never take ownership of certificates.
// No JSON or proxy dependencies: presentation schemas belong to callers.
namespace socle::ossl {

using bio_ptr = std::unique_ptr<BIO, decltype(&BIO_free)>;

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
    if(!output || PEM_write_bio_X509(output.get(), certificate) != 1) return {};
    return bio_text(output.get());
}

// Unbounded diagnostic rendering, unlike the legacy fixed-buffer overloads.
inline std::string time_text_full(ASN1_TIME const* value) {
    if(!value) return {};
    bio_ptr output(BIO_new(BIO_s_mem()), BIO_free);
    if(!output || ASN1_TIME_print(output.get(), value) != 1) return {};
    return bio_text(output.get());
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
    if(!output || X509_NAME_print_ex(output.get(), name, 0, XN_FLAG_RFC2253) < 0) return {};
    return bio_text(output.get());
}

inline bool time_text(ASN1_TIME const* value, char* output, size_t size) {
    if(!value || !output || size == 0 || size > static_cast<size_t>(INT_MAX)) return false;
    output[0] = '\0';
    bio_ptr bio(BIO_new(BIO_s_mem()), BIO_free);
    return bio && ASN1_TIME_print(bio.get(), value) > 0 &&
           BIO_gets(bio.get(), output, static_cast<int>(size)) > 0;
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

inline std::string fingerprint(X509 const* certificate, EVP_MD const* algorithm,
                               hex_case casing = hex_case::lower) {
    if(!certificate || !algorithm) return {};
    std::array<unsigned char, EVP_MAX_MD_SIZE> digest{};
    unsigned size = 0;
    if(X509_digest(certificate, algorithm, digest.data(), &size) != 1) return {};
    auto const* hex = casing == hex_case::upper ? "0123456789ABCDEF" : "0123456789abcdef";
    std::string result;
    result.reserve(size * 2);
    for(unsigned i = 0; i < size; ++i) {
        result += hex[digest[i] >> 4];
        result += hex[digest[i] & 15];
    }
    return result;
}

inline std::string serial_hex(X509 const* certificate) {
    if(!certificate) return {};
    std::unique_ptr<BIGNUM, decltype(&BN_free)> serial(
        ASN1_INTEGER_to_BN(X509_get0_serialNumber(certificate), nullptr), BN_free);
    if(!serial) return {};
    auto free_hex = [](char* value) { OPENSSL_free(value); };
    std::unique_ptr<char, decltype(free_hex)> hex(BN_bn2hex(serial.get()), free_hex);
    return hex ? std::string(hex.get()) : std::string{};
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
        std::unique_ptr<GENERAL_NAMES, decltype(&GENERAL_NAMES_free)> names(
            static_cast<GENERAL_NAMES*>(X509V3_EXT_d2i(extension)), GENERAL_NAMES_free);
        if(!names) continue;
        result.present = true;
        for(int i = 0; i < sk_GENERAL_NAME_num(names.get()); ++i) {
            if(inspected++ >= options.maximum_names) {
                result.truncated = true;
                return result;
            }
            auto const* name = sk_GENERAL_NAME_value(names.get(), i);
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
    if(!output) return false;
    X509V3_extensions_print(output.get(), nullptr, X509_get0_extensions(certificate), 0, indent);
    text = bio_text(output.get());
    return true;
}

inline std::string extensions_text(X509 const* certificate) {
    std::string text;
    extensions_text(certificate, text);
    return text;
}

} // namespace socle::ossl
