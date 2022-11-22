/*
    Socle - Socket Library Ecosystem
    Copyright (c) 2014, Ales Stibal <astib@mag0.net>, All rights reserved.

    This library  is free  software;  you can redistribute  it and/or
    modify  it  under   the  terms of the  GNU Lesser  General Public
    License  as published by  the   Free Software Foundation;  either
    version 3.0 of the License, or (at your option) any later version.
    This library is  distributed  in the hope that  it will be useful,
    but WITHOUT ANY WARRANTY;  without  even  the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. 
    
    See the GNU Lesser General Public License for more details.
    
    You  should have received a copy of the GNU Lesser General Public
    License along with this library.
*/

#ifndef __SSLCERTSTORE_HPP__
#define __SSLCERTSTORE_HPP__

#include <map>

#include <openssl/rsa.h>
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include <log/logger.hpp>
#include <ptr_cache.hpp>
#include <mpstd.hpp>
#include <sslcertval.hpp>
#include <socle_size.hpp>

#include <regex>
#include <thread>
#include <string>
#include <optional>

struct session_holder;

struct crl_holder {
    X509_CRL* ptr = nullptr;

    crl_holder(crl_holder const&) = delete;
    crl_holder& operator=(crl_holder const&) = delete;

    explicit crl_holder(X509_CRL* c): ptr(c) {};
    virtual ~crl_holder() { if(ptr) X509_CRL_free(ptr); }
};

struct session_holder {
    SSL_SESSION* ptr = nullptr;

    session_holder(session_holder const&) = delete;
    session_holder& operator=(session_holder const&) = delete;

    explicit session_holder(SSL_SESSION* p): ptr(p) {};
    virtual ~session_holder() { if(ptr) SSL_SESSION_free(ptr); }
    
    uint32_t cnt_loaded = {0};
};

struct SpoofOptions;

using namespace inet::cert;

class CertCacheEntry {
public:
    using X509_PAIR = std::pair<EVP_PKEY*,X509*>;

    explicit CertCacheEntry(X509_PAIR v) : value(std::move(v)) { };
    CertCacheEntry(CertCacheEntry const& v) = delete;
    CertCacheEntry& operator=(CertCacheEntry const& v) = delete;

    CertCacheEntry(CertCacheEntry && v) noexcept { assign(std::move(v)); }
    CertCacheEntry& operator=(CertCacheEntry && v) noexcept { assign(std::move(v)); return *this; };

    void assign(CertCacheEntry&& v) noexcept {
        reset();

        value = v.value;
        v.value = {nullptr, nullptr};
    }

    X509_PAIR release() noexcept {
        auto ret = value;
        value = {nullptr, nullptr};
        return ret;
    }

    inline void reset() noexcept {
        EVP_PKEY_free(value.first);
        X509_free(value.second);

        release();
    }

    ~CertCacheEntry() {
        reset();
    };

    [[nodiscard]] X509_PAIR const* keypair() const { return &value; }
    [[nodiscard]] EVP_PKEY const* key() const { return value.first; }
    [[nodiscard]] X509 const* cert() const { return value.second; }

private:
    X509_PAIR value;
};

struct SSLFactorySizing {
#ifdef BUILD_RELEASE
    constexpr static size_t cert_multi = 5;
    constexpr static size_t verify_multi = 3;
    constexpr static size_t session_multi = 2;
    constexpr static size_t crl_multi = 1;
#else
    constexpr static size_t cert_multi = 1;
    constexpr static size_t verify_multi = 1;
    constexpr static size_t session_multi = 1;
    constexpr static size_t crl_multi = 1;
#endif
};

class SSLFactory : public SSLFactorySizing {

public:

    struct config_t {
        constexpr static const char* CL_CERTF = "cl-cert.pem";
        constexpr static const char* CL_KEYF = "cl-key.pem";
        constexpr static const char* SR_CERTF = "srv-cert.pem";
        constexpr static const char* SR_KEYF = "srv-key.pem";

        constexpr static const char* CA_CERTF = "ca-cert.pem";
        constexpr static const char* CA_KEYF =  "ca-key.pem";

        std::string def_ca_cert_str;
        std::string def_ca_key_str;
        std::string def_sr_cert_str;
        std::string def_sr_key_str;
        std::string def_cl_cert_str;
        std::string def_cl_key_str;

        constexpr static size_t SSLCERTSTORE_BUFSIZE = 512;

        constexpr static size_t CERTSTORE_CACHE_SIZE = socle::size::base_table * cert_multi;
        constexpr static size_t VERIFY_CACHE_SIZE = socle::size::base_table * verify_multi;
        constexpr static size_t SESSION_CACHE_SIZE = socle::size::base_table * session_multi;
        constexpr static size_t CRL_CACHE_SIZE = socle::size::base_table * crl_multi;
    };

    SSLFactory::config_t config;

    using X509_PAIR = CertCacheEntry::X509_PAIR;
    using X509_CACHE = ptr_cache<std::string, CertCacheEntry>;

    using expiring_verify_result = expiring<VerifyStatus>;
    using expiring_crl = expiring_ptr<crl_holder>;


    static expiring_verify_result* make_exp_ocsp_status(int result, int ttl)
            { return new expiring_verify_result(VerifyStatus(result, ttl, VerifyStatus::status_origin::OCSP), ttl); };
    static expiring_verify_result* make_exp_crl_status(int result, int ttl)
            { return new expiring_verify_result(VerifyStatus(result, ttl, VerifyStatus::status_origin::CRL), ttl); };


    static expiring_crl* make_expiring_crl(X509_CRL* crl)
                                { return new SSLFactory::expiring_crl(new crl_holder(crl), ssl_crl_status_ttl); }

    // default path for CA trust-store. It's marked as CL, since CL side will use it (sx -> real server)
    std::string ca_path_;
    std::string& ca_path() { return ca_path_; };

    // path for smithproxy own PKI authority and certificates
    std::string certs_path_ = "./certs/";
    std::string& certs_path() {  return certs_path_; };

    std::string certs_password_ = "";
    std::string& certs_password() { return certs_password_; };

    std::string ctlog_ = "ct_log_list.cnf";
    std::string& ctlogfile() { return ctlog_; };

    bool is_ct_available() const { return is_ct_available_; };

private:
    void is_ct_available(bool n) { is_ct_available_ = n; };
    bool is_ct_available_ = false;
    
    long serial = 0xCABA1AL;
    
    X509*     ca_cert = nullptr; // ca certificate
    EVP_PKEY* ca_key = nullptr;  // ca key to self-sign 
    
    X509*     def_sr_cert = nullptr; // default server certificate
    EVP_PKEY* def_sr_key = nullptr;  // default server key
    SSL_CTX*  def_sr_ctx = nullptr;  // default server ctx
    SSL_CTX*  def_dtls_sr_ctx = nullptr;  // default server ctx for DTLS
    
    X509*     def_cl_cert = nullptr;  // default client certificate
    EVP_PKEY* def_cl_key = nullptr;   // default client key
    SSL_CTX*  def_cl_ctx = nullptr;   // default client ctx
    SSL_CTX*  def_dtls_cl_ctx = nullptr;   // default client ctx for DTLS

    static inline unsigned long def_cl_options = SSL_OP_NO_SSLv3+SSL_OP_NO_SSLv2;
    static inline unsigned long def_sr_options = SSL_OP_NO_SSLv3+SSL_OP_NO_SSLv2;

    bool load_ca_cert();
    bool load_def_cl_cert();
    bool load_def_sr_cert();

    std::regex re_hostname = std::regex("^[a-zA-Z0-9-]+\\.");

    X509_CACHE cert_cache_ = X509_CACHE("pki.cert", config_t::CERTSTORE_CACHE_SIZE, true);

    using verify_cache_t = ptr_cache<std::string,expiring_verify_result>;
    using crl_cache_t = ptr_cache<std::string,SSLFactory::expiring_crl>;
    using session_cache_t = ptr_cache<std::string,session_holder>;

    verify_cache_t verify_cache_ = verify_cache_t("pki.verify", config_t::VERIFY_CACHE_SIZE, true);
    crl_cache_t crl_cache_ = crl_cache_t("crl_cache", config_t::CRL_CACHE_SIZE,true);
    session_cache_t session_cache_ = session_cache_t("ssl_session_cache", config_t::SESSION_CACHE_SIZE,true, ptr_cache<std::string,session_holder>::mode_t::LRU);

    X509_STORE* trust_store_ = nullptr;

    mutable std::recursive_mutex mutex_cache_write_;

    SSLFactory() = default;

public:
    // avoid having copies of SSLFactory
    SSLFactory(SSLFactory const&) = delete;
    void operator=(SSLFactory const&) = delete;
    static SSLFactory& factory() {
        static SSLFactory f;
        return f;
    }

    // creates static instance and calls load() and creates default values
    SSLFactory& init();

    SSL_CTX* client_ctx_setup(const char* ciphers = nullptr);
    SSL_CTX* server_ctx_setup(EVP_PKEY* priv = nullptr, X509* cert = nullptr, const char* ciphers = nullptr);

    SSL_CTX* client_dtls_ctx_setup(const char* ciphers = nullptr);
    SSL_CTX* server_dtls_ctx_setup(EVP_PKEY* priv = nullptr, X509* cert = nullptr, const char* ciphers = nullptr);

    // load certs, initialize stores and cache structures (all you need to use this Factory)
    bool load();

    //always use locking when using this class!
    std::recursive_mutex& lock() const { return mutex_cache_write_; };
    std::atomic_bool is_initialized = false;


    // get spoofed certificate cache, based on cert's subject
    X509_CACHE& cache() { return cert_cache_; };
    X509_CACHE const& cache() const { return cert_cache_; };
    // trusted CA store
    X509_STORE* trust_store() { return trust_store_; };
    X509_STORE const* trust_store() const { return trust_store_; };

    verify_cache_t& verify_cache() { return verify_cache_; }
    verify_cache_t const& verify_cache() const { return verify_cache_; }

    crl_cache_t& crl_cache() { return crl_cache_; }
    crl_cache_t const& crl_cache() const { return crl_cache_; }

    session_cache_t& session_cache() { return session_cache_; }
    session_cache_t const& session_cache() const { return session_cache_; }


    [[nodiscard]] inline SSL_CTX* default_tls_server_cx() const  { return def_sr_ctx; }
    [[nodiscard]] inline SSL_CTX* default_tls_client_cx() const  { return def_cl_ctx; }
    [[nodiscard]] inline SSL_CTX* default_dtls_server_cx() const  { return def_dtls_sr_ctx; }
    [[nodiscard]] inline SSL_CTX* default_dtls_client_cx() const  { return def_dtls_cl_ctx; }


    // sign the CSR. CSR is consumed - if operation fails, CSR is destroyed.
    std::optional<X509_REQ*> sign_csr(X509_REQ*&& corpus) const;
    // create CSR from original certificate
    std::optional<X509_REQ*> create_csr_from(X509* cert_orig, bool self_sign=false, std::vector<std::string>* additional_sans=nullptr);

    // our killer feature here
    [[nodiscard]] // discarding result will leak memory
    std::optional<X509_PAIR> spoof(X509* cert_orig, bool self_sign=false, std::vector<std::string>* additional_sans=nullptr);
    bool validate_spoof_requirements(X509 const* cert, X509_NAME const* cert_name, X509_NAME const* issuer_name, EVP_PKEY const* pkey) const;
     
    static int convert_ASN1TIME(ASN1_TIME*, char*, size_t);
    static std::string print_cert(X509* cert, int indent=4, bool add_cr=false);

    [[maybe_unused]] static std::string print_cn(X509*);
    [[maybe_unused]] static std::string print_issuer(X509* x);
    [[maybe_unused]] static std::string print_not_after(X509* x);
    [[maybe_unused]] static std::string print_not_before(X509* x);
    [[maybe_unused]] static std::vector<std::string> get_sans(X509* x);
    [[maybe_unused]] static std::string get_sans_csv(X509* x);
    [[maybe_unused]] static std::string fingerprint(X509 *cert);
    [[maybe_unused]] static std::string print_ASN1_OCTET_STRING(ASN1_OCTET_STRING*);


    static std::string make_store_key(X509* cert_orig, const SpoofOptions& spo);

    bool add(std::string const& store_key, X509_PAIR parek);

    std::optional<const X509_PAIR> find(std::string const& subject);
    std::optional<std::string> find_subject_by_fqdn(std::string const& fqdn);
    bool erase(const std::string &subject);
     

    // static members must be public
    static inline int ssl_ocsp_status_ttl = 1800;
    static inline int ssl_crl_status_ttl = 86400;

    void destroy();
    virtual ~SSLFactory();

    static logan_lite& get_log() {
        static auto l = logan_lite("pki.store");
        return l;
    }
    using extensions_t = std::vector<std::pair<std::string,std::string>>;
    extensions_t const& extensions() const { return extensions_; }

private:
    extensions_t extensions_ {
            std::make_pair("basicConstraints", "CA:FALSE"),
            std::make_pair("nsComment", "\"Mitm generated certificate\""),
            std::make_pair("subjectKeyIdentifier", "hash"),
            std::make_pair("authorityKeyIdentifier", "keyid,issuer:always")
    };
};

#endif //__SSLCERTSTORE_HPP__