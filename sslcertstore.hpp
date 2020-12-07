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

#include <regex>
#include <thread>
#include <string>

/* define HOME to be dir for key and cert files... */
#define HOME "./certs/"
/* Make these what you want for cert & key files */
#define CL_CERTF  "cl-cert.pem"
#define CL_KEYF   "cl-key.pem"
#define SR_CERTF  "srv-cert.pem"
#define SR_KEYF   "srv-key.pem"

#define CA_CERTF  "ca-cert.pem"
#define CA_KEYF   "ca-key.pem"


#define SSLCERTSTORE_BUFSIZE 512

struct session_holder;

struct crl_holder {
    X509_CRL* ptr = nullptr;
    explicit crl_holder(X509_CRL* c): ptr(c) {};
    virtual ~crl_holder() { if(ptr) X509_CRL_free(ptr); }
};

struct session_holder {
    SSL_SESSION* ptr = nullptr;
    explicit session_holder(SSL_SESSION* p): ptr(p) {};
    virtual ~session_holder() { if(ptr) SSL_SESSION_free(ptr); }
    
    uint32_t cnt_loaded = {0};
};

struct SpoofOptions;



#define CERTSTORE_CACHE_SIZE 500

using namespace inet::cert;

class SSLFactory {

public:

    template<class K, class V>
    using map_type = mp::map<K, V>;
    using X509_PAIR = std::pair<EVP_PKEY*,X509*> ;
    using X509_CACHE = map_type<std::string, X509_PAIR*>;

    using FQDN_CACHE = map_type<std::string, std::string>;

    using expiring_verify_result = expiring<VerifyStatus>;
    using expiring_crl = expiring_ptr<crl_holder>;


    static expiring_verify_result* make_exp_ocsp_status(int result, int ttl)
            { return new expiring_verify_result(VerifyStatus(result, ttl, VerifyStatus::status_origin::OCSP), ttl); };
    static expiring_verify_result* make_exp_crl_status(int result, int ttl)
            { return new expiring_verify_result(VerifyStatus(result, ttl, VerifyStatus::status_origin::CRL), ttl); };


    static expiring_crl* make_expiring_crl(X509_CRL* crl)
                                { return new SSLFactory::expiring_crl(new crl_holder(crl), ssl_crl_status_ttl); }

    // default path for CA trust-store. It's marked as CL, since CL side will use it (sx -> real server)
    static std::string& ca_path() { static std::string ca_path; return ca_path; };

    // path for smithproxy own PKI authority and certificates
    static std::string& certs_path() { static std::string certs_path = "./certs/"; return certs_path; };
    static std::string& certs_password() { static std::string certs_password = "password"; return certs_password; };

    static std::string& ctlogfile() { static std::string ctl = "ct_log_list.cnf"; return ctl; };

    bool is_ct_available() const { return is_ct_available_; };
private:
    void is_ct_available(bool n) { is_ct_available_ = n; };
    bool is_ct_available_ = false;
    
    int       serial=0xCABA1A;
    
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

    static unsigned long def_cl_options;
    static unsigned long def_sr_options;

    [[maybe_unused]]
    static int password_callback(char* buf, int size, int rwflag, void*u);
private:

    bool load_ca_cert();
    bool load_def_cl_cert();
    bool load_def_sr_cert();

    std::regex re_hostname = std::regex("^[a-zA-Z0-9-]+\\.");

    X509_CACHE cache_;
    X509_STORE* trust_store_ = nullptr;

    mutable std::recursive_mutex mutex_cache_write_;

    SSLFactory(): verify_cache("verify cache", CERTSTORE_CACHE_SIZE, true) {
    }
public:
    // avoid having copies of SSLFactory
    SSLFactory(SSLFactory const&) = delete;
    void operator=(SSLFactory const&) = delete;
    static SSLFactory& factory() {
        static SSLFactory f;
        return f;
    }

    // creates static instance and calls load() and creates default values
    static SSLFactory& init();

    SSL_CTX* client_ctx_setup(EVP_PKEY* priv = nullptr, X509* cert = nullptr, const char* ciphers = nullptr);
    SSL_CTX* server_ctx_setup(EVP_PKEY* priv = nullptr, X509* cert = nullptr, const char* ciphers = nullptr);
    SSL_CTX* client_dtls_ctx_setup(EVP_PKEY* priv = nullptr, X509* cert = nullptr, const char* ciphers = nullptr);
    SSL_CTX* server_dtls_ctx_setup(EVP_PKEY* priv = nullptr, X509* cert = nullptr, const char* ciphers = nullptr);

    // load certs, initialize stores and cache structures (all you need to use this Factory)
    bool load();

    //always use locking when using this class!
    std::recursive_mutex& lock() const { return mutex_cache_write_; };


    // get spoofed certificate cache, based on cert's subject
    X509_CACHE& cache() { return cache_; };
    X509_CACHE const& cache() const { return cache_; };
    // trusted CA store
    X509_STORE* trust_store() { return trust_store_; };
    X509_STORE const* trust_store() const { return trust_store_; };

    [[nodiscard]] inline SSL_CTX* default_tls_server_cx() const  { return def_sr_ctx; }
    [[nodiscard]] inline SSL_CTX* default_tls_client_cx() const  { return def_cl_ctx; }
    [[nodiscard]] inline SSL_CTX* default_dtls_server_cx() const  { return def_dtls_sr_ctx; }
    [[nodiscard]] inline SSL_CTX* default_dtls_client_cx() const  { return def_dtls_cl_ctx; }


    // our killer feature here
    [[nodiscard]] // discarding result will leak memory
    SSLFactory::X509_PAIR* spoof(X509* cert_orig, bool self_sign=false, std::vector<std::string>* additional_sans=nullptr);
     
    static int convert_ASN1TIME(ASN1_TIME*, char*, size_t);
    static std::string print_cert(X509* cert, int indent=4);

    [[maybe_unused]] static std::string print_cn(X509*);
    [[maybe_unused]] static std::string print_issuer(X509* x);
    [[maybe_unused]] static std::string print_not_after(X509* x);
    [[maybe_unused]] static std::string print_not_before(X509* x);
    [[maybe_unused]] static std::vector<std::string> get_sans(X509* x);
    [[maybe_unused]] static std::string get_sans_csv(X509* x);
    [[maybe_unused]] static std::string fingerprint(X509 *cert);
    [[maybe_unused]] static std::string print_ASN1_OCTET_STRING(ASN1_OCTET_STRING*);


    static std::string make_store_key(X509* cert_orig, const SpoofOptions& spo);

    bool add(std::string& store_key, EVP_PKEY* cert_privkey,X509* cert,X509_REQ* req=nullptr);
    bool add(std::string& store_key, X509_PAIR* p,X509_REQ* req=nullptr);

    std::optional<SSLFactory::X509_PAIR*> find(std::string const& subject) const;
    std::optional<std::string> find_subject_by_fqdn(std::string const& fqdn) const;
    bool erase(const std::string &subject);
     

    // static members must be public
    static int ssl_ocsp_status_ttl;
    static int ssl_crl_status_ttl;

    ptr_cache<std::string,expiring_verify_result> verify_cache;

    static ptr_cache<std::string,expiring_crl> crl_cache;
    static ptr_cache<std::string,session_holder> session_cache;

    void destroy();
    virtual ~SSLFactory();

    static logan_lite& get_log() {
        static logan_lite l = logan_lite("pki.store");
        return l;
    }

    class CertParseException : public std::exception {};

    static std::vector<std::pair<std::string,std::string>> const& extensions() {

        static std::vector<std::pair<std::string,std::string>> r = {

            std::make_pair("basicConstraints", "CA:FALSE"),
            std::make_pair("nsComment", "\"Mitm generated certificate\""),
            std::make_pair("subjectKeyIdentifier", "hash"),
            std::make_pair("authorityKeyIdentifier", "keyid,issuer:always")
        };

        return r;
    }
};

#endif //__SSLCERTSTORE_HPP__