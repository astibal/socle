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

class SSLFactory {

public:
    typedef std::pair<EVP_PKEY*,X509*> X509_PAIR;
    typedef std::map<std::string,X509_PAIR*> X509_CACHE;
    typedef std::map<std::string,std::string> FQDN_CACHE;

    typedef expiring_int expiring_ocsp_result;
    typedef expiring_ptr<crl_holder> expiring_crl;


    static expiring_ocsp_result* make_expiring_ocsp(bool result)
                                { return new SSLFactory::expiring_ocsp_result(result, ssl_ocsp_status_ttl); };

    static expiring_crl* make_expiring_crl(X509_CRL* crl)
                                { return new SSLFactory::expiring_crl(new crl_holder(crl), ssl_crl_status_ttl); }


private:
    
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

    // default path for CA trust-store. It's marked as CL, since CL side will use it (sx -> real server)
    static std::string def_cl_capath;

    // path for smithproxy own PKI authority and certificates
    static std::string certs_path;
    static std::string certs_password;

    static unsigned long def_cl_options;
    static unsigned long def_sr_options;

    static int password_callback(char* buf, int size, int rwflag, void*u);
private:

    bool load_ca_cert();
    bool load_def_cl_cert();
    bool load_def_sr_cert();
    
    X509_CACHE cache_;
    X509_STORE* trust_store_ = nullptr;

    std::recursive_mutex mutex_cache_write_;


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
    static SSLFactory& init();

    SSL_CTX* client_ctx_setup(EVP_PKEY* priv = nullptr, X509* cert = nullptr, const char* ciphers = nullptr);
    SSL_CTX* server_ctx_setup(EVP_PKEY* priv = nullptr, X509* cert = nullptr, const char* ciphers = nullptr);
    SSL_CTX* client_dtls_ctx_setup(EVP_PKEY* priv = nullptr, X509* cert = nullptr, const char* ciphers = nullptr);
    SSL_CTX* server_dtls_ctx_setup(EVP_PKEY* priv = nullptr, X509* cert = nullptr, const char* ciphers = nullptr);

    // load certs, initialize stores and cache structures (all you need to use this Factory)
    bool load();

    //always use locking when using this class!
    std::recursive_mutex& lock() { return mutex_cache_write_; };


    // get spoofed certificate cache, based on cert's subject
    X509_CACHE& cache() { return cache_; };
    // trusted CA store
    X509_STORE* trust_store() { return trust_store_; };

    [[nodiscard]] inline SSL_CTX* default_tls_server_cx() const  { return def_sr_ctx; }
    [[nodiscard]] inline SSL_CTX* default_tls_client_cx() const  { return def_cl_ctx; }
    [[nodiscard]] inline SSL_CTX* default_dtls_server_cx() const  { return def_dtls_sr_ctx; }
    [[nodiscard]] inline SSL_CTX* default_dtls_client_cx() const  { return def_dtls_cl_ctx; }

    static std::string& default_client_ca_path() { return def_cl_capath; }
    static std::string& default_cert_path() { return certs_path; }
    static std::string& default_cert_password() { return certs_password; }

    // our killer feature here
    SSLFactory::X509_PAIR* spoof(X509* cert_orig, bool self_sign=false, std::vector<std::string>* additional_sans=nullptr);
     
    static int convert_ASN1TIME(ASN1_TIME*, char*, size_t);
    static std::string print_cert(X509* cert, int indent=4);
    static std::string print_cn(X509*);
    static std::string print_issuer(X509* x);
    static std::string print_not_after(X509* x);
    static std::string print_not_before(X509* x);
    static std::vector<std::string> get_sans(X509* x);
    static std::string get_sans_csv(X509* x);
    static std::string fingerprint(X509 *cert);
    static std::string print_ASN1_OCTET_STRING(ASN1_OCTET_STRING*);


    static std::string make_store_key(X509* cert_orig, const SpoofOptions& spo);

    bool add(std::string& store_key, EVP_PKEY* cert_privkey,X509* cert,X509_REQ* req=nullptr);
    bool add(std::string& store_key, X509_PAIR* p,X509_REQ* req=nullptr);
     
    SSLFactory::X509_PAIR*  find(std::string& subject);
    std::string find_subject_by_fqdn(std::string& fqdn);
    void erase(std::string& subject);
     

    // static members must be public
    static int ssl_ocsp_status_ttl;
    static int ssl_crl_status_ttl;
    static ptr_cache<std::string,expiring_ocsp_result> ocsp_result_cache;
    static ptr_cache<std::string,expiring_crl> crl_cache;
    static ptr_cache<std::string,session_holder> session_cache;

    void destroy();
    virtual ~SSLFactory();

    static logan_lite& get_log() {
        static logan_lite l = logan_lite("pki.store");
        return l;
    }
};

#endif //__SSLCERTSTORE_HPP__