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

#include <logger.hpp>
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

typedef std::pair<EVP_PKEY*,X509*> X509_PAIR;
typedef std::map<std::string,X509_PAIR*> X509_CACHE;
typedef std::map<std::string,std::string> FQDN_CACHE;

typedef expiring_int expiring_ocsp_result;
struct crl_holder;
typedef expiring_ptr<crl_holder> expiring_crl;

#define SSLCERTSTORE_BUFSIZE 512

struct session_holder;
typedef ptr_cache<std::string,session_holder> ssl_session_cache;

struct crl_holder {
    X509_CRL* ptr = nullptr;
    crl_holder(X509_CRL* c): ptr(c) {};
    virtual ~crl_holder() { if(ptr) X509_CRL_free(ptr); }
};

struct session_holder {
    SSL_SESSION* ptr = nullptr;
    session_holder(SSL_SESSION* p): ptr(p) {};
    virtual ~session_holder() { if(ptr) SSL_SESSION_free(ptr); }
    
    uint32_t cnt_loaded = {0};
};


class SSLCertStore {
   
public:
    
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

    static std::string def_cl_capath;
    
    static std::string certs_path;
    static std::string password;
    
    static int password_callback(char* buf, int size, int rwflag, void*u);
    
    static unsigned long def_cl_options;
    static unsigned long def_sr_options;
    
    bool load();
        bool load_ca_cert();
        bool load_def_cl_cert();
        bool load_def_sr_cert();
    
    void destroy();
    
     X509_CACHE cache_;
     X509_CACHE& cache() { return cache_; };
     
     FQDN_CACHE fqdn_cache_;
     FQDN_CACHE& fqdn_cache() { return fqdn_cache_; };
     
     static int ssl_ocsp_status_ttl;
     static int ssl_crl_status_ttl;
     static ptr_cache<std::string,expiring_ocsp_result> ocsp_result_cache;
     static ptr_cache<std::string,expiring_crl> crl_cache;
     static ptr_cache<std::string,session_holder> session_cache;
     
     std::mutex mutex_cache_write_;
     void lock() { mutex_cache_write_.lock(); };
     void unlock() { mutex_cache_write_.unlock(); }

     // our killer feature here 
     X509_PAIR* spoof(X509* cert_orig, bool self_sign=false, std::vector<std::string>* additional_sans=nullptr);
     
     static int convert_ASN1TIME(ASN1_TIME*, char*, size_t);
     static std::string print_cert(X509*);
     static std::string print_cn(X509*);
     static std::string print_issuer(X509* x);
     static std::string print_not_after(X509* x);
     static std::string print_not_before(X509* x);
     static std::vector<std::string> get_sans(X509* x);
     
     bool add(std::string& subject, EVP_PKEY* cert_privkey,X509* cert,X509_REQ* req=NULL);
     bool add(std::string& subject, X509_PAIR* p,X509_REQ* req=NULL);
     
     X509_PAIR*  find(std::string& subject);
     std::string find_subject_by_fqdn(std::string& fqdn);
     void erase(std::string& subject);
     
     virtual ~SSLCertStore();

public:
    static loglevel& log_level_ref() { return log_level; }
private:
    static loglevel log_level;
};

#endif //__SSLCERTSTORE_HPP__