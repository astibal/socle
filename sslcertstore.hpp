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

#include <thread>

/* define HOME to be dir for key and cert files... */
#define HOME "./certs/"
/* Make these what you want for cert & key files */
#define CL_CERTF  HOME "cl-cert.pem"
#define CL_KEYF   HOME "cl-key.pem"
#define SR_CERTF  HOME "srv-cert.pem"
#define SR_KEYF   HOME "srv-key.pem"

#define CA_CERTF  HOME "ca-cert.pem"
#define CA_KEYF  HOME "ca-key.pem"

typedef std::pair<EVP_PKEY*,X509*> X509_PAIR;
typedef std::map<std::string,X509_PAIR*> X509_CACHE;

class SSLCertStore {
public:
    int       serial=0xCABA1A;
    
    X509*     ca_cert; // ca certificate
    EVP_PKEY* ca_key;  // ca key to self-sign 
    
    X509*     def_sr_cert; // default server certificate
    EVP_PKEY* def_sr_key;  // default server key
    
    X509*     def_cl_cert;  // default client certificate
    EVP_PKEY* def_cl_key;   // default client key
    
    static int password_callback(char* buf, int size, int rwflag, void*u);
    
    bool load();
        bool load_ca_cert();
        bool load_def_cl_cert();
        bool load_def_sr_cert();
    
    void destroy();
    
     X509_CACHE cache_;
     std::mutex mutex_cache_write_;

     // our killer feature here 
     X509_PAIR* spoof(X509* cert);
     
     static int convert_ASN1TIME(ASN1_TIME*, char*, size_t);
     static std::string print_cert(X509*);
     
     bool add(std::string& subject, EVP_PKEY* cert_privkey,X509* cert,X509_REQ* req=NULL);
     bool add(std::string& subject, X509_PAIR* p,X509_REQ* req=NULL);
     
     X509_PAIR* find(std::string& subject);
     void erase(std::string& subject);

};




#endif //__SSLCERTSTORE_HPP__