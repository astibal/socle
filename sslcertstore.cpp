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

#include <cstdio>
#include <ctime>
#include <regex>

#include <display.hpp>
#include <sslcertstore.hpp>
#include <sslmitmcom.hpp>

#include <openssl/ssl.h>

std::string SSLCertStore::certs_path = "./certs/";
std::string SSLCertStore::certs_password = "password";
std::string SSLCertStore::def_cl_capath;

#define CERTSTORE_CACHE_SIZE 500

int SSLCertStore::ssl_crl_status_ttl  = 86400;
int SSLCertStore::ssl_ocsp_status_ttl = 1800;
ptr_cache<std::string,expiring_ocsp_result> SSLCertStore::ocsp_result_cache("ocsp response cache",CERTSTORE_CACHE_SIZE,true);
ptr_cache<std::string,expiring_crl> SSLCertStore::crl_cache("crl cache",CERTSTORE_CACHE_SIZE,true);
ptr_cache<std::string,session_holder> SSLCertStore::session_cache("ssl session cache",CERTSTORE_CACHE_SIZE,true);

loglevel SSLCertStore::log_level = NON;

unsigned long SSLCertStore::def_cl_options = SSL_OP_NO_SSLv3+SSL_OP_NO_SSLv2;
unsigned long SSLCertStore::def_sr_options = SSL_OP_NO_SSLv3+SSL_OP_NO_SSLv2;

bool SSLCertStore::load() {
    bool ret = true;
    
    OpenSSL_add_all_algorithms();
    
    serial=time(NULL);
    
    load_ca_cert();
    load_def_cl_cert();
    load_def_sr_cert();
    
    // final check
    if (ca_cert == NULL || ca_key == NULL 
        || def_cl_cert == NULL || def_cl_key == NULL 
        || def_sr_cert == NULL || def_sr_key == NULL) {
        DIA__("SSLCertStore::load: key/certs: ca(%x/%x) def_cl(%x/%x) def_sr(%x/%x)", ca_key,ca_cert,  
             def_cl_key,def_cl_cert,  def_sr_key,def_sr_cert);
        
        destroy();
        return false;
    }

    // initialize trust store
    if(trust_store_) {
        X509_STORE_free(trust_store_);
    }
    trust_store_ = X509_STORE_new();
    if(X509_STORE_load_locations(trust_store_, nullptr, def_cl_capath.c_str()) == 0)  {
        ERRS__("cannot load trusted store.");
    }

    ocsp_result_cache.clear();
    ocsp_result_cache.expiration_check(expiring_ocsp_result::is_expired);
    
    return ret;
}

int SSLCertStore::password_callback(char* buf, int size, int rwflag, void* u) {
    const char* pw = "pwd";
    const int len = strlen(pw);
    memcpy(buf,pw,len);
    
    return 0;
}


bool SSLCertStore::load_ca_cert() {
    std::string cer = certs_path + CA_CERTF;

    FILE *fp_crt = fopen(cer.c_str(), "r");
    FILE *fp_key = nullptr;
    
    if (!fp_crt) {
        FAT__("SSLCertStore::load_ca_cert: unable to open: %s",cer.c_str());
        return false;
    }
    
    std::string key = certs_path + CA_KEYF;
    fp_key = fopen(key.c_str(), "r");
    
    if (!fp_key) {
        FAT__("SSLCertStore::load_ca_cert: unable to open: %s",key.c_str());

        fclose(fp_crt);
        return false;
    }
    

    if(ca_cert) {
        X509_free(ca_cert);
    }
    if(ca_key) {
        EVP_PKEY_free(ca_key);
    }

    ca_cert = PEM_read_X509(fp_crt, NULL, NULL, NULL);  
    ca_key = PEM_read_PrivateKey(fp_key,NULL, NULL, (void*)certs_password.c_str());
    
    fclose(fp_crt);
    fclose(fp_key);
    
    return true;
}

bool SSLCertStore::load_def_cl_cert() {
    
    std::string cer = certs_path + CL_CERTF;
    
    FILE *fp_crt = fopen(cer.c_str(), "r");
    FILE *fp_key = nullptr;
    
    if (!fp_crt) {
        FAT__("SSLCertStore::load_def_cl_cert: unable to open: %s",cer.c_str());
        return false;
    }
    
    std::string key = certs_path + CL_KEYF; 
    fp_key = fopen(key.c_str(), "r");
    
    if (!fp_key) {
        FAT__("SSLCertStore::load_def_cl_cert: unable to open: %s",key.c_str());
        fclose(fp_crt);
        return false;
    }
    
    
    def_cl_cert = PEM_read_X509(fp_crt, NULL, NULL, NULL);  
    def_cl_key = PEM_read_PrivateKey(fp_key,NULL, NULL, NULL);
    
    fclose(fp_crt);
    fclose(fp_key);
    
    return true;
}

bool SSLCertStore::load_def_sr_cert() {
    
    std::string cer = certs_path + SR_CERTF;
    
    FILE *fp_crt = fopen(cer.c_str(), "r");
    FILE *fp_key = nullptr;
    
    if (!fp_crt) {
        FAT__("SSLCertStore::load_def_sr_cert: unable to open: %s",cer.c_str());
        return false;
    }
    
    std::string key = certs_path + SR_KEYF;
    fp_key = fopen(key.c_str(), "r");
    
    if (!fp_key) {
        FAT__("SSLCertStore::load_def_sr_cert: unable to open: %s",key.c_str());
        fclose(fp_crt);
        return false;
    }
    
    
    def_sr_cert = PEM_read_X509(fp_crt, NULL, NULL, NULL);  
    def_sr_key = PEM_read_PrivateKey(fp_key,NULL, NULL, NULL);
    
    fclose(fp_crt);
    fclose(fp_key);
    
    return true;
}


SSL_CTX* SSLCertStore::client_ctx_setup(EVP_PKEY* priv, X509* cert, const char* ciphers) {
//SSL_CTX* SSLCom::client_ctx_setup() {

    // SSLv3 -> latest TLS
    const SSL_METHOD *method = SSLv23_client_method();

    SSL_CTX* ctx = SSL_CTX_new (method);

    if (!ctx) {
        ERRS__("SSLCom::client_ctx_setup: Error creating SSL context!");
        //log_if_error(ERR,"SSLCom::init_client");
        exit(2);
    }

    ciphers == nullptr ? SSL_CTX_set_cipher_list(ctx,"ALL:!ADH:!LOW:!aNULL:!EXP:!MD5:@STRENGTH") : SSL_CTX_set_cipher_list(ctx,ciphers);

    // testing for LogJam:
    // SSL_CTX_set_cipher_list(ctx,"kEECDH kEECDH kEDH HIGH !kRSA !RC4 !aNULL !eNULL !LOW !3DES !MD5 !EXP !DSS !PSK !SRP !kECDH !CAMELLIA !IDEA !SEED");
    SSL_CTX_set_options(ctx, def_cl_options); //used to be also SSL_OP_NO_TICKET+
    SSL_CTX_set_session_cache_mode(ctx,SSL_SESS_CACHE_CLIENT);



//     DIAS__("SSLCom::client_ctx_setup: loading default key/cert");
//     priv == nullptr ? SSL_CTX_use_PrivateKey(ctx,certstore()->def_cl_key) : SSL_CTX_use_PrivateKey(ctx,priv);
//     cert == nullptr ? SSL_CTX_use_certificate(ctx,certstore()->def_cl_cert) : SSL_CTX_use_certificate(ctx,cert);
//
//     if (!SSL_CTX_check_private_key(ctx)) {
//         ERRS__("SSLCom::client_ctx_setup: Private key does not match the certificate public key\n");
//         exit(5);
//     }

    return ctx;
}

SSL_CTX* SSLCertStore::client_dtls_ctx_setup(EVP_PKEY* priv, X509* cert, const char* ciphers) {
//SSL_CTX* SSLCom::client_ctx_setup() {

    // SSLv3 -> latest TLS
#ifdef USE_OPENSSL11
    const SSL_METHOD *method = DTLS_client_method();
#else
    const SSL_METHOD *method = DTLSv1_client_method();
#endif

    SSL_CTX* ctx = SSL_CTX_new (method);

    if (!ctx) {
        ERRS__("SSLCom::client_ctx_setup: Error creating SSL context!");
        //log_if_error(ERR,"SSLCom::init_client");
        exit(2);
    }

    ciphers == nullptr ? SSL_CTX_set_cipher_list(ctx,"ALL:!ADH:!LOW:!aNULL:!EXP:!MD5:@STRENGTH") : SSL_CTX_set_cipher_list(ctx,ciphers);

    // testing for LogJam:
    // SSL_CTX_set_cipher_list(ctx,"kEECDH kEECDH kEDH HIGH !kRSA !RC4 !aNULL !eNULL !LOW !3DES !MD5 !EXP !DSS !PSK !SRP !kECDH !CAMELLIA !IDEA !SEED");
    // SSL_CTX_set_options(ctx,certstore()->def_cl_options); //used to be also SSL_OP_NO_TICKET+
    SSL_CTX_set_session_cache_mode(ctx,SSL_SESS_CACHE_CLIENT);



//     DIAS__("SSLCom::client_ctx_setup: loading default key/cert");
//     priv == nullptr ? SSL_CTX_use_PrivateKey(ctx,certstore()->def_cl_key) : SSL_CTX_use_PrivateKey(ctx,priv);
//     cert == nullptr ? SSL_CTX_use_certificate(ctx,certstore()->def_cl_cert) : SSL_CTX_use_certificate(ctx,cert);
//
//     if (!SSL_CTX_check_private_key(ctx)) {
//         ERRS__("SSLCom::client_ctx_setup: Private key does not match the certificate public key\n");
//         exit(5);
//     }

    return ctx;
}

SSL_CTX* SSLCertStore::server_ctx_setup(EVP_PKEY* priv, X509* cert, const char* ciphers) {

    // SSLv3 -> latest TLS
    const SSL_METHOD *method = SSLv23_server_method();
    SSL_CTX* ctx = SSL_CTX_new (method);

    if (!ctx) {
        ERRS__("SSLCom::server_ctx_setup: Error creating SSL context!");
        exit(2);
    }

    ciphers == nullptr ? SSL_CTX_set_cipher_list(ctx,"ALL:!ADH:!LOW:!EXP:!MD5:@STRENGTH") : SSL_CTX_set_cipher_list(ctx,ciphers);
    SSL_CTX_set_options(ctx, def_sr_options);

    DEBS__("SSLCom::server_ctx_setup: loading default key/cert");
    priv == nullptr ? SSL_CTX_use_PrivateKey(ctx, def_sr_key) : SSL_CTX_use_PrivateKey(ctx,priv);
    cert == nullptr ? SSL_CTX_use_certificate(ctx, def_sr_cert) : SSL_CTX_use_certificate(ctx,cert);


    if (!SSL_CTX_check_private_key(ctx)) {
        ERRS__("SSLCom::server_ctx_setup: private key does not match the certificate public key\n");
        exit(5);
    }

    return ctx;
}


SSL_CTX* SSLCertStore::server_dtls_ctx_setup(EVP_PKEY* priv, X509* cert, const char* ciphers) {

    // DTLS method
#ifdef USE_OPENSSL11
    const SSL_METHOD *method = DTLS_server_method();
#else
    const SSL_METHOD *method = DTLSv1_server_method();
#endif
    SSL_CTX* ctx = SSL_CTX_new (method);

    if (!ctx) {
        ERRS__("SSLCom::server_dtls_ctx_setup: Error creating SSL context!");
        exit(2);
    }

    ciphers == nullptr ? SSL_CTX_set_cipher_list(ctx,"ALL:!ADH:!LOW:!EXP:!MD5:@STRENGTH") : SSL_CTX_set_cipher_list(ctx,ciphers);
    //SSL_CTX_set_options(ctx,certstore()->def_sr_options);

    DEBS__("SSLCom::server_dtls_ctx_setup: loading default key/cert");
    priv == nullptr ? SSL_CTX_use_PrivateKey(ctx, def_sr_key) : SSL_CTX_use_PrivateKey(ctx,priv);
    cert == nullptr ? SSL_CTX_use_certificate(ctx, def_sr_cert) : SSL_CTX_use_certificate(ctx,cert);


    if (!SSL_CTX_check_private_key(ctx)) {
        ERRS__("SSLCom::server_dtls_ctx_setup: private key does not match the certificate public key\n");
        exit(5);
    }

    return ctx;
}


SSLCertStore* SSLCertStore::create() {

    DIAS__("SSLCertStore::create: loading central certification store: start");

    SSLCertStore* fac = new SSLCertStore();
    bool ret = fac->load();

    if(! ret) {
        FATS__("SSLCertStore::create: failure loading certificates, bailing out.");
        exit(2);
    }

    fac->def_cl_ctx = fac->client_ctx_setup();
    fac->def_dtls_cl_ctx = fac->client_dtls_ctx_setup();

    DIAS__("SSLCertStore::create: default ssl client context: ok");

    if(fac->def_cl_capath.size() > 0) {
        int r = SSL_CTX_load_verify_locations(fac->def_cl_ctx, nullptr, def_cl_capath.c_str());
        DEB__("SSLCertStore::create: loading default certification store: %s", r > 0 ? "ok" : "failed");

        if(r <= 0) {
            ERR__("SSLCertStore::create: failed to load verify location: %d", r);
        }
    } else {
        WARS__("SSLCertStore::create: loading default certification store: path not set!");
    }


    fac->def_sr_ctx = fac->server_ctx_setup();
    fac->def_dtls_sr_ctx = fac->server_dtls_ctx_setup();

    DIAS__("SSLCertStore::create: default ssl server context: ok");

    return fac;
}


void SSLCertStore::destroy() {
    if(ca_cert != NULL) X509_free(ca_cert);
    if(ca_key != NULL) EVP_PKEY_free(ca_key);
    
    if(def_cl_cert != NULL) X509_free(def_cl_cert);
    if(def_cl_key != NULL) EVP_PKEY_free(def_cl_key);
    
    if(def_sr_cert != NULL) X509_free(def_sr_cert);
    if(def_sr_key != NULL) EVP_PKEY_free(def_sr_key);

    for (auto i = cache_.begin(); i != cache_.end(); ++i ) {
        std::string key = (*i).first;
        
        X509_PAIR* parek = (*i).second;
        
        DEB__("SSLCertStore::destroy cache: %s",key.c_str());
        EVP_PKEY_free(parek->first);
        
        X509* cert = parek->second;
//         STACK_OF(X509_EXTENSION) *exts = cert->cert_info->extensions;
//         sk_X509_EXTENSION_free(exts);

//        Causes some mysterious locks:
//        DEB__("SSLCertStore::destroy cache: %s - cert",key.c_str());
        X509_free(cert);
        delete parek;
    }
    
    cache_.clear();

    if(trust_store_) {
        X509_STORE_free(trust_store_);
        trust_store_ = nullptr;
    }
}

bool SSLCertStore::add(std::string& subject,EVP_PKEY* cert_privkey, X509* cert, X509_REQ* req) {

    X509_PAIR* parek = new X509_PAIR(cert_privkey,cert);
    
    if (cert_privkey == NULL || cert == NULL || parek == NULL) {
        DIA__("SSLCertStore::add[%x]: one of about to be stored components is NULL",this);
        return false;
    }
    
    return add(subject,parek,req);
}

bool SSLCertStore::add(std::string& subject,X509_PAIR* parek, X509_REQ* req) {


    bool op_status = true;
    
    try {
        // lock, don't mess with cache_, I will write into it now
        mutex_cache_write_.lock();

        // free underlying keypair
        if(cache().find(subject) != cache().end()) {
            DIA__("SSLCertStore::add[%x] keypair associated with subject '%s' already exists (freeing)",this,subject.c_str());
            auto keypair = cache()[subject];


            // if this is last usage of keypair components, we want to free them
            EVP_PKEY_free(keypair->first);
            X509_free(keypair->second);
        }

        cache()[subject] = parek;
        DIA__("SSLCertStore::add[%x] cert %s",this,subject.c_str());

    }
    catch (std::exception& e) {
        op_status = false;
        DIA__("SSLCertStore::add[%x] - exception caught: %s",this,e.what());
    }
    
    // now you can write too
    mutex_cache_write_.unlock();
    
    if(!op_status) {
        ERR__("Error to add certificate '%s' into memory cache!",subject.c_str());
        return false;
    }
    
    return true;
}

X509_PAIR* SSLCertStore::find(std::string& subject) {

    // cache lookup
    auto entry = cache().find(subject);
    if (entry == cache().end()) {
        DEB__("SSLCertStore::find[%x]: NOT cached '%s'",this,subject.c_str());
    } else {
        DEB__("SSLCertStore::find[%x]: found cached '%s'",this,subject.c_str());
        
        return (*entry).second;  //first is the map key (cert subject in our case)
    }    
    
    return NULL;
}

std::string SSLCertStore::find_subject_by_fqdn(std::string& fqdn) {
     auto entry = cache().find(fqdn);
     if (entry == cache().end()) {
        DEB__("SSLCertStore::find_subject_by_fqdn[%x]: NOT cached '%s'",this, fqdn.c_str());
     } else {
        DEB__("SSLCertStore::find_subject_by_fqdn[%x]: found cached '%s'",this,fqdn.c_str());
        return (*entry).first;
     }

     std::regex hostname_re("^[a-zA-Z0-9-]+\\.");
     std::string wildcard_fqdn = std::regex_replace(fqdn,hostname_re,"*.");
     
     entry = cache_.find(wildcard_fqdn);
     if (entry == cache_.end()) {
        DEB__("SSLCertStore::find_subject_by_fqdn[%x]: wildcard NOT cached '%s'",this, wildcard_fqdn.c_str());
     } else {
        DEB__("SSLCertStore::find_subject_by_fqdn[%x]: found cached wildcard '%s'",this,fqdn.c_str());
        return (*entry).first;
     }     
     
     
     return "";     
}

//don't call erase for now, it can delete cert/key while being used by different threads!!!
//FIXME: either duplicates should be returned, or each pair should contain some reference checking/delete flag to kill themselves

void SSLCertStore::erase(std::string& subject) {

    bool op_status = true;
    
    try {
        mutex_cache_write_.lock();
        
        X509_PAIR* p = find(subject);
        if(p) {
            EVP_PKEY_free(p->first);
            X509_free(p->second);
            cache_.erase(subject);
            
            delete p;
        }
        
        mutex_cache_write_.unlock();
    }
    catch(std::exception& e) {
        op_status = false;
        DIA__("SSLCertStore::add[x] - exception caught: %s",this,e.what());            
    }
    if(!op_status) {
        ERR__("Error to remove certificate '%s' from cache",subject.c_str());
    }
    
    
}

int add_ext(STACK_OF(X509_EXTENSION) *sk, int nid, char *value) {
  X509_EXTENSION *ex;
  ex = X509V3_EXT_conf_nid(NULL, NULL, nid, value);
  if (!ex)
    return 0;
  sk_X509_EXTENSION_push(sk, ex);
  return 1;
}

std::vector<std::string> SSLCertStore::get_sans(X509* x) {
    
    std::vector<std::string> ret;
    
    // Copy extensions
#ifdef USE_OPENSSL11
    const STACK_OF(X509_EXTENSION) *exts = X509_get0_extensions(x);
#else
    STACK_OF(X509_EXTENSION) *exts = x->cert_info->extensions;
#endif

    int num_of_exts;

    if (exts) {   
        num_of_exts = sk_X509_EXTENSION_num(exts);    
        if(num_of_exts > 0) {
            for (int i=0; i < num_of_exts; i++) {
                X509_EXTENSION *ex = sk_X509_EXTENSION_value(exts, i);
                if(!ex) {
                    ERR__("SSLCertStore::get_sans: error obtaining certificate extension [%d] value ",i)
                    continue;
                }
                ASN1_OBJECT *obj = X509_EXTENSION_get_object(ex);
                if(!obj) {
                    ERR__("SSLCertStore::get_sans: unable to extract ASN1 object from extension [%d]",i);
                    continue;
                }
                
                unsigned nid = OBJ_obj2nid(obj); 
                if(nid == NID_subject_alt_name) {
                    DEBS__("SSLCertStore::get_sans: adding subjAltName to extensions");
#ifdef USE_OPENSSL11

                    STACK_OF(GENERAL_NAME) *alt = (STACK_OF(GENERAL_NAME)*)X509V3_EXT_d2i(ex);
                    if(alt) {

                        int alt_len = sk_GENERAL_NAME_num(alt);
                        for (int i = 0; i < alt_len; i++) {
                            GENERAL_NAME *gn = sk_GENERAL_NAME_value(alt, i);

                            int name_type = 0;

                            // GENERAL_NAME_get0_value returns mostly ASN1STRING, with exceptions
                            // of othername and maybe others ...
                            // arg1 is original GENERAL_NAME, arg2 where to write type of returned name
                            // learned from: https://github.com/openssl/openssl/issues/8973

                            void* name_ptr = GENERAL_NAME_get0_value(gn, &name_type);
                            if(name_type == GEN_DNS) {
                                ASN1_STRING *dns_name = (ASN1_STRING *) name_ptr; //in ASN1 we trust

                                std::string san((const char *) ASN1_STRING_get0_data(dns_name),
                                                (unsigned long) ASN1_STRING_length(dns_name));
                                ret.push_back("DNS:"+san);

                                DEB__("SSLCertStore::get_sans: adding GEN_DNS: %s", san.c_str());
                            } else {
                              // pass ... # ehm
                            }

                        }
                    }
                    GENERAL_NAMES_free(alt);

#else
                    BIO *ext_bio = BIO_new(BIO_s_mem());
                    if (!X509V3_EXT_print(ext_bio, ex, 0, 0)) {
                        M_ASN1_OCTET_STRING_print(ext_bio, ex->value);
                    }
                    BUF_MEM *bptr;
                    BIO_get_mem_ptr(ext_bio, &bptr);
                    int sc = BIO_set_close(ext_bio, BIO_NOCLOSE);
                    
                    
                    std::string san(bptr->data,bptr->length);
                    BIO_free(ext_bio);
                    BUF_MEM_free(bptr);

                    ret.push_back(san);
#endif
                }
            }
        }
    }   
    
    return ret;
}

std::string SSLCertStore::get_sans_csv(X509 *x) {

    std::vector<std::string> sans_vec = SSLCertStore::get_sans(x);
    return string_csv(sans_vec);
}

X509_PAIR* SSLCertStore::spoof(X509* cert_orig, bool self_sign, std::vector<std::string>* additional_sans) {
    char tmp[2048];
    DEB__("SSLCertStore::spoof[%x]: about to spoof certificate!",this);
    
    if(self_sign) {
      DIA__("SSLCertStore::spoof[%x]: about to spoof certificate (self-signed)!",this);
    }
    if(additional_sans != nullptr && additional_sans->size() > 0) {
        DIA__("SSLCertStore::spoof[%x]: about to spoof certificate (+sans):",this);
        std::vector<std::string>& sans = *additional_sans;
        for (auto san: sans) {
            DIA__("SSLCertStore::spoof[%x]:  SAN: %s",this, san.c_str());
        }
    }
    
    // get info from the peer certificate
    X509_NAME_get_text_by_NID(X509_get_subject_name(cert_orig),NID_commonName, tmp,2048);
    std::string cn(tmp);
    
    X509_NAME_oneline(X509_get_subject_name(cert_orig), tmp, 2048);
    std::string subject(tmp);
          
    
    DEB__("SSLCertStore::spoof[%x]: generating CSR for '%s'",this,subject.c_str());    
        
    X509_REQ* copy = X509_REQ_new();
    X509_NAME* copy_subj = NULL;
    EVP_PKEY *pkey = def_sr_key;
    const EVP_MD *digest;

    
    if(!copy) {
        ERR__("SSLCertStore::spoof[%x]: cannot create request",this);
        return NULL;
    }
    
    EVP_PKEY* pub_sr_cert = X509_get_pubkey(def_sr_cert);
    X509_REQ_set_pubkey(copy,pub_sr_cert);
    EVP_PKEY_free(pub_sr_cert);

    if (!(copy_subj = X509_NAME_new())) {
        ERR__("SSLCertStore::spoof[%x]: cannot create subject for request",this);
        return NULL;
    }

    X509_NAME* n_dup = X509_NAME_dup(X509_get_subject_name(cert_orig));
    if (X509_REQ_set_subject_name(copy,n_dup) != 1) {
        ERR__("SSLCertStore::spoof[%x]: error copying subject to request",this);
        return NULL;
    }
    
    // Copy extensions
#ifdef USE_OPENSSL11
    const STACK_OF(X509_EXTENSION) *exts = X509_get0_extensions(cert_orig);
#else
    STACK_OF(X509_EXTENSION) *exts = cert_orig->cert_info->extensions;
#endif // USE_OPENSSL11

    int num_of_exts;

    
    // prepare additional SANs
    std::string san_add;
    if(additional_sans != nullptr) {
        std::vector<std::string>& as = *additional_sans;
        if(as.size() > 0) {
            san_add = string_csv(as);
            DIA__("SSLCertStore::spoof[%x]: additional sans = '%s'",this,san_add.c_str());
        }
    }    
    
    bool san_added = false;
    if (exts) {   
        STACK_OF(X509_EXTENSION) *s = sk_X509_EXTENSION_new_null();
        num_of_exts = sk_X509_EXTENSION_num(exts);    
        if(num_of_exts > 0) {
            for (int i=0; i < num_of_exts; i++) {
                X509_EXTENSION *ex = sk_X509_EXTENSION_value(exts, i);
                if(!ex) {
                    ERR__("SSLCertStore::spoof[%x]: error obtaining certificate extension [%d] value ",this,i)
                    continue;
                }
                ASN1_OBJECT *obj = X509_EXTENSION_get_object(ex);
                if(!obj) {
                    ERR__("SSLCertStore::spoof[%x]: unable to extract ASN1 object from extension [%d]",this,i);
                    continue;
                }
                
                unsigned nid = OBJ_obj2nid(obj); 
                if(nid == NID_subject_alt_name) {
                    DEB__("SSLCertStore::spoof[%x]: adding subjAltName to extensions",this);

#ifdef USE_OPENSSL11
                    // it's easier to get san list with different call, instead of diging it out from here.
                    std::string san = get_sans_csv(cert_orig);
                    DEB__("SSLCertStore::spoof[%x]: original cert sans to be added: %s",this, san.c_str());

#else

                    // get original SAN
                    BIO *ext_bio = BIO_new(BIO_s_mem());
                    if (!X509V3_EXT_print(ext_bio, ex, 0, 0)) {
                        M_ASN1_OCTET_STRING_print(ext_bio, ex->value);
                    }
                    BUF_MEM *bptr;
                    BIO_get_mem_ptr(ext_bio, &bptr);
                    int sc = BIO_set_close(ext_bio, BIO_NOCLOSE);
                    
                    
                    std::string san(bptr->data,bptr->length);
                    
                    BIO_free(ext_bio);
                    BUF_MEM_free(bptr);
#endif
                    
                    // we have SAN now in san string

                    if(! san_add.empty()) {
                        san += "," + san_add;
                    }
            
                    int a_r = add_ext(s,NID_subject_alt_name, (char*) san.c_str());
                    DEB__("SSLCertStore::spoof[%x]: add_ext returned %d",this,a_r);

                    san_added = true;
                }
            }
            

        }
        
        if(!san_added) {
            
            int a_r = add_ext(s,NID_subject_alt_name, (char*) san_add.c_str());
            DUM__("SSLCertStore::spoof[%x]: add_ext returned %d",this,a_r);
                        
        }
        
        int r = X509_REQ_add_extensions(copy,s);
        DUM__("SSLCertStore::spoof[%x]: X509_REQ_add_extensions returned %d",this,r);
        
        sk_X509_EXTENSION_pop_free(s,X509_EXTENSION_free);
    }

#ifdef USE_OPENSSL11
    // don't bother selecting digest alg, sha2-256 is well settled.
    // Selection can be further improved by checking signature mechanism in the real certificate,
    // but it's hardly worth it.
    digest = EVP_sha256();
#else
    // pick the correct digest and sign the request 
    if (EVP_PKEY_type(pkey->type) == EVP_PKEY_DSA) {
        digest = EVP_dss1();
    }
    else if (EVP_PKEY_type(pkey->type) == EVP_PKEY_RSA) {
        digest = EVP_sha256();
    }
    else if (EVP_PKEY_type(pkey->type) == EVP_PKEY_EC) {
        digest = EVP_sha256();
    }
    else {
        ERR__("SSLCertStore::spoof[%x]: error checking public key for a valid digest",this);
        return NULL;
    }
#endif //USE_OPENSSL11
    
    if (!(X509_REQ_sign( copy, pkey, digest))) {
        ERR__("SSLCertStore::spoof[%x]: error signing request",this);
    }
    
    DEB__("SSLCertStore::spoof[%x]: generating CSR finished",this);    

    //------------------------------------------------------------------------------------------

    DIA__("SSLCertStore::spoof[%x]: faking certificate '%s'",this,subject.c_str());     
    

    X509 *cert = NULL;
    X509_NAME *name = NULL;


    // create new certificate 
    if (!(cert = X509_new( ))) {
        ERR__("SSLCertStore::spoof[%x]: error creating X509 object",this);
        return NULL;
    }

    // set version number for the certificate (X509v3) and then serial #
    if (X509_set_version (cert, 2L) != 1) {
        ERR__("SSLCertStore::spoof[%x]: cannot set X509 version!",this);
        return NULL;
    }

    ASN1_INTEGER_set(X509_get_serialNumber(cert), serial++);
    
    // get public key from request
    if (!(pkey = X509_REQ_get_pubkey(copy))) {
        ERR__("SSLCertStore::spoof[%x]: error getting public key from request",this);
        return NULL;
    }

    // Setting subject name
    if (!(name = X509_REQ_get_subject_name(copy))) {
        ERR__("SSLCertStore::spoof[%x]: error getting subject name from request",this);
        return NULL;
    }
    if (X509_set_subject_name(cert, name) != 1) {
        ERR__("SSLCertStore::spoof[%x]: error setting subject name of certificate",this);
        return NULL;
    }     

    int subjAltName_pos = -1;
    X509_EXTENSION* subjAltName = NULL;
    
    STACK_OF(X509_EXTENSION) *req_exts = NULL;
    if (!(req_exts = X509_REQ_get_extensions(copy))) {
        INF__("SSLCertStore::spoof[%x]: error getting the request's extension",this);
    } else {
        subjAltName_pos = X509v3_get_ext_by_NID(req_exts,OBJ_sn2nid("subjectAltName"),-1);
        subjAltName = X509v3_get_ext(req_exts, subjAltName_pos);
    }

    
    // Setting issuer
    if (!(name = X509_get_subject_name(ca_cert))) {
        ERR__("SSLCertStore::spoof[%x]: error getting subject name from CA certificate",this);
        return NULL;
    }
    if (X509_set_issuer_name(cert, name) != 1) {
        ERR__("SSLCertStore::spoof[%x]: error setting issuer name of certificate",this);
        return NULL;
        
    }
    // set public key in the certificate 
    if ((X509_set_pubkey( cert, pkey)) != 1) {
        ERR__("SSLCertStore::spoof[%x]: error setting public key of the certificate",this);
        return NULL;
    }
    
    #define EXPIRE_START (-60*60*24)
    
    // set duration for the certificate
    if (!(X509_gmtime_adj(X509_get_notBefore(cert), EXPIRE_START))) {
        ERR__("SSLCertStore::spoof[%x]: error setting beginning time of the certificate",this);
        return NULL;
    }
    
    #define DAYS_TILL_EXPIRE 364
    #define EXPIRE_SECS (60* 60*24*DAYS_TILL_EXPIRE)

    if (!(X509_gmtime_adj(X509_get_notAfter(cert), EXPIRE_SECS))) {
        ERR__("SSLCertStore::spoof[%x]: error setting ending time of the certificate",this);
        return NULL;
    }

    X509V3_CTX ctx;

    
    // add x509v3 extensions as specified 
    X509V3_set_ctx(&ctx, ca_cert, cert, NULL, NULL, 0);
    for (int i = 0; i < EXT_COUNT; i++) {

        X509_EXTENSION * ext;
        if (!(ext = X509V3_EXT_conf(NULL, &ctx, ext_ent[i].key, ext_ent[i].value))) {
            WAR__("SSLCertStore::spoof[%x]: error on \"%s = %s\"",this,ext_ent[i].key, ext_ent[i].value);
            WAR__("SSLCertStore::spoof[%x]: error creating X509 extension object",this);
            continue;
        }
        if (!X509_add_ext(cert, ext, -1)) {
            ERR__("SSLCertStore::spoof[%x]: error on \"%s = %s\"",this,ext_ent[i].key, ext_ent[i].value);
            ERR__("SSLCertStore::spoof[%x]: error adding X509 extension into certificate",this);
        }
        X509_EXTENSION_free(ext);
    }
    
    if(subjAltName != NULL) {
        if (!X509_add_ext(cert, subjAltName, -1)) {
            ERR__("SSLCertStore::spoof[%x]: error adding subjectAltName to certificate",this);
            return NULL;
        }
    }
    
    EVP_PKEY* sign_key = ca_key;
    if(self_sign) {
      X509_set_issuer_name(cert, X509_get_subject_name(cert));
      sign_key = def_sr_key;
    }


#ifdef USE_OPENSSL11
    // same as few lines above. Don't really bother, and select sha2-256.
    digest = EVP_sha256();
#else
    // sign the certific ate with the CA private key 
    if (EVP_PKEY_type(sign_key->type) == EVP_PKEY_DSA) {
        digest = EVP_dss1();
    }
    else if (EVP_PKEY_type(sign_key->type) == EVP_PKEY_RSA ) {
        digest = EVP_sha256();
    }
    else if (EVP_PKEY_type(sign_key->type) == EVP_PKEY_EC) {
        digest = EVP_sha256();
    }
    else {
        ERR__("SSLCertStore::spoof[%x]: error checking CA private key for a valid digest",this);
        return NULL;
    }
#endif

    if (!(X509_sign(cert, sign_key, digest))) {
        ERR__("SSLCertStore::spoof[%x]: error signing certificate",this);
        return NULL;
    }

    EVP_PKEY_free(pkey);  
    X509_REQ_free(copy);  
    X509_NAME_free(n_dup);   
    X509_NAME_free(copy_subj);
    sk_X509_EXTENSION_pop_free(req_exts,X509_EXTENSION_free);

    
    auto parek = new X509_PAIR(def_sr_key,cert);
    return parek;    

}


int SSLCertStore::convert_ASN1TIME(ASN1_TIME *t, char* buf, size_t len) {
    int rc;
    BIO *b = BIO_new(BIO_s_mem());
    rc = ASN1_TIME_print(b, t);
    if (rc <= 0) {
        BIO_free(b);
        return EXIT_FAILURE;
    }
    rc = BIO_gets(b, buf, len);
    if (rc <= 0) {
        BIO_free(b);
        return EXIT_FAILURE;
    }
    BIO_free(b);
    return EXIT_SUCCESS;
}


std::string SSLCertStore::print_cn(X509* x) {
    char tmp[SSLCERTSTORE_BUFSIZE];
    std::string s;

    // get info from the peer certificate
    X509_NAME_get_text_by_NID(X509_get_subject_name(x),NID_commonName, tmp,SSLCERTSTORE_BUFSIZE-1);
    s.append(tmp);
    
    return s;
}

std::string SSLCertStore::print_issuer(X509* x) {
    char tmp[SSLCERTSTORE_BUFSIZE];
    std::string s;

    // get info from the peer certificate
    X509_NAME_get_text_by_NID(X509_get_issuer_name(x),NID_commonName, tmp,SSLCERTSTORE_BUFSIZE-1);
    s.append(tmp);
    
    return s;
}

std::string SSLCertStore::print_not_before(X509* x) {
    char tmp[SSLCERTSTORE_BUFSIZE];
    std::string s;
    ASN1_TIME *not_before = X509_get_notBefore(x);
    
    convert_ASN1TIME(not_before, tmp, SSLCERTSTORE_BUFSIZE-1); 
    s.append(tmp);
    
    return s;
}


std::string SSLCertStore::print_not_after(X509* x) {
    char tmp[SSLCERTSTORE_BUFSIZE];
    std::string s;
    ASN1_TIME *not_after = X509_get_notAfter(x);
    
    convert_ASN1TIME(not_after, tmp, SSLCERTSTORE_BUFSIZE-1); 
    s.append(tmp);
    
    return s;
}

std::string SSLCertStore::print_cert(X509* x) {
    char tmp[SSLCERTSTORE_BUFSIZE];
    std::string s;

    // get info from the peer certificate
    // TODO: should be replaced, as per https://linux.die.net/man/3/x509_name_get_text_by_nid - examples section
    X509_NAME_get_text_by_NID(X509_get_subject_name(x),NID_commonName, tmp,SSLCERTSTORE_BUFSIZE-1);
    s.append("Common Name: ");
    s.append(tmp);
    s.append("\n ");
    

    X509_NAME_oneline(X509_get_subject_name(x), tmp, SSLCERTSTORE_BUFSIZE-1);
    s.append("Subject: ");
    s.append(tmp);
    s.append("\n ");
    
    X509_NAME* issuer = X509_get_issuer_name(x);
    if(!issuer) {
    s.append("# Issuer: <unable to obtain issuer from certificate> \n ");
    } else {
        X509_NAME_oneline(issuer,tmp,SSLCERTSTORE_BUFSIZE-1);
        s.append(string_format("Issuer: '%s'\n ",tmp));
        s.append("\n ");
        
    }

#ifdef USE_OPENSSL11
    int pkey_nid = X509_get_signature_type(x);
#else
    int pkey_nid = OBJ_obj2nid(x->cert_info->key->algor->algorithm);
#endif
    const char* sslbuf = OBJ_nid2ln(pkey_nid);
    s.append("Signature type: ");
    s.append(sslbuf);
    s.append("\n ");

    ASN1_TIME *not_before = X509_get_notBefore(x);
    ASN1_TIME *not_after = X509_get_notAfter(x);            
    
    convert_ASN1TIME(not_before, tmp, SSLCERTSTORE_BUFSIZE-1);    
    s.append("Valid from: ");
    s.append(tmp);
    s.append("\n ");
    convert_ASN1TIME(not_after, tmp, SSLCERTSTORE_BUFSIZE-1);
    s.append("Valid to: ");
    s.append(tmp);
    s.append("\n ");


#ifdef USE_OPENSSL11
    const STACK_OF(X509_EXTENSION) *exts = X509_get0_extensions(x);

    BIO *ext_bio = BIO_new(BIO_s_mem());
    if (!ext_bio) {
        s.append(" ... unable to allocate BIO");
        return s;
    }

    X509V3_extensions_print(ext_bio, nullptr, exts, 0, 0);

    BUF_MEM *bptr = nullptr;
    BIO_get_mem_ptr(ext_bio, &bptr);
    int sc = BIO_set_close(ext_bio, BIO_CLOSE);

    s.append((const char*) bptr->data, bptr->length);

    BIO_free(ext_bio);

#else
    STACK_OF(X509_EXTENSION) *exts = x->cert_info->extensions;

    int num_of_exts = 0;
    if (exts) {
        num_of_exts = sk_X509_EXTENSION_num(exts);
        s.append("Extensions: ");
        s.append("\n ");

    } else {
        num_of_exts = 0;
        s.append(" Extensions: <no extenstions in the certificate> ");
        s.append("\n ");

    }

    for (int i=0; i < num_of_exts; i++) {
    
        X509_EXTENSION *ex = sk_X509_EXTENSION_value(exts, i);
        if(!ex) {
            s.append(string_format("# Extension[%d] unable to extract extension from stack\n ",i));
            continue;
        }

        ASN1_OBJECT *obj = X509_EXTENSION_get_object(ex);
        if(!obj) {
            s.append(string_format("# Extension[%d] unable to extract ASN1 object from extension\n ",i));
            continue;
        }
    
        BIO *ext_bio = BIO_new(BIO_s_mem());
        if (!ext_bio) {
            s.append(string_format("# Extension[%d] unable to allocate memory for extension value BIO\n ",i));
            continue;
        }
        else{
            if (!X509V3_EXT_print(ext_bio, ex, 0, 0)) {
                M_ASN1_OCTET_STRING_print(ext_bio, ex->value);
            }
        
#pragma GCC diagnostic ignored "-Wunused-value"
#pragma GCC diagnostic push

            BUF_MEM *bptr;
            BIO_get_mem_ptr(ext_bio, &bptr);
            int sc = BIO_set_close(ext_bio, BIO_CLOSE);
        
#pragma GCC diagnostic pop
            
            // remove newlines
            int lastchar = bptr->length;
            if (lastchar > 1 && (bptr->data[lastchar-1] == '\n' || bptr->data[lastchar-1] == '\r')) {
                bptr->data[lastchar-1] = (char) 0;
            }
            if (lastchar > 0 && (bptr->data[lastchar] == '\n' || bptr->data[lastchar] == '\r')) {
                bptr->data[lastchar] = (char) 0;
            }
        
            if(lastchar != 0) {
                bptr->data[lastchar] = (char) 0;
            }
        
            unsigned nid = OBJ_obj2nid(obj);    
            if (nid == NID_undef) {
                // no lookup found for the provided OID so nid came back as undefined.
                OBJ_obj2txt(tmp, SSLCERTSTORE_BUFSIZE , (const ASN1_OBJECT *) obj, 1);
                s.append(string_format("Extension[%d]: '%s'\n ", i, tmp));
            } 
            else {
                // the OID translated to a NID which implies that the OID has a known sn/ln
                const char *c_ext_name = OBJ_nid2ln(nid);
                if(!c_ext_name) { 
                    s.append(string_format("Extension[%d]: <invalid X509v3 extension name>\n ",i));
                }
                else {
                    s.append(string_format("Extension[%d]: '%s'\n ", i,c_ext_name));
                }
            }
            
            s.append(string_format("Extension[%d] length = %u\n ", i,bptr->length));
            s.append(string_format("Extension[%d] value = '%s'\n ", i,bptr->data));
            
            BIO_free(ext_bio);
        }
    }

#endif

    return s;
            
}

SSLCertStore::~SSLCertStore() {
    destroy();
}
