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
#include <array>

#include <display.hpp>
#include <sslcertstore.hpp>
#include <sslmitmcom.hpp>

#include <openssl/ssl.h>
#include <openssl/ct.h>

std::string FILE_to_string(FILE* file) {
    std::stringstream ss;
    if(file) {
        int c = EOF;
        do {
            c = fgetc(file);
            if(feof(file)) break;

            ss << (unsigned char) c;
        } while(true);

        rewind(file);
    }

    return ss.str();
}

bool SSLFactory::load_from_files() {

    auto lc_ = std::scoped_lock(lock());

    auto const& log = get_log();

    bool ret = true;
    
    OpenSSL_add_all_algorithms();
    
    serial += time(nullptr);

    if (not (load_ca_cert() and load_def_cl_cert() and load_def_sr_cert())) {
        _dia("SSLFactory::load: key/certs: ca(%x/%x) def_cl(%x/%x) def_sr(%x/%x)", ca_key,ca_cert,
             def_cl_key,def_cl_cert,  def_sr_key,def_sr_cert);
        
        destroy();
        return false;
    }

    return ret;
}

bool SSLFactory::load_ca_cert() {

    auto const& log = get_log();
    std::string cer = certs_path() + config_t::CA_CERTF;

    FILE *fp_crt = fopen(cer.c_str(), "r");
    FILE *fp_key = nullptr;
    
    if (!fp_crt) {
        _fat("SSLFactory::load_ca_cert: unable to open: %s",cer.c_str());
        return false;
    }
    
    std::string key = certs_path() + config_t::CA_KEYF;
    fp_key = fopen(key.c_str(), "r");
    
    if (!fp_key) {
        _fat("SSLFactory::load_ca_cert: unable to open: %s",key.c_str());

        fclose(fp_crt);
        return false;
    }


    [&]{
        auto lc_ = std::scoped_lock(lock());

        if (ca_cert) {
            X509_free(ca_cert);
        }
        if (ca_key) {
            EVP_PKEY_free(ca_key);
        }

        config.def_ca_cert_str = FILE_to_string(fp_crt);
        config.def_ca_key_str = FILE_to_string(fp_key);

        ca_cert = PEM_read_X509(fp_crt, nullptr, nullptr, nullptr);
        ca_key = PEM_read_PrivateKey(fp_key, nullptr, nullptr, (void *) certs_password().c_str());
    }();

    fclose(fp_crt);
    fclose(fp_key);
    
    return ( ca_cert and ca_key );
}

bool SSLFactory::load_def_cl_cert() {

    auto const& log = get_log();
    std::string cer = certs_path() + config_t::CL_CERTF;

    FILE *fp_crt = fopen(cer.c_str(), "r");
    FILE *fp_key = nullptr;
    
    if (!fp_crt) {
        _fat("SSLFactory::load_def_cl_cert: unable to open: %s",cer.c_str());
        return false;
    }
    
    std::string key = certs_path() + config_t::CL_KEYF;
    fp_key = fopen(key.c_str(), "r");
    
    if (!fp_key) {
        _fat("SSLFactory::load_def_cl_cert: unable to open: %s",key.c_str());
        fclose(fp_crt);
        return false;
    }

    [&]{
        auto lc_ = std::scoped_lock(lock());

        if (def_cl_cert) {
            X509_free(def_cl_cert);
        }
        if (def_cl_key) {
            EVP_PKEY_free(def_cl_key);
        }

        config.def_cl_cert_str = FILE_to_string(fp_crt);
        config.def_cl_key_str = FILE_to_string(fp_key);
        def_cl_cert = PEM_read_X509(fp_crt, nullptr, nullptr, nullptr);
        def_cl_key = PEM_read_PrivateKey(fp_key, nullptr, nullptr, (void *) certs_password().c_str());
    }();
    
    fclose(fp_crt);
    fclose(fp_key);
    
    return ( def_cl_cert and def_cl_key );
}

bool SSLFactory::load_def_sr_cert() {

    auto const& log = get_log();
    std::string cer = certs_path() + config_t::SR_CERTF;
    
    FILE *fp_crt = fopen(cer.c_str(), "r");
    FILE *fp_key = nullptr;
    
    if (!fp_crt) {
        _fat("SSLFactory::load_def_sr_cert: unable to open: %s",cer.c_str());
        return false;
    }
    
    std::string key = certs_path() + config_t::SR_KEYF;
    fp_key = fopen(key.c_str(), "r");
    
    if (!fp_key) {
        _fat("SSLFactory::load_def_sr_cert: unable to open: %s",key.c_str());
        fclose(fp_crt);
        return false;
    }

    [&]{
        auto lc_ = std::scoped_lock(lock());

        if (def_sr_cert) {
            X509_free(def_sr_cert);
        }
        if (def_sr_key) {
            EVP_PKEY_free(def_sr_key);
        }
        config.def_sr_cert_str = FILE_to_string(fp_crt);
        config.def_sr_key_str = FILE_to_string(fp_key);

        def_sr_cert = PEM_read_X509(fp_crt, nullptr, nullptr, nullptr);
        def_sr_key = PEM_read_PrivateKey(fp_key, nullptr, nullptr, (void *) certs_password().c_str());
    }();

    fclose(fp_crt);
    fclose(fp_key);
    
    return ( def_sr_cert and def_sr_key );
}


SSL_CTX* SSLFactory::client_ctx_setup(const char* ciphers) {

    auto const& log = get_log();
    const SSL_METHOD *method = SSLv23_client_method();

    SSL_CTX* ctx = SSL_CTX_new (method);

    if (!ctx) {
        _err("SSLCom::client_ctx_setup: Error creating SSL context!");
        exit(2);
    }
    if (not set_verify_locations(ctx)) {
        _err("SSLFactory::client_ctx_setup: cannot load CA locations!");
        exit(3);
    }

    ciphers == nullptr ? SSL_CTX_set_cipher_list(ctx,"ALL:!ADH:!LOW:!aNULL:!EXP:!MD5:@STRENGTH") : SSL_CTX_set_cipher_list(ctx,ciphers);

    auto ctx_options = def_cl_options;
#ifdef USE_OPENSSL300
    if (options::ktls) {
        _dia("SSLFactory::client_ctx_setup: KTLS on");
        ctx_options += SSL_OP_ENABLE_KTLS;
    }
    else {
        _dia("SSLFactory::client_ctx_setup: KTLS off");
    }
#endif

    SSL_CTX_set_options(ctx, ctx_options); //used to be also SSL_OP_NO_TICKET+
    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_NO_INTERNAL);

    SSL_CTX_sess_set_new_cb(ctx, SSLCom::new_session_callback);

    #ifdef USE_OPENSSL111
    SSL_CTX_set_keylog_callback(ctx, SSLCom::ssl_keylog_callback);
    #endif

    struct stat s{};
    if (stat(SSLFactory::ctlogfile().c_str(), &s) == 0) {
        if (SSL_CTX_set_ctlog_list_file(ctx, SSLFactory::ctlogfile().c_str()) == 1) {
            is_ct_available(true);
        }
    } else {
        _war("certificate transparency log not found: %s", SSLFactory::ctlogfile().c_str());
    }

    return ctx;
}

SSL_CTX* SSLFactory::client_dtls_ctx_setup(const char* ciphers) {
    auto const& log = get_log();
#ifdef USE_OPENSSL11
    const SSL_METHOD *method = DTLS_client_method();
#else
    const SSL_METHOD *method = DTLSv1_client_method();
#endif

    SSL_CTX* ctx = SSL_CTX_new (method);

    if (!ctx) {
        _err("SSLCom::client_ctx_setup: Error creating SSL context!");
        exit(2);
    }
    if (not set_verify_locations(ctx)) {
        _err("SSLFactory::init: cannot load CA locations!");
        exit(3);
    }

    ciphers == nullptr ? SSL_CTX_set_cipher_list(ctx,"ALL:!ADH:!LOW:!aNULL:!EXP:!MD5:@STRENGTH") : SSL_CTX_set_cipher_list(ctx,ciphers);

    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_NO_INTERNAL);

    #ifdef USE_OPENSSL111
    SSL_CTX_set_keylog_callback(ctx, SSLCom::ssl_keylog_callback);
    #endif
    return ctx;
}

SSL_CTX* SSLFactory::server_ctx_setup(EVP_PKEY* priv, X509* cert, const char* ciphers) {

    auto const& log = get_log();
    const SSL_METHOD *method = SSLv23_server_method();
    SSL_CTX* ctx = SSL_CTX_new (method);

    if (!ctx) {
        _err("SSLCom::server_ctx_setup: Error creating SSL context!");
        exit(2);
    }

    ciphers == nullptr ? SSL_CTX_set_cipher_list(ctx,"ALL:!ADH:!LOW:!EXP:!MD5:@STRENGTH") : SSL_CTX_set_cipher_list(ctx,ciphers);

    auto ctx_options = def_sr_options;
#ifdef USE_OPENSSL300
    if (options::ktls) {
        _dia("SSLFactory::server_ctx_setup: KTLS on");
        ctx_options += SSL_OP_ENABLE_KTLS;
    }
    else {
        _dia("SSLFactory::server_ctx_setup: KTLS off");
    }
#endif

    SSL_CTX_set_options(ctx, ctx_options); //used to be also SSL_OP_NO_TICKET+
    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_NO_INTERNAL);

    SSL_CTX_sess_set_new_cb(ctx, SSLCom::new_session_callback);
    // set server callback on internal cache miss
    SSL_CTX_sess_set_get_cb(ctx, SSLCom::server_get_session_callback);

    _deb("SSLCom::server_ctx_setup: loading default key/cert");
    priv == nullptr ? SSL_CTX_use_PrivateKey(ctx, def_sr_key) : SSL_CTX_use_PrivateKey(ctx,priv);
    cert == nullptr ? SSL_CTX_use_certificate(ctx, def_sr_cert) : SSL_CTX_use_certificate(ctx,cert);


    if (!SSL_CTX_check_private_key(ctx)) {
        _err("SSLCom::server_ctx_setup: private key does not match the certificate public key\n");
        exit(5);
    }
    #ifdef USE_OPENSSL111
    SSL_CTX_set_keylog_callback(ctx, SSLCom::ssl_keylog_callback);
    #endif

    return ctx;
}


SSL_CTX* SSLFactory::server_dtls_ctx_setup(EVP_PKEY* priv, X509* cert, const char* ciphers) {

    auto const& log = get_log();
    // DTLS method
#ifdef USE_OPENSSL11
    const SSL_METHOD *method = DTLS_server_method();
#else
    const SSL_METHOD *method = DTLSv1_server_method();
#endif
    SSL_CTX* ctx = SSL_CTX_new (method);

    if (!ctx) {
        _err("SSLCom::server_dtls_ctx_setup: Error creating SSL context!");
        exit(2);
    }

    ciphers == nullptr ? SSL_CTX_set_cipher_list(ctx,"ALL:!ADH:!LOW:!EXP:!MD5:@STRENGTH") : SSL_CTX_set_cipher_list(ctx,ciphers);

    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_NO_INTERNAL);

    _deb("SSLCom::server_dtls_ctx_setup: loading default key/cert");
    priv == nullptr ? SSL_CTX_use_PrivateKey(ctx, def_sr_key) : SSL_CTX_use_PrivateKey(ctx,priv);
    cert == nullptr ? SSL_CTX_use_certificate(ctx, def_sr_cert) : SSL_CTX_use_certificate(ctx,cert);


    if (!SSL_CTX_check_private_key(ctx)) {
        _err("SSLCom::server_dtls_ctx_setup: private key does not match the certificate public key\n");
        exit(5);
    }

    #ifdef USE_OPENSSL111
    SSL_CTX_set_keylog_callback(ctx, SSLCom::ssl_keylog_callback);
    #endif

    return ctx;
}


bool SSLFactory::load_trust_store() {
    auto const& log = SSLFactory::get_log();

    // initialize trust store
    if(trust_store_) {
        X509_STORE_free(trust_store_);
    }
    trust_store_ = X509_STORE_new();

    bool bundle_loaded = false;
    bool ca_path_loaded = false;

    if (not ca_file().empty()) {
        const int r = X509_STORE_load_locations(trust_store_, ca_file().c_str(), nullptr);
        _deb("SSLFactory::load_trust_store: loading certificate bundle file: %s", r > 0 ? "ok" : "failed");

        if(r <= 0) {
            _err("SSLFactory::load_trust_store: failed to load certificate bundle file: %d", r);
        }
        else {
            stats.ca_store_use_file = true;
            bundle_loaded = true;
        }
    }

    if(not bundle_loaded and not ca_path().empty()) {
        const int r = X509_STORE_load_locations(trust_store_, nullptr, ca_path().c_str());
        _deb("SSLFactory::load_trust_store: loading default certificate store from directory: %s", r > 0 ? "ok" : "failed");

        if(r <= 0) {
            _err("SSLFactory::load_trust_store: failed to load verify location: %d", r);
        }
        else {
            ca_path_loaded = true;
        }
    }
    else {
        _war("SSLFactory::load_trust_store: loading default certification store: path not set!");
    }

    return ( ca_path_loaded or bundle_loaded );

}
bool SSLFactory::set_verify_locations(SSL_CTX *ctx) {

    auto const& log = SSLFactory::get_log();

    bool bundle_loaded = false;
    bool ca_path_loaded = false;

    if (not ca_file().empty()) {
        const int r = SSL_CTX_load_verify_locations(ctx, ca_file().c_str(), nullptr);
        _deb("SSLFactory::set_verify_locations: loading certificate bundle file: %s", r > 0 ? "ok" : "failed");

        if(r <= 0) {
            _err("SSLFactory::set_verify_locations: failed to load certificate bundle file: %d", r);
        }
        else {
            stats.ca_verify_use_file = true;
            bundle_loaded = true;
        }
    }

    if(not bundle_loaded and not ca_path().empty()) {
        const int r = SSL_CTX_load_verify_locations(ctx, nullptr, ca_path().c_str());
        _deb("SSLFactory::set_verify_locations: loading default certificate store: %s", r > 0 ? "ok" : "failed");

        if(r <= 0) {
            _err("SSLFactory::set_verify_locations: failed to load verify location: %d", r);
        }
        else {
            ca_path_loaded = true;
        }
    }
    else {
        _war("SSLFactory::set_verify_locations: loading default certification store: path not set!");
    }

    return ( ca_path_loaded or bundle_loaded );
}

bool SSLFactory::reset_caches() {
    verify_cache().clear();
    verify_cache().expiration_check(expiring_verify_result::is_expired);

    return true;
}

SSLFactory& SSLFactory::init () {
    auto const& log = get_log();

    _dia("SSLFactory::init: loading central certification store: start");

    SSLFactory& fac = SSLFactory::factory();

    auto lc_ = std::scoped_lock(fac.lock());

    // don't run again if done
    if(fac.is_initialized) return fac;
    auto make_initized = raw::guard([&fac](){ fac.is_initialized = true; });


    bool ret_files = fac.load_from_files();
    if(! ret_files) {
        _fat("SSLFactory::init: failure loading certificates, bailing out.");
        exit(3);
    }
    bool ret_store = fac.load_trust_store();
    if(! ret_store) {
        _fat("SSLFactory::init: failure loading trust store, bailing out.");
        exit(3);
    }

    fac.def_cl_ctx = fac.client_ctx_setup();
    fac.def_dtls_cl_ctx = fac.client_dtls_ctx_setup();

    _dia("SSLFactory::init: default ssl client context: ok");

    fac.def_sr_ctx = fac.server_ctx_setup();
    fac.def_dtls_sr_ctx = fac.server_dtls_ctx_setup();

    _dia("SSLFactory::init: default ssl server context: ok");

    reset_caches();

    return fac;
}


void SSLFactory::destroy() {

    auto lc_ = std::scoped_lock(lock());
    auto const& log = get_log();

    if(ca_cert) {
        _deb("SSLFactory::destroy: ca_cert");

        X509_free(ca_cert);
        ca_cert = nullptr;
    }
    if(ca_key) {
        _deb("SSLFactory::destroy: ca_key");

        EVP_PKEY_free(ca_key);
        ca_key = nullptr;
    }
    
    if(def_cl_cert) {
        _deb("SSLFactory::destroy: def_cl_cert");

        X509_free(def_cl_cert);
        def_cl_cert = nullptr;
    }

    if(def_cl_key) {
        _deb("SSLFactory::destroy: def_cl_key");

        EVP_PKEY_free(def_cl_key);
        def_cl_key = nullptr;
    }
    
    if(def_sr_cert) {
        _deb("SSLFactory::destroy: def_sr_cert");

        X509_free(def_sr_cert);
        def_sr_cert = nullptr;
    }
    if(def_sr_key) {
        _deb("SSLFactory::destroy: def_sr_key");

        EVP_PKEY_free(def_sr_key);
        def_sr_key = nullptr;
    }

    _deb("SSLFactory::destroy: cert_cache");
    cert_cache_.clear();


    if(trust_store_) {
        _deb("SSLFactory::destroy: trust_store");

        X509_STORE_free(trust_store_);
        trust_store_ = nullptr;
    }

    _deb("SSLFactory::destroy: finished");
}

bool SSLFactory::add(std::string const& store_key, X509_PAIR parek) {

    auto const& log = get_log();
    bool op_status = true;

    if (parek.first == nullptr || parek.second == nullptr) {
        _dia("SSLFactory::add[%X]: one of about to be stored components is nullptr", serial);

        return false;
    }

    try {
        // lock, don't mess with cache_, I will write into it now
        auto lc_  = std::scoped_lock(lock());

        // free underlying keypair
        auto it = cache().get(store_key);
        if(it) {
            _err("SSLFactory::add: keypair associated with store_key '%s' already exists (keeping it there)", store_key.c_str());

            _deb("SSLFactory::add:         existing pointers:  keyptr=0x%x certptr=0x%x", it->keypair()->first, it->keypair()->second);
            _deb("SSLFactory::add:         offending pointers: keyptr=0x%x certptr=0x%x", parek.first, parek.second);

            op_status = false;
        } else {

            cache().set(store_key, std::make_shared<CertCacheEntry>(parek));
            _dia("SSLFactory::add: new cert '%s' successfully added to cache", store_key.c_str());
        }
    }
    catch (std::exception const& e) {
        op_status = false;
        _dia("SSLFactory::add - exception caught: %s", e.what());
    }

    if(not op_status) {
        _err("Error to add certificate '%s' into memory cache!",store_key.c_str());
        return false;
    }
    
    return true;
}


#ifndef  USE_OPENSSL11

std::string SSLFactory::make_store_key(X509* cert_orig, const SpoofOptions& spo) {

    char tmp[512];
    X509_NAME_oneline( X509_get_subject_name(cert_orig) , tmp, 512);
    std::string subject(tmp);

    std::stringstream store_key_ss;

    store_key_ss << subject;

    if(spo.self_signed) {
        store_key_ss << "+self_signed";
    }

    std::vector<std::string> cert_sans = SSLFactory::get_sans(cert_orig);
    for(auto const& s1: cert_sans) {
        store_key_ss << string_format("+san:%s",s1.c_str());
    }

    if( ! spo.sans.empty() ) {
        for(auto const& san: spo.sans) {
            store_key_ss << string_format("+san:%s",san.c_str());
        }
    }

    return store_key_ss.str();

}

#else

std::string SSLFactory::make_store_key(X509* cert_orig, const SpoofOptions& spo) {

    char tmp[512]; memset(tmp, 0, 512);

    const ASN1_BIT_STRING* bs = nullptr;
    const X509_ALGOR* pal = nullptr;

    X509_get0_signature(&bs, &pal, cert_orig);

    //TODO: add signature as part of the key, to cover new orig certificates with also new spoofed ones

    X509_NAME_oneline( X509_get_subject_name(cert_orig) , tmp, 512);
    std::string subject(tmp);

    std::stringstream store_key_ss;

    store_key_ss << subject;

    if(spo.self_signed) {
        store_key_ss << "+self_signed";
    }

    std::vector<std::string> cert_sans = SSLFactory::get_sans(cert_orig);
    for(auto const& s1: cert_sans) {
        store_key_ss << string_format("+san:%s",s1.c_str());
    }

    if( ! spo.sans.empty() ) {
        for(auto const& san: spo.sans) {
            store_key_ss << string_format("+san:%s",san.c_str());
        }
    }

    return store_key_ss.str();

}

#endif

std::optional<const SSLFactory::X509_PAIR> SSLFactory::find(std::string const& subject) {

    auto lc_ = std::scoped_lock(lock());
    auto const& log = get_log();

    auto entry = cache().get(subject);
    if (not entry) {
        _deb("SSLFactory::find[%x]: NOT cached '%s'",this,subject.c_str());
    } else {
        _deb("SSLFactory::find[%x]: found cached '%s'",this,subject.c_str());
        
        return *entry->keypair();  //first is the map key (cert subject in our case)
    }    
    
    return std::nullopt;
}

std::optional<std::string> SSLFactory::find_subject_by_fqdn(std::string const& fqdn) {

    {
        auto lc_ = std::scoped_lock(lock());
        auto const& log = get_log();

        auto entry = cache().get(fqdn);
        if (not entry) {
            _deb("SSLFactory::find_subject_by_fqdn[%x]: NOT cached '%s'", this, fqdn.c_str());
        } else {
            _deb("SSLFactory::find_subject_by_fqdn[%x]: found cached '%s'", this, fqdn.c_str());
            return std::optional(fqdn);
        }
    }

    // do this outside locked section
    mp::string re_wildcard("*.");
    std::string wildcard_fqdn = std::regex_replace(fqdn, re_hostname, re_wildcard);

    {
        auto lc_ = std::scoped_lock(lock());
        auto const& log = get_log();

        auto entry = cache().get(wildcard_fqdn);
        if (not entry) {
            _deb("SSLFactory::find_subject_by_fqdn[%x]: wildcard NOT cached '%s'", this, wildcard_fqdn.c_str());
        } else {
            _deb("SSLFactory::find_subject_by_fqdn[%x]: found cached wildcard '%s'", this, fqdn.c_str());
            return std::optional(wildcard_fqdn);
        }
    }

    return std::nullopt;
}

bool SSLFactory::erase(const std::string &subject) {

    auto const& log = get_log();

    try {
        _dia("SSLFactory::erase - %s", subject.c_str());
        cache().erase(subject);
    }

    catch(std::exception const& e) {

        _dia("SSLFactory::erase - exception caught: %s", e.what());
        return false;
    }

    return true;
}

int add_ext(STACK_OF(X509_EXTENSION) *sk, int nid, char *value) {

  X509_EXTENSION *ex;
  ex = X509V3_EXT_conf_nid(nullptr, nullptr, nid, value);

  if (!ex)
      return 0;

  sk_X509_EXTENSION_push(sk, ex);
  return 1;
}

std::vector<std::string> SSLFactory::get_sans(X509* x) {

    auto const& log = get_log();
    std::vector<std::string> ret;
    
    // Copy extensions
#ifdef USE_OPENSSL11
    const STACK_OF(X509_EXTENSION) *exts = X509_get0_extensions(x);
#else
    STACK_OF(X509_EXTENSION) *exts = x->cert_info->extensions;
#endif

    if(not exts) return ret;

    const auto num_of_exts = sk_X509_EXTENSION_num(exts);

    for (int i=0; i < num_of_exts; i++) {
        auto* ex = sk_X509_EXTENSION_value(exts, i);
        if(not ex) {
            _err("SSLFactory::get_sans: error obtaining certificate extension [%d] value ",i);
            continue;
        }
        auto* obj = X509_EXTENSION_get_object(ex);
        if(not obj) {
            _err("SSLFactory::get_sans: unable to extract ASN1 object from extension [%d]",i);
            continue;
        }

        const auto nid = OBJ_obj2nid(obj);
        if(nid == NID_subject_alt_name) {
            _deb("SSLFactory::get_sans: adding subjAltName to extensions");
#ifdef USE_OPENSSL11

            auto* alt = (STACK_OF(GENERAL_NAME)*)X509V3_EXT_d2i(ex);
            if(not alt) continue;
            auto g_alt = raw::guard([&alt]{ if(alt) GENERAL_NAMES_free(alt); });


            auto alt_len = sk_GENERAL_NAME_num(alt);
            for (int gn_i = 0; gn_i < alt_len; gn_i++) {
                auto* gn = sk_GENERAL_NAME_value(alt, gn_i);
                if(not gn) continue;

                int name_type = 0;

                void* name_ptr = GENERAL_NAME_get0_value(gn, &name_type);
                if(name_type == GEN_DNS) {
                    auto* dns_name = static_cast<ASN1_STRING*>(name_ptr); //in ASN1 we trust

                    std::string san((const char *) ASN1_STRING_get0_data(dns_name),
                                    (unsigned long) ASN1_STRING_length(dns_name));
                    ret.emplace_back("DNS:"+san);

                    _deb("SSLFactory::get_sans: adding GEN_DNS: %s", san.c_str());
                }
                else if(name_type == GEN_IPADD) {
                    auto* ip = static_cast<ASN1_STRING*>(name_ptr);
                    std::string str_ip((const char *) ASN1_STRING_get0_data(ip),
                                    (unsigned long) ASN1_STRING_length(ip));
                    ret.emplace_back("IP:"+str_ip);

                    _deb("SSLFactory::get_sans: adding GEN_IP: %s", str_ip.c_str());

                }

            }

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

    return ret;
}

std::string SSLFactory::get_sans_csv(X509 *x) {

    std::vector<std::string> sans_vec = SSLFactory::get_sans(x);
    return string_csv(sans_vec);
}


std::optional<X509_REQ*> SSLFactory::sign_csr(X509_REQ*&& corpus) const {

    auto* own_corpus = std::move(corpus);
    auto const& log = get_log();

    EVP_PKEY *pkey = def_sr_key;

    EVP_MD const* digest = EVP_sha256();

    if (!(X509_REQ_sign( own_corpus, pkey, digest))) {
        _err("SSLFactory::spoof[%X]: error signing request", serial);
        return std::nullopt;
    }

    return own_corpus;
}

std::optional<X509_REQ*> SSLFactory::create_csr_from(X509* cert_orig, bool self_sign, std::vector<std::string>* additional_sans) {

    auto const& log = get_log();

    auto a_tmp = std::array<char,2048>();
    auto* tmp = a_tmp.data();


    _deb("SSLFactory::spoof[%X]: about to spoof certificate!", serial);

    if(self_sign) {
        _dia("SSLFactory::spoof[%X]: about to spoof certificate (self-signed)!", serial);
    }
    if(additional_sans != nullptr && ! additional_sans->empty()) {
        _dia("SSLFactory::spoof[%X]: about to spoof certificate (+sans):", serial);
        std::vector<std::string>const & sans = *additional_sans;
        for (auto const& san: sans) {
            _dia("SSLFactory::spoof[%X]:  SAN: %s", serial, san.c_str());
        }
    }

    // get info from the peer certificate
    X509_NAME_get_text_by_NID(X509_get_subject_name(cert_orig),NID_commonName, tmp,2048);
    std::string cn(tmp);

    X509_NAME_oneline(X509_get_subject_name(cert_orig), tmp, 2048);
    std::string subject(tmp);


    _deb("SSLFactory::spoof[%X]: generating CSR for '%s'", serial, subject.c_str());

    auto* copy = X509_REQ_new();
    X509_NAME* copy_subj = X509_NAME_new();


    EVP_PKEY* pub_sr_cert = X509_get_pubkey(def_sr_cert);
    X509_REQ_set_pubkey(copy, pub_sr_cert);
    EVP_PKEY_free(pub_sr_cert);

    if( not copy) {
        _err("SSLFactory::spoof[%X]: cannot init request", serial);
        return std::nullopt;
    }

    if (not copy_subj) {
        _err("SSLFactory::spoof[%X]: cannot init subject for request", serial);
        return std::nullopt;
    }

    auto g_copy_sub = raw::guard([&copy_subj]{
        if(copy_subj) X509_NAME_free(copy_subj);
    });

    X509_NAME* n_dup = X509_NAME_dup(X509_get_subject_name(cert_orig));
    auto g_n_dup = raw::guard([&n_dup]{
        if(n_dup) X509_NAME_free(n_dup);
    });

    if (X509_REQ_set_subject_name(copy, n_dup) != 1) {
        _err("SSLFactory::spoof[%X]: error copying subject to request", serial);
        return std::nullopt;
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
    if(additional_sans != nullptr and not additional_sans->empty()) {
        san_add = string_csv(*additional_sans);
        _dia("SSLFactory::spoof[%X]: additional sans = '%s'", serial, san_add.c_str());
    }

    bool san_added = false;
    if (exts) {
        auto *ext_stack = sk_X509_EXTENSION_new_null();
        auto g_ext_stack = raw::guard([&ext_stack]{ if(ext_stack) sk_X509_EXTENSION_pop_free(ext_stack, X509_EXTENSION_free); });

        num_of_exts = sk_X509_EXTENSION_num(exts);
        if(num_of_exts > 0) {
            for (int i=0; i < num_of_exts; i++) {
                X509_EXTENSION *ex = sk_X509_EXTENSION_value(exts, i);
                if(!ex) {
                    _err("SSLFactory::spoof[%X]: error obtaining certificate extension [%d] value ", serial, i);
                    continue;
                }
                ASN1_OBJECT *obj = X509_EXTENSION_get_object(ex);
                if(!obj) {
                    _err("SSLFactory::spoof[%X]: unable to extract ASN1 object from extension [%d]", serial, i);
                    continue;
                }

                unsigned nid = OBJ_obj2nid(obj);
                if(nid == NID_subject_alt_name) {
                    _deb("SSLFactory::spoof[%X]: adding subjAltName to extensions", serial);

#ifdef USE_OPENSSL11
                    // it'ext_stack easier to get san list with different call, instead of diging it out from here.
                    std::string san = get_sans_csv(cert_orig);
                    _deb("SSLFactory::spoof[%X]: original cert sans to be added: %ext_stack", serial, san.c_str());

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

                    int a_r = add_ext(ext_stack, NID_subject_alt_name, san.data());
                    _deb("SSLFactory::spoof[%X]: add_ext returned %d", serial, a_r);

                    san_added = true;
                }
            }
        }

        if(not san_added) {

            int a_r = add_ext(ext_stack, NID_subject_alt_name, san_add.data());
            _dum("SSLFactory::spoof[%X]: add_ext returned %d", serial, a_r);

        }

        int r = X509_REQ_add_extensions(copy, ext_stack);
        _dum("SSLFactory::spoof[%X]: X509_REQ_add_extensions returned %d", serial, r);
    }

    _deb("SSLFactory::spoof[%X]: generating CSR finished", serial);

    return sign_csr(std::move(copy));
}

bool SSLFactory::validate_spoof_requirements(X509 const* cert, X509_NAME const* cert_name, X509_NAME const* issuer_name, EVP_PKEY const* pkey) const {
    auto const& log = get_log();

    // init new certificate
    if (not cert) {
        _err("SSLFactory::spoof[%X]: validate - error creating X509 object", serial);
        return false;
    }
    if (not cert_name) {
        _err("SSLFactory::spoof[%X]: validate - subjectName cannot be extracted from CSR", serial);
        return false;
    }
    if (not issuer_name) {
        _cri("SSLFactory::spoof[%X]: validate - subjectName cannot be extracted from CA!",  serial);
        return false;
    }
    if (not pkey) {
        _err("SSLFactory::spoof[%X]: validate - error getting public key from request", serial);
        return false;
    }

    return true;
}

std::optional<SSLFactory::X509_PAIR> SSLFactory::spoof(X509* cert_orig, bool self_sign, std::vector<std::string>* additional_sans) {

    auto const& log = get_log();

    ++serial;
    auto copy = create_csr_from(cert_orig, self_sign, additional_sans);
    if(not copy) {

        _err("SSLFactory::spoof[%X]: no CSR generated", serial);
        return std::nullopt;
    }

    auto* cert = X509_new();
    auto* name = X509_REQ_get_subject_name(copy.value());
    auto* issuer_name = X509_get_subject_name(ca_cert);
    EVP_PKEY* pkey = X509_REQ_get_pubkey(copy.value());


    if(not validate_spoof_requirements(cert, name, issuer_name, pkey)) {
        return std::nullopt;
    }
    auto g_pkey = raw::guard([&pkey]{
        if(pkey) EVP_PKEY_free(pkey);
    });
    auto g_copy = raw::guard([&copy]{
            X509_REQ_free(copy.value());
    });


    // set version number for the certificate (X509v3) and then serial #
    if (X509_set_version (cert, 2L) != 1) {
        _err("SSLFactory::spoof[%X]: cannot set X509 version!", serial);
        return std::nullopt;
    }

    ASN1_INTEGER_set(X509_get_serialNumber(cert), serial);

    if (X509_set_subject_name(cert, name) != 1) {
        _err("SSLFactory::spoof[%X]: error setting subject name of certificate", serial);
        return std::nullopt;
    }     

    int subjAltName_pos = -1;
    X509_EXTENSION* subjAltName = nullptr;
    
    auto req_exts = X509_REQ_get_extensions(copy.value());
    auto g_req_exts = raw::guard([&req_exts]{
        sk_X509_EXTENSION_pop_free(req_exts, X509_EXTENSION_free);
    });

    if (not req_exts) {
        _inf("SSLFactory::spoof[%X]: error getting the request's extension", serial);
    } else {
        subjAltName_pos = X509v3_get_ext_by_NID(req_exts,OBJ_sn2nid("subjectAltName"),-1);
        subjAltName = X509v3_get_ext(req_exts, subjAltName_pos);
    }

    if (X509_set_issuer_name(cert, issuer_name) != 1) {
        _err("SSLFactory::spoof[%X]: error setting issuer name of certificate", serial);
        return std::nullopt;
        
    }
    // set public key in the certificate 
    if ((X509_set_pubkey( cert, pkey)) != 1) {
        _err("SSLFactory::spoof[%X]: error setting public key of the certificate", serial);
        return std::nullopt;
    }
    
    constexpr long const EXPIRE_START = -60L*60*24;
    constexpr long const DAYS_TILL_EXPIRE = 364L;
    constexpr long const EXPIRE_SECS = 60L* 60*24*DAYS_TILL_EXPIRE;

    // set duration for the certificate
    if (!(X509_gmtime_adj(X509_get_notBefore(cert), EXPIRE_START))) {
        _err("SSLFactory::spoof[%X]: error setting beginning time of the certificate", serial);
        return std::nullopt;
    }

    if (!(X509_gmtime_adj(X509_get_notAfter(cert), EXPIRE_SECS))) {
        _err("SSLFactory::spoof[%X]: error setting ending time of the certificate", serial);
        return std::nullopt;
    }

    X509V3_CTX ctx;

    // add x509v3 extensions as specified 
    X509V3_set_ctx(&ctx, ca_cert, cert, nullptr, nullptr, 0);
    for (auto const& [ext_name, ext_value]: extensions()) {

        X509_EXTENSION* ext = X509V3_EXT_conf(nullptr, &ctx, ext_name.c_str(), ext_value.c_str());
        auto ga_ = raw::guard([&ext]{ if(ext) X509_EXTENSION_free(ext); });

        if (not ext) {
            _war("SSLFactory::spoof[%X]: error on \"%s = %s\"", serial, ext_name.c_str(), ext_value.c_str());
            _war("SSLFactory::spoof[%X]: error creating X509 extension object", serial);
            continue;
        }
        if (not X509_add_ext(cert, ext, -1)) {
            _err("SSLFactory::spoof[%X]: error on \"%s = %s\"", serial, ext_name.c_str(), ext_value.c_str());
            _err("SSLFactory::spoof[%X]: error adding X509 extension into certificate", serial);
        }
    }

    if(subjAltName != nullptr and not X509_add_ext(cert, subjAltName, -1)) {
        _err("SSLFactory::spoof[%X]: error adding subjectAltName to certificate", serial);
        return std::nullopt;
    }

    EVP_PKEY* sign_key = ca_key;
    if(self_sign) {
      X509_set_issuer_name(cert, X509_get_subject_name(cert));
      sign_key = def_sr_key;
    }


    const EVP_MD* digest = EVP_sha256();
    if (!(X509_sign(cert, sign_key, digest))) {
        _err("SSLFactory::spoof[%X]: error signing certificate", serial);
        return std::nullopt;
    }

    return X509_PAIR(def_sr_key, cert);
}


int SSLFactory::convert_ASN1TIME(ASN1_TIME *t, char* buf, size_t len) {
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


std::string SSLFactory::print_cn(X509* x) {
    auto a_tmp = std::array<char,config_t::SSLCERTSTORE_BUFSIZE>();
    auto* tmp = a_tmp.data();

    std::string s;

    // get info from the peer certificate
    X509_NAME_get_text_by_NID(X509_get_subject_name(x),NID_commonName, tmp, config_t::SSLCERTSTORE_BUFSIZE - 1);
    s.append(tmp);
    
    return s;
}

std::string SSLFactory::print_issuer(X509* x) {
    auto a_tmp = std::array<char,config_t::SSLCERTSTORE_BUFSIZE>();
    auto* tmp = a_tmp.data();
    std::string s;

    // get info from the peer certificate
    X509_NAME_get_text_by_NID(X509_get_issuer_name(x),NID_commonName, tmp, config_t::SSLCERTSTORE_BUFSIZE - 1);
    s.append(tmp);
    
    return s;
}

std::string SSLFactory::print_not_before(X509* x) {
    auto a_tmp = std::array<char,config_t::SSLCERTSTORE_BUFSIZE>();
    auto* tmp = a_tmp.data();
    std::string s;
    ASN1_TIME *not_before = X509_get_notBefore(x);
    
    convert_ASN1TIME(not_before, tmp, config_t::SSLCERTSTORE_BUFSIZE - 1);
    s.append(tmp);
    
    return s;
}


std::string SSLFactory::print_not_after(X509* x) {
    auto a_tmp = std::array<char,config_t::SSLCERTSTORE_BUFSIZE>();
    auto* tmp = a_tmp.data();
    std::string s;
    ASN1_TIME *not_after = X509_get_notAfter(x);
    
    convert_ASN1TIME(not_after, tmp, config_t::SSLCERTSTORE_BUFSIZE - 1);
    s.append(tmp);
    
    return s;
}

std::string SSLFactory::print_cert(X509* x, int indent, bool add_cr) {

    if(not x) return {};

    std::stringstream s;
    auto ar = [&s,&add_cr] {
        if(add_cr) s << '\r';
    };

    auto a_tmp = std::array<char,config_t::SSLCERTSTORE_BUFSIZE>();
    auto* tmp = a_tmp.data();

    std::string pref;
    for(int i = 0; i < indent; i++) {
        pref += " ";
    }

    // get info from the peer certificate
    // TODO: should be replaced, as per https://linux.die.net/man/3/x509_name_get_text_by_nid - examples section
    X509_NAME_get_text_by_NID(X509_get_subject_name(x),NID_commonName, tmp, config_t::SSLCERTSTORE_BUFSIZE - 1);
    s << pref << "Common Name: ";
    s << std::string(tmp);
    ar(); s << "\n ";
    

    X509_NAME_oneline(X509_get_subject_name(x), tmp, config_t::SSLCERTSTORE_BUFSIZE - 1);
    s << pref << "Subject: ";
    s << std::string(tmp);
    ar(); s << "\n ";
    
    X509_NAME const* issuer = X509_get_issuer_name(x);
    if(!issuer) {
        s << pref << "# Issuer: <unable to obtain issuer from certificate> ";
        ar(); s << "\n ";

    } else {
        X509_NAME_oneline(issuer,tmp, config_t::SSLCERTSTORE_BUFSIZE - 1);
        s << pref << string_format("Issuer: '%s'",tmp);
        ar(); s << "\n ";
        ar(); s << "\n ";

    }

#ifdef USE_OPENSSL11
    int pkey_nid = X509_get_signature_type(x);
#else
    int pkey_nid = OBJ_obj2nid(x->cert_info->key->algor->algorithm);
#endif
    const char* sslbuf = OBJ_nid2ln(pkey_nid);
    s << pref << "Signature type: ";
    s << sslbuf;
    ar(); s << "\n ";

    ASN1_TIME *not_before = X509_get_notBefore(x);
    ASN1_TIME *not_after = X509_get_notAfter(x);            
    
    convert_ASN1TIME(not_before, tmp, config_t::SSLCERTSTORE_BUFSIZE - 1);
    s << pref << "Valid from: " << std::string(tmp);
    ar(); s << "\n ";

    convert_ASN1TIME(not_after, tmp, config_t::SSLCERTSTORE_BUFSIZE - 1);
    s << pref << "Valid to: " << std::string(tmp);
    ar(); s << "\n ";


#ifdef USE_OPENSSL11
    const STACK_OF(X509_EXTENSION) *exts = X509_get0_extensions(x);

    BIO *ext_bio = BIO_new(BIO_s_mem());
    if (!ext_bio) {
        s << " ... unable to allocate BIO";
        return s.str();
    }

    X509V3_extensions_print(ext_bio, nullptr, exts, 0, indent);

    BUF_MEM *bptr = nullptr;
    BIO_get_mem_ptr(ext_bio, &bptr);
    BIO_set_close(ext_bio, BIO_CLOSE);

    std::string it(bptr->data, bptr->length);
    s << pref << it;

    BIO_free(ext_bio);

#else
    STACK_OF(X509_EXTENSION) *exts = x->cert_info->extensions;

    int num_of_exts = 0;
    if (exts) {
        num_of_exts = sk_X509_EXTENSION_num(exts);
        s << pref << "Extensions: \n";;

    } else {
        num_of_exts = 0;
        s << pref << " Extensions: <no extenstions in the certificate> \n");
    }

    for (int i=0; i < num_of_exts; i++) {
    
        X509_EXTENSION *ex = sk_X509_EXTENSION_value(exts, i);
        if(!ex) {
            s << pref << string_format("# Extension[%d] unable to extract extension from stack\n ",i);
            continue;
        }

        ASN1_OBJECT *obj = X509_EXTENSION_get_object(ex);
        if(!obj) {
            s << pref << string_format("# Extension[%d] unable to extract ASN1 object from extension\n ",i);
            continue;
        }
    
        BIO *ext_bio = BIO_new(BIO_s_mem());
        if (!ext_bio) {
            s << pref << string_format("# Extension[%d] unable to allocate memory for extension value BIO\n ",i);
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
                s << pref string_format("Extension[%d]: '%s'\n ", i, tmp);
            } 
            else {
                // the OID translated to a NID which implies that the OID has a known sn/ln
                const char *c_ext_name = OBJ_nid2ln(nid);
                if(!c_ext_name) { 
                    s << pref << string_format("Extension[%d]: <invalid X509v3 extension name>\n ",i);
                }
                else {
                    s << pref << string_format("Extension[%d]: '%s'\n ", i,c_ext_name);
                }
            }
            
            s << pref << string_format("Extension[%d] length = %u\n ", i,bptr->length);
            s << pref << string_format("Extension[%d] value = '%s'\n ", i,bptr->data);
            
            BIO_free(ext_bio);
        }
    }

#endif

    return s.str();
            
}

SSLFactory::~SSLFactory() {
    destroy();
}


std::string SSLFactory::fingerprint(X509* cert) {

    if(not cert) return {};

    const EVP_MD *fprint_type = nullptr;
    unsigned fprint_size;
    unsigned char fprint[EVP_MAX_MD_SIZE];

    fprint_type = EVP_sha1();

    if (!X509_digest(cert, fprint_type, fprint, &fprint_size)) {
        auto const& log = SSLFactory::get_log();
        _err("error creating the certificate fingerprint");
    }

    std::string ret;
    for (unsigned int j = 0; j < fprint_size; ++j)  {
        ret += string_format("%02x", fprint[j]);
    }


    return ret;
}


std::string SSLFactory::print_ASN1_OCTET_STRING(ASN1_OCTET_STRING* ostr) {

    auto ret = hex_print(ostr->data, ostr->length);
    return ret;
}