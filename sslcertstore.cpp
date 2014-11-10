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

#include <display.hpp>
#include <sslcertstore.hpp>
#include <sslmitmcom.hpp>

std::string SSLCertStore::certs_path = "./certs/";
std::string SSLCertStore::password = "password";


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
        DIA_("SSLCertStore::load: key/certs: ca(%x/%x) def_cl(%x/%x) def_sr(%x/%x)", ca_key,ca_cert,  
             def_cl_key,def_cl_cert,  def_sr_key,def_sr_cert);
        
        destroy();
        return false;
    }
    
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
        FAT_("SSLCertStore::load_ca_cert: unable to open: %s",cer.c_str());
        return false;
    }
    
    std::string key = certs_path + CA_KEYF;
    fp_key = fopen(key.c_str(), "r");
    
    if (!fp_key) {
        FAT_("SSLCertStore::load_ca_cert: unable to open: %s",key.c_str());

        fclose(fp_crt);
        return false;
    }
    
    
    ca_cert = PEM_read_X509(fp_crt, NULL, NULL, NULL);  
    ca_key = PEM_read_PrivateKey(fp_key,NULL, NULL, (void*)password.c_str());
    
    fclose(fp_crt);
    fclose(fp_key);
    
    return true;
}

bool SSLCertStore::load_def_cl_cert() {
    
    std::string cer = certs_path + CL_CERTF;
    
    FILE *fp_crt = fopen(cer.c_str(), "r");
    FILE *fp_key = nullptr;
    
    if (!fp_crt) {
        FAT_("SSLCertStore::load_def_cl_cert: unable to open: %s",cer.c_str());
        return false;
    }
    
    std::string key = certs_path + CL_KEYF; 
    fp_key = fopen(key.c_str(), "r");
    
    if (!fp_key) {
        FAT_("SSLCertStore::load_def_cl_cert: unable to open: %s",key.c_str());
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
        FAT_("SSLCertStore::load_def_sr_cert: unable to open: %s",cer.c_str());
        return false;
    }
    
    std::string key = certs_path + SR_KEYF;
    fp_key = fopen(key.c_str(), "r");
    
    if (!fp_key) {
        FAT_("SSLCertStore::load_def_sr_cert: unable to open: %s",key.c_str());
        fclose(fp_crt);
        return false;
    }
    
    
    def_sr_cert = PEM_read_X509(fp_crt, NULL, NULL, NULL);  
    def_sr_key = PEM_read_PrivateKey(fp_key,NULL, NULL, NULL);
    
    fclose(fp_crt);
    fclose(fp_key);
    
    return true;
}



void SSLCertStore::destroy() {
    if(ca_cert != NULL) X509_free(ca_cert);
    if(ca_key != NULL) EVP_PKEY_free(ca_key);
    
    if(def_cl_cert != NULL) X509_free(def_cl_cert);
    if(def_cl_key != NULL) EVP_PKEY_free(def_cl_key);
    
    if(def_sr_cert != NULL) X509_free(def_sr_cert);
    if(def_sr_key != NULL) EVP_PKEY_free(def_sr_key);

    for (auto i = cache_.begin(); i != cache_.end(); ++i ) {
        auto key = (*i).first;
        
        X509_PAIR* parek = (*i).second;
        
        DEB_("SSLCertStore::destroy cache: %s - private key",key.c_str());
        EVP_PKEY_free(parek->first);
        
        X509* cert = parek->second;
//         STACK_OF(X509_EXTENSION) *exts = cert->cert_info->extensions;
//         sk_X509_EXTENSION_free(exts);
        DEB_("SSLCertStore::destroy cache: %s - cert",key.c_str());
        X509_free(cert);
        delete parek;
    }
    
    cache_.clear();
}

bool SSLCertStore::add(std::string& subject,EVP_PKEY* cert_privkey, X509* cert, X509_REQ* req) {

    X509_PAIR* parek = new X509_PAIR(cert_privkey,cert);
    
    if (cert_privkey == NULL || cert == NULL || parek == NULL) {
        DIA_("SSLCertStore::add[x]: one of about to be stored componet is NULL",this);
        return false;
    }
    
    return add(subject,parek,req);
}

bool SSLCertStore::add(std::string& subject,X509_PAIR* parek, X509_REQ* req) {


    bool op_status = true;
    
    try {
        // lock, don't mess with cache_, I will write into it now
        mutex_cache_write_.lock();
        cache_[subject] = parek;
    }
    catch (std::exception& e) {
        op_status = false;
        DIA_("SSLCertStore::add[x] - exception caught: %s",this,e.what());
    }
    
    // now you can write too
    mutex_cache_write_.unlock();
    
    if(!op_status) {
        ERR_("Error to add certificate '%s' into memory cache!",subject.c_str());
        return false;
    }
    
    return true;
}

X509_PAIR* SSLCertStore::find(std::string& subject) {

    // cache lookup
    X509_CACHE::iterator entry = cache_.find(subject);
    if (entry == cache_.end()) {
        DEB_("SSLCertStore::find[%x]: NOT cached '%s'",this,subject.c_str());
    } else {
        DEB_("SSLCertStore::find[%x]: found cached '%s'",this,subject.c_str());
        
        return (*entry).second;  //first is the map key (cert subject in our case)
    }    
    
    return NULL;
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
    }
    catch(std::exception& e) {
        op_status = false;
        DIA_("SSLCertStore::add[x] - exception caught: %s",this,e.what());            
    }
    if(!op_status) {
        ERR_("Error to remove certificate '%s' from cache",subject.c_str());
    }
    
    mutex_cache_write_.unlock();
}

X509_PAIR* SSLCertStore::spoof(X509* cert_orig) {
    char tmp[2048];
    DEB_("SSLCertStore::spoof[%x]: about to spoof certificate!",this);
    
    
    // get info from the peer certificate
    X509_NAME_get_text_by_NID(X509_get_subject_name(cert_orig),NID_commonName, tmp,2048);
    std::string cn(tmp);
    
    X509_NAME_oneline(X509_get_subject_name(cert_orig), tmp, 2048);
    std::string subject(tmp);
          
    
    DEB_("SSLCertStore::spoof[%x]: generating CSR for '%s'",this,subject.c_str());    
        
    X509_REQ* copy = X509_REQ_new();
    X509_NAME* copy_subj = NULL;
    EVP_PKEY *pkey = def_sr_key;
    const EVP_MD *digest;

    
    if(!copy) {
        ERR_("SSLCertStore::spoof[%x]: cannot create request",this);
        return NULL;
    }
    
    EVP_PKEY* pub_sr_cert = X509_get_pubkey(def_sr_cert);
    X509_REQ_set_pubkey(copy,pub_sr_cert);
    EVP_PKEY_free(pub_sr_cert);

    if (!(copy_subj = X509_NAME_new())) {
        ERR_("SSLCertStore::spoof[%x]: cannot create subject for request",this);
        return NULL;
    }

    X509_NAME* n_dup = X509_NAME_dup(X509_get_subject_name(cert_orig));
    if (X509_REQ_set_subject_name(copy,n_dup) != 1) {
        ERR_("SSLCertStore::spoof[%x]: error copying subject to request",this);
        return NULL;
    }
    
    // Copy extensions
    STACK_OF(X509_EXTENSION) *exts = cert_orig->cert_info->extensions;
    int num_of_exts;

    if (exts) {   
        STACK_OF(X509_EXTENSION) *s = sk_X509_EXTENSION_new_null();
        num_of_exts = sk_X509_EXTENSION_num(exts);    
        if(num_of_exts > 0) {
            for (int i=0; i < num_of_exts; i++) {
                X509_EXTENSION *ex = sk_X509_EXTENSION_value(exts, i);
                if(!ex) {
                    ERR_("SSLCertStore::spoof[%x]: error obtaining certificate extension [%d] value ",this,i)
                    continue;
                }
                ASN1_OBJECT *obj = X509_EXTENSION_get_object(ex);
                if(!obj) {
                    ERR_("SSLCertStore::spoof[%x]: unable to extract ASN1 object from extension [%d]",this,i);
                    continue;
                }
                
                unsigned nid = OBJ_obj2nid(obj); 
                if(nid == NID_subject_alt_name) {
                    DEB_("SSLCertStore::spoof[%x]: adding subjAltName to extensions",this);
                    X509_EXTENSION* n_ex = X509_EXTENSION_dup(ex);
                    sk_X509_EXTENSION_push(s,n_ex);
//                     X509_EXTENSION_free(n_ex);  //leak hunt
                }                
            }
        }
        
        int r = X509_REQ_add_extensions(copy,s);
        DEB_("SSLCertStore::spoof[%x]: X509_REQ_add_extensions returned %d",this,r);
        
        sk_X509_EXTENSION_pop_free(s,X509_EXTENSION_free);
    }   
    
    // pick the correct digest and sign the request 
    if (EVP_PKEY_type(pkey->type) == EVP_PKEY_DSA) {
        digest = EVP_dss1();
    }
    else if (EVP_PKEY_type(pkey->type) == EVP_PKEY_RSA) {
        digest = EVP_sha1();
    }
    else {
        ERR_("SSLCertStore::spoof[%x]: error checking public key for a valid digest",this);
        return NULL;
    }
    
    if (!(X509_REQ_sign( copy, pkey, digest))) {
        ERR_("SSLCertStore::spoof[%x]: error signing request",this);
    }
    
    DEB_("SSLCertStore::spoof[%x]: generating CSR finished",this);    

    //------------------------------------------------------------------------------------------

    DIA_("SSLCertStore::spoof[%x]: faking certificate '%s'",this,subject.c_str());     
    

    X509 *cert = NULL;
    X509_NAME *name = NULL;


    // create new certificate 
    if (!(cert = X509_new( ))) {
        ERR_("SSLCertStore::spoof[%x]: error creating X509 object",this);
        return NULL;
    }

    // set version number for the certificate (X509v3) and then serial #
    if (X509_set_version (cert, 2L) != 1) {
        ERR_("SSLCertStore::spoof[%x]: cannot set X509 version!",this);
        return NULL;
    }

    ASN1_INTEGER_set(X509_get_serialNumber(cert), serial++);
    
    // get public key from request
    if (!(pkey = X509_REQ_get_pubkey(copy))) {
        ERR_("SSLCertStore::spoof[%x]: error getting public key from request",this);
        return NULL;
    }

    // Setting subject name
    if (!(name = X509_REQ_get_subject_name(copy))) {
        ERR_("SSLCertStore::spoof[%x]: error getting subject name from request",this);
        return NULL;
    }
    if (X509_set_subject_name(cert, name) != 1) {
        ERR_("SSLCertStore::spoof[%x]: error setting subject name of certificate",this);
        return NULL;
    }     

    int subjAltName_pos = -1;
    X509_EXTENSION* subjAltName = NULL;
    
    STACK_OF(X509_EXTENSION) *req_exts = NULL;
    if (!(req_exts = X509_REQ_get_extensions(copy))) {
        INF_("SSLCertStore::spoof[%x]: error getting the request's extension",this);
    } else {
        subjAltName_pos = X509v3_get_ext_by_NID(req_exts,OBJ_sn2nid("subjectAltName"),-1);
        subjAltName = X509v3_get_ext(req_exts, subjAltName_pos);
    }

    
    // Setting issuer
    if (!(name = X509_get_subject_name(ca_cert))) {
        ERR_("SSLCertStore::spoof[%x]: error getting subject name from CA certificate",this);
        return NULL;
    }
    if (X509_set_issuer_name(cert, name) != 1) {
        ERR_("SSLCertStore::spoof[%x]: error setting issuer name of certificate",this);
        return NULL;
        
    }
    // set public key in the certificate 
    if ((X509_set_pubkey( cert, pkey)) != 1) {
        ERR_("SSLCertStore::spoof[%x]: error setting public key of the certificate",this);
        return NULL;
    }
    
    // set duration for the certificate
    if (!(X509_gmtime_adj(X509_get_notBefore(cert), 0))) {
        ERR_("SSLCertStore::spoof[%x]: error setting beginning time of the certificate",this);
        return NULL;
    }
    
    #define DAYS_TILL_EXPIRE 365
    #define EXPIRE_SECS (60* 60*24*DAYS_TILL_EXPIRE)

    if (!(X509_gmtime_adj(X509_get_notAfter(cert), EXPIRE_SECS))) {
        ERR_("SSLCertStore::spoof[%x]: error setting ending time of the certificate",this);
        return NULL;
    }

    X509V3_CTX ctx;

    
    // add x509v3 extensions as specified 
    X509V3_set_ctx(&ctx, ca_cert, cert, NULL, NULL, 0);
    for (int i = 0; i < EXT_COUNT; i++) {

        X509_EXTENSION * ext;
        if (!(ext = X509V3_EXT_conf(NULL, &ctx, ext_ent[i].key, ext_ent[i].value))) {
            WAR_("SSLCertStore::spoof[%x]: error on \"%s = %s\"",this,ext_ent[i].key, ext_ent[i].value);
            WAR_("SSLCertStore::spoof[%x]: error creating X509 extension object",this);
            continue;
        }
        if (!X509_add_ext(cert, ext, -1)) {
            ERR_("SSLCertStore::spoof[%x]: error on \"%s = %s\"",this,ext_ent[i].key, ext_ent[i].value);
            ERR_("SSLCertStore::spoof[%x]: error adding X509 extension into certificate",this);
        }
        X509_EXTENSION_free(ext);
    }
    
    if(subjAltName != NULL) {
        if (!X509_add_ext(cert, subjAltName, -1)) {
            ERR_("SSLCertStore::spoof[%x]: error adding subjectAltName to certificate",this);
            return NULL;
        }
    }
    
    // sign the certific ate with the CA private key 
    if (EVP_PKEY_type(ca_key->type) == EVP_PKEY_DSA) {
        digest = EVP_dss1();
    }
    else if (EVP_PKEY_type(ca_key->type) == EVP_PKEY_RSA ) {
        digest = EVP_sha1();
    }
    else {
        ERR_("SSLCertStore::spoof[%x]: error checking CA private key for a valid digest",this);
        return NULL;
    }

    if (!(X509_sign(cert, ca_key, digest))) {
        ERR_("SSLCertStore::spoof[%x]: error signing certificate",this);
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

std::string SSLCertStore::print_cert(X509* x) {
    char tmp[512];
    std::string s;

    // get info from the peer certificate
    X509_NAME_get_text_by_NID(X509_get_subject_name(x),NID_commonName, tmp,512);
    s.append("Common Name: ");
    s.append(tmp);
    s.append("\n ");
    

    X509_NAME_oneline(X509_get_subject_name(x), tmp, 512);
    s.append("Subject: ");
    s.append(tmp);
    s.append("\n ");
    
    X509_NAME* issuer = X509_get_issuer_name(x);
    if(!issuer) {
    s.append("# Issuer: <unable to obtain issuer from certificate> \n ");
    } else {
        X509_NAME_oneline(issuer,tmp,512);
        s.append(string_format("Issuer: '%s'\n ",tmp));
        s.append("\n ");
        
    }
    
    int pkey_nid = OBJ_obj2nid(x->cert_info->key->algor->algorithm);
    const char* sslbuf = OBJ_nid2ln(pkey_nid);
    s.append("Signature type: ");
    s.append(sslbuf);
    s.append("\n ");

    ASN1_TIME *not_before = X509_get_notBefore(x);
    ASN1_TIME *not_after = X509_get_notAfter(x);            
    
    convert_ASN1TIME(not_before, tmp, 512);    
    s.append("Valid from: ");
    s.append(tmp);
    s.append("\n ");
    convert_ASN1TIME(not_after, tmp, 512);
    s.append("Valid to: ");
    s.append(tmp);
    s.append("\n ");


    STACK_OF(X509_EXTENSION) *exts = x->cert_info->extensions;

    int num_of_exts;
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
            BIO_set_close(ext_bio, BIO_CLOSE);
        
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
                OBJ_obj2txt(tmp, 512, (const ASN1_OBJECT *) obj, 1);
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
    return s;
            
}

SSLCertStore::~SSLCertStore() {
    destroy();
}
