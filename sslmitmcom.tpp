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

#ifndef __SSLMITMCOM_TPP__
#define __SSLMITMCOM_TPP__


#include <sslmitmcom.hpp>
#include <hostcx.hpp>



template <class SSLProto>
bool baseSSLMitmCom<SSLProto>::check_cert(const char* peer_name) {
    
    DEBS__("SSLMitmCom::check_cert: called");
    bool r = SSLProto::check_cert(peer_name);
    X509* cert = SSL_get_peer_certificate(SSLProto::sslcom_ssl);
    
    baseSSLMitmCom* p = dynamic_cast<baseSSLMitmCom*>(this->peer());
    
    if(p != nullptr) {
        // FIXME: this is not right, design another type of test
        p->sslcom_server_ = true;
        
        SpoofOptions spo;
        if (this->verify_status != this->VERIFY_OK) {
            if(!this->opt_failed_certcheck_replacement) {
                spo.self_signed = true;
            } else {
                
                // we WILL pretend target certificate is OK 
                spo.self_signed = false;

                // there is problem, and we do relaxed cert check. Add DNS and IP SAN,
                // to raise significantly possibility to pass e.g. browser checks
                if(this->sslcom_peer_hello_sni().size() > 0) {
                    spo.sans.push_back(string_format("DNS:%s",this->sslcom_peer_hello_sni().c_str()));
                } 
                if(this->owner_cx()) {
                    spo.sans.push_back(string_format("IP:%s",this->owner_cx()->host().c_str()));
                }
            }
        }
        
        
        if(p->sslcom_server_) {
            
            if(! this->sslcom_peer_sni_shortcut) {
                DIA__("SSLMitmCom::check_cert[%x]: slow-path, calling to spoof peer certificate",this);
                r = p->spoof_cert(cert,spo);
                if (r) {
                    // this is inefficient: many SSLComs are already initialized, this is running it once 
                    // more ...
                    // check if is waiting would help
                    if (p->sslcom_waiting) {
                        p->init_server();
                    } else {
                        WARS__("FIXME: Trying to init SSL server while it's already running!");
                    } 
                }
            } else {
                DIA__("SSLMitmCom::check_cert[%x]: fast-path, spoof not necessary",this);
            }
        } else {
            WAR__("SSLMitmCom::check_cert[%x]: cannot spoof, peer is not SSL server",this);
        }
    } else {
        WARS__("SSLMitmCom::check_cert: cannot set peer's cert to spoof: peer is not SSLMitmCom type");
    }
    
    X509_free(cert);
    return r;
}

template <class SSLProto>
bool baseSSLMitmCom<SSLProto>::spoof_cert(X509* cert_orig, SpoofOptions& spo) {
    char tmp[512];
    DEB__("SSLMitmCom::spoof_cert[%x]: about to spoof certificate!",this);
    // get info from the peer certificate
    //
    // not used at this time
    // X509_NAME_get_text_by_NID(X509_get_subject_name(cert_orig),NID_commonName, tmp,512);
    // std::string cn(tmp);
    
    X509_NAME_oneline( X509_get_subject_name(cert_orig) , tmp, 512);
    std::string subject(tmp);
    std::string store_key = subject;
    
    
    X509_PAIR* parek = nullptr;
    
    if(spo.self_signed == true) {
        store_key += "+self_signed";
    }
    
    std::vector<std::string> cert_sans = this->certstore()->get_sans(cert_orig);
    for(auto s1: cert_sans) {
        DUM__("SAN: '%s'",s1.c_str());
        uint32_t c = socle_crc32(0xCABA1A,s1.c_str(),s1.size());
       
        DUM__("SAN CRC32: 0x%x",c);
        store_key += string_format("+san32:%x",c);
    }
    
    if(spo.sans.size() > 0) {
        for(auto san: spo.sans) {
            store_key += string_format("+san:%s",san.c_str());
        }
    }

    // cache lookup - only if it's valid, verified cert
    parek = this->certstore()->find(store_key);
    if (parek) {
        DIA__("SSLMitmCom::spoof_cert[%x]: certstore hit for '%s'",this,store_key.c_str());
        this->sslcom_pref_cert = parek->second;
        this->sslcom_pref_key = parek->first;
        
        return true;
    } 
    else {
    
        DIA__("SSLMitmCom::spoof_cert[%x]: NOT in my certstore '%s'",this,store_key.c_str());    
        
        parek = this->certstore()->spoof(cert_orig,spo.self_signed,&spo.sans);
        if(!parek) {
            WAR__("SSLMitmCom::spoof_cert[%x]: certstore failed to spoof '%d' - default will be used",this,store_key.c_str()); 
            return false;
        } 
        else {
            this->sslcom_pref_cert = parek->second;
            this->sslcom_pref_key  = parek->first;

            // just increment key refcount, cert is new (made from key), thus refcount is already 1
            CRYPTO_add(&this->sslcom_pref_key->references,+1,CRYPTO_LOCK_EVP_PKEY);
        }
        
        if (! this->certstore()->add(store_key,parek)) {
            DIA__("SSLMitmCom::spoof_cert[%x]: spoof was successful, but cache add failed for %s",this,store_key.c_str());
            return true;
        }
    }
        
    return true;
}


#endif

