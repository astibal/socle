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
        } else {
            
            // If certificate is formally valid, see if it also matches SNI. This is extra check,
            // to avoid SNI evasions.
            
            std::vector<std::string> hostnames = SSLFactory::get_sans(cert);
            hostnames.push_back("DNS:"+SSLFactory::print_cn(cert));
            
            bool validated = false;
            std::string validated_san;
            
            for(std::string& candidate: hostnames) {
                DIA___("Target server SAN/CN line: %s",candidate.c_str());
                
                std::vector<std::string> can_dns = string_split(candidate,',');
                for(std::string can_dns_item: can_dns) {
                    std::string item = string_trim(can_dns_item);
                    DIA___("           SAN/CN entry: '%s'",item.c_str());   
                    
                    if(this->sslcom_peer_hello_sni().size() > 0) {
                        if(item.size() > 4 && item.find("DNS:") == 0) {
                            item = item.substr(4);
                            std::transform(item.begin(), item.end(), item.begin(), ::tolower);
                            
                            
                            // wildcard
                            if(item.find("*.") == 0) {
                                std::string sni_wild;
                                
                                std::size_t firstdot = this->sslcom_peer_hello_sni().find(".");
                                if( firstdot != std::string::npos) {
                                    sni_wild = "*" + this->sslcom_peer_hello_sni().substr(firstdot);
                                    std::transform(sni_wild.begin(), sni_wild.end(), sni_wild.begin(), ::tolower);
                                }
                                
                                if(sni_wild == item) {
                                    DIA___("Matched sni wildcard: '%s' to cert san/cn wildcard: '%s'",sni_wild.c_str(),item.c_str());
                                    validated = true;
                                    validated_san = "DNS:" + item;
                                    break;
                                }
                            } 
                            // FQDN 
                            else {
                                
                                std::string sni = this->sslcom_peer_hello_sni();
                                std::transform(sni.begin(), sni.end(), sni.begin(), ::tolower);
                                
                                if(this->sslcom_peer_hello_sni() == item) {
                                    DIA___("Matched sni: '%s' to cert san/cn: '%s'",this->sslcom_peer_hello_sni().c_str(),item.c_str());
                                    validated = true;
                                    validated_san = "DNS:" + item;
                                    break;
                                }
                            }
                        }
                    } else if(item.size() > 3 && item.find("IP:") == 0) {
                        item = item.substr(3);
                        
                        if(this->owner_cx() && (this->owner_cx()->host() == item)) {
                            DIA___("Comapring IP: '%s' to cert san/cn: '%s'",this->owner_cx()->host().c_str(),item.c_str());
                            validated = true;
                            validated_san = "IP:" + item;
                            break;
                        }
                    } else {
                        DIA___("   ignoring item: %s", item.c_str());
                    } 
                }
                
                
                if(validated){
                    break;
                }
            }
            
            if(validated) {
                LOG___(loglevel(iDIA,0),"SSL hostname check succeeded on %s",validated_san.c_str());
            }
            else {
                LOG___(loglevel(iWAR,0),"SSL hostname check failed (sni %s).",this->sslcom_peer_hello_sni().c_str());
                this->verify_set(this->HOSTNAME_FAILED);

                if(!this->opt_failed_certcheck_replacement) {
                    spo.self_signed = true;
                } else {
                    // if neither DNS nor IP could be added, fallback to self-signed cert
                    spo.self_signed = true;
                    
                    if(this->sslcom_peer_hello_sni().size()) {
                        spo.sans.push_back(string_format("DNS:%s",this->sslcom_peer_hello_sni().c_str()));
                        spo.self_signed = false;
                    }
                    else
                    if(this->owner_cx()) {
                        // we WILL pretend target certificate is OK 
                        spo.sans.push_back(string_format("IP:%s",this->owner_cx()->host().c_str()));
                        spo.self_signed = false;
                    }                    
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
    DEB__("SSLMitmCom::spoof_cert[%x]: about to spoof certificate!",this);
    // get info from the peer certificate
    //
    // not used at this time
    // X509_NAME_get_text_by_NID(X509_get_subject_name(cert_orig),NID_commonName, tmp,512);
    // std::string cn(tmp);

    std::scoped_lock<std::recursive_mutex> l_(this->certstore()->lock());

    std::string store_key = SSLFactory::make_store_key(cert_orig, spo);
    X509_PAIR* parek = nullptr;

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

#ifdef USE_OPENSSL11
            EVP_PKEY_up_ref(this->sslcom_pref_key);
#else
            // just increment key refcount, cert is new (made from key), thus refcount is already 1
            CRYPTO_add(&this->sslcom_pref_key->references,+1,CRYPTO_LOCK_EVP_PKEY);
#endif //USE_OPENSSL11
        }
        
        if (! this->certstore()->add(store_key,parek)) {
            DIA__("SSLMitmCom::spoof_cert[%x]: spoof was successful, but cache add failed for %s",this,store_key.c_str());
            return true;
        }
    }
        
    return true;
}


#endif

