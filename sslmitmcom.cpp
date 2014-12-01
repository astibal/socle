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

#include <sslmitmcom.hpp>

int SSLMitmCom::log_level = NON;

bool SSLMitmCom::check_cert(const char* peer_name) {
    
    DEBS__("SSLMitmCom::check_cert: called");
    bool r = SSLCom::check_cert(peer_name);
    X509* cert = SSL_get_peer_certificate(SSLCom::sslcom_ssl);
    
    SSLMitmCom* p = dynamic_cast<SSLMitmCom*>(peer());
    
    if(p) {
        
        // FIXME: this is not right, design another type of test
        p->sslcom_server = true;
        
        if(p->sslcom_server) {
            DEB__("SSLMitmCom::check_cert[%x]: calling to spoof peer certificate",this);
            r = p->spoof_cert(cert);
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
            WAR__("SSLMitmCom::check_cert[%x]: cannot spoof, peer is not SSL server",this);
        }
    } else {
        WARS__("SSLMitmCom::check_cert: cannot set peer's cert to spoof: peer is not SSLMitmCom type");
    }
    
    X509_free(cert);
    return r;
}

bool SSLMitmCom::spoof_cert(X509* cert_orig) {
    char tmp[512];
    DEB__("SSLMitmCom::spoof_cert[%x]: about to spoof certificate!",this);
    
    
    // get info from the peer certificate
    //
    // not used at this time
    // X509_NAME_get_text_by_NID(X509_get_subject_name(cert_orig),NID_commonName, tmp,512);
    // std::string cn(tmp);
    
    X509_NAME_oneline( X509_get_subject_name(cert_orig) , tmp, 512);
    std::string subject(tmp);
    
    
    // cache lookup
    X509_PAIR* parek = certstore()->find(subject);
    if (parek) {
        DIA__("SSLMitmCom::spoof_cert[%x]: certstore hit for '%s'",this,subject.c_str());
        sslcom_pref_cert = parek->second;
        sslcom_pref_key = parek->first;
        
        return true;
    }
    
  
    DIA__("SSLMitmCom::spoof_cert[%x]: NOT in my certstore '%s'",this,subject.c_str());    
    
    parek = certstore()->spoof(cert_orig);
    if(!parek) {
        WAR__("SSLMitmCom::spoof_cert[%x]: certstore failed to spoof '%d' - default will be used",this,subject.c_str()); 
        return false;
    } 
    else {
        sslcom_pref_cert = parek->second;
        sslcom_pref_key  = parek->first;
    }
    
    if (! certstore()->add(subject,parek)) {
        DIA__("SSLMitmCom::spoof_cert[%x]: spoof was successful, but cache add failed for %s",this,subject.c_str());
        return true;
    }
    
    return true;
}
