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

#include <cassert>

#include <sslmitmcom.hpp>
#include <hostcx.hpp>



template <class SSLProto>
bool baseSSLMitmCom<SSLProto>::check_cert(const char* peer_name) {
    auto const& log = log::mitm();
    
    _deb("SSLMitmCom::check_cert: called");
    bool r = SSLProto::check_cert(peer_name);
    X509* cert = SSL_get_peer_certificate(SSLProto::sslcom_ssl);
    
    auto* remote = dynamic_cast<baseSSLMitmCom*>(this->peer());
    
    if(remote) {
        remote->sslcom_server_ = true;
        
        SpoofOptions spo;
        spo.sni = this->sslcom_sni();

        if (this->verify_get() != verify_status_t::VRF_OK) {
            if(not this->opt.cert.failed_check_replacement) {
                spo.self_signed = true;
            } else {

                // we WILL pretend target certificate is OK 
                spo.self_signed = false;

                // there is problem, and we do relaxed cert check. Add DNS and IP SAN,
                // to raise significantly possibility to pass e.g. browser checks
                if(this->sslcom_sni().size() > 0) {
                    spo.sans.push_back(string_format("DNS:%s", this->sslcom_sni().c_str()));
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

            for(std::string const& candidate: hostnames) {
                _dia("Target server SAN/CN line: %s",candidate.c_str());

                std::vector<std::string> can_dns = string_split(candidate,',');
                for(std::string const& can_dns_item: can_dns) {
                    std::string item = string_trim(can_dns_item);
                    _dia("           SAN/CN entry: '%s'",item.c_str());

                    if(not this->sslcom_sni().empty()) {
                        if(item.size() > 4 && item.find("DNS:") == 0) {
                            item = item.substr(4);
                            std::transform(item.begin(), item.end(), item.begin(), ::tolower);


                            // wildcard
                            if(item.find("*.") == 0) {
                                std::string sni_wild;

                                std::size_t firstdot = this->sslcom_sni().find(".");
                                if( firstdot != std::string::npos) {
                                    sni_wild = "*" + this->sslcom_sni().substr(firstdot);
                                    std::transform(sni_wild.begin(), sni_wild.end(), sni_wild.begin(), ::tolower);
                                }

                                if(sni_wild == item) {
                                    _dia("Matched sni wildcard: '%s' to cert san/cn wildcard: '%s'",sni_wild.c_str(),item.c_str());
                                    validated = true;
                                    validated_san = "DNS:" + item;
                                    break;
                                }
                            }
                            // FQDN
                            else {

                                std::string sni = this->sslcom_sni();
                                std::transform(sni.begin(), sni.end(), sni.begin(), ::tolower);

                                if(this->sslcom_sni() == item) {
                                    _dia("Matched sni: '%s' to cert san/cn: '%s'", this->sslcom_sni().c_str(), item.c_str());
                                    validated = true;
                                    validated_san = "DNS:" + item;
                                    break;
                                }
                            }
                        }
                    } else if(item.size() > 3 && item.find("IP:") == 0) {
                        item = item.substr(3);

                        if(this->owner_cx() && (this->owner_cx()->host() == item)) {
                            _dia("Comparing IP: '%s' to cert san/cn: '%s'",this->owner_cx()->host().c_str(),item.c_str());
                            validated = true;
                            validated_san = "IP:" + item;
                            break;
                        }
                    } else {
                        _dia("   ignoring item: %s", item.c_str());
                    }
                }


                if(validated){
                    break;
                }
            }

            if(validated) {
                _dia("SSL hostname check succeeded on %s",validated_san.c_str());
            }
            else {
                _war("SSL hostname check failed (sni %s).", this->sslcom_sni().c_str());
                this->verify_bitset(verify_status_t::VRF_HOSTNAME_FAILED);

                if(!this->opt.cert.failed_check_replacement) {
                    spo.self_signed = true;
                } else {
                    // if neither DNS nor IP could be added, fallback to self-signed cert
                    spo.self_signed = true;

                    if(not this->sslcom_sni().empty()) {
                        spo.sans.push_back(string_format("DNS:%s", this->sslcom_sni().c_str()));
                        spo.self_signed = false;
                    }
                    else if(this->owner_cx()) {
                        // we WILL pretend target certificate is OK 
                        spo.sans.push_back(string_format("IP:%s",this->owner_cx()->host().c_str()));
                        spo.self_signed = false;
                    }
                }

            }

        }


        if(remote->sslcom_server_) {
            
            if(! this->sslcom_peer_sni_shortcut) {
                _dia("SSLMitmCom::check_cert[%x]: slow-path, calling to spoof peer certificate",this);
                r = remote->spoof_cert(cert, spo);
                if (r) {
                    // this is inefficient: many SSLComs are already initialized, this is running it once 
                    // more ...
                    // check if is waiting would help
                    if (remote->sslcom_waiting) {
                        if(not remote->upgraded()) {
                            remote->init_server();
                            remote->upgraded(true);
                        } else {
                            _dia("remote is already upgraded");
                        }
                    } else {
                        _war("Trying to init SSL server while it's already running!");
                    } 
                }
            } else {
                _dia("SSLMitmCom::check_cert[%x]: fast-path, spoof not necessary",this);
            }
        } else {
            _war("SSLMitmCom::check_cert[%x]: cannot spoof, peer is not SSL server",this);
        }
    } else {
        _war("SSLMitmCom::check_cert: cannot set peer's cert to spoof: peer is not SSLMitmCom type");
    }
    
    X509_free(cert);
    return r;
}


template <class SSLProto>
bool baseSSLMitmCom<SSLProto>::use_cert_sni(SpoofOptions &spo) {
    auto const& log = log::mitm();

    if (not spo.sni.empty()) {
        _dia("SSLMitmCom::use_cert_sni: looking for certificate bound to SNI '%s'", spo.sni.c_str());

        auto parek = this->factory()->find_custom("sni:" + spo.sni);
        if (parek) {
            _dia("SSLMitmCom::use_cert_sni: factory found SNI match: '%s'", spo.sni.c_str());

            this->sslcom_pref_cert = parek.value().chain.cert;
            this->sslcom_pref_key = parek.value().chain.key;

            auto custom_ctx = parek.value().ctx;
            if(custom_ctx)
                this->sslcom_pref_ctx = custom_ctx;

            return true;
        }
    }

    return false;
}

template <class SSLProto>
bool baseSSLMitmCom<SSLProto>::use_cert_ip(SpoofOptions &spo) {
    auto const& log = log::mitm();


    if (this->owner_cx() and this->owner_cx()->peer()) {
        auto address = this->owner_cx()->peer()->host();
        _dia("SSLMitmCom::use_cert_ip: looking for certificate bound to IP '%s'", address.c_str());

        if(not address.empty()) {
            auto parek = this->factory()->find_custom("ip:" + address);
            if (parek) {
                _dia("SSLMitmCom::use_cert_ip: factory found IP match: '%s'", address.c_str());

                this->sslcom_pref_cert = parek.value().chain.cert;
                this->sslcom_pref_key = parek.value().chain.key;

                auto custom_ctx = parek.value().ctx;
                if(custom_ctx) {
                    _dia("SSLMitmCom::use_cert_ip: custom context set");
                    this->sslcom_pref_ctx = custom_ctx;
                }

                return true;
            }
        }
    }

    return false;
}

template <class SSLProto>
bool baseSSLMitmCom<SSLProto>::use_cert_mitm(X509 *cert_orig, SpoofOptions &spo) {
    auto const& log = log::mitm();

    _deb("SSLMitmCom::use_cert_mitm: about to spoof certificate!");

    std::string store_key = SSLFactory::make_store_key(cert_orig, spo);

    auto parek = this->factory()->find_mitm(store_key);
    if (parek.has_value()) {
        _dia("SSLMitmCom::use_cert_mitm: factory found '%s'", store_key.c_str());
        this->sslcom_pref_cert = parek.value().chain.cert;
        this->sslcom_pref_key = parek.value().chain.key;

        auto custom_ctx = parek.value().ctx;
        if(custom_ctx)
            this->sslcom_pref_ctx = custom_ctx;

        return true;
    }
    else {

        _dia("SSLMitmCom::use_cert_mitm: NOT found '%s'", store_key.c_str());

        auto spoof_ret = this->factory()->spoof(cert_orig, spo.self_signed, &spo.sans);
        if(not spoof_ret.has_value()) {
            _war("SSLMitmCom::use_cert_mitm: factory failed to spoof '%s' - default will be used", store_key.c_str());
            return false;
        }
        else {
            this->sslcom_pref_cert = spoof_ret.value().chain.cert;
            this->sslcom_pref_key  = spoof_ret.value().chain.key;

            auto custom_ctx = spoof_ret.value().ctx;
            if(custom_ctx)
                this->sslcom_pref_ctx = custom_ctx;

#ifdef USE_OPENSSL11
            EVP_PKEY_up_ref(this->sslcom_pref_key);
#else
            // just increment key refcount, cert is new (made from key), thus refcount is already 1
            CRYPTO_add(&this->sslcom_pref_key->references,+1,CRYPTO_LOCK_EVP_PKEY);
#endif //USE_OPENSSL11

            if (!this->factory()->add_mitm(store_key, spoof_ret.value())) {
                _dia("SSLMitmCom::use_cert_mitm: spoofed, but cache failed to update with %s", store_key.c_str());
                return true;
            }
        }
    }

    return true;
}

template <class SSLProto>
bool baseSSLMitmCom<SSLProto>::spoof_cert(X509* cert_orig, SpoofOptions& spo) {
    auto const& log = log::mitm();


    auto lc_ = std::scoped_lock(this->factory()->lock());

    if(this->opt.cert.mitm_cert_sni_search && this->use_cert_sni(spo)) return true;

    if(this->opt.cert.mitm_cert_ip_search && this->use_cert_ip(spo)) return true;

    return use_cert_mitm(cert_orig, spo);
}


#endif

