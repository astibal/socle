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
#include <internet.hpp>



template <class SSLProto>
bool baseSSLMitmCom<SSLProto>::check_cert(const char* peer_name) {
    auto const& log = log::mitm();
    
    _deb("SSLMitmCom::check_cert: called");
    bool r = SSLProto::check_cert(peer_name);
    if (not r) {
        return false;
    }
#ifdef USE_OPENSSL300
    X509* cert = const_cast<X509*>(SSL_get0_peer_certificate(SSLProto::sslcom_ssl));
#else
    X509* cert = SSL_get_peer_certificate(SSLProto::sslcom_ssl);
#endif
    auto* remote = dynamic_cast<baseSSLMitmCom*>(this->peer());
    const std::string& client_sni = remote && !remote->sslcom_sni().empty()
        ? remote->sslcom_sni() : this->sslcom_sni();

    if (not cert) {
        _err("SSLMitmCom::check_cert: upstream handshake provided no peer certificate");
        return false;
    }

    if(remote) {
        remote->sslcom_server_ = true;
        
        SpoofOptions spo;
        spo.sni = client_sni;
        auto add_client_sni = [&]() {
            if(client_sni.empty()) return;
            const bool sni_is_ip = inet::is_ipv4_address(client_sni) ||
                                   inet::is_ipv6_address(client_sni);
            const std::string san = (sni_is_ip ? "IP:" : "DNS:") + client_sni;
            if(std::find(spo.sans.begin(), spo.sans.end(), san) == spo.sans.end())
                spo.sans.push_back(san);
        };

        // Routing may rewrite only the origin-facing SNI. The certificate
        // presented back to the client must retain the identity it requested.
        if(client_sni != this->sslcom_sni())
            add_client_sni();

        if (this->verify_get() != verify_status_t::VRF_OK) {
            if(not this->opt.cert.failed_check_replacement) {
                spo.self_signed = true;
            } else {

                // we WILL pretend target certificate is OK 
                spo.self_signed = false;

                // there is problem, and we do relaxed cert check. Add DNS and IP SAN,
                // to raise significantly possibility to pass e.g. browser checks
                add_client_sni();
                if(this->owner_cx()) {
                    spo.sans.push_back(string_format("IP:%s",this->owner_cx()->host().c_str()));
                }
            }
        } else {

            // If certificate is formally valid, see if it also matches SNI. This is extra check,
            // to avoid SNI evasions.

            bool validated = false;
            if(not this->sslcom_sni().empty()) {
                if(inet::is_ipv4_address(this->sslcom_sni()) ||
                   inet::is_ipv6_address(this->sslcom_sni())) {
                    validated = X509_check_ip_asc(
                        cert, this->sslcom_sni().c_str(), 0) == 1;
                } else {
                    validated = X509_check_host(
                        cert, this->sslcom_sni().c_str(), this->sslcom_sni().size(),
                        0, nullptr) == 1;
                }
            } else if(this->owner_cx()) {
                validated = X509_check_ip_asc(
                    cert, this->owner_cx()->host().c_str(), 0) == 1;
            }

            if(validated) {
                _dia("SSL hostname check succeeded");
            }
            else {
                _war("SSL hostname check failed (sni '%s').", this->sslcom_sni().c_str());
                this->verify_bitset(verify_status_t::VRF_HOSTNAME_FAILED);

                if(!this->opt.cert.failed_check_replacement) {
                    spo.self_signed = true;
                } else {
                    // if neither DNS nor IP could be added, fallback to self-signed cert
                    spo.self_signed = true;

                    if(not client_sni.empty()) {
                        add_client_sni();
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
                            if (remote->sslcom_ssl) {
                                remote->upgraded(true);
                            } else {
                                _err("SSLMitmCom::check_cert: failed to initialize client-facing TLS state");
                                r = false;
                            }
                        } else {
                            _dia("remote is already upgraded");
                        }
                    } else {
                        _war("Trying to init SSL server while it's already running!");
                        r = false;
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
    
#ifndef USE_OPENSSL300
    X509_free(cert);
#endif
    return r;
}

template <class SSLProto>
bool baseSSLMitmCom<SSLProto>::use_cert_null() {
    auto const& log = log::mitm();

    _dia("SSLMitmCom::use_cert_null: unsetting certifiace key-pair");
    this->sslcom_pref_cert = nullptr;
    this->sslcom_pref_key = nullptr;

    return false;
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

    // Serialize only callers creating the same (or same-shard) certificate.
    // Unrelated cold SNI handshakes may sign in parallel, while the second
    // lookup below still prevents duplicate generation for one cache key.
    auto key_lock = std::scoped_lock(this->factory()->mitm_key_lock(store_key));

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


    if(this->opt.cert.mitm_cert_sni_search && this->use_cert_sni(spo)) return true;

    if(this->opt.cert.mitm_cert_ip_search && this->use_cert_ip(spo)) return true;

    if(this->opt.cert.mitm_cert_searched_only) {
        use_cert_null();
        this->error(baseCom::ERROR_UNSPEC);
        return false;
    }

    if(not cert_orig) {
        _err("SSLMitmCom::spoof_cert: missing original certificate");
        use_cert_null();
        this->error(baseCom::ERROR_UNSPEC);
        return false;
    }

    return use_cert_mitm(cert_orig, spo);
}


#endif
