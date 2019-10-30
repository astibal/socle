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

#ifndef __SSLCOM_INCL__
#define __SSLCOM_INCL__

#include <linux/in6.h>

#include <openssl/rsa.h>
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/dh.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/tls1.h>
#include <openssl/x509_vfy.h>
#include <openssl/ocsp.h>

#include <sslcom.hpp>
#include <sslcom_dh.hpp>
#include <logger.hpp>
#include <display.hpp>
#include <timeops.hpp>

#include <cstdio>
#include <functional>

#include <crc32.hpp>
#include <display.hpp>
#include <buffer.hpp>
#include <internet.hpp>
#include "hostcx.hpp"

template <class L4Proto> std::once_flag baseSSLCom<L4Proto>::openssl_thread_setup_done;
template <class L4Proto> std::once_flag baseSSLCom<L4Proto>::certstore_setup_done;
template <class L4Proto> SSLFactory*  baseSSLCom<L4Proto>::sslcom_certstore_;

template <class L4Proto> int baseSSLCom<L4Proto>::sslcom_ssl_extdata_index = -1;

template <class L4Proto> int baseSSLCom<L4Proto>::counter_ssl_connect = 0;
template <class L4Proto> int baseSSLCom<L4Proto>::counter_ssl_accept = 0;
template <class L4Proto> loglevel baseSSLCom<L4Proto>::log_level = NON;
template <class L4Proto> std::string baseSSLCom<L4Proto>::ci_def_filter = "HIGH RC4 !aNULL !eNULL !LOW !3DES !MD5 !EXP !DSS !PSK !SRP !kECDH !CAMELLIA !IDEA !SEED @STRENGTH";


inline void set_timer_now(struct timeval* t) {
    gettimeofday(t,nullptr);
}

template <class L4Proto>
baseSSLCom<L4Proto>::baseSSLCom(): L4Proto() {

    log = logan::attach<baseSSLCom<L4Proto>>(this);
    log.area("ssl");

    sslcom_peer_hello_buffer.capacity(1500);
    set_timer_now(&timer_start);
    set_timer_now(&timer_read_timeout);
    set_timer_now(&timer_write_timeout);
}

template <class L4Proto>
std::string baseSSLCom<L4Proto>::flags_str()
{
    std::stringstream msg(baseCom::flags_str());
    msg << ":ssl<";

    if(flags_ & HSK_REUSED ) {
        msg << "A";
    }
    else {
        msg << "a";
    }
    msg << ">";

    return msg.str();
}


template <class L4Proto>
void baseSSLCom<L4Proto>::certstore_setup() {
    baseSSLCom::certstore(& SSLFactory::init());
}

template <class L4Proto>
void baseSSLCom<L4Proto>::static_init() {

    baseCom::static_init();

    _deb("SSL: Static INIT");

    // call openssl threads support - only once from all threads!
    std::call_once (baseSSLCom::openssl_thread_setup_done ,THREAD_setup);
    std::call_once (baseSSLCom::certstore_setup_done ,baseSSLCom::certstore_setup);
}


template <class L4Proto>
void baseSSLCom<L4Proto>::init(baseHostCX* owner)  {

    L4Proto::init(owner);
}


template <class L4Proto>
std::string& baseSSLCom<L4Proto>::to_string()  {

    bool online = false;
    if(owner_cx() != nullptr) {
        online = owner_cx()->online_name;
    }

    if(hr_.size() > 0 && ! online) {
        return hr_;
    }

    if(owner_cx() != nullptr) {
        hr_ = owner_cx()->full_name('L');
        return hr_;
    }

    // last resort
    
    hr_ = "baseSSLCom";
    return hr_;
}

// server callback on internal cache miss
template <class L4Proto>
SSL_SESSION* baseSSLCom<L4Proto>::server_get_session_callback(SSL* ssl, const unsigned char* , int, int* ) {
    SSL_SESSION* ret = nullptr;
    auto log = logan::create("ssl.callback");

    void* data = SSL_get_ex_data(ssl, baseSSLCom::extdata_index());
    const char *name = "unknown_cx";
    auto* com = static_cast<baseSSLCom*>(data);
    if(com != nullptr) {
        const char* n = com->hr();
        if(n != nullptr) {
            name = n;
        }
    }

    _inf("lookup server session[%s]: SSL: 0x%x", name, ssl);
    return ret;
}
template <class L4Proto>
int baseSSLCom<L4Proto>::new_session_callback(SSL* ssl, SSL_SESSION* session) {
    auto log = logan::create("ssl.callback");

    void* data = SSL_get_ex_data(ssl, baseSSLCom::extdata_index());
    const char *name = "unknown_cx";
    auto* com = static_cast<baseSSLCom*>(data);
    if(com != nullptr) {
        const char* n = com->hr();
        if(n != nullptr) {
            name = n;
        }
    }

    _inf("new session[%s]: SSL: 0x%x, SSL_SESSION: 0x%x", name, ssl, session);

    return 1;
}



template <class L4Proto>
void baseSSLCom<L4Proto>::ssl_info_callback(const SSL* s, int where, int ret) {

#ifdef USE_OPENSSL11
    // dropping support for this here, new API masks out msg_callback_arg
    // actually we don't need com object, and sufficient debug level
    // messages are printed out in msg callback.
    std::string name = string_format("ssl-0x%x", s);
#else
    std::string name = "unknown_cx";
    baseSSLCom* com = static_cast<baseSSLCom*>(s->msg_callback_arg);
    if(com != nullptr) {
        const char* n = com->hr();
        if(n != nullptr) {
            name = n;
        }
    }
#endif
    const char *str;
    auto log = logan::create("ssl.callback");

    int w = where& ~SSL_ST_MASK;

    if (w & SSL_ST_CONNECT) str="SSL_connect";
    else if (w & SSL_ST_ACCEPT) str="SSL_accept";
    else str="undefined";

    if (where & SSL_CB_LOOP)
    {
        _deb("[%s]: SSLCom::ssl_info_callback: %s:%s",name.c_str(),str,SSL_state_string_long(s));
    }
    else if (where & SSL_CB_ALERT)
    {
        str=(where & SSL_CB_READ)?"read":"write";
        _dia("[%s]: SSLCom::ssl_info_callback: SSL3 alert %s:%s:%s", name.c_str(), str, SSL_alert_type_string_long(ret), SSL_alert_desc_string_long(ret));
    }
    else if (where & SSL_CB_EXIT)
    {
        if (ret == 0) {
            _deb("[%s]: SSLCom::ssl_info_callback: %s:failed in %s", name.c_str(), str,SSL_state_string_long(s));

#ifndef USE_OPENSSL11
            // close the session
            if(com != nullptr)
                if(com->owner_cx() != nullptr) {
                    com->owner_cx()->error(true);
                    _dia("[%s]: failure callback, owning CX error flag set", name.c_str());
                }
#endif
        }
        else if (ret < 0)  {
            _deb("[%s]: SSLCom::ssl_info_callback %s:error in %s", name.c_str(), str,SSL_state_string_long(s));
        }
    }

}

template <class L4Proto>
void baseSSLCom<L4Proto>::log_profiling_stats(unsigned int lev) {
    
    baseSSLCom* com = this;
    const char *name = "unknown_cx";
    const char* n = com->hr();
    if(n != nullptr) {
        name = n;
    }

    log.log(loglevel(lev,0), "  [%s]: prof_accept_cnt %d, prof_connect_cnt %d, prof_peek_cnt %d, prof_read_cnt %d, prof_want_read_cnt %d, prof_want_write_cnt %d, prof_write_cnt %d",name, com->prof_accept_cnt   , com->prof_connect_cnt   , com->prof_peek_cnt   , com->prof_read_cnt   , com->prof_want_read_cnt   , com->prof_want_write_cnt   , com->prof_write_cnt);
    log.log(loglevel(lev,0), "  [%s]: prof_accept_ok %d, prof_connect_ok %d",name, com->prof_accept_ok, com->prof_connect_ok);
}

template <class L4Proto>
void baseSSLCom<L4Proto>::ssl_msg_callback(int write_p, int version, int content_type, const void* buf, size_t len, SSL* ssl, void* arg)
{
    const char *msg_version;
    std::string msg_version_unknown;
    const char *msg_direction;
    const char *msg_content_type;
    std::string msg_content_unknown;

    const char *name = "unknown_cx";

    auto log = logan::create("ssl");

    baseSSLCom* com = static_cast<baseSSLCom*>(arg);
    if(com != nullptr) {
        const char* n = com->hr();
        if(n != nullptr) {
            name = n;
        }
    }

    switch (version) {
        case 0:
            msg_version = "pseudo";
            break;
        case SSL2_VERSION:
            msg_version = "ssl2";
            break;
        case SSL3_VERSION:
            msg_version = "ssl3";
            break;
        case TLS1_VERSION:
            msg_version = "tls1.0";
            break;
        case TLS1_1_VERSION:
            msg_version = "tls1.1";
            break;
        case TLS1_2_VERSION:
            msg_version = "tls1.2";
            break;
#ifdef USE_OPENSSL111
        case TLS1_3_VERSION:
            msg_version = "tls1.3";
            break;
#endif

        default:
            msg_version_unknown = string_format("Unknown-%d", version);
            msg_version = msg_version_unknown.c_str();
    }

    switch(content_type) {

        case SSL3_RT_CHANGE_CIPHER_SPEC:
            msg_content_type = "ChangeCipherSpec";
            break;
        case SSL3_RT_ALERT:
            msg_content_type = "Alert";
            break;
        case SSL3_RT_HANDSHAKE:
            msg_content_type = "Handshake";
            break;
        case SSL3_RT_APPLICATION_DATA:
            msg_content_type = "ApplicationData";
            break;
        case SSL3_RT_HEADER:
            msg_content_type = "RtHeader";
            break;
#ifdef USE_OPENSSL111
        case SSL3_RT_INNER_CONTENT_TYPE:
            msg_content_type = "InnerContent";
            break;

#endif

        default:
            msg_content_unknown = string_format("Unknown-%d", content_type);
            msg_content_type = msg_content_unknown.c_str();
    }

    if(write_p == 0) {
        msg_direction = "received";
    } else {
        msg_direction = "sent";
    }

    _deb("[%s]: SSLCom::ssl_msg_callback: %s/%s has been %s",name,msg_version,msg_content_type,msg_direction);

    if(content_type == 21) {
        _dum("[%s]: SSLCom::ssl_msg_callback: alert dump:\n%s",name,hex_dump((unsigned char*)buf,len).c_str());
        uint16_t int_code = ntohs(buffer::get_at_ptr<uint16_t>((unsigned char*)buf));
        uint8_t level = buffer::get_at_ptr<uint8_t>((unsigned char*)buf);
        uint8_t code = buffer::get_at_ptr<uint8_t>((unsigned char*)buf+1);
        if(com) {
            _dia("[%s]: SSLCom::ssl_msg_callback: alert info: %s/%s [%d/%d]",name,SSL_alert_type_string_long(int_code),SSL_alert_desc_string_long(int_code),level,code);

            
            if(code == 10) {
                // unexpected message
                com->log_profiling_stats(iDEB);
            }
            
            // if level is Fatal, log com error and close. 
            if(level > 1) {
                _err("[%s]: SSL alert: %s/%s [%d/%d]",name,SSL_alert_type_string_long(int_code),SSL_alert_desc_string_long(int_code),level,code);
                com->error(ERROR_UNSPEC);
            }
            
        }
    }
    else if(content_type ==20) {
        if(write_p == 0) {
            if(!com->is_server()) {

#ifndef USE_OPENSSL11
                int bits = check_server_dh_size(ssl);
                if(bits < 768) {
                    if(bits > 0) {
                        _war("  [%s]: server dh key bits equivalent: %d",name,bits);
                        SSL_shutdown(ssl);
                        if(com->owner_cx() != nullptr) {
                            com->owner_cx()->error(true);
                        }
                    } else {
                        _war("  [%s]: PFS not used!",name);
                    }
                } else {
                    _dia("  [%s]: server dh key bits equivalent: %d",name,bits);
                }
#endif
            }
        }
    }
}


template <class L4Proto>
int baseSSLCom<L4Proto>::check_server_dh_size(SSL* ssl) {
#ifdef USE_OPENSSL11
    // FIXME: adapt 1.0.2 API code to 1.1.x.
    // Currently it doesn't seem to be possible to get DH parameters for current SSL_SESSION

    // Workaround: return acceptable strength. Ugly.

    // see DH_check() for more DH tests!

    return 1024;
#else

    auto log = logan::create("ssl");

    _deb("Checking peer DH parameters:");
    if(ssl != nullptr) {
        if (ssl->session != nullptr) {
            if(ssl->session->sess_cert != nullptr) {
                DH* dh = ssl->session->sess_cert->peer_dh_tmp;
                if(dh != nullptr) {
                    int s = DH_size(dh)*8;
                    _deb("Server DH size: %d",s);
                    return s;
                }
                else if (ssl->session->sess_cert->peer_ecdh_tmp != nullptr) {
                    EC_KEY* ec = ssl->session->sess_cert->peer_ecdh_tmp;
                    _deb("check_server_dh_size: have peer ecdh key");
                    EC_POINT* pub = ec->pub_key;
                    int xb = BN_num_bits(&pub->X);
                    int yb = BN_num_bits(&pub->Y);
                    _deb("check_server_dh_size: have peer ecdh key size: %d,%d",xb,yb);

                    // maybe  there is better formula than *6.
                    if(xb < yb) return xb*6;
                    return yb*6;
                }
                else {
                    _deb("check_server_dh_size: both dh and ecdh is null");
                }
            } else {
                _deb("check_server_dh_size: sess_cert is null");
            }
        } else {
            _deb("check_server_dh_size: session is null");
        }
    } else {
        _deb("check_server_dh_size: ssl is null");
    }
    _deb("done.");
    return 0;
#endif
}

template <class L4Proto>
int baseSSLCom<L4Proto>::ssl_client_vrfy_callback(int ok, X509_STORE_CTX *ctx) {

    X509 * err_cert = X509_STORE_CTX_get_current_cert(ctx);
    int err =   X509_STORE_CTX_get_error(ctx);
    int depth = X509_STORE_CTX_get_error_depth(ctx);
    int idx = SSL_get_ex_data_X509_STORE_CTX_idx();
    int ret = ok;

    auto log = logan::create("ssl");

    _deb("SSLCom::ssl_client_vrfy_callback: data index = %d, ok = %d, depth = %d",idx,ok,depth);

    SSL* ssl = static_cast<SSL*>(X509_STORE_CTX_get_ex_data(ctx, SSL_get_ex_data_X509_STORE_CTX_idx()));
    void* data = SSL_get_ex_data(ssl, sslcom_ssl_extdata_index);
    const char *name = "unknown_cx";

    baseSSLCom* com = static_cast<baseSSLCom*>(data);
    if(com != nullptr) {
        
        auto* pcom = dynamic_cast<baseSSLCom*>(com->peer());
        if(pcom != nullptr) {
            const char* n = pcom->hr();
            if(n != nullptr) {
                name = n;
            }
        }
        else {
            const char* n = com->hr();
            if(n != nullptr) {
                name = n;
            }
        }
    }

    X509* xcert = X509_STORE_CTX_get_current_cert(ctx);

    if(com != nullptr) {
        if (depth == 0) {
            if(com->sslcom_target_cert) { _err("already having peer cert"); X509_free(com->sslcom_target_cert); }
            com->sslcom_target_cert = X509_dup(xcert);
        }
        else if (depth == 1) {
            if(com->sslcom_target_issuer) { _err("already having peer issuer"); X509_free(com->sslcom_target_issuer); }
            com->sslcom_target_issuer = X509_dup(xcert);
        }
        else if (depth == 2) {
            if(com->sslcom_target_issuer_issuer)  { _err("already having peer issuer_issuer"); X509_free(com->sslcom_target_issuer_issuer); }
            com->sslcom_target_issuer_issuer = X509_dup(xcert);
        }
    }

    if (!ok) {
        if (err_cert) {
            _dia("[%s]: SSLCom::ssl_client_vrfy_callback: '%s' issued by '%s'",name,SSLFactory::print_cn(err_cert).c_str(),
                  SSLFactory::print_issuer(err_cert).c_str());
        }
        else {
            _dia("[%s]: SSLCom::ssl_client_vrfy_callback: no server certificate",name);
        }
        _dia("[%s]: SSLCom::ssl_client_vrfy_callback: %d:%s",name, err, X509_verify_cert_error_string(err));
    }

    switch (err)  {
        case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
        case X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE:
        case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:

            _dia("[%s]: SSLCom::ssl_client_vrfy_callback: unknown issuer: %d", name, err);

            if(com != nullptr) {
                com->verify_set(UNKNOWN_ISSUER);
                if(com->opt_allow_unknown_issuer) {
                    ret = 1;
                } 
                if(com->opt_failed_certcheck_replacement) {
                    ret = 1;
                }            
            }
        case X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN:
        case X509_V_ERR_CERT_UNTRUSTED:

            _dia("[%s]: SSLCom::ssl_client_vrfy_callback: self-signed cert in the chain: %d", name, err);

            if(com != nullptr) {
                com->verify_set(SELF_SIGNED_CHAIN);
                if(com->opt_allow_self_signed_chain) {
                    ret = 1;
                }
                if(com->opt_failed_certcheck_replacement) {
                    ret = 1;
                }
            }

            break;
        case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:

            _dia("[%s]: SSLCom::ssl_client_vrfy_callback: end-entity cert is self-signed: %d", name, err);

            if(com != nullptr) {
                com->verify_set(SELF_SIGNED);
                if(com->opt_allow_self_signed_cert) {
                    ret = 1;
                }
                if(com->opt_failed_certcheck_replacement) {
                    ret = 1;
                }
            }
                
            break;

        case X509_V_ERR_CERT_NOT_YET_VALID:
        case X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD:
            _dia("[%s]: SSLCom::ssl_client_vrfy_callback: not before: %s",name, SSLFactory::print_not_before(err_cert).c_str());
            if(com != nullptr) {
                com->verify_set(INVALID);
                if(com->opt_allow_not_valid_cert) {
                    ret = 1;
                }
                if(com->opt_failed_certcheck_replacement) {
                    ret = 1;
                }
            }

            break;
        case X509_V_ERR_CERT_HAS_EXPIRED:
        case X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD:
            _dia("[%s]: SSLCom::ssl_client_vrfy_callback: not after: %s",name, SSLFactory::print_not_after(err_cert).c_str());
            if(com != nullptr) {
                com->verify_set(INVALID);
                if(com->opt_allow_not_valid_cert) {
                    ret = 1;
                }
                if(com->opt_failed_certcheck_replacement) {
                    ret = 1;
                }
            }

            break;
        case X509_V_ERR_NO_EXPLICIT_POLICY:
            _dia("[%s]: SSLCom::ssl_client_vrfy_callback: no explicit policy",name);
            break;
            
    }
    
    
    if (err == X509_V_OK && ok == 2) {
        _dia("[%s]: SSLCom::ssl_client_vrfy_callback: explicit policy", name);
    }

    std::string cn = "unknown";
    if(xcert != nullptr) {   
        cn = SSLFactory::print_cn(xcert) + ";"+ fingerprint(xcert);
    }
    _dia("[%s]: SSLCom::ssl_client_vrfy_callback[%d:%s]: returning %s (pre-verify %d)",name,depth,cn.c_str(),(ret > 0 ? "ok" : "failed" ),ok);

    if(ret <= 0) {
        _not("[%s]: target server ssl certificate check failed:%d: %s",name, err,X509_verify_cert_error_string(err));
    }
    
    
    if(depth == 0 && com != nullptr) {
        if(com->opt_ocsp_mode > 0 &&  com->sslcom_target_cert && com->sslcom_target_issuer
            && com->ocsp_cert_is_revoked == -1 && com->opt_ocsp_enforce_in_verify) {
         
            int is_revoked = baseSSLCom::ocsp_explicit_check(com);

            _deb("[%s]: SSLCom::ssl_client_vrfy_callback[%d:%s]: explicit check returned %d",name, depth, cn.c_str(), is_revoked);

            if(is_revoked  == 0) { 
                ret = 1;
            }
            else if(is_revoked > 0)  {
                _dia("[%s]: SSLCom::ssl_client_vrfy_callback[%d:%s]: revoked",name, depth, cn.c_str());

                com->verify_set(REVOKED);
                ret = 0;
                
                if(com->opt_failed_certcheck_replacement) {
                    _dia("[%s]: SSLCom::ssl_client_vrfy_callback[%d:%s]: revoked, but replacement is enabled",
                            name, depth, cn.c_str());
                    ret = 1;
                }
                
            }
        } else {
            if(com->opt_ocsp_mode == 0 || (! com->opt_ocsp_enforce_in_verify) )
                _dia("[%s]: SSLCom::ssl_client_vrfy_callback[%d:%s]: ocsp not enabled",name, depth, cn.c_str());
        }
    }

    return ret;
}


template <class L4Proto>
long int baseSSLCom<L4Proto>::log_if_error(unsigned int level, const char* prefix) {

    long err2 = ERR_get_error();
    do {
        if(err2 != 0) {
            log.log(loglevel(level,0), "%s: error code:%u:%s", prefix, err2, ERR_error_string(err2, nullptr));
            err2 = ERR_get_error();
        }
    } while (err2 != 0);

    return err2;
}


template <class L4Proto>
long int baseSSLCom<L4Proto>::log_if_error2(unsigned int level, const char* prefix) {

    long err2 = ERR_get_error();
    do {
        if(err2 != 0) {

            auto log = logan::create("ssl");

            log.log(loglevel(level,0), "%s: error code:%u:%s", prefix, err2, ERR_error_string(err2,nullptr));
            err2 = ERR_get_error();
        }
    } while (err2 != 0);

    return err2;
}

template <class L4Proto>
DH* baseSSLCom<L4Proto>::ssl_dh_callback(SSL* s, int is_export, int key_length)  {
    void* data = SSL_get_ex_data(s, sslcom_ssl_extdata_index);
    const char *name = "unknown_cx";

    baseSSLCom* com = static_cast<baseSSLCom*>(data);
    if(com != nullptr) {
        const char* n = com->hr();
        if(n != nullptr) {
            name = n;
        }
    }

    auto log = logan::create("ssl");

    _dia("[%s]: SSLCom::ssl_dh_callback: %d bits requested",name,key_length);
    switch(key_length) {
        case 512:
            //return get_dh512();
        case 768:
            //return get_dh768();
        case 1024:
            return get_dh1024();
        case 1536:
            return get_dh1536();
        case 2048:
            return get_dh2048();


        default:
            return get_dh2048();
    }

    return nullptr;
}


template <class L4Proto>
EC_KEY* baseSSLCom<L4Proto>::ssl_ecdh_callback(SSL* s, int is_export, int key_length) {
    void* data = SSL_get_ex_data(s, sslcom_ssl_extdata_index);
    const char *name = "unknown_cx";

    baseSSLCom* com = static_cast<baseSSLCom*>(data);
    if(com != nullptr) {
        const char* n = com->hr();
        if(n != nullptr) {
            name = n;
        }
    }

    auto log = logan::create("ssl");
    _dia("[%s]: SSLCom::ssl_ecdh_callback: %d bits requested", name, key_length);
    return nullptr;
}

template <class L4Proto>
int baseSSLCom<L4Proto>::ocsp_explicit_check(baseSSLCom* com) {
    int is_revoked = -1;
    auto log = logan::create("ssl");

    if(com != nullptr) {

        const char *name = "unknown_cx";
        baseSSLCom* pcom = dynamic_cast<baseSSLCom*>(com->peer());
        if(pcom != nullptr) {
            const char* n = pcom->hr();
            if(n != nullptr) {
                name = n;
            }
        }
        else {
            const char* n = com->hr();
            if(n != nullptr) {
                name = n;
            }
        }

        std::string cn = "unknown";
        if(com->sslcom_target_cert != nullptr) {   
            cn = SSLFactory::print_cn(com->sslcom_target_cert) + ";" + fingerprint(com->sslcom_target_cert);
        }

        const char* str_cached = "cached";
        const char* str_fresh = "fresh";
        const char* str_status = "unknown";


        SSLFactory::expiring_ocsp_result *cached_result = nullptr;

        // ocsp_result_cache - locked
        {
            std::lock_guard<std::recursive_mutex> l_(com->certstore()->ocsp_result_cache.getlock());

            cached_result = com->certstore()->ocsp_result_cache.get(cn);

            if (cached_result != nullptr) {
                is_revoked = cached_result->value();
                str_status = str_cached;
            } else {
                is_revoked = ocsp_check_cert(com->sslcom_target_cert, com->sslcom_target_issuer);
                str_status = str_fresh;
            }
        }

        _dia("[%s]: SSLCom::ocsp_explicit_check[%s]: ocsp is_revoked = %d)",name,cn.c_str(),is_revoked);
        
        com->ocsp_cert_is_revoked = is_revoked;
        if(is_revoked > 0) {
            _war("Connection from %s: certificate %s is revoked (%s OCSP))",name,cn.c_str(),str_status);
        } else if (is_revoked == 0){
            _dia("Connection from %s: certificate %s is valid (%s OCSP))",name,cn.c_str(),str_status);
        } else {
            /*< 0*/
            if(com->opt_ocsp_mode > 1) {
            }
            _war("Connection from %s: certificate %s revocation status is unknown (%s OCSP))",name,cn.c_str(),str_status);
        }

        
        if(cached_result == nullptr) {

            std::lock_guard<std::recursive_mutex> l_(com->certstore()->ocsp_result_cache.getlock());
            // set cache for 3 minutes
            certstore()->ocsp_result_cache.set(cn, SSLFactory::make_expiring_ocsp(is_revoked));
        }
        
        
        if(is_revoked < 0) {
            //if(true) { // testing -- uncomment if needed to test CRL download despite we have OCSP result (and comment if statement above ;))
            
            _not("Connection from %s: certificate OCSP revocation status cannot be obtained)",name);
            
            std::vector<std::string> crls = crl_urls(com->sslcom_target_cert);
            
            SSLFactory::expiring_crl* crl_h = nullptr;
            X509_CRL* crl = nullptr;


            std::lock_guard<std::recursive_mutex> l_(com->certstore()->crl_cache.getlock());
            for(auto crl_url: crls) {
                
                std::string crl_printable = printable(crl_url);
                crl_h = certstore()->crl_cache.get(crl_url);
                
                if(crl_h != nullptr) {
                    crl = crl_h->value()->ptr;
                    _dia("found cached crl: %s",crl_printable.c_str());
                    str_status = str_cached;
                }
                else {
                    _dia("crl not cached: %s",crl_printable.c_str());
                    
                    const int tolerated_dnld_time = 3;
                    time_t start = ::time(nullptr);

                    _dia("Connection from %s: downloading CRL at %s)",name,crl_printable.c_str());

                    buffer b;
                    bool dnld_failed = false;
                    int bytes = download(crl_url.c_str(),b,tolerated_dnld_time*3);
                    if(bytes < 0) dnld_failed = true;

                    if(! dnld_failed ) {
                        time_t t_dif = ::time(nullptr) - start;
                        
                        int crl_size = b.size();
                        _dia("CRL downloaded: size %d bytes in %d seconds",crl_size,t_dif);
                        if(t_dif > tolerated_dnld_time) {
                            _war("it took long time to download CRL. You should consider to disable CRL check :(");
                        }

                        crl = new_CRL(b);
                        str_status = str_fresh;
                        

                        if(crl != nullptr) {
                            _dia("Caching CRL 0x%x", crl);
                            certstore()->crl_cache.set(crl_url.c_str(),SSLFactory::make_expiring_crl(crl));
                            // but because we are locked, we are happy to overwrite it!
                        }
                    } else {
                        _war("downloading CRL from %s failed.",crl_printable.c_str());
                    }

                }
                // all control-paths are locked now
                
                int is_revoked_by_crl = -1;
                
                if(crl != nullptr && com->sslcom_target_cert != nullptr && com->sslcom_target_issuer != nullptr) {
                    int crl_trust = crl_verify_trust(com->sslcom_target_cert,
                                                     com->sslcom_target_issuer,
                                                     crl,
                                                     com->certstore()->default_client_ca_path().c_str());
                    _dia("CRL 0x%x trusted = %d",crl, crl_trust);
                    
                    bool trust_blindly_downloaded_CRL = true;
                    if(crl_trust == 0 && !trust_blindly_downloaded_CRL) {
                        _war("CRL %s is not verified, it's untrusted",crl_printable.c_str());
                    }
                    else {
                        if(crl_trust == 0 && crl_h == nullptr) {
                            // complain only at download time only
                            _not("CRL %s is not verified, but we are instructed to trust it.",crl_printable.c_str());
                        }
                        _dia("Checking revocation status: CRL 0x%x", crl);
                        is_revoked_by_crl = crl_is_revoked_by(com->sslcom_target_cert,com->sslcom_target_issuer,crl);
                    }
                }

                _dia("CRL says this certificate is revoked = %d",is_revoked_by_crl);

                if(is_revoked_by_crl > 0) {
                    _war("Connection from %s: certificate %s revocation status is revoked (%s CRL))",name,cn.c_str(),str_status);
                } else
                if(is_revoked_by_crl == 0) {
                    _dia("Connection from %s: certificate %s revocation status is valid (%s CRL))",name,cn.c_str(),str_status);
                } else {
                    _war("Connection from %s: certificate %s revocation status is still unknown (%s CRL))",name,cn.c_str(),str_status);
                }
                
                is_revoked = is_revoked_by_crl;
                
                if(is_revoked_by_crl >= 0) {
                    break;
                }
            }
        }
    }
    
    if(is_revoked > 0) {
        com->verify_set(REVOKED);
    }

    _dia("ocsp_explicit_check: final result %d", is_revoked);
    return is_revoked;
}

template <class L4Proto>
int baseSSLCom<L4Proto>::ocsp_resp_callback_explicit(baseSSLCom* com, int cur_status) {
    
    if(com != nullptr) {
        if(!com->opt_ocsp_enforce_in_verify) {
            DIAS_("ocsp_resp_callback_explicit: still no result, running full OCSP request");
            int is_revoked = baseSSLCom::ocsp_explicit_check(com);
            
            if(is_revoked > 0) {
                com->verify_set(REVOKED);
                if(com->opt_failed_certcheck_replacement) {
                    ERR_clear_error();
                    return 1;
                }
            } else
            if(is_revoked == 0) {
                return 1;
            }
        }
    }
    return cur_status;
}


template <class L4Proto>
int baseSSLCom<L4Proto>::ocsp_resp_callback(SSL *s, void *arg) {

    void* data = SSL_get_ex_data(s, sslcom_ssl_extdata_index);
    const char *name = "unknown_cx";

    baseSSLCom* com = static_cast<baseSSLCom*>(data);

    bool opt_ocsp_strict = false;
    bool opt_ocsp_require = false;
    X509* peer_cert = nullptr;
    X509* issuer_cert = nullptr;

    if(com != nullptr) {
        baseSSLCom* pcom = dynamic_cast<baseSSLCom*>(com->peer());
        if(pcom != nullptr) {
            const char* n = pcom->hr();
            if(n != nullptr) {
                name = n;
            }
        } else {  
            const char* n = com->hr();
            if(n != nullptr) {
                name = n;
            }
        }
        opt_ocsp_strict = (com->opt_ocsp_stapling_mode >= 1);
        opt_ocsp_require = (com->opt_ocsp_stapling_mode == 2);
        peer_cert   = com->sslcom_target_cert;
        issuer_cert = com->sslcom_target_issuer;

        if (!peer_cert || !issuer_cert) {
            DIA__("[%s]: ocsp_resp_callback: verify hasn't been yet called",name);
            com->opt_ocsp_enforce_in_verify = true;
            return baseSSLCom::ocsp_resp_callback_explicit(com,opt_ocsp_require ? 0 : 1);
        }
        
        DEB_("ocsp_resp_callback[%s]: peer cert=%x, issuer_cert=%x",name,peer_cert,issuer_cert);
       
    } else {
        ERRS_("SSLCom::ocsp_resp_callback: argument data is not SSLCom*!");
        return 1;
    }

    
    const unsigned char *p;
    int len, status, reason;
    OCSP_RESPONSE *rsp;
    OCSP_BASICRESP *basic;
    OCSP_CERTID *id;
    ASN1_GENERALIZEDTIME *produced_at, *this_update, *next_update;

    len = SSL_get_tlsext_status_ocsp_resp(s, &p);
    if (!p) {
        if(opt_ocsp_strict)
            WAR_("[%s]: no OCSP response received",name);

        com->opt_ocsp_enforce_in_verify = true;
        return baseSSLCom::ocsp_resp_callback_explicit(com,opt_ocsp_require ? 0 : 1);
    }
    DUM__("[%s]: OCSP Response:  \n%s",name,hex_dump((unsigned char*)p,len,2).c_str());

    rsp = d2i_OCSP_RESPONSE(NULL, &p, len);
    if (!rsp) {
        ERR__("[%s] failed to parse OCSP response",name);
        com->opt_ocsp_enforce_in_verify = true;
        return baseSSLCom::ocsp_resp_callback_explicit(com,opt_ocsp_strict ? 0 : 1);
    }

    status = OCSP_response_status(rsp);
    if (status != OCSP_RESPONSE_STATUS_SUCCESSFUL) {
        ERR__("[%s] OCSP responder error %d (%s)", name, status, OCSP_response_status_str(status));
        com->opt_ocsp_enforce_in_verify = true;
        return baseSSLCom::ocsp_resp_callback_explicit(com,opt_ocsp_strict ? 0 : 1);
    }

    basic = OCSP_response_get1_basic(rsp);
    if (!basic) {
        ERR__("[%s] could not find BasicOCSPResponse",name);
        com->opt_ocsp_enforce_in_verify = true;
        return baseSSLCom::ocsp_resp_callback_explicit(com,opt_ocsp_strict ? 0 : 1);
    }

    status = OCSP_basic_verify(basic, NULL, com->certstore()->trust_store() ,0);


    if (status <= 0) {

        int err = SSL_get_error(s,status);
        DIA__("    error: %s",ERR_error_string(err,nullptr));


        OCSP_BASICRESP_free(basic);
        OCSP_RESPONSE_free(rsp);

        int r = opt_ocsp_strict ? 0 : 1;

        if(r > 0) {
            NOT__("[%s] OCSP stapling response failed verification",name);
            ERR_clear_error();
        }
        else {
            ERR__("[%s] OCSP stapling response failed verification",name);
        }

        int ocsp_check =  baseSSLCom::ocsp_resp_callback_explicit(com,r);
        DIA__("SSLCom::ocsp_resp_callback: OCSP returned %d", ocsp_check);
        
        return ocsp_check;
    }

    DIA__("[%s] OCSP response verification succeeded",name);

    id = OCSP_cert_to_id(NULL, com->sslcom_target_cert, com->sslcom_target_issuer);
    if (!id) {
        ERR__("[%s] could not create OCSP certificate identifier",name);
        OCSP_BASICRESP_free(basic);
        OCSP_RESPONSE_free(rsp);

        int r = opt_ocsp_strict ? 0 : 1;
        if(r > 0)
            ERR_clear_error();

        com->opt_ocsp_enforce_in_verify = true;
        int ocsp_check = baseSSLCom::ocsp_resp_callback_explicit(com,r);
        DIA__("SSLCom::ocsp_resp_callback: OCSP returned %d", ocsp_check);
        
        return ocsp_check;        
    }


    if (!OCSP_resp_find_status(basic, id, &status, &reason, &produced_at, &this_update, &next_update)) {
        ERR__("[%s] could not find current server certificate from OCSP response %s", name,
                                                       (opt_ocsp_require) ? "" : " (OCSP not required)");
        OCSP_BASICRESP_free(basic);
        OCSP_RESPONSE_free(rsp);

        int r = opt_ocsp_require ? 0 : 1;
        if(r > 0)
            ERR_clear_error();

        com->opt_ocsp_enforce_in_verify = true;
        int ocsp_check =  baseSSLCom::ocsp_resp_callback_explicit(com,r);
        DIA__("SSLCom::ocsp_resp_callback: OCSP returned %d", ocsp_check);
        
        return ocsp_check;
    }

    if (!OCSP_check_validity(this_update, next_update, 5 * 60, -1)) {
        ERR__("[%s] OCSP status times invalid", name);
        OCSP_BASICRESP_free(basic);
        OCSP_RESPONSE_free(rsp);

        int r = opt_ocsp_strict ? 0 : 1;
        if(r > 0)
            ERR_clear_error();

        com->opt_ocsp_enforce_in_verify = true;
        int ocsp_check = baseSSLCom::ocsp_resp_callback_explicit(com,r);
        DIA__("SSLCom::ocsp_resp_callback: OCSP returned %d", ocsp_check);
        
        return ocsp_check;        
    }

    OCSP_CERTID_free(id);
    OCSP_BASICRESP_free(basic);
    OCSP_RESPONSE_free(rsp);

    DIA__("[%s] OCSP status for server certificate: %s", name, OCSP_cert_status_str(status));

    std::string cn = SSLFactory::print_cn(com->sslcom_target_cert) + ";" + fingerprint(com->sslcom_target_cert);
    
    if (status == V_OCSP_CERTSTATUS_GOOD) {
        DIA__("[%s] OCSP status is good",name);
        if(com != nullptr){
            com->ocsp_cert_is_revoked = 0;
            DIA__("Connection from %s: certificate %s is valid (stapling OCSP))",name,cn.c_str());            
            
        }
        return 1;
    } else
    if (status == V_OCSP_CERTSTATUS_REVOKED) {
        DIA__("[%s] OCSP status is revoked",name);
        if(com != nullptr){
            com->ocsp_cert_is_revoked = 1;
            com->verify_set(REVOKED);
            WAR__("Connection from %s: certificate %s is revoked (stapling OCSP))",name,cn.c_str());
            return com->opt_failed_certcheck_replacement;
        }
        return 0;
    } else
    if (opt_ocsp_require) {
        ERR__("[%s] OCSP status unknown, but OCSP required, failing", name);
        
        int ocsp_check = baseSSLCom::ocsp_resp_callback_explicit(com,0);
        DIA__("SSLCom::ocsp_resp_callback: OCSP returned %d", ocsp_check);
        
        return ocsp_check;             
    }

    DIA__("[%s] OCSP status unknown, but OCSP was not required, continue", name);

    int ocsp_check = baseSSLCom::ocsp_resp_callback_explicit(com,1);
    DIA__("SSLCom::ocsp_resp_callback: OCSP returned %d", ocsp_check);
    
    return ocsp_check;         
}

template <class L4Proto>
int baseSSLCom<L4Proto>::ssl_client_cert_callback(SSL* ssl, X509** x509, EVP_PKEY** pkey) {
    //return 0 if we don't want to provide cert, 1 if yes.
    //if yes, x509 and pkey has to point to pointers with cert.
    
    
    void* data = SSL_get_ex_data(ssl, sslcom_ssl_extdata_index);
    const char *name = "unknown_cx";

    *x509 = nullptr;
    *pkey = nullptr;

    
    baseSSLCom* com = static_cast<baseSSLCom*>(data);
    if(com != nullptr) {
        baseSSLCom* pcom = dynamic_cast<baseSSLCom*>(com->peer());
        if(pcom != nullptr) {
            const char* n = pcom->hr();
            if(n != nullptr) {
                name = n;
            }
        } else {  
            const char* n = com->hr();
            if(n != nullptr) {
                name = n;
            }
        }
        
        com->verify_set(baseSSLCom::CLIENT_CERT_RQ);
        switch(com->opt_client_cert_action) {
            
            case 0:
                INF__("[%s] sending empty client certificate disabled", name);
                if(com->opt_failed_certcheck_replacement) {
                    INF__("[%s] replacement will be displayed", name);
                    return 0;
                }
                else {
                    com->error(ERROR_UNSPEC);
                    return 1;
                }
                break;
                
            case 1:
                INF__("[%s] sending empty client certificate", name);
                return 0;
                
            default:
                return 1;
        }
    }
    
    ERR__("[%s], Oops. Com object not SSL, sending client certificate disabled", name);
    return 1;
}



template <class L4Proto>
void baseSSLCom<L4Proto>::init_ssl_callbacks() {
    SSL_set_msg_callback(sslcom_ssl,ssl_msg_callback);
    SSL_set_msg_callback_arg(sslcom_ssl,(void*)this);
    SSL_set_info_callback(sslcom_ssl,ssl_info_callback);

    if((is_server() && opt_left_kex_dh) || (!is_server() && opt_right_kex_dh)) {
        SSL_set_tmp_dh_callback(sslcom_ssl,ssl_dh_callback);

#ifndef USE_OPENSSL11
        // OpenSSL 1.1 API doesn't seem to contain ECDH callback.
        // considering ECDH callback only prints out bit size, we can disable it
        // makking it:
        // FIXME - is ECDH callback needed with openssl 1.1.x
        SSL_set_tmp_ecdh_callback(sslcom_ssl,ssl_ecdh_callback);
#endif
    }


    _deb("init ssl callbacks");

    // add this pointer to ssl external data
    if(sslcom_ssl_extdata_index < 0) {
        sslcom_ssl_extdata_index = SSL_get_ex_new_index(0, (void*) "sslcom object", nullptr, nullptr, nullptr);
    }
    SSL_set_ex_data(sslcom_ssl,sslcom_ssl_extdata_index, static_cast<void*>(this));

    if(! is_server()) {
        SSL_set_verify(sslcom_ssl,SSL_VERIFY_PEER,&ssl_client_vrfy_callback);
        SSL_CTX_set_client_cert_cb(sslcom_ctx,ssl_client_cert_callback);

        if(opt_ocsp_stapling_enabled || opt_ocsp_mode > 0) {

            if(certstore()->trust_store() != nullptr) {

                std::lock_guard<std::recursive_mutex> l_(certstore()->lock());

                _dia("[%s]: OCSP stapling enabled, mode %d", hr(), opt_ocsp_stapling_mode);
                SSL_set_tlsext_status_type(sslcom_ssl, TLSEXT_STATUSTYPE_ocsp);
                SSL_CTX_set_tlsext_status_cb(sslcom_ctx, ocsp_resp_callback);
                SSL_CTX_set_tlsext_status_arg(sslcom_ctx, this);
            }
            else {
                _err("cannot load trusted store for OCSP. Fail-open.");
                opt_ocsp_stapling_mode = 0;
            }
        }
    } 
}

template <class L4Proto>
void baseSSLCom<L4Proto>::init_client() {

    if(sslcom_ssl) {
        DEBS___("SSLCom::init_client: freeing old sslcom_ssl");
        SSL_free(sslcom_ssl);
        sslcom_ssl = nullptr;
    }


    if(l4_proto() == SOCK_STREAM) {

        std::lock_guard<std::recursive_mutex> l_(certstore()->lock());

        sslcom_ctx = certstore()->default_tls_client_cx();
        sslcom_ssl = SSL_new(sslcom_ctx);
    } else 
    if(l4_proto() == SOCK_DGRAM) {

        std::lock_guard<std::recursive_mutex> l_(certstore()->lock());

        sslcom_ctx = certstore()->default_dtls_client_cx();
        sslcom_ssl = SSL_new(sslcom_ctx);
    }
    
    std::string my_filter = ci_def_filter;
    
    if(!opt_right_allow_sha1)
                my_filter += " !SHA1";
    if(!opt_right_allow_rc4)
                my_filter += " !RC4";
    if(!opt_right_allow_aes128)
                my_filter += " !AES128";
    
    
    if(!opt_right_kex_dh)
                my_filter += " !kEECDH !kEDH";
    
    if(!opt_right_kex_rsa)
                my_filter += " !kRSA";
    
    
    DIA___("right ciphers: %s",my_filter.c_str());
    
    SSL_set_cipher_list(sslcom_ssl,my_filter.c_str());
    
    if(!sslcom_ssl) {
        ERRS___("Client: Error creating SSL context!");
        log_if_error(iERR,"SSLCom::init_client");
    }

    
    if(opt_right_no_tickets) {
        SSL_set_options(sslcom_ssl,SSL_OP_NO_TICKET);
    }
    else {
        load_session_if_needed();
    }
    
    SSL_set_mode(sslcom_ssl, SSL_MODE_ENABLE_PARTIAL_WRITE|SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER|SSL_MODE_RELEASE_BUFFERS);

    init_ssl_callbacks();
}


template <class L4Proto>
void baseSSLCom<L4Proto>::init_server() {

    if(sslcom_ecdh) {
        EC_KEY_free(sslcom_ecdh);
        sslcom_ecdh = nullptr;
    }
    
    if(sslcom_ssl) {
        DEBS___("SSLCom::init_server: freeing old sslcom_ssl");
        SSL_free(sslcom_ssl);
        sslcom_ssl = nullptr;
    }

    
    DEB___("baseSSLCom<L4Proto>::init_server: l4 proto = %d", l4_proto());
    
    if(l4_proto() == SOCK_STREAM) {

        std::lock_guard<std::recursive_mutex> l_(certstore()->lock());

        sslcom_ctx = certstore()->default_tls_server_cx();
        sslcom_ssl = SSL_new(sslcom_ctx);
    } else
    if(l4_proto() == SOCK_DGRAM) {

        std::lock_guard<std::recursive_mutex> l_(certstore()->lock());

        sslcom_ctx = certstore()->default_dtls_server_cx();
        sslcom_ssl = SSL_new(sslcom_ctx);
        SSL_set_options(sslcom_ssl, SSL_OP_COOKIE_EXCHANGE);
    }
    
    //if(l4_proto() == SOCK_DGRAM) INF___("DTLS sslcom_ssl 0x%x",sslcom_ssl);

    std::string my_filter = ci_def_filter;
    
    if(!opt_left_allow_sha1)
                my_filter += " !SHA1";
    if(!opt_left_allow_rc4)
                my_filter += " !RC4";
    if(!opt_left_allow_aes128)
                my_filter += " !AES128";
    
    
    if(!opt_left_kex_dh) {
                my_filter += " !kEECDH !kEDH";
    } else {
                // ok, use DH, in that case select 
                if(sslcom_ecdh == nullptr) {
                    sslcom_ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
                }
                if(sslcom_ecdh != nullptr) {
                    // this actually disables ecdh callback
                    SSL_set_tmp_ecdh(sslcom_ssl,sslcom_ecdh);
                }        
    }
                
    if(!opt_left_kex_rsa)
                my_filter += " !kRSA";
    
    
    DIA___("left ciphers: %s",my_filter.c_str());
    SSL_set_cipher_list(sslcom_ssl,my_filter.c_str());

    if (sslcom_pref_cert && sslcom_pref_key) {
        DEB__("SSLCom::init_server[%x]: loading preferred key/cert",this);
        SSL_use_PrivateKey(sslcom_ssl,sslcom_pref_key);
        SSL_use_certificate(sslcom_ssl,sslcom_pref_cert);
        
        if(!sslcom_refcount_incremented__) {
#ifdef USE_OPENSSL11
            EVP_PKEY_up_ref(sslcom_pref_key);
            X509_up_ref(sslcom_pref_cert);
#else
            CRYPTO_add(&sslcom_pref_key->references,+1,CRYPTO_LOCK_EVP_PKEY);
            CRYPTO_add(&sslcom_pref_cert->references,+1,CRYPTO_LOCK_X509);
#endif
            sslcom_refcount_incremented__ = true;
        }
    }

    SSL_set_session(sslcom_ssl, NULL);
    
    if(opt_left_no_tickets) {
        SSL_set_options(sslcom_ssl,SSL_OP_NO_TICKET);
    }    
    
    SSL_set_mode(sslcom_ssl, SSL_MODE_ENABLE_PARTIAL_WRITE|SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);

    SSL_set_fd (sslcom_ssl, sslcom_fd);

    is_server(true);

    init_ssl_callbacks();
    
}

template <class L4Proto>
bool baseSSLCom<L4Proto>::check_cert (const char* host) {
    X509 *peer;
    char peer_CN[256]; memset(peer_CN,0,256);

    if ( !is_server() && SSL_get_verify_result ( sslcom_ssl ) !=X509_V_OK ) {
        DIAS___( "check_cert: ssl client: target server's certificate cannot be verified!" );
    }

    /*Check the cert chain. The chain length
      is automatically checked by OpenSSL when
      we set the verify depth in the ctx */

    /*Check the common name*/
    peer=SSL_get_peer_certificate ( sslcom_ssl );

    if(peer == NULL) {
        ERRS___("check_cert: unable to retrieve peer certificate");

        // cannot proceed, next checks require peer X509 data
        return false;
    };

    X509_NAME* x509_name = X509_get_subject_name(peer);
    
    X509_NAME_get_text_by_NID(x509_name,NID_commonName, peer_CN, 255);

    // X509_NAME_oneline(X509_get_subject_name(peer),peer_CERT,1024);
    // DIA___("Peer certificate:\n%s",peer_CERT);

    //DIA___("peer CN: %s",ESC(str_peer));
    if(host != NULL) {
//     ERR_("what:\n%s",hex_dump((unsigned char*)peer_CN,256).c_str());
	std::string str_host(host);
	std::string str_peer(peer_CN,255);

	DIA___("peer host: %s",host);

        if ( str_host != str_peer ) {
            DIAS___( "Common name doesn't match host name" );
        }
    }

    X509_free(peer);
    // X509_NAME_free(x509_name);

    // finally, SSL is up, set status flag
    sslcom_status(true);

    return true;
}


/* OK set  */
template <class L4Proto>
bool baseSSLCom<L4Proto>::readable(int s) {
    // 	bool r = ( sslcom_write_blocked_on_read  || !sslcom_read_blocked_on_write || sslcom_waiting );
    bool r = !sslcom_read_blocked_on_write;
    sslcom_read_blocked_on_write = false;

    DUM___("SSLCom::readable[%d]: sslcom_read_blocked_on_write: %d",s,sslcom_read_blocked_on_write);
    DUM___("SSLCom::readable[%d]: sslcom_write_blocked_on_read: %d",s,sslcom_write_blocked_on_read);

    if (r) {
        DUM___("SSLCom::readable[%d]: %d",s,r);
    } else {
        DEB___("SSLCom::readable[%d]: %d",s,r);
    }

    return r;
};

template <class L4Proto>
bool baseSSLCom<L4Proto>::writable(int s) {
    // 	bool r  = ( sslcom_read_blocked_on_write ||  !sslcom_write_blocked_on_read ||  sslcom_waiting );

    bool r = !sslcom_write_blocked_on_read;
    sslcom_write_blocked_on_read = false;

    DUM___("SSLCom::writable[%d]: sslcom_read_blocked_on_write: %d",s,sslcom_read_blocked_on_write);
    DUM___("SSLCom::writable[%d]: sslcom_write_blocked_on_read: %d",s,sslcom_write_blocked_on_read);

    if (r) {
        DUM___("SSLCom::writable[%d]: %d",s,r);
    } else {
        DEB___("SSLCom::writable[%d]: %d",s,r);
    }

    return r;
};

template <class L4Proto>
bool baseSSLCom<L4Proto>::bypass_me_and_peer() {
    if(peer()) {
        baseSSLCom* speer = dynamic_cast<baseSSLCom*>(peer());
        
        if(speer) {
            opt_bypass = true;
            speer->opt_bypass = true;
            return true;
        }
    }
    
    return false;
}


template <class L4Proto>
void baseSSLCom<L4Proto>::accept_socket ( int sockfd )  {

    DIA___("SSLCom::accept_socket[%d]: attempt %d",sockfd,prof_accept_cnt);

    L4Proto::on_new_socket(sockfd);
    L4Proto::accept_socket(sockfd);

    if(l4_proto() == SOCK_DGRAM && sockfd < 0) {
        UDPCom* l4com = dynamic_cast<UDPCom*>(this);
        if(l4com) {
            INFS___("Underlying com is UDPCom using virtual sockets");
            
            auto it_rec = l4com->datagrams_received.find(sockfd);
            if(it_rec != l4com->datagrams_received.end()) {
                Datagram& rec = it_rec->second;
                sslcom_fd = socket(rec.dst_family(),SOCK_DGRAM,IPPROTO_UDP);
                int n = 1;
                setsockopt(sslcom_fd,SOL_IP,IP_TRANSPARENT,&n,sizeof(n));
                setsockopt(sslcom_fd,SOL_IPV6,IPV6_TRANSPARENT,&n,sizeof(n));
                int ret_con = ::connect(sslcom_fd, (sockaddr*)&rec.src,sizeof(sockaddr_storage));
                int ret_bind = ::bind(sslcom_fd,(sockaddr*)&rec.dst,sizeof(sockaddr_storage));
                
                INF___("Masked socket: connect=%d, bind=%d",ret_con, ret_bind);
            }
        }
    }
    
    upgrade_server_socket(sockfd);
    if(opt_bypass) {
        prof_accept_bypass_cnt++;
        return;
    }

    
    if(l4_proto() == SOCK_DGRAM) {

#ifdef USE_OPENSSL11
        BIO_ADDR* bia = BIO_ADDR_new();
        if (!DTLSv1_listen(sslcom_ssl, bia)) {
            BIO_ADDR_free(bia);
            return;
        }
        BIO_ADDR_free(bia);
#else
        sockaddr_storage ss;
        if (!DTLSv1_listen(sslcom_ssl,(sockaddr_in6*)&ss)) {
            return;
        }
#endif
    }

    ERR_clear_error();
    int r = SSL_accept (sslcom_ssl);
    if (r > 0) {
        DIA___("SSLCom::accept_socket[%d]: success at 1st attempt.",sockfd);
        prof_accept_ok++;
        sslcom_waiting = false;

        // reread socket
        forced_read(true);
        forced_write(true);

        if(SSL_session_reused(sslcom_ssl)) {
            flags_ |= HSK_REUSED;
        }

#ifndef USE_OPENSSL111
        if(sslkeylog) {
            dump_keys();
            sslkeylog = false;
        }
#endif
        
    } else {
        DIA___("SSLCom::accept_socket[%d]: ret %d, need to call later.",sockfd,r);
    }
    prof_accept_cnt++;
}

template <class L4Proto>
void baseSSLCom<L4Proto>::ssl_keylog_callback(const SSL* ssl, const char* line) {
    void* data = SSL_get_ex_data(ssl, sslcom_ssl_extdata_index);
    baseSSLCom* com = static_cast<baseSSLCom*>(data);

    if(com && com->sslkeylog) {
        LOGS_(loglevel(NOT,flag_add(iNOT,CRT|KEYS),&LOG_EXEXACT,LOG_FLRAW),line);
    }
}


template <class L4Proto>
void baseSSLCom<L4Proto>::dump_keys() {
    if(sslkeylog) {
        std::string ret;

        #ifdef USE_OPENSSL111
        // this should not be called with openssl1.1.1, which has its own keylog callback

        #elif def USE_OPENSSL11
        unsigned char client_random[SSL3_RANDOM_SIZE];
        memset(client_random, 0, SSL3_RANDOM_SIZE);

        unsigned char master_key[SSL3_MASTER_SECRET_SIZE];
        memset(master_key, 0, SSL3_MASTER_SECRET_SIZE);

        SSL_get_client_random(sslcom_ssl, client_random, SSL3_RANDOM_SIZE);
        SSL_SESSION_get_master_key(SSL_get_session(sslcom_ssl), master_key, SSL3_MASTER_SECRET_SIZE);

        ret = string_format("CLIENT_RANDOM %s %s",
                hex_print(client_random, SSL3_RANDOM_SIZE).c_str(),
                hex_print(master_key, SSL3_MASTER_SECRET_SIZE).c_str()
        );

        #else
        ret = string_format("CLIENT_RANDOM %s %s",
                      hex_print(sslcom_ssl->s3->client_random, SSL3_RANDOM_SIZE).c_str(),
                      hex_print(sslcom_ssl->session->master_key, SSL3_MASTER_SECRET_SIZE).c_str()
        );

        #endif // USE_OPENSSL11

        LOGS_(loglevel(NOT,flag_add(iNOT,CRT|KEYS),&LOG_EXEXACT,LOG_FLRAW),ret.c_str());
    }
}


template <class L4Proto>
void baseSSLCom<L4Proto>::delay_socket(int sockfd) {
    // we need to know even delayed socket
    sslcom_fd = sockfd;
}


template <class L4Proto>
int baseSSLCom<L4Proto>::upgrade_server_socket(int sockfd) {

    sslcom_fd = sockfd;
    sslcom_waiting = true;
    unblock(sslcom_fd);

    if(opt_bypass) {
        DIA___("SSLCom::upgrade_server_socket[%d]: bypassed",sockfd);
        return sockfd;
    }

    init_server();

//     sslcom_sbio = BIO_new_socket(sockfd,BIO_NOCLOSE);
//     if (sslcom_sbio == NULL) {
//         ERR___("BIO allocation failed for socket %d",sockfd)
//     }
//
//     SSL_set_bio(sslcom_ssl,sslcom_sbio,sslcom_sbio);

    upgraded(true);
    return sockfd;
}


template <class L4Proto>
int baseSSLCom<L4Proto>::handshake_server() {
    if(auto_upgrade() && !upgraded()) {
        DIA___("SSLCom::handshake: server auto upgrade socket %d",sslcom_fd);
        upgrade_server_socket(sslcom_fd);
    }

    int op_code = SSL_accept(sslcom_ssl);

    prof_accept_cnt++;
    baseSSLCom::counter_ssl_accept++;

    return op_code;
}

template <class L4Proto>
bool baseSSLCom<L4Proto>::handshake_peer_client() {

    // if we still wait for client hello, try to fetch and enforce (first attempt not successful on connect())
    if(!sslcom_peer_hello_received()) {

        if(! waiting_peer_hello()) {
            // nope, still nothing. Wait further
            return false;
        }

        // if we got here, upgrade client socket prior SSL_connect! Keep it here, it has to be just once!
        if(auto_upgrade()) {
            DIA___("SSLCom::waiting[%d]: executing client auto upgrade",sslcom_fd);
            if(owner_cx() != nullptr && sslcom_fd == 0) {
                sslcom_fd = owner_cx()->socket();
                DIA___("SSLCom::waiting[%d]: socket 0 has been auto-upgraded to owner's socket",sslcom_fd);
            }
            upgrade_client_socket(sslcom_fd);
        }
    }

    // we have client hello
    if(sslcom_peer_hello_received()) {

        DEBS___("SSLCom:waiting: check SNI filter");

        // Do we have sni_filter_to_bypass set? If so, check if we do have also SNI
        // and check all entries in the filter.

        if (sni_filter_to_bypass_.refval() != nullptr) {
            if (sslcom_peer_hello_sni().size() > 0) {

                for (std::string &filter_element: *sni_filter_to_bypass_.refval()) {

                    std::size_t pos = sslcom_peer_hello_sni().rfind(filter_element);
                    if (pos != std::string::npos && pos + filter_element.size() >= sslcom_peer_hello_sni().size()) {

                        //ok, we know SNI ends with the filter entry. We need to check if the character BEFORE match pos in SNI is '.' to prevent
                        // match www.mycnn.com with cnn.com SNI entry.
                        bool cont = true;

                        if (pos > 0) {
                            if (sslcom_peer_hello_sni().at(pos - 1) != '.') {
                                DIA___("%s NOT bypassed with sni filter %s", sslcom_peer_hello_sni().c_str(),
                                       filter_element.c_str());
                                cont = false;
                            }
                        }

                        if (cont) {
                            DIA___("SSLCom:waiting: matched SNI filter: %s!", filter_element.c_str());
                            sni_filter_to_bypass_matched = true;

                            auto *p = dynamic_cast<baseSSLCom *>(peer());
                            if (p != nullptr) {
                                opt_bypass = true;
                                p->opt_bypass = true;

                                INF___("%s bypassed with sni filter %s", sslcom_peer_hello_sni().c_str(),
                                       filter_element.c_str());
                                return false;
                            } else {
                                DIAS___("SSLCom:waiting: SNI filter matched, but peer is not SSLCom");
                            }
                        }
                    }
                }
            }
        }
    }

    return true;
}

// return values according to SSL_connect, except:
// return 2 when connection should be bypassed due to clienthello
template <class L4Proto>
int baseSSLCom<L4Proto>::handshake_client() {

    int r = -1;

    DEBS___("SSLCom::waiting: before SSL_connect");

    ERR_clear_error();
    r = SSL_connect(sslcom_ssl);

    prof_connect_cnt++;
    baseSSLCom::counter_ssl_connect++;

    return r;
}

template <class L4Proto>
void baseSSLCom<L4Proto>::handshake_dia_error2(int op_code, int err, unsigned int xerr2) {

    unsigned long err2 = xerr2;
    int maxiter = 16;

    do {
        if(err2 != 0) {
            constexpr unsigned int sz = 256;
            char err_desc[sz]; memset(err_desc, 0, sz);
            ERR_error_string(err2, err_desc);

            DIA___("SSLCom::handshake:   error code: %s", err_desc);
            err2 = ERR_get_error();
        }

        if(maxiter-- <= 0) {
            ERRS___("handshake_dia_error2: too many errors in the stack");
            break;
        }
    } while (err2 != 0);
}

// return -1 on unrecoverable and we should stop
// return 0 when still waiting
// return > 0 when not waiting anymore

template <class L4Proto>
ret_handshake baseSSLCom<L4Proto>::handshake() {

    const char* op_accept = "accept";
    const char* op_connect = "connect";
    const char* op_unknown = "?unknown?";

    const char* op_descr = op_unknown;

    if (sslcom_ssl == nullptr and ! auto_upgrade()) {
        WARS___("SSLCom::handshake: sslcom_ssl = NULL");
        return ret_handshake::ERROR;
    }

    ret_handshake XXXXto_ret = ret_handshake::AGAIN;
    int op_code = -1;


    ERR_clear_error();

    if (!is_server() ) {
        op_descr = op_connect;

        if(! handshake_peer_client() ) {
            DIA___("SSLCom::handshake: %s on socket %d: waiting for the peer...", op_descr, sslcom_fd);
            return ret_handshake::AGAIN;
        }

        op_code = handshake_client();

    }
    else {
        op_descr = op_accept;
        op_code = handshake_server();
    }

    int err = SSL_get_error(sslcom_ssl, op_code);
    unsigned long err2 = ERR_get_error();

    DIA___("SSLCom::handshake: %s on socket %d: r=%d, err=%d, err2=%d", op_descr, sslcom_fd, op_code, err, err2);

    // general error handling code - both accept and connect yield the same errors
    if (op_code < 0) {
        // potentially OK if non-blocking socket

        if (err == SSL_ERROR_WANT_READ) {
            DIA___("SSLCom::handshake: SSL_%s[%d]: pending on want_read", op_descr , sslcom_fd);

            sslcom_waiting = true;
            prof_want_read_cnt++;

            // unmonitor, wait a while and monitor read back
            rescan_read(sslcom_fd);

            return ret_handshake::AGAIN;
        }
        else if (err == SSL_ERROR_WANT_WRITE) {
            DIA___("SSLCom::handshake: SSL_%s[%d]: pending on want_write", op_descr, sslcom_fd);

            sslcom_waiting = true;
            prof_want_write_cnt++;

            // unmonitor, wait a while and monitor write only
            set_write_monitor_only(sslcom_fd);
            return ret_handshake::AGAIN;
        }
        // this is error code produced by SSL_connect via OCSP callback. 
        // Unfortunately this error code is undocumented, added here to make it work
        // our way based on observation.
        else if (err2 == 654741622 || err2 == 654741605) {
            
            if(ocsp_cert_is_revoked > 0) {
                DIAS___("SSLCom::handshake: aborted due to certificate verification failure.");
                return ret_handshake::ERROR;
            }
            
            return ret_handshake::AGAIN; // return again, we continue.
        }
        else {
            // any other error < 0 is considered as BAD thing.

            DIA___("SSLCom::handshake: SSL_%s: error: %d:%d",op_descr , err, err2);
            handshake_dia_error2(op_code, err, err2);
            sslcom_waiting = true;
            return ret_handshake::ERROR;
        }

    } else if (op_code == 0) {
        // positively handshake error signalled by SSL_connect or SSL_accept
        DIA___("SSLCom::handshake: SSL_%s: error: %d:%d",op_descr , err, err2);
        handshake_dia_error2(op_code, err, err2);

        // shutdown OK, but connection failed
        sslcom_waiting = false;
        return ret_handshake::ERROR;
    }
    else if (op_code == 2) {

        // our internal signalling for bypass
        opt_bypass = true;
        DIAS___("SSLCom::handshake: bypassed.");

        return ret_handshake::AGAIN;
    }


    if(SSL_session_reused(sslcom_ssl)) {
        flags_ |= HSK_REUSED;
    }


    if(!is_server()) {
        check_cert(ssl_waiting_host);
        store_session_if_needed();
    }

#ifndef USE_OPENSSL111
    if(( op_code > 0 ) && sslkeylog) {
        // dump only successfully established connections
        dump_keys();
        sslkeylog = false;
    }
#endif

    DIA___("SSLCom::handshake: %s finished on socket %d", op_descr, sslcom_fd);
    sslcom_waiting = false;

    return ret_handshake::AGAIN;
}


template <class L4Proto>
bool baseSSLCom<L4Proto>::store_session_if_needed() {
    bool ret = false;
    
    if(!is_server() && certstore() && owner_cx() && !opt_right_no_tickets) {
        std::string sni;
        
        if(sslcom_peer_hello_sni().length() > 0)
            sni = sslcom_peer_hello_sni();
        
        std::string key;
        if (sni.length() > 0) {
            key = sni;
        } else {
            key = string_format("%s:%s",owner_cx()->host().c_str(),owner_cx()->port().c_str());
        }
        
        if(!SSL_session_reused(sslcom_ssl)) {
            DIA___("ticketing: key %s: full key exchange, connect attempt %d on socket %d",key.c_str(),prof_connect_cnt,owner_cx()->socket());
            
            if(verify_status == VERIFY_OK) {

                std::lock_guard<std::recursive_mutex> l_( certstore()->session_cache.getlock() );

#if defined USE_OPENSSL111
                if(SSL_SESSION_is_resumable(SSL_get0_session(sslcom_ssl))) {
                    DIAS___("session is resumable");
                    certstore()->session_cache.set(key, new session_holder(SSL_get1_session(sslcom_ssl)));
                    DIA___("ticketing: key %s: keying material stored, cache size = %d",key.c_str(),certstore()->session_cache.cache().size());

                    ret = true;

                } else {
                    DIAS___("session is NOT resumable");
                }
#else
                certstore()->session_cache.set(key,new session_holder(SSL_get1_session(sslcom_ssl)));
                DIA___("ticketing: key %s: keying material stored, cache size = %d",key.c_str(),certstore()->session_cache.cache().size());

                ret = true;

#endif // USE_OPENSSL11
            } else {
                DIAS__("certificate verification failed, not storing in the cache.");
                ret = false;
            }
            
        } else {
            DIA___("ticketing: key %s: abbreviated key exchange, connect attempt %d on socket %d",key.c_str(),prof_connect_cnt,owner_cx()->socket());
            flags_ |= HSK_REUSED;
        }
    }
    
    return ret;
}


template <class L4Proto>
bool baseSSLCom<L4Proto>::load_session_if_needed() {

    bool ret = false;
    
    if(!is_server() && certstore() && owner_cx() && !opt_right_no_tickets) {
        std::string sni;
        
        if(sslcom_peer_hello_sni().length() > 0)
            sni = sslcom_peer_hello_sni();
        
        std::string key;
        if (sni.length() > 0) {
            key = sni;
        } else {
            key = string_format("%s:%s",owner_cx()->host().c_str(),owner_cx()->port().c_str());
        }

        std::lock_guard<std::recursive_mutex> l_(certstore()->session_cache.getlock());

        session_holder* h = certstore()->session_cache.get(key);
        
        if(h != nullptr) {
            DIA___("ticketing: key %s:target server TLS ticket found!",key.c_str());
            SSL_set_session(sslcom_ssl, h->ptr);
            h->cnt_loaded++;
            
            ret = true;
        } else {
            DIA___("ticketing: key %s:target server TLS ticket not found",key.c_str());
            SSL_set_session(sslcom_ssl, NULL);
        }
    }
    
    return ret;
}

template <class L4Proto>
bool baseSSLCom<L4Proto>::waiting_peer_hello() {

    DUMS___("SSLCom::waiting_peer_hello: start");

    if(sslcom_peer_hello_received_) {
        DEBS___("SSLCom::waiting_peer_hello: already called, returning true");
        return true;
    }

    DUMS___("SSLCom::waiting_peer_hello: called");
    if(peer()) {
        baseSSLCom *p = dynamic_cast<baseSSLCom*>(peer());
        if(p != nullptr) {
            if(p->sslcom_fd > 0) {
                DUMS___("SSLCom::waiting_peer_hello: peek max %d bytes from peer socket %d",sslcom_peer_hello_buffer.capacity(),p->sslcom_fd);

                int red = ::recv(p->sslcom_fd,sslcom_peer_hello_buffer.data(),sslcom_peer_hello_buffer.capacity(),MSG_PEEK);
                if (red > 0) {
                    sslcom_peer_hello_buffer.size(red);

                    DIA___("SSLCom::waiting_peer_hello: %d bytes in buffer for hello analysis",red);
                    DUM___("SSLCom::waiting_peer_hello: ClientHello data:\n%s",hex_dump(sslcom_peer_hello_buffer.data(),sslcom_peer_hello_buffer.size()).c_str());

                    int parse_hello_result = parse_peer_hello();
                    if(parse_hello_result == 0) {
                        DIAS___("SSLCom::waiting_peer_hello: analysis failed");
                        DIA___("SSLCom::waiting_peer_hello: failed ClientHello data:\n%s",hex_dump(sslcom_peer_hello_buffer.data(),sslcom_peer_hello_buffer.size()).c_str());
                        
                        if(peer() != nullptr) {
                            baseSSLCom* s = dynamic_cast<baseSSLCom*>(peer());
                            if(s != nullptr) {
                                opt_bypass = true;
                                s->opt_bypass = true;
                                INFS___("bypassing non-TLS connection");
                                return false; //return false to return from read() or write()
                            }
                        }
                        
                        error_flag_ = ERROR_UNSPEC; // peer nullptr or its com() is not SSLCom
                        return false;
                        
                    } else {
                        if(parse_hello_result < 0) {

                            // not enough of data
                            return false;
                        }
                        else /* > 0*/ {
                            // we are okay
                            ;
                        }
                    }
                    
                    sslcom_peer_hello_received_ = true;

                    if(sslcom_peer_hello_sni_.size() > 0) {

                        std::lock_guard<std::recursive_mutex> l_(certstore()->lock());

                        std::string subj = certstore()->find_subject_by_fqdn(sslcom_peer_hello_sni_);
                        if(subj.size() > 0) {
                            DIA___("SSLCom::waiting_peer_hello: peer's SNI found in subject cache: '%s'",subj.c_str());
                            if(! enforce_peer_cert_from_cache(subj)) {
                                DIAS___("SSLCom::waiting_peer_hello: fallback to slow-path");
                            }
                        } else {
                            DIAS___("Peer's SNI NOT found in certstore, no shortcuts possible.");
                        }
                    }

                } else {
                    DUM___("SSLCom::waiting_peer_hello: peek returns %d, readbuf=%d",red,owner_cx()->readbuf()->size());
                    DUM___("SSLCom::waiting_peer_hello: peek errno: %s",string_error().c_str());
                }

            } else {
                DIA___("SSLCom::waiting_peer_hello: SSLCom peer doesn't have sslcom_fd set, socket %d",p->sslcom_fd);
               
                // FIXME: definitely not correct
                if(p->l4_proto() == SOCK_DGRAM) {
                    // atm don't wait for hello
                    sslcom_peer_hello_received(true);
                }
            }
        } else {
            DIAS___("SSLCom::waiting_peer_hello: peer not SSLCom type");
        }
    } else {
        DIAS___("SSLCom::waiting_peer_hello: no peers, setting hello received.");
        sslcom_peer_hello_received(true);
    }

    return sslcom_peer_hello_received_;
}

template <class L4Proto>
bool baseSSLCom<L4Proto>::enforce_peer_cert_from_cache(std::string & subj) {
    if(peer() != nullptr) {

        if(peer()->owner_cx() != nullptr) {
            DIAS___("SSLCom::enforce_peer_cert_from_cache: about to force peer's side to use cached certificate");

            std::lock_guard<std::recursive_mutex> l_(certstore()->lock());

            auto* parek = certstore()->find(subj);
            if (parek != nullptr) {
                DIA___("Found cached certificate %s based on fqdn search.",subj.c_str());
                baseSSLCom* p = dynamic_cast<baseSSLCom*>(peer());
                if(p != nullptr) {

                    if(p->sslcom_waiting) {
                        p->sslcom_pref_cert = parek->second;
                        p->sslcom_pref_key = parek->first;
                        //p->init_server(); this will be done automatically, peer was waiting_for_peercom
                        p->owner_cx()->waiting_for_peercom(false);
                        DIAS___("SSLCom::enforce_peer_cert_from_cache: peer certs replaced by SNI lookup, peer was unpaused.");
                        sslcom_peer_sni_shortcut = true;

                        return true;
                    } else {
                        DIAS_("SSLCom::enforce_peer_cert_from_cache: cannot modify non-waiting peer!");
                    }
                } else {
                    DIAS___("SSLCom::enforce_peer_cert_from_cache: failed to update peer:  it's not SSLCom* type!");
                }
            } else {
                DIAS___("SSLCom::enforce_peer_cert_from_cache: failed to update initiator with cached certificate: certificate was not found.!");
            }
        }
    }

    return false;
}


template <class L4Proto>
int baseSSLCom<L4Proto>::parse_peer_hello() {

    int ret = -1;

    uint8_t content_type = 0;

    try {

        buffer& b = sslcom_peer_hello_buffer;
        if(b.size() >= 34) {

            buffer session_id = buffer();
            unsigned int curpos = 0;

            unsigned char message_type = b.get_at<unsigned char>(curpos);
            curpos+=sizeof(unsigned char);
            unsigned char version_maj = b.get_at<unsigned char>(curpos);
            curpos+=sizeof(unsigned char);
            unsigned char version_min = b.get_at<unsigned char>(curpos);
            curpos+=sizeof(unsigned char);

            unsigned short message_length = ntohs(b.get_at<unsigned short>(curpos));
            curpos+=sizeof(unsigned short);


            DIA___("SSLCom::parse_peer_hello: buffer size %d, received message type %d, version %d.%d, length %d",b.size(),message_type,version_maj, version_min, message_length);
            if(b.size() != (unsigned int)message_length + 5) {
                DEBS___("SSLCom::parse_peer_hello: strange SSL payload received");
                if(message_type != 22 || version_maj > 5) {
                    DIAS___("SSLCom::parse_peer_hello: message is not ClientHello");
                    return 0;
                }
            }

            unsigned char handshake_type = b.get_at<unsigned char>(curpos);
            curpos+=(sizeof(unsigned char) + 1); //@6 (there is padding 0x00, or length is 24bit :-O)
            
            if(message_type == 22 && handshake_type == 1) {

                unsigned short handshake_length = ntohs(b.get_at<unsigned short>(curpos));
                curpos+=sizeof(unsigned short); //@9
                unsigned char handshake_version_maj = b.get_at<unsigned char>(curpos);
                curpos+=sizeof(unsigned char); //@10
                unsigned char handshake_version_min = b.get_at<unsigned char>(curpos);
                curpos+=sizeof(unsigned char); //@11
                unsigned int  handshake_unixtime = ntohl(b.get_at<unsigned char>(curpos));
                curpos+=sizeof(unsigned int); //@15

                curpos += 28; // skip random 24B bytes

                unsigned char session_id_length = b.get_at<unsigned char>(curpos);
                curpos+=sizeof(unsigned char);

                // we already know it's handshake, it's ok to return true
                DIA___("SSLCom::parse_peer_hello: handshake (type %u), version %u.%u, length %u",handshake_type,handshake_version_maj,handshake_version_min,handshake_length);
                if(handshake_type == 1) {
                    ret = 1;
                }

                if(session_id_length > 0) {
                    session_id = b.view(curpos,session_id_length);
                    curpos+=session_id_length;
                    DEB___("SSLCom::parse_peer_hello: session_id (length %d)",session_id_length);
                    DUM___("SSLCom::parse_peer_hello: session_id :\n%s",hex_dump(session_id.data(),session_id.size()).c_str());
                } else {
                    DEBS___("SSLCom::parse_peer_hello: no session_id found.");
                }

                unsigned short ciphers_length = ntohs(b.get_at<unsigned short>(curpos));
                curpos+=sizeof(unsigned short);
                curpos += ciphers_length; //skip ciphers
                unsigned char compression_length = b.get_at<unsigned char>(curpos);
                curpos+=sizeof(unsigned char);
                curpos += compression_length; // skip compression methods

                DEB___("SSLCom::parse_peer_hello: ciphers length %d, compression length %d",ciphers_length,compression_length);

                /* extension section */
                unsigned short extensions_length = ntohs(b.get_at<unsigned short>(curpos));
                curpos+=sizeof(unsigned short);
                DEB___("SSLCom::parse_peer_hello: extensions payload length %d",extensions_length);

                if(extensions_length > 0) {

                    // minimal extension size is 5 (2 for ID, 2 for len)
                    while(curpos + 4 < b.size()) {
                        curpos += parse_peer_hello_extensions(b,curpos);
                    }
                }
            } 
            else if(message_type == 22 && handshake_type != 1) {
                ERR___("SSLCom::parse_peer_hello: handshake message, but not ClientHello; message_type %d, handshake_type %d", message_type, handshake_type);
                ret = 1; // we need to assume we are late, so let continue without SNI.
            }
            else if(message_type > 22) {
                ERR___("SSLCom::parse_peer_hello: post-handshake message; message_type %d, handshake_type %d", message_type, handshake_type);
                ret = 1; // we need to assume we are late, so let continue without SNI.
            } else {
                ERR___("SSLCom::parse_peer_hello: unknown message; message_type %d, handshake_type %d", message_type, handshake_type);
                ret = 1; // we need to assume we are late, so let continue without SNI.
            }
            
                
        } else {
            baseSSLCom* p = dynamic_cast<baseSSLCom*>(peer());
            if(p != nullptr) 
                master()->poller.poller->rescan_in(p->sslcom_fd);
            
            DIA___("SSLCom::parse_peer_hello: only %d bytes in peek:\n%s",b.size(),hex_dump(b.data(),b.size()).c_str());
            if(timeval_msdelta_now(&timer_start) > SSLCOM_CLIENTHELLO_TIMEOUT) {
                ERRS___("handshake timeout: waiting for ClientHello");
                error(ERROR_UNSPEC);
            }
        }

        DIA___("SSLCom::parse_peer_hello: return status %d",ret);
    }
    catch (std::out_of_range const& e) {
        DIAS___(string_format("SSLCom::parse_peer_hello: failed to parse hello: %s",e.what()).c_str());
        error(ERROR_UNSPEC);
    }

    return ret;
}

template <class L4Proto>
unsigned short baseSSLCom<L4Proto>::parse_peer_hello_extensions(buffer& b, unsigned int curpos) {

    unsigned short ext_id = ntohs(b.get_at<unsigned short>(curpos));
    curpos+=sizeof(unsigned short);
    unsigned short ext_length = ntohs(b.get_at<unsigned short>(curpos));
    curpos+=sizeof(unsigned short);

    DEB___("SSLCom::parse_peer_hello_extensions: extension id 0x%x, length %d", ext_id, ext_length);

    switch(ext_id) {

        /* server name*/
        case 0:
            unsigned short sn_list_length = htons(b.get_at<unsigned short>(curpos));
            curpos+= sizeof(unsigned short);
            unsigned  char sn_type = b.get_at<unsigned char>(curpos);
            curpos+= sizeof(unsigned char);

            /* type is hostname*/
            if(sn_type == 0) {
                unsigned short sn_hostname_length = htons(b.get_at<unsigned short>(curpos));
                curpos+= sizeof(unsigned short);
                std::string s;
                s.append((const char*)b.data()+curpos,(size_t)sn_hostname_length);

                DIA___("SSLCom::parse_peer_hello_extensions:    SNI hostname: %s",s.c_str());

                sslcom_peer_hello_sni_ = s;
                //SSL_set_tlsext_host_name(sslcom_ssl,s.c_str());
            }

            break;
    }

    return ext_length + 4;  // +4 for ext_id and ext_length
}



#pragma GCC diagnostic ignored "-Wpointer-arith"
#pragma GCC diagnostic push

template <class L4Proto>
int baseSSLCom<L4Proto>::read ( int __fd, void* __buf, size_t __n, int __flags )  {

    int total_r = 0;
    int rounds = 0;

    if(opt_bypass) {
        return L4Proto::read(__fd,__buf,__n,__flags);
    }

    // non-blocking socket can be still opening
    if( sslcom_waiting ) {
        DUM___("SSLCom::read[%d]: still waiting for handshake to complete.",__fd);
        ret_handshake c = handshake();

        if (c == ret_handshake::AGAIN) {
            DUM___("SSLCom:: read[%d]: ssl_waiting() returned %d: still waiting",__fd,c);
            return -1;
        } else if (c == ret_handshake::ERROR) {
            DIA___("SSLCom:: read[%d]: ssl_waiting() returned %d: unrecoverable!",__fd,c);
            return 0;
        }

        DIA___("SSLCom::read[%d]: handshake finished, continue with %s from socket",__fd, __flags & MSG_PEEK ? "peek" : "read");
        // if we were waiting, force next round of read
        forced_read(true);
        monitor_peer();
    }

    // if we are peeking, just do it and return, no magic done is here
    if ((__flags & MSG_PEEK) != 0) {
        DUM___("SSLCom::read[%d]: about to peek  max %4d bytes",__fd,__n);
        int peek_r = SSL_peek(sslcom_ssl,__buf,__n);
        prof_peek_cnt++;

        if(peek_r > 0) {
            DIA___("SSLCom::read[%d]: peek returned %d",__fd, peek_r);
        } else {
            DUM___("SSLCom::read[%d]: peek returned %d",__fd, peek_r);
        }

        return peek_r;
    }

    do {

        if(total_r >= (int)__n) {
            DEB___("SSLCom::read[%d]: reached buffer capacity of %4d bytes, forcing new read",__fd,__n);

            // this is tricky one :)
            // I have spent quite couple of hours of troubleshooting this:
            // ...
            // We have to break here, since write buffer is full
            // BUT
            // openssl already has it internally
            // => select|poll won't return this socket as in read_set == no reads anymore !!!
            // => we have to have mechanism which will enforce read in the next round
            forced_read(true);
            break;
        }

        EXT___("SSLCom::read[%d]: about to read  max %4d bytes",__fd,__n);

        ERR_clear_error();
        int r = SSL_read (sslcom_ssl, __buf + total_r, __n - total_r);
        prof_read_cnt++;

        if(r == 0) {
            DEBS___("SSLCom::read: SSL_read returned 0");
        }

        int err = SSL_get_error ( sslcom_ssl,r);
        switch ( err ) {
            case SSL_ERROR_NONE:

                DEB___("SSLCom::read [%d]: %4d bytes read:(round %d) %s, %X",__fd,r,rounds,
                                                                    (r == (signed int)__n) ? "(max)" : "(no-max)",
                                                                         debug_log_data_crc ? socle_crc32(0,__buf,r) : 0
                    );

                if(r > 0)
                    total_r += r;

                
                if(sslcom_read_blocked_on_write > 0) {
                    master()->poller.modify(__fd,EPOLLIN);
                    sslcom_read_blocked_on_write=0;
                }
                
                sslcom_read_blocked=0;
                
                // reset IO timeouts
                set_timer_now(&timer_read_timeout);
                set_timer_now(&timer_write_timeout);
                
                
                break;

            case SSL_ERROR_ZERO_RETURN:
                DEB___("SSLCom::read[%d]: zero returned",__fd);
                SSL_shutdown (sslcom_ssl);
                return r;

            case SSL_ERROR_WANT_READ:
                if(r == -1) {
                    DEB___("SSLCom::read[%d]: want read: err=%d,read_now=%4d,total=%4d",__fd,err,r,total_r);
                }
                else {
                    DEB___("SSLCom::read[%d]: want read: err=%d,read_now=%4d,total=%4d",__fd,err,r,total_r);
                }
                sslcom_read_blocked=1;
                
                // defer read operation
                rescan_read(sslcom_fd);

                // check timers and bail on timeout
                if(timeval_msdelta_now(&timer_read_timeout) > SSLCOM_READ_TIMEOUT) {
                    ERR___("SSLCom::read[%d]: read timeout, closing.",__fd);
                    error(ERROR_READ);
                    return 0;
                }
                
                if(total_r > 0) return total_r;
                return r;

                /* We get a WANT_WRITE if we're
                trying to rehandshake and we block on
                a write during that rehandshake.

                We need to wait on the socket to be
                writeable but reinitiate the read
                when it is */

            case SSL_ERROR_WANT_CONNECT:
                DIA___("SSLCom::read[%d]: want connect",__fd);

                if(total_r > 0) return total_r;
                return r;

            case SSL_ERROR_WANT_ACCEPT:
                DIA___("SSLCom::read[%d]: want accept",__fd);

                if(total_r > 0) return total_r;
                return r;


            case SSL_ERROR_WANT_WRITE:
                DEB___("SSLCom::read[%d]: want write, last read returned %d, total read %4d",__fd,r,total_r);

                forced_read_on_write(true);
                sslcom_read_blocked_on_write=1;
                master()->poller.modify(__fd,EPOLLIN|EPOLLOUT);

                // check timers and bail on timeout
                if(timeval_msdelta_now(&timer_read_timeout) > SSLCOM_READ_TIMEOUT) {
                    ERR___("SSLCom::read[%d]: read timeout, closing.",__fd);
                    error(ERROR_READ);
                    return 0;
                }
                                
                
                if(total_r > 0) return total_r;
                return r;

            case SSL_ERROR_WANT_X509_LOOKUP:
                DIA___("SSLCom::read[%d]: want x509 lookup",__fd);
                if(total_r > 0) return total_r;
                return r;

            case SSL_ERROR_SYSCALL:
                DIA___("SSLCom::read[%d]: syscall error",__fd);
                if(total_r > 0) return total_r;
                return r;

            default:
                if (r != -1 && err != 1) {
                    DIA___("SSLCom::read[%d] problem: %d, read returned %4d",__fd,err,r);
                }
                // 			SSL_shutdown (sslcom_ssl);
                if(total_r > 0) return total_r;
                return r;
        }

        /* We need a check for read_blocked here because
           SSL_pending() doesn't work properly during the
           handshake. This check prevents a busy-wait
           loop around SSL_read() */
        rounds++;

        //} while ( SSL_pending ( sslcom_ssl ) && !sslcom_read_blocked );
    } while ( SSL_pending ( sslcom_ssl ) && !sslcom_read_blocked);

    DIA___("SSLCom::read: total %4d bytes read",total_r);

    if(total_r == 0) {
        DIAS___("SSLCom::read: logic error, total_r == 0");
    }

    return total_r;
}


template <class L4Proto>
int baseSSLCom<L4Proto>::write ( int __fd, const void* __buf, size_t __n, int __flags )  {

    if(__n == 0) {
        EXT___("SSLCom::write[%d]: called: about to write %d bytes",__fd,__n);
    } else {
        DEB___("SSLCom::write[%d]: called: about to write %d bytes",__fd,__n);
    }


    if(opt_bypass) {
        return L4Proto::write(__fd,__buf,__n,__flags);
    }

    // this one will be much trickier than just single call of SSL_read
    // return SSL_write(sslcom_ssl, __buf, __n);

    // non-blocking socket can be still opening
    if( sslcom_waiting ) {
        DUM___("SSLCom::write[%d]: still waiting for handshake to complete.",__fd);

        ret_handshake c = handshake();
        if (c == ret_handshake::AGAIN) {
            DUM___("SSLCom::write[%d]: ssl_waiting() returned %d: still waiting",__fd,c);
            return 0;
        } else if (c == ret_handshake::ERROR) {
            DIA___("SSLCom::write[%d]: ssl_waiting() returned %d: unrecoverable!",__fd,c);
            return -1;
        }
        DIA___("SSLCom::write[%d]: handshake finished, continue with writing to socket",__fd);
        // if we were waiting, force next round of write
        forced_write(true);
        monitor_peer();
    }

    sslcom_write_blocked_on_read=0;
    int normalized__n = 20480;
    void *ptr = (void*)__buf;

    if(__n == 0) {
        EXT___("SSLCom::write[%d]: attempt to send %d bytes",__fd,__n);
    } else {
        DEB___("SSLCom::write[%d]: attempt to send %d bytes",__fd,__n);
    }
    if ( __n < 20480) {
        normalized__n = __n;
    }

    if (__n <= 0 ) {
        return 0;
    }

    /* Try to write */
    ERR_clear_error();
    int r = SSL_write (sslcom_ssl,ptr,normalized__n);

    if(r >= normalized__n) {
        forced_write(true);
    }

    prof_write_cnt++;

    int err = SSL_get_error ( sslcom_ssl,r );
    bool is_problem = true;
    bool apply_error_timer = false;

    switch ( err ) {

            /* We wrote something*/
        case SSL_ERROR_NONE:
            DEB___("SSLCom::write[%d]: %4d bytes written to the ssl socket %s, %X",__fd,r, r != (signed int)__n ? "(incomplete)" : "",
                debug_log_data_crc ? socle_crc32(0,__buf,r) : 0
                );
            is_problem = false;

            if(sslcom_write_blocked_on_read > 0) {
                sslcom_write_blocked_on_read = 0;
                forced_write_on_read(false);
                DIA___("SSLCom::write[%d]: want read: cleared",__fd);
            }
            if(sslcom_write_blocked_on_write > 0) {
                sslcom_write_blocked_on_write = 0;
                master()->poller.modify(__fd,EPOLLIN);
                DIA___("SSLCom::write[%d]: want write: cleared",__fd);
            }
            
            // reset IO timeouts
            set_timer_now(&timer_read_timeout);
            set_timer_now(&timer_write_timeout);

            break;

            /* We would have blocked */
        case SSL_ERROR_WANT_WRITE:
            DIA___("SSLCom::write[%d]: want write: %d (written %4d)",__fd,err,r);

            // trigger write again
            master()->poller.modify(__fd,EPOLLIN|EPOLLOUT);
            sslcom_write_blocked_on_write=1;

            if (r > 0) {
                normalized__n = normalized__n - r;
                ptr += r;
            } else {
                DUM___("SSLCom::write[%d]: want write: repeating last operation",__fd);
            }

            apply_error_timer = true;
            break;

            /* We get a WANT_READ if we're
                    trying to rehandshake and we block on
                    write during the current connection.

                    We need to wait on the socket to be readable
                    but reinitiate our write when it is */
        case SSL_ERROR_WANT_READ:
            DIA___("SSLCom::write[%d]: want read: %d (written %4d)",__fd,err,r);
            sslcom_write_blocked_on_read=1;

            forced_write_on_read(true);
            master()->poller.modify(__fd,EPOLLIN);

            apply_error_timer = true;
            break;

            /* Some other error */
        default:
            DEB___("SSLCom::write[%d]: problem: %d",__fd,err);
            apply_error_timer = true;


    }
    
    if(apply_error_timer && timeval_msdelta_now(&timer_write_timeout) > SSLCOM_WRITE_TIMEOUT) {
        ERR___("SSLCom::write[%d]: write timeout, closing.",__fd);
        error(ERROR_WRITE);
        is_problem = true;
    }    

    if (is_problem) {
        return 0;
    }

    DIA___("SSLCom::write[%d]: %4d bytes written",__fd,r);
    return r;
};

#pragma GCC diagnostic pop

template <class L4Proto>
void baseSSLCom<L4Proto>::cleanup()  {

    DIA__("  prof_accept %d, prof_connect %d, prof_peek %d, prof_read %d, prof_want_read %d, prof_want_write %d, prof_write %d",
          prof_accept_cnt   , prof_connect_cnt   , prof_peek_cnt   , prof_read_cnt   , prof_want_read_cnt   , prof_want_write_cnt   , prof_write_cnt);
    DIA__("   prof_accept_ok %d, prof_connect_ok %d",prof_accept_ok, prof_connect_ok);

//     if(sslcom_sbio) {
//         BIO_free(sslcom_sbio); // produces Invalid read of size 8: at 0x539D840: BIO_free (in /usr/lib/x86_64-linux-gnu/libcrypto.so.1.0.0)
//         sslcom_sbio = nullptr;
//     }

    if (!sslcom_waiting) {
        int shit = SSL_shutdown(sslcom_ssl);  //_sh_utdown _it_
        if (shit == 0) {
                DEBS__("  shutdown success");
            }
        else {
            if(shit < 0) {
                DEB__("  shutdown failed: %d", SSL_get_error(sslcom_ssl, shit));
            }
        }
    }

    if(sslcom_ssl) 	{
        SSL_free (sslcom_ssl);
        sslcom_ssl = nullptr;
    }


    L4Proto::cleanup();
}

template <class L4Proto>
int baseSSLCom<L4Proto>::upgrade_client_socket(int sock) {

    sslcom_fd = sock;

    bool ch = waiting_peer_hello();

    if(ch) {

        if(opt_bypass) {
            DIA___("SSLCom::upgrade_client_socket[%d]: bypassed",sock);
            return sock;
        }


        init_client();

        if(sslcom_ssl == NULL) {
            ERR___("SSLCom::upgrade_client_socket[%d]: failed to create SSL structure!",sock);
        }
        //  SSL_set_fd (sslcom_ssl, sock);

        if(sslcom_peer_hello_sni_.size() > 0) {
            DIA_("SSLCom::upgrade_client_socket[%d]: set sni extension to: %s",sock, sslcom_peer_hello_sni_.c_str());
            SSL_set_tlsext_host_name(sslcom_ssl, sslcom_peer_hello_sni_.c_str());
        }

        sslcom_sbio = BIO_new_socket(sock,BIO_NOCLOSE);
        if (sslcom_sbio == NULL) {
            ERR___("SSLCom::upgrade_client_socket[%d]: BIO allocation failed! ",sock)
        }

        SSL_set_bio(sslcom_ssl,sslcom_sbio,sslcom_sbio);

        ERR_clear_error();
        int r = SSL_connect(sslcom_ssl);
        prof_connect_cnt++;

        if(r <= 0 && is_blocking(sock)) {
            ERR___("SSL connect error on socket %d",sock);
            close(sock);
            return -1;
        }
        else if (r <= 0) {
            /* non-blocking may return -1 */

            if (r == -1) {
                int err = SSL_get_error(sslcom_ssl,r);
                if (err == SSL_ERROR_WANT_WRITE) {
                    DIA___("upgrade_client_socket[%d]: SSL_connect: pending on want_write",sock);
                    
                    // interested in WRITE, so ignore read events
                    set_write_monitor_only(sslcom_fd);
                    
                    // since connect is not immediate, ignore all read events of the peer causing busy loop
                    unmonitor_peer();
                   
                }
                else if(err == SSL_ERROR_WANT_READ) {
                    DIA___("upgrade_client_socket[%d]: SSL_connect: pending on want_read",sock);
                    
                    // since connect is not immediate, ignore all read events of the peer causing busy loop
                    unmonitor_peer();
                }
                sslcom_waiting = true;
                return sock;
            }
            return sock;
        }

        prof_connect_ok++;

        DEB___("SSLCom::upgrade_client_socket[%d]: connection succeeded",sock);
        sslcom_waiting = false;
        
        // restore peer monitoring
        monitor_peer();
        store_session_if_needed();

        //ssl_waiting_host = (char*)host;
        check_cert(nullptr);

        forced_read(true);
        forced_write(true);

        upgraded(true);

#ifndef USE_OPENSSL111
        if(sslkeylog) {
            dump_keys();
            sslkeylog = false;
        }
#endif
    }


    return sock;


}

template <class L4Proto>
int baseSSLCom<L4Proto>::connect(const char* host, const char* port)  {
    int sock = L4Proto::connect( host, port);

    DIA___("SSLCom::connect[%d]: %s connected",sock,L4Proto::name().c_str());
    sock = upgrade_client_socket(sock);

//     ERRS___("DIABLING MEM CHECK");
//     CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_DISABLE);
    
    if(upgraded()) {
        DIA___("SSLCom::connect[%d]: socket upgraded at 1st attempt!",sock);
    }

    return sock;
}


template <class L4Proto>
bool baseSSLCom<L4Proto>::com_status() {
    if(L4Proto::com_status()) {
        if(opt_bypass) {
            DIAS___("SSLCom::com_status: L4 OK, bypassed")
            return true;
        }

        bool r = sslcom_status();
        // T_DIA___("sslcom_status_ok",1,"SSLCom::com_status: returning %d",r);

        if(r) {
            DIAS___("SSLCom::com_status: L4 and SSL layers OK")
        } else {
            DEBS___("SSLCom::com_status: L4 OK, but SSL layer not ready.")
        }

        DEB___("SSLCom::com_status: returning %d",r);
        return r;
    }

    // T_DIAS___("sslcom_status_nok",1,"SSLCom::com_status: returning 0");
    DEBS___("SSLCom::com_status: L4 layer not ready, returning 0");
    return false;
}

template <class L4Proto>
void baseSSLCom<L4Proto>::shutdown(int __fd) {
    
    if(sslcom_ssl != nullptr) {
        SSL_shutdown(sslcom_ssl);
    }
    L4Proto::shutdown(__fd);
}


#endif // __SSLCOM_INCL__
