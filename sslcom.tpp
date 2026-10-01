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

#ifndef SSLCOM_INCL
#define SSLCOM_INCL

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
#include <log/logger.hpp>
#include <display.hpp>
#include <timeops.hpp>
#include <vars.hpp>

#include <cstdio>
#include <functional>

#include <crc32.hpp>
#include <display.hpp>
#include <biomem.hpp>
#include <buffer.hpp>
#include <internet.hpp>
#include "hostcx.hpp"

inline void set_timer_now(struct timeval* t) {
    gettimeofday(t,nullptr);
}

template <class L4Proto>
baseSSLCom<L4Proto>::baseSSLCom(): L4Proto() {

    sslcom_peer_hello_buffer.capacity(1500);
    sslcom_server_hello_buffer.capacity(0); // don't waste memory for optional collection
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
    baseSSLCom::factory(&SSLFactory::factory().init());
}

template <class L4Proto>
void baseSSLCom<L4Proto>::static_init() {

    baseCom::static_init();

    _deb("SSL: Static INIT");

    // call openssl threads support - only once from all threads!
    std::call_once(baseSSLCom::openssl_thread_setup_done , CompatThreading::THREAD_setup);
    std::call_once(baseSSLCom::certstore_setup_done , baseSSLCom::certstore_setup);
}


template <class L4Proto>
void baseSSLCom<L4Proto>::init(baseHostCX* owner)  {

    L4Proto::init(owner);
}


template <class L4Proto>
std::string baseSSLCom<L4Proto>::to_string(int verbosity) const {
    mp::stringstream ss;

    ss << "SSLCom[" << ( is_server() ? "server] <-" : "client] ->" );
    if(owner_cx()) {
        ss << " ip: " << owner_cx()->host() << ":" << owner_cx()->port() << ", ";
    }
    ss << "sni:" << get_sni() << " alpn: " << sslcom_alpn_;

    if(opt.bypass) ss << " bypassed";
    if(opt.no_fallback_bypass) ss << " no_fallback_bypass";

    return ss.str().c_str();
}

// server callback on internal cache miss
template <class L4Proto>
SSL_SESSION* baseSSLCom<L4Proto>::server_get_session_callback(SSL* ssl, const unsigned char* , int, int* ) {
    SSL_SESSION* ret = nullptr;

    auto const& log = log_cb_session();

    void* data = SSL_get_ex_data(ssl, baseSSLCom::extdata_index());
    std::string name = "unknown_cx";
    auto* com = static_cast<baseSSLCom*>(data);
    if(com != nullptr) {
        _if_inf name = com->hr();
    }

    _inf("lookup server session[%s]: SSL: 0x%x", name.c_str(), ssl);
    return ret;
}
template <class L4Proto>
int baseSSLCom<L4Proto>::new_session_callback(SSL* ssl, SSL_SESSION* session) {

    auto const& log = log_cb_session();

    void* data = SSL_get_ex_data(ssl, baseSSLCom::extdata_index());
    std::string name = "unknown_cx";
    auto* com = static_cast<baseSSLCom*>(data);
    if(com != nullptr) {
        _if_inf {
            const std::string title = com->hr();
            _inf("new session[%s]: SSL: 0x%x, SSL_SESSION: 0x%x", title.c_str(), ssl, session);
        }

        if (com->verify_bitcheck(verify_status_t::VRF_REVOKED)) {
            _if_inf {
                const std::string title = com->hr();
                _inf("new session[%s]: SSL: 0x%x, session rejected due verify status: 0x%04x", title.c_str(), ssl,
                     com->verify_get());
            }
            return 0;
        }


        if(com->store_session_if_needed()) {

            // we stored the session, return 1 to be used
            return 1;
        }

        return 0;
    }

    _err("new session[%s]: SSL: 0x%x, SSL_SESSION: 0x%x - cannot cast", name.c_str(), ssl, session);
    return 0;
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
        name = com->hr();
    }
#endif
    const char *str;
    auto const& log = log_cb_info();

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
    std::string name = com->hr();

    log.log(loglevel(lev,0), "com.ssl", "  [%s]: prof_accept_cnt %d, prof_connect_cnt %d, prof_peek_cnt %d, prof_read_cnt %d, "
                             "prof_want_read_cnt %d, prof_want_write_cnt %d, prof_write_cnt %d", name.c_str(),
                             com->counters.prof_accept_cnt, com->counters.prof_connect_cnt, com->counters.prof_peek_cnt, com->counters.prof_read_cnt,
                             com->counters.prof_want_read_cnt, com->counters.prof_want_write_cnt   , com->counters.prof_write_cnt);

    log.log(loglevel(lev,0), "com.ssl", "  [%s]: prof_accept_ok %d, prof_connect_ok %d",name.c_str(), com->counters.prof_accept_ok,
                             com->counters.prof_connect_ok);
}

template <class L4Proto>
void baseSSLCom<L4Proto>::ssl_msg_callback(int write_p, int version, int content_type, const void* buf, size_t len, SSL* ssl, void* arg)
{
    auto const& log = log_cb_msg();
    auto* com = static_cast<baseSSLCom*>(arg);
    const auto* data = static_cast<const unsigned char*>(buf);

    // On production log levels almost all callback invocations are merely
    // notifications about ordinary handshake records. Preserve the optional
    // ServerHello capture, but avoid constructing connection names and
    // decoding message metadata unless diagnostics or alert handling needs it.
    if (content_type == SSL3_RT_HANDSHAKE && com && data && len > 0 &&
        data[0] == SSL3_MT_SERVER_HELLO && SSLComOptions::server_hello_copy) {
        com->sslcom_server_hello_buffer.assign(data, len);
        _dum("ServerHello: %s", hex_print(data, len).c_str());
    }

    const bool diagnostics_enabled = *log.level() >= DEB;
#ifdef USE_OPENSSL11
    if (content_type != SSL3_RT_ALERT && !diagnostics_enabled)
        return;
#else
    if (content_type != SSL3_RT_ALERT && content_type != SSL3_RT_CHANGE_CIPHER_SPEC &&
        !diagnostics_enabled)
        return;
#endif

    const char *msg_version;
    std::string msg_version_unknown;
    const char *msg_direction;
    const char *msg_content_type;
    std::string msg_content_unknown;

    std::string name = "unknown_cx";

    if(com != nullptr) {
        name = com->hr();
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

    _deb("[%s]: SSLCom::ssl_msg_callback: %s/%s has been %s",name.c_str(), msg_version, msg_content_type, msg_direction);

    if(content_type == 21) {

        auto const* buffy = static_cast<uint8_t const*>(buf);

        if (not buffy || len < 2) {
            _err("[%s]: SSLCom::ssl_msg_callback: truncated TLS alert (%zu bytes)",
                 name.c_str(), len);
            if (com)
                com->error(ERROR_UNSPEC);
            return;
        }

        _dum("[%s]: SSLCom::ssl_msg_callback: alert dump:\r\n%s", name.c_str(), hex_dump(buffy, len, 4, 0, true).c_str());
        uint16_t int_code = ntohs(buffer::get_at_ptr<uint16_t>(buffy));
        uint8_t level = buffer::get_at_ptr<uint8_t>(buffy);
        uint8_t code = buffer::get_at_ptr<uint8_t>(buffy+1);
        if(com) {
            _dia("[%s]: SSLCom::ssl_msg_callback: alert info: %s/%s [%d/%d]", name.c_str(),
                    SSL_alert_type_string_long(int_code),SSL_alert_desc_string_long(int_code),level,code);

            
            if(code == 10) {
                // unexpected message
                com->log_profiling_stats(iDEB);
            }

            auto state = SSL_get_state(com->sslcom_ssl);

            // if handsake is finished and there is decode error, it's in vast majority
            // cases abruptly closed socket from the peer.
            bool skip_this_one = ((not com->opt.alerts.decode_error_in_operational)
                                and com->sslcom_op_state == sslcom_op_state_t::READY
                                and code == TLS1_AD_DECODE_ERROR);
            bool skip_all = com->opt.alerts.suppress_all;

            // if level is Fatal, log com error and close.
            if(level > 1) {
                const char* side_comment = com->is_server() ? "left" : "right";
                const char* state_comment = SSL_state_string(com->sslcom_ssl);

                _err("[%s|%s|%s]: TLS alert: %s/%s [%d/%d]", name.c_str(), side_comment, state_comment,
                        SSL_alert_type_string_long(int_code),SSL_alert_desc_string_long(int_code),level,code);
                com->error(ERROR_UNSPEC);

                if(not skip_all and not skip_this_one) {
                    auto event = log.event_block();

                    log.event(ERR, "[%s|%s|%s]: TLS alert: %s/%s [%d/%d]", com->to_string(iINF).c_str(), side_comment,
                              state_comment,
                              SSL_alert_type_string_long(int_code), SSL_alert_desc_string_long(int_code), level, code);

                    baseSSLCom *details_com = com;
                    if (com->is_server()) {
                        details_com = nullptr;
                        if (com->peer()) details_com = dynamic_cast<baseSSLCom *>(com->peer());
                    }

                    if (details_com) log.event_detail(event.eid, "%s", details_com->ssl_error_details().c_str());
                }
            }
            
        }
    }
    else if(content_type ==20) {
        if(write_p == 0 && com && !com->is_server()) {

#ifndef USE_OPENSSL11
            int bits = check_server_dh_size(ssl);
            if(bits < 768) {
                if(bits > 0) {
                    _war("  [%s]: server dh key bits equivalent: %d",name.c_str(),bits);
                    if(not sslcom_fatal)
                        sslcom_ret = SSL_shutdown(ssl);

                    if(com->owner_cx() != nullptr) {
                        com->owner_cx()->error(true);
                    }
                } else {
                    _war("  [%s]: PFS not used!",name.c_str());
                }
            } else {
                _dia("  [%s]: server dh key bits equivalent: %d",name.c_str(),bits);
            }
#endif
        }
    }
}


template <class L4Proto>
int baseSSLCom<L4Proto>::check_server_dh_size(SSL* ssl) {
#ifdef USE_OPENSSL11
    // Currently it doesn't seem to be possible to get DH parameters for current SSL_SESSION

    // Workaround: return acceptable strength. Ugly.

    // see DH_check() for more DH tests!

    return 1024;
#else

    auto const& log = log_cb_dh();

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

template<class L4Proto>
bool baseSSLCom<L4Proto>::is_cert_validation_err_code_allowed_by_options(int err_code) const
{
    switch(err_code) {

        case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
        case X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE:
        case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
            return opt.cert.allow_unknown_issuer;

        case X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN:
        case X509_V_ERR_CERT_UNTRUSTED:
            return opt.cert.allow_self_signed_chain;

        case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
            return opt.cert.allow_self_signed;

        case X509_V_ERR_CERT_NOT_YET_VALID:
        case X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD:
            return opt.cert.allow_not_valid;

        case X509_V_ERR_CERT_HAS_EXPIRED:
        case X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD:
            return opt.cert.allow_not_valid;

        default:
            break;
    }

    return false;
}

template<class L4Proto>
void baseSSLCom<L4Proto>::report_certificate_problem(X509* err_cert, int err_code) const {
    auto better_name = socle::com::ssl::connection_name(this, true);

    // don't log if validation fails, but reason of failure is tolerated and allowed by options
    // still we want to show debugs, so _log* macros are still executed

    bool do_log = not is_cert_validation_err_code_allowed_by_options(err_code);

    _deb("[%s]: SSLCom::ssl_client_vrfy_callback: %d:%s",better_name.c_str(), err_code, X509_verify_cert_error_string(err_code));

    if(not do_log) {
        // announce this problem won't be reported in event log
        _deb("[%s]: SSLCom::ssl_client_vrfy_callback: event supressed due to profile settings", better_name.c_str());
    }

    auto event = log.event_block();

    if(do_log)
        log.event(ERR, "[%s]: certificate verify problem: %d:%s", better_name.c_str(), err_code, X509_verify_cert_error_string(err_code));

    if (err_cert) {
        _dia("[%s]: SSLCom::ssl_client_vrfy_callback: '%s' issued by '%s'", better_name.c_str(),
             SSLFactory::print_cn(err_cert).c_str(),
             SSLFactory::print_issuer(err_cert).c_str());

        if(do_log) {
            log.event(ERR, "[%s]: certificate verify problem: '%s' issued by '%s'", better_name.c_str(),
                      SSLFactory::print_cn(err_cert).c_str(),
                      SSLFactory::print_issuer(err_cert).c_str());

            log.event_detail(event.eid, "%s", ssl_error_details().c_str());
        }
    }
    else {
        _dia("[%s]: SSLCom::ssl_client_vrfy_callback: no server certificate", better_name.c_str());

        if(do_log)
            log.event(ERR, "%s: no server certificate", better_name.c_str());
    }
}

template <class L4Proto>
int baseSSLCom<L4Proto>::ssl_client_vrfy_callback(int lib_preverify, X509_STORE_CTX *ctx) {

    X509 * err_cert = X509_STORE_CTX_get_current_cert(ctx);
    int err_code =   X509_STORE_CTX_get_error(ctx);
    int depth = X509_STORE_CTX_get_error_depth(ctx);
    int idx = SSL_get_ex_data_X509_STORE_CTX_idx();
    int callback_return = lib_preverify;

    auto const& log = log_cb_verify();

    _deb("SSLCom::ssl_client_vrfy_callback: data index = %d, lib_preverify = %d, depth = %d", idx, lib_preverify, depth);

    auto const* ssl = static_cast<SSL*>(X509_STORE_CTX_get_ex_data(ctx, SSL_get_ex_data_X509_STORE_CTX_idx()));
    void* data = SSL_get_ex_data(ssl, extdata_index());
    std::string name = "unknown_cx";

    auto* com = static_cast<baseSSLCom*>(data);

    // update name via expensive dynamic cast only if we diagnose
    _if_dia if(com != nullptr) {
        
        auto* pcom = dynamic_cast<baseSSLCom*>(com->peer());
        if(pcom != nullptr) {
            name = pcom->hr();
        }
        else {
            name = com->hr();
        }
    }

    if(not com or not ssl) {
        _err("SSLCom::ssl_client_vrfy_callback: cannot get associated com object, failing validation!");
        return 0;
    }
    // now we don't need check com and ssl anymore

    X509* xcert = X509_STORE_CTX_get_current_cert(ctx);

    auto retain_certificate = [&](X509*& destination) {
        if(destination) {
            _err("already having peer certificate chain entry");
            X509_free(destination);
            destination = nullptr;
        }
        if (!xcert || X509_up_ref(xcert) != 1)
            return false;
        destination = xcert;
        return true;
    };


    if (depth == 0) {
        if (!retain_certificate(com->sslcom_target_cert))
            return 0;
    }
    else if (depth == 1) {
        if (!retain_certificate(com->sslcom_target_issuer))
            return 0;

        if(xcert) {
            int sig_nid = X509_get_signature_nid(xcert);
            _dia("Intermediate signature type(%d): %s", sig_nid, OBJ_nid2ln(sig_nid));
            if(sig_nid == NID_sha1WithRSAEncryption) {
                com->verify_bitset(verify_status_t::VRF_EXTENDED_INFO);
                com->verify_extended_info().emplace_back(vrf_other_values_t::VRF_OTHER_SHA1_SIGNATURE);
            }
        }
    }
    else if (depth == 2) {
        if (!retain_certificate(com->sslcom_target_issuer_issuer))
            return 0;
    }

    switch(err_code)  {
        case X509_V_OK:
            break;

        case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
        case X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE:
        case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:

            _dia("[%s]: SSLCom::ssl_client_vrfy_callback: unknown issuer: %d", name.c_str(), err_code);

            com->verify_bitset(verify_status_t::VRF_UNKNOWN_ISSUER);
            com->report_certificate_problem(err_cert, err_code);
            if(com->opt.cert.allow_unknown_issuer || com->opt.cert.failed_check_replacement) {
                callback_return = 1;
            }

            break;

        case X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN:
        case X509_V_ERR_CERT_UNTRUSTED:

            _dia("[%s]: SSLCom::ssl_client_vrfy_callback: self-signed cert in the chain: %d", name.c_str(), err_code);

            com->verify_bitset(verify_status_t::VRF_SELF_SIGNED_CHAIN);
            com->report_certificate_problem(err_cert, err_code);
            if(com->opt.cert.allow_self_signed_chain || com->opt.cert.failed_check_replacement) {
                callback_return = 1;
            }

            break;

        case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:

            _dia("[%s]: SSLCom::ssl_client_vrfy_callback: end-entity cert is self-signed: %d", name.c_str(), err_code);

            com->verify_bitset(verify_status_t::VRF_SELF_SIGNED);
            com->report_certificate_problem(err_cert, err_code);
            if(com->opt.cert.allow_self_signed || com->opt.cert.failed_check_replacement) {
                callback_return = 1;
            }

            break;

        case X509_V_ERR_CERT_NOT_YET_VALID:
        case X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD:
            _dia("[%s]: SSLCom::ssl_client_vrfy_callback: not before: %s", name.c_str(),
                    SSLFactory::print_not_before(err_cert).c_str());

            com->verify_bitset(verify_status_t::VRF_INVALID);
            com->report_certificate_problem(err_cert, err_code);
            if(com->opt.cert.allow_not_valid || com->opt.cert.failed_check_replacement) {
                callback_return = 1;
            }

            break;

        case X509_V_ERR_CERT_HAS_EXPIRED:
        case X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD:
            _dia("[%s]: SSLCom::ssl_client_vrfy_callback: not after: %s",name.c_str(),
                    SSLFactory::print_not_after(err_cert).c_str());

            com->verify_bitset(verify_status_t::VRF_INVALID);
            com->report_certificate_problem(err_cert, err_code);
            if(com->opt.cert.allow_not_valid || com->opt.cert.failed_check_replacement) {
                callback_return = 1;
            }

            break;
        case X509_V_ERR_NO_EXPLICIT_POLICY:
            _dia("[%s]: SSLCom::ssl_client_vrfy_callback: no explicit policy", name.c_str());
            break;

        default:

            // if not OK and no specific handling was treated by switch-case above, mark connection
            // as erroneous, according to "invalid certificate" settings.
            if(err_code > X509_V_OK) {
                com->verify_bitset(verify_status_t::VRF_INVALID);
                com->report_certificate_problem(err_cert, err_code);
                if(com->opt.cert.allow_not_valid || com->opt.cert.failed_check_replacement) {
                    callback_return = 1;
                }
            }

            _dia("[%s]: SSLCom::ssl_client_vrfy_callback: unknown verify status %d", name.c_str(), err_code);
    }
    
    
    _if_dia {
        if (err_code == X509_V_OK && lib_preverify == 2) {
            _dia("[%s]: SSLCom::ssl_client_vrfy_callback: explicit policy", name.c_str());
        }

        std::string cn = "unknown";
        if (xcert != nullptr) {
            cn = SSLFactory::print_cn(xcert) + ";" + SSLFactory::fingerprint(xcert);
        }
        _dia("[%s]: SSLCom::ssl_client_vrfy_callback[%d:%s]: returning %s (pre-verify %d)", name.c_str(), depth,
             cn.c_str(),
             (callback_return > 0 ? "ok" : "failed"), lib_preverify);

        if (callback_return <= 0) {
            _not("[%s]: target server ssl certificate check failed:%d: %s", name.c_str(), err_code,
                 X509_verify_cert_error_string(err_code));
        }
    }


    // Note: OCSP checks were removed from here. Only place to do OCSP is *status callback*

    return callback_return;
}

template <class L4Proto>
int baseSSLCom<L4Proto>::ssl_alpn_select_callback(SSL *s, const unsigned char **out, unsigned char *outlen,
                                                  const unsigned char *in, unsigned int inlen,
                                                  void *arg) {

    auto const& log = log_cb_alpn();

    auto* this_com = static_cast<baseSSLCom*>(SSL_get_ex_data(s, baseSSLCom<L4Proto>::extdata_index()));
    if(not this_com) {

        _err("SSLCom::ssl_alpn_select_callback: cannot retrieve this_com ssl external data");
        return SSL_TLSEXT_ERR_NOACK;
    }

    if(this_com->peer() and not this_com->opt.alpn_block) {

        if(not this_com->sslcom_alpn_.empty()) {

            *out = reinterpret_cast<const unsigned char*>(this_com->sslcom_alpn_.data());
            *outlen = this_com->sslcom_alpn_.length();

            _dia("SSLCom::ssl_alpn_select_callback: alpn already set, setting again: %s", this_com->sslcom_alpn_.c_str());

            return SSL_TLSEXT_ERR_OK;
        }

        if(auto* peer_com = dynamic_cast<baseSSLCom*>(this_com->peer()); peer_com) {
            SSL_get0_alpn_selected(peer_com->sslcom_ssl, &in, &inlen);

            if(inlen > 0) {

                _dia("SSLCom::ssl_alpn_select_callback: server offered alpn: \r\n%s",
                     hex_dump((unsigned char *) in, inlen).c_str(), 4, 0, true);

                *out = in;
                *outlen = inlen;

                this_com->sslcom_alpn_.assign(reinterpret_cast<const char*>(in), inlen);
                peer_com->sslcom_alpn_.assign(reinterpret_cast<const char*>(in), inlen);

                return SSL_TLSEXT_ERR_OK;
            } else {

                _dia("SSLCom::ssl_alpn_select_callback: no alpn from server");
                *out = nullptr;
                *outlen = 0;
            }
        }
    }

    return SSL_TLSEXT_ERR_NOACK;
}

template <class L4Proto>
unsigned long baseSSLCom<L4Proto>::log_if_error(unsigned int level, const char* prefix) {

    auto err2 = ERR_get_error();
    do {
        if(err2 != 0) {
            log.log(loglevel(level,0), "%s: error code:%u:%s", prefix, err2, ERR_error_string(err2, nullptr));
            err2 = ERR_get_error();
        }
    } while (err2 != 0);

    return err2;
}

#ifndef USE_OPENSSL300
template <class L4Proto>
DH* baseSSLCom<L4Proto>::ssl_dh_callback(SSL* s, int is_export, int key_length)  {
    void* data = SSL_get_ex_data(s, extdata_index());
    std::string name = "unknown_cx";

    auto* com = static_cast<baseSSLCom*>(data);
    if(com != nullptr) {
        name = com->hr();
    }

    auto const& log = log_cb_dh();

    _dia("[%s]: SSLCom::ssl_dh_callback: %d bits requested",name.c_str(),key_length);
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
#endif


#ifndef  USE_OPENSSL11
template <class L4Proto>
EC_KEY* baseSSLCom<L4Proto>::ssl_ecdh_callback(SSL* s, int is_export, int key_length) {
    void* data = SSL_get_ex_data(s, extdata_index());
    std::string name = "unknown_cx";

    auto const& log = log_cb_ecdh();

    auto* com = static_cast<baseSSLCom*>(data);
    if(com != nullptr) {
        name = com->hr();
    }

    _dia("[%s]: SSLCom::ssl_ecdh_callback: %d bits requested", name.c_str(), key_length);
    return nullptr;
}
#endif

template <class L4Proto>
std::string baseSSLCom<L4Proto>::ssl_error_details() const {
    std::stringstream info;
    info << "Target certificate: \r\n";
    info << SSLFactory::print_cert(sslcom_target_cert) << "\r\n";
    info << "Issuer certificate:  \r\n";
    info << SSLFactory::print_cert(sslcom_target_issuer) << "\r\n";
    auto ret = info.str();

    return ret;
}

template <class L4Proto>
int baseSSLCom<L4Proto>::certificate_status_ocsp_check(baseSSLCom* com) {

    inet::cert::VerifyStatus res;

    auto const& log = inet::ocsp::OcspFactory::log();

    verify_origin_t origin {verify_origin_t::NONE};

    if(com && com->sslcom_target_cert && com->sslcom_target_issuer) {

        std::string name = "unknown_cx";

        auto* pcom = dynamic_cast<baseSSLCom*>(com->peer());
        if(pcom != nullptr) {
            name = pcom->hr();
        }
        else {
            name = com->hr();
        }

        std::string cn = "unknown";
        if(com->sslcom_target_cert != nullptr) {
            cn = SSLFactory::print_cn(com->sslcom_target_cert) + ";" + SSLFactory::fingerprint(com->sslcom_target_cert);
        }

        const char* str_cached = "cached";
        const char* str_fresh = "fresh";
        const char* str_status = "unknown";


        auto cached_result = com->factory()->verify_cache().get(cn);;

        if (cached_result) {
            res.revoked = cached_result->value().revoked;
            str_status = str_cached;
            origin = verify_origin_t::OCSP_CACHE;

        } else {
            res = inet::ocsp::ocsp_check_cert(com->sslcom_target_cert, com->sslcom_target_issuer);
            str_status = str_fresh;
            factory()->verify_cache().set(cn, SSLFactory::make_exp_ocsp_status(res.revoked, res.ttl));
            origin = verify_origin_t::OCSP;
        }

        com->ocsp_cert_is_revoked = res.revoked;


        // logging block

        _dia("[%s]: SSLCom::ocsp_explicit_check[%s]: ocsp is_revoked = %d)", name.c_str(), cn.c_str(), res.revoked);
        if(res.revoked > 0) {
            _war("Connection from %s: certificate %s is revoked (%s OCSP))", name.c_str(), cn.c_str(), str_status);
        } else if (res.revoked == 0){
            _dia("Connection from %s: certificate %s is valid (%s OCSP))", name.c_str(), cn.c_str(), str_status);
        } else {
            if(com->opt.ocsp.mode > 1) {
                _war("Connection from %s: certificate %s revocation status is unknown (%s OCSP))",
                                                                name.c_str(), cn.c_str(), str_status);
            }
        }

        if(res.revoked < 0) {

            _not("Connection from %s: certificate OCSP revocation status cannot be obtained)",name.c_str());

            std::vector<std::string> crls = inet::crl::crl_urls(com->sslcom_target_cert);

            for(auto crl_url: crls) {

                std::string crl_printable = printable(crl_url);
                auto crl_url_guard = std::scoped_lock(com->factory()->crl_key_lock(crl_url));
                auto crl_cache_entry = factory()->crl_cache().get(crl_url);
                X509_CRL* crl_struct = nullptr;

                if(crl_cache_entry != nullptr) {
                    auto crl_struct_e = crl_cache_entry->value()->ptr;
                    crl_struct = crl_struct_e;
                    _dia("found cached crl: %s",crl_printable.c_str());
                    str_status = str_cached;

                    // we have crl cached, but it points to null (we indicate failed download)
                    if(!crl_struct_e) {
                        _war("failed download was cached for crl: %s, waiting for expire", crl_printable.c_str());
                    }

                    origin = verify_origin_t::CRL_CACHE;
                }
                else {
                    _dia("crl not cached: %s",crl_printable.c_str());

                    const int tolerated_dnld_time = 3;
                    time_t start = ::time(nullptr);

                    _dia("Connection from %s: downloading CRL at %s)",name.c_str(),crl_printable.c_str());

                    buffer b;
                    bool dnld_failed = false;
                    int bytes = inet::download(crl_url.c_str(),b,tolerated_dnld_time*3);
                    if(bytes < 0) dnld_failed = true;

                    if(! dnld_failed ) {
                        time_t t_dif = ::time(nullptr) - start;

                        int crl_size = b.size();
                        _dia("CRL downloaded: size %d bytes in %d seconds",crl_size,t_dif);
                        if(t_dif > tolerated_dnld_time) {
                            _war("it took long time to download CRL. You should consider to disable CRL check :(");
                        }

                        crl_struct = inet::crl::crl_from_bytes(b);
                        str_status = str_fresh;


                        if(crl_struct) {

                            _dia("Caching CRL 0x%x", crl_struct);
                            crl_cache_entry.reset(SSLFactory::make_expiring_crl(crl_struct));
                            factory()->crl_cache().set(crl_url, crl_cache_entry);
                        } else {
                            _war("downloaded CRL from %s cannot be parsed", crl_printable.c_str());
                            crl_cache_entry.reset(SSLFactory::make_expiring_crl(nullptr));
                            factory()->crl_cache().set(crl_url, crl_cache_entry);
                        }
                    } else {
                        _war("downloading CRL from %s failed.",crl_printable.c_str());
                        crl_cache_entry.reset(SSLFactory::make_expiring_crl(nullptr));
                        factory()->crl_cache().set(crl_url, crl_cache_entry);
                    }

                }

                int is_revoked_by_crl = -1;

                if(crl_struct) {

                    int crl_trust = inet::crl::crl_verify_trust(
                            com->sslcom_target_cert,
                            com->sslcom_target_issuer,
                            crl_struct,
                            com->factory()->ca_path().c_str());
                    _dia("CRL 0x%x trusted = %d", crl_struct, crl_trust);

                    if(crl_trust == 0) {
                        _war("CRL %s signature is not verified - untrusted",crl_printable.c_str());
                    }
                    else {
                        _dia("Checking revocation status: CRL 0x%x", crl_struct);
                        is_revoked_by_crl = inet::crl::crl_is_revoked_by(com->sslcom_target_cert, com->sslcom_target_issuer, crl_struct);
                    }
                }

                _dia("CRL says this certificate is revoked = %d",is_revoked_by_crl);

                if(is_revoked_by_crl > 0) {
                    _war("Connection from %s: certificate %s revocation status is revoked (%s CRL))",name.c_str(),cn.c_str(),str_status);
                } else
                if(is_revoked_by_crl == 0) {
                    _dia("Connection from %s: certificate %s revocation status is valid (%s CRL))",name.c_str(),cn.c_str(),str_status);
                } else {
                    _war("Connection from %s: certificate %s revocation status is still unknown (%s CRL))",name.c_str(),cn.c_str(),str_status);
                }

                res.revoked = is_revoked_by_crl;

                if(is_revoked_by_crl >= 0) {
                    origin = verify_origin_t::CRL;
                    break;
                }
            }
        }
    } else {
        if(com) {
            _err("ocsp_explicit_check__: failed call requirements: cert 0x%x, issuer 0x%x" , com->sslcom_target_cert, com->sslcom_target_issuer);
        } else {
            _err("ocsp_explicit_check__: failed call requirements: com 0x%x", com);
        }
    }

    if(com) {

        com->verify_origin(origin);

        if (res.revoked > 0) {
            com->verify_bitreset(verify_status_t::VRF_OK);
            com->verify_bitset(verify_status_t::VRF_REVOKED);

            auto eid = log.event(ERR, "[%s]: certificate is revoked (OCSP query)", socle::com::ssl::connection_name(com, true).c_str());
            log.event_detail(eid, "%s", com->ssl_error_details().c_str());

        } else if (res.revoked == 0) {
            com->verify_bitset(verify_status_t::VRF_OK);
        } else {
            com->verify_bitreset(verify_status_t::VRF_OK);
            com->verify_bitset(verify_status_t::VRF_DEFERRED);
        }
    }
    _dia("ocsp_explicit_check__: final result %d", res.revoked);
    return res.revoked;
}

template <class L4Proto>
int baseSSLCom<L4Proto>::certificate_status_oob_check(baseSSLCom* com, int default_action) {

    auto const& log = inet::ocsp::OcspFactory::log();


    if(com != nullptr) {
        com->verify_bitreset(verify_status_t::VRF_DEFERRED);

        if(com->opt.ocsp.enforce_in_verify) {
            _dia("certificate_status_oob_check: full OCSP request query (callback context)");
            int is_revoked = baseSSLCom::certificate_status_ocsp_check(com);

            std::string cn = SSLFactory::print_cn(com->sslcom_target_cert) + ";" + SSLFactory::fingerprint(com->sslcom_target_cert);
            std::string name = "unknown_cx";
            if(is_revoked != 0) {

                auto* pcom = dynamic_cast<baseSSLCom*>(com->peer());
                if(pcom != nullptr) {
                    name = pcom->hr();
                } else {
                    name = com->hr();
                }

                _war("Connection from %s: certificate %s OCSP validation error %d, replacement=%d)", name.c_str(), cn.c_str(),
                     is_revoked,
                     com->opt.cert.failed_check_replacement);

                if(is_revoked > 0) {
                    com->verify_bitreset(verify_status_t::VRF_OK);
                    com->verify_bitset(verify_status_t::VRF_REVOKED);
                    log.event(ERR, "[%s]: certificate is revoked (OCSP query)", socle::com::ssl::connection_name(com, true).c_str());
                } else {
                    // is_revoked < 0 - various errors
                    com->verify_bitreset(verify_status_t::VRF_OK);
                    com->verify_bitset(verify_status_t::VRF_ALLFAILED);
                }

                if(com->opt.cert.failed_check_replacement) {
                    ERR_clear_error();
                }
                return com->opt.cert.failed_check_replacement;

            } else {
                _dia("certificate_status_oob_check: GOOD: returning 1");
                return 1;
            }
        } else {
            _dia("certificate_status_oob_check:  OCSP request query not enforced");
        }
    }

    _dia("certificate_status_oob_check: default action - returning %d", default_action);
    return default_action;
}

template <class L4Proto>
std::string baseSSLCom<L4Proto>::verify_origin_str(verify_origin_t const& v) {
    switch(v) {
        case verify_origin_t::NONE:
            return "none";
        case verify_origin_t::OCSP_STAPLING:
            return "ocsp stapling";
        case verify_origin_t::OCSP:
            return "ocsp";
        case verify_origin_t::OCSP_CACHE:
            return "ocsp cache";
        case verify_origin_t::CRL:
            return "crl";
        case verify_origin_t::CRL_CACHE:
            return "crl cache";


        default:
            return "<?>";
    }
}


template <class L4Proto>
std::pair<typename baseSSLCom<L4Proto>::staple_code_t, int> baseSSLCom<L4Proto>::check_revocation_stapling(std::string const& name, baseSSLCom* com, SSL* ssl) {

    auto const& log = log_ocsp();

    const unsigned char *stapling_body = nullptr;

    auto proc_status = staple_code_t::NOT_PROCESSED;
    int  ocsp_status = -1;
    int  ocsp_reason = -1;

    STACK_OF(X509*) signers = nullptr;
    OCSP_RESPONSE *ocsp_response = nullptr;
    OCSP_BASICRESP *basic_response = nullptr;
    OCSP_CERTID *cert_id = nullptr;

    ASN1_GENERALIZEDTIME* produced_at = nullptr;
    ASN1_GENERALIZEDTIME* this_update = nullptr;
    ASN1_GENERALIZEDTIME* next_update = nullptr;

    bool opt_ocsp_strict = (com->opt.ocsp.stapling_mode >= 1);
    bool opt_ocsp_require = (com->opt.ocsp.stapling_mode >= 2);

    auto stapling_len = SSL_get_tlsext_status_ocsp_resp(ssl, &stapling_body);
    if (!stapling_body) {
        if(opt_ocsp_strict)
            _dia("[%s]: no OCSP stapling status response", name.c_str());

        com->opt.ocsp.enforce_in_verify = true;

        proc_status = staple_code_t::MISSING_BODY;
        goto the_end;
    }

    _dum("[%s]: OCSP Response:  \r\n%s",name.c_str(),hex_dump((unsigned char*) stapling_body, stapling_len, 4, 0, true).c_str());

    ocsp_response = d2i_OCSP_RESPONSE(nullptr, &stapling_body, stapling_len);
    if (!ocsp_response) {
        _err("[%s] failed to parse OCSP response",name.c_str());

        com->opt.ocsp.enforce_in_verify = true;

        proc_status = staple_code_t::PARSING_FAILED;
        goto the_end;
    }

    ocsp_status = OCSP_response_status(ocsp_response);
    if (ocsp_status != OCSP_RESPONSE_STATUS_SUCCESSFUL) {
        _err("[%s] OCSP responder error %d (%s)", name.c_str(), ocsp_status, OCSP_response_status_str(ocsp_status));

        com->opt.ocsp.enforce_in_verify = true;

        proc_status = staple_code_t::STATUS_NOK;
        goto the_end;
    }

    basic_response = OCSP_response_get1_basic(ocsp_response);
    if (!basic_response) {
        _err("[%s] could not find BasicOCSPResponse",name.c_str());

        com->opt.ocsp.enforce_in_verify = true;

        proc_status = staple_code_t::GET_BASIC_FAILED;
        goto the_end;
    }

    signers = sk_X509_new_null();
    sk_X509_push(signers, com->sslcom_target_issuer);
    ocsp_status = OCSP_basic_verify(basic_response, signers , com->factory()->trust_store() , 0);

    if (ocsp_status <= 0) {

        int err = SSL_get_error(ssl, ocsp_status);
        _dia("    error: %s",ERR_error_string(err,nullptr));


        if(not opt_ocsp_strict) {
            _not("[%s] OCSP stapling response failed verification",name.c_str());
            ERR_clear_error();
        }
        else {
            _err("[%s] OCSP stapling response failed verification",name.c_str());
        }

        proc_status = staple_code_t::BASIC_VERIFY_FAILED;
        goto the_end;
    }

    _dia("[%s] OCSP stapling response verification succeeded",name.c_str());

    cert_id = OCSP_cert_to_id(nullptr, com->sslcom_target_cert, com->sslcom_target_issuer);
    if (!cert_id) {
        _err("[%s] could not create OCSP certificate identifier",name.c_str());

        if(not opt_ocsp_strict)
            ERR_clear_error();

        com->opt.ocsp.enforce_in_verify = true;

        proc_status = staple_code_t::CERT_TO_ID_FAILED;
        goto the_end;
    }


    if (!OCSP_resp_find_status(basic_response, cert_id, & ocsp_status, &ocsp_reason, &produced_at, &this_update, &next_update)) {
        _err("[%s] could not find current server certificate from OCSP stapling response %s", name.c_str(),
             (opt_ocsp_require) ? "" : " (OCSP not required)");

        if(!opt_ocsp_require)
            ERR_clear_error();

        com->opt.ocsp.enforce_in_verify = true;

        proc_status = staple_code_t::NO_FIND_STATUS;
        goto the_end;
    }

    if (!OCSP_check_validity(this_update, next_update, 5 * 60, -1)) {
        _err("[%s] OCSP stapling times invalid", name.c_str());

        if(not opt_ocsp_strict)
            ERR_clear_error();

        com->opt.ocsp.enforce_in_verify = true;

        proc_status = staple_code_t::INVALID_TIME;
    }

    the_end:

    if(cert_id)
        OCSP_CERTID_free(cert_id);

    if(basic_response)
        OCSP_BASICRESP_free(basic_response);

    if(ocsp_response)
        OCSP_RESPONSE_free(ocsp_response);

    if(signers) sk_X509_free(signers);

    if(proc_status == staple_code_t::NOT_PROCESSED) {
        proc_status = staple_code_t::SUCCESS;
    }

    _dia("[%s] OCSP status for server certificate: %s", name.c_str(), OCSP_cert_status_str(ocsp_status));

    return std::make_pair(proc_status, ocsp_status);
}


template <class L4Proto>
bool baseSSLCom<L4Proto>::is_verify_status_opt_allowed() {
    bool this_is_allowed_by_option = true;
    auto problem_mask = verify_get();

    // do test run for cases the TLS problem is explicitly allowed by policy
    // and therefore are NOT eligible for replacement

    if(this_is_allowed_by_option and verify_bitcheck(verify_status_t::VRF_SELF_SIGNED)) {
        this_is_allowed_by_option = opt.cert.allow_self_signed;

        problem_mask = flag_reset<decltype(problem_mask)>(problem_mask, verify_status_t::VRF_SELF_SIGNED);
    }
    if(this_is_allowed_by_option and verify_bitcheck(verify_status_t::VRF_SELF_SIGNED_CHAIN)) {
        this_is_allowed_by_option = opt.cert.allow_self_signed_chain;

        problem_mask = flag_reset<decltype(problem_mask)>(problem_mask, verify_status_t::VRF_SELF_SIGNED_CHAIN);
    }
    if(this_is_allowed_by_option and verify_bitcheck(verify_status_t::VRF_INVALID)) {
        this_is_allowed_by_option = opt.cert.allow_not_valid;

        problem_mask = flag_reset<decltype(problem_mask)>(problem_mask, verify_status_t::VRF_INVALID);
    }
    if(this_is_allowed_by_option and verify_bitcheck(verify_status_t::VRF_UNKNOWN_ISSUER)) {
        this_is_allowed_by_option = opt.cert.allow_unknown_issuer;

        problem_mask = flag_reset<decltype(problem_mask)>(problem_mask, verify_status_t::VRF_UNKNOWN_ISSUER);
    }

    if(this_is_allowed_by_option) {
        // we hit allow options while not failing other
        // remove VRF_DEFERRED flag (which made connection reach this code)
        // remove VRF_ALLFAILED because any of certificates are not possible to validate
        //  (even OCSP/CRL works, it doesn't make sense to use such information, they are officially not usable)

        problem_mask = flag_reset<decltype(problem_mask)>(problem_mask, verify_status_t::VRF_OK);
        problem_mask = flag_reset<decltype(problem_mask)>(problem_mask, verify_status_t::VRF_DEFERRED);
        problem_mask = flag_reset<decltype(problem_mask)>(problem_mask, verify_status_t::VRF_ALLFAILED);

        if ((problem_mask == 0) or
            (problem_mask == verify_status_t::VRF_CLIENT_CERT_RQ)) {

            // indicate exceptions are satisfied and we can proceed with proxy
            return true;
        }
    }

    // exceptions are not satisfied - more handling is needed
    return false;
}



template <class L4Proto>
int baseSSLCom<L4Proto>::status_resp_callback(SSL* ssl, void* arg) {

    auto const& log = inet::ocsp::OcspFactory::log();

    void* data = SSL_get_ex_data(ssl, extdata_index());
    std::string name = "unknown_cx";

    auto* com = static_cast<baseSSLCom*>(data);

    bool opt_ocsp_require = false; // refuse to continue if OCSP is not responded

    X509* peer_cert = nullptr;
    X509* issuer_cert = nullptr;

    if(! com) {
        _err("status_resp_callback[%s]: argument data is not SSLCom*!", name.c_str());
        return -1;
    }

    if(not com->opt.ocsp.stapling_enabled and com->opt.ocsp.mode == 0) {
        _dia("status_resp_callback[%s]: OCSP is completely disabled", name.c_str());
        com->verify_reset(verify_status_t::VRF_OK);
        com->verify_origin(verify_origin_t::NONE);
        return 1;
    }

    // it's not necessary to run any further checks, certificate is not OK
    // status callback comes usually earlier then certificate verify callback, but this can't be guaranteed.
    // keeping it here.

    auto* pcom = dynamic_cast<baseSSLCom*>(com->peer());
    if(pcom != nullptr) {
        name = pcom->hr();
    } else {
        name = com->hr();
    }
    opt_ocsp_require = (com->opt.ocsp.stapling_mode >= 2);
    peer_cert   = com->sslcom_target_cert;
    issuer_cert = com->sslcom_target_issuer;


    // before OCSP/CRL and other complicated checks, check if the connection
    // isn't broken or distrust. Check also for allow_* exceptions we should honor.
    auto non_ok = com->verify_get();

    non_ok = flag_reset<decltype(non_ok)>(non_ok, verify_status_t::VRF_NOTTESTED);
    non_ok = flag_reset<decltype(non_ok)>(non_ok, verify_status_t::VRF_DEFERRED);
    non_ok = flag_reset<decltype(non_ok)>(non_ok, verify_status_t::VRF_OK);

    if(non_ok > 0) {

        // check how it was tested already
        if (com->verify_get() != verify_status_t::VRF_OK && !com->verify_bitcheck(verify_status_t::VRF_CLIENT_CERT_RQ)) {
            _dia("status_resp_callback[%s]: certificate verification failed already (%d), no need to check stapling",
                 name.c_str(),
                 com->verify_get());


            // break verify loop
            com->verify_bitreset(verify_status_t::VRF_NOTTESTED);
            if (com->is_verify_status_opt_allowed()) {
                com->verify_bitset(verify_status_t::VRF_OK);
                com->verify_origin(verify_origin_t::EXEMPT);
                return 1;
            }
            else {
                com->verify_bitreset(verify_status_t::VRF_OK);
                com->verify_bitset(verify_status_t::VRF_ALLFAILED);
                return com->opt.cert.failed_check_replacement;
            }
        }
    }

    com->verify_bitreset(verify_status_t::VRF_NOTTESTED);

    if (!peer_cert || !issuer_cert) {
        _dia("status_resp_callback[%s]: status_resp_callback: verify hasn't been yet called", name.c_str());
        com->opt.ocsp.enforce_in_verify = true;

        auto cb_status = baseSSLCom::certificate_status_oob_check(com, opt_ocsp_require ? 0 : 1);
        return cb_status;
    }

    _deb("status_resp_callback[%s]: peer cert=%x, issuer_cert=%x", name.c_str(), peer_cert, issuer_cert);

    std::string cn = SSLFactory::print_cn(com->sslcom_target_cert) + ";" + SSLFactory::fingerprint(com->sslcom_target_cert);

    auto stap_result = check_revocation_stapling(name, com, ssl);

    if(stap_result.first == staple_code_t::SUCCESS) {
        com->verify_bitreset(verify_status_t::VRF_OK);

        if (stap_result.second == V_OCSP_CERTSTATUS_GOOD) {
            _dia("[%s] OCSP status is good",name.c_str());
            com->verify_bitset(verify_status_t::VRF_OK);
            com->verify_origin(verify_origin_t::OCSP_STAPLING);

            com->ocsp_cert_is_revoked = 0;
            _dia("Connection from %s: certificate %s is valid (stapling OCSP))",name.c_str(),cn.c_str());

            return 1;
        } else
        if (stap_result.second == V_OCSP_CERTSTATUS_REVOKED) {
            _dia("[%s] OCSP status is revoked", name.c_str());

            com->ocsp_cert_is_revoked = 1;
            com->verify_bitset(verify_status_t::VRF_REVOKED);
            com->verify_origin(verify_origin_t::OCSP_STAPLING);

            _war("Connection from %s: certificate %s is revoked (stapling OCSP), replacement=%d)", name.c_str(),
                       cn.c_str(),
                       com->opt.cert.failed_check_replacement);
            auto eid = log.event(ERR, "[%s]: certificate is revoked (OCSP stapling status)", socle::com::ssl::connection_name(com, true).c_str());
            log.event_detail(eid, "%s", com->ssl_error_details().c_str());

            return com->opt.cert.failed_check_replacement;
        }
    }


    if (opt_ocsp_require) {
        com->verify_bitset(verify_status_t::VRF_DEFERRED);
        com->verify_bitreset(verify_status_t::VRF_OK);
        _dia("[%s] cert status (stapling) not received, but OCSP required", name.c_str());

        int cb_status = baseSSLCom::certificate_status_oob_check(com, 0);
        _dia("SSLCom::ocsp_resp_callback: required OCSP returned %d", cb_status);

        return cb_status;
    }
    else {
        _dia("[%s] cert status unknown, but OCSP was not required, failing only on positive negative", name.c_str());

        int cb_status = baseSSLCom::certificate_status_oob_check(com, 1);
        _dia("SSLCom::ocsp_resp_callback: OCSP returned %d", cb_status);

        return cb_status;
    }
}

template <class L4Proto>
int baseSSLCom<L4Proto>::ssl_client_cert_callback(SSL* ssl, X509** x509, EVP_PKEY** pkey) {
    //return 0 if we don't want to provide cert, 1 if yes.
    //if yes, x509 and pkey has to point to pointers with cert.

    auto const& log = log_cb_ccert();
    
    void* data = SSL_get_ex_data(ssl, extdata_index());
    std::string name = "unknown_cx";

    *x509 = nullptr;
    *pkey = nullptr;

    
    auto* com = static_cast<baseSSLCom*>(data);
    if(com != nullptr) {
        auto sni = com->get_sni();
        auto* owner = com->owner_cx();

        name = "sni:[" + sni;
        if(owner) {
             name += "]/" + owner->to_string(iINF);
        }
        
        com->verify_bitset(verify_status_t::VRF_CLIENT_CERT_RQ);
        switch(com->opt.cert.client_cert_action) {

            case 0:
                _dia("[%s] sending empty client certificate disabled", name.c_str());
                if(com->opt.cert.failed_check_replacement) {
                    _dia("[%s]: client certificate requested - replacement will be displayed", name.c_str());
                    log.event(INF, "[%s]: client certificate requested - replacement will be displayed", name.c_str());
                    return 0;
                }
                else {
                    _dia("[%s]: client certificate requested - configured to drop connection", name.c_str());
                    log.event(INF,"[%s]: client certificate requested - configured to drop connection", name.c_str());
                    com->error(ERROR_UNSPEC);
                    return 1;
                }
                break;

            case 1:
                _dia("[%s] sending empty client certificate", name.c_str());
                log.event(INF,"[%s]: client certificate requested - sent empty", name.c_str());
                return 0;
                
            case 2:
                return 1;

            case 3: {
                int found = 0;

                auto find_client_cert = [&](std::string const& what, std::string const& prefix) {
                    _dia("looking for client certificate for: %s: %s", prefix.c_str(), what.c_str());

                    std::string key = prefix + ":" + what;
                    auto parek = SSLFactory::factory().find_custom(key);
                    if (parek) {
                        *x509 = parek.value().chain.cert;
                        X509_up_ref(*x509);

                        *pkey = parek.value().chain.key;
                        EVP_PKEY_up_ref(*pkey);

                        _dia("found client certificate for: %s: %s", prefix.c_str(), what.c_str());

                        return 1;
                    }
                    return 0;
                };

                if(not sni.empty()) {
                    found = find_client_cert(sni, "cc-sni");
                }
                if(not found and owner) {
                    auto ip = owner->host();

                    if(not ip.empty()) {
                        found = find_client_cert(ip, "cc-ip");
                    }
                }
                if(not found) {
                    _dia("no client certificate found - using empty");
                }
                return found;
            }
        }
    }
    
    _err("[%s], Oops. Com object not SSL, sending client certificate disabled", name.c_str());
    return 0;
}



template <class L4Proto>
int baseSSLCom<L4Proto>::ct_verify_callback(const CT_POLICY_EVAL_CTX *ctx, const STACK_OF(SCT) *scts, void *arg) {

    bool result = true;

    auto sc_num = sk_SCT_num(scts);
    auto* sslcom = static_cast<baseSSLCom*>(arg);

    if(sslcom) {
        auto const& log = log_cb_ct();

        _dia("certificate transparency callback: %d entries in certificate", sc_num);

        if(sc_num < 2) {
            sslcom->verify_bitreset(verify_status_t::VRF_OK);
            sslcom->verify_bitset(verify_status_t::VRF_CT_MISSING);

            result = false;
        } else {

            // how many good and valid SCTs were recognized
            int res_ok = 0;
            int res_failed = 0;

            for(int i = 0; i < sc_num; i++) {
                auto* sc_entry = sk_SCT_value(scts, i);
                int ret_validate  = SCT_validate(sc_entry, ctx);
                auto  res_validate = SCT_get_validation_status(sc_entry);

                _dia("ct: sct#%d - ret:%d,%s", i, ret_validate, socle::com::ssl::SCT_validation_status_str(res_validate));

                // eliminate in Release
                _if_deb {
                    const CTLOG_STORE *log_store = SSL_CTX_get0_ctlog_store(SSLFactory::factory().default_tls_client_cx());

                    BioMemory bm;
                    SCT_print(sc_entry, bm, 4, log_store);

                    auto v_of_s = string_split(bm.str(), '\n');

                    _deb("    : SCT info");
                    for(auto const& s: v_of_s) {
                        _deb(s.c_str());
                    }
                }

                if(ret_validate == 1) {
                    switch(res_validate) {
                        case SCT_VALIDATION_STATUS_VALID:
                            // increment only if status is valid
                            if(res_ok >= 0) res_ok++;
                            continue;

                        case SCT_VALIDATION_STATUS_INVALID:
                            res_ok=-1; // message there is invalid entry, ensure it will not get any non-negative value anymore
                            res_failed++;
                            break;

                        case SCT_VALIDATION_STATUS_UNKNOWN_LOG:
                        case SCT_VALIDATION_STATUS_NOT_SET:
                        case SCT_VALIDATION_STATUS_UNVERIFIED:
                        case SCT_VALIDATION_STATUS_UNKNOWN_VERSION:
                        default:
                            res_failed++;
                    }
                } else {
                    // 0 or -1 is failed verification
                    res_failed++;
                }
            }

            // now all logs are processed, we have res_ok and res_failed to check
            if(res_failed > 0) {
                _dia("%d SCT entries were not verified", res_failed);
            }
            if(res_ok < 0) {
                // there is invalid entry - fail to connect
                result = false;

                // announce error and invalid entry
                sslcom->verify_bitreset(verify_status_t::VRF_OK);
                sslcom->verify_bitset(verify_status_t::VRF_CT_FAILED);
                sslcom->verify_extended_info().emplace_back(vrf_other_values_t::VRF_OTHER_CT_INVALID);
            }
            else if(res_ok < 2) {
                // announce error and insufficient understood
                sslcom->verify_bitreset(verify_status_t::VRF_OK);
                sslcom->verify_bitset(verify_status_t::VRF_CT_MISSING);
            }

            for(int f = 0; f < res_failed; f++) {
                sslcom->verify_bitset(verify_status_t::VRF_CT_FAILED);
                sslcom->verify_extended_info().emplace_back(vrf_other_values_t::VRF_OTHER_CT_FAILED);
            }

        }
    }

    return result or sslcom->opt.cert.failed_check_replacement;
}

template <class L4Proto>
void baseSSLCom<L4Proto>::init_ssl_callbacks() {

    SSL_set_msg_callback_arg(sslcom_ssl,(void*)this);

    SSL_set_msg_callback(sslcom_ssl,ssl_msg_callback);
#ifndef BUILD_RELEASE
    SSL_set_info_callback(sslcom_ssl,ssl_info_callback);
#endif

    if((is_server() && opt.left.kex_dh) || (!is_server() && opt.right.kex_dh)) {

    // Note: various historic and new OpenSSL versions have different
    //       level of DH/ECDH parameters callback deprecation.

#ifndef USE_OPENSSL300
        /// OpenSSL 3.x API deprecates DH callbacks
        SSL_set_tmp_dh_callback(sslcom_ssl,ssl_dh_callback);
#else
        SSL_set_dh_auto(sslcom_ssl, 1);
#endif

#ifndef USE_OPENSSL11
        // OpenSSL 1.1 API doesn't seem to contain ECDH callback.
        SSL_set_tmp_ecdh_callback(sslcom_ssl,ssl_ecdh_callback);
#else
        SSL_set_ecdh_auto(sslcom_ssl, 1);
#endif
    }


    _deb("init ssl callbacks");

    // add this pointer to ssl external data
    SSL_set_ex_data(sslcom_ssl, extdata_index(), static_cast<void*>(this));

    if(! is_server()) {
        SSL_set_verify(sslcom_ssl,SSL_VERIFY_PEER,&ssl_client_vrfy_callback);
        if(opt.ocsp.stapling_enabled || opt.ocsp.mode > 0) {

            if(factory()->trust_store() != nullptr) {

                _dia("[%s]: OCSP stapling enabled, mode %d", hr().c_str(), opt.ocsp.stapling_mode);
                SSL_set_tlsext_status_type(sslcom_ssl, TLSEXT_STATUSTYPE_ocsp);
            }
            else {
                _err("cannot load trusted store for OCSP. Fail-open.");
                opt.ocsp.stapling_mode = 0;
            }
        }
        else {
            verify_bitset(verify_status_t::VRF_OK);
            verify_origin(verify_origin_t::NONE);
        }

        if (opt.ct_enable) {

            if(SSLFactory::factory().is_ct_available()) {

                _dia("setting up certificate transparency mode to strict");
                SSL_enable_ct(sslcom_ssl, SSL_CT_VALIDATION_STRICT);
                _dia("setting up certificate transparency callback");
                SSL_set_ct_validation_callback(sslcom_ssl, ct_verify_callback, this);

            } else {
                _war("certificate transparency desired but not available");
            }

        }

    }
}

template <class L4Proto>
void baseSSLCom<L4Proto>::init_client() {

    if(sslcom_ssl) {
        _deb("SSLCom::init_client: freeing old sslcom_ssl");
        SSL_free(sslcom_ssl);
        sslcom_ssl = nullptr;
    }


    if(l4_proto() == SOCK_STREAM) {

        sslcom_ctx = factory()->default_tls_client_cx();
        if(sslcom_ctx)
            sslcom_ssl = SSL_new(sslcom_ctx);
    } else 
    if(l4_proto() == SOCK_DGRAM) {

        sslcom_ctx = factory()->default_dtls_client_cx();
        if(sslcom_ctx)
            sslcom_ssl = SSL_new(sslcom_ctx);
    }

    if(not sslcom_ssl) {
        _err("Client: Error creating SSL object!");
        log_if_error(iERR,"SSLCom::init_client");
        error(ERROR_UNSPEC);
        return;
    }
    
    if (!uses_default_cipher_filter(opt.right)) {
        std::string my_filter = ci_def_filter;

        if(!opt.right.allow_sha1)
                    my_filter += " !SHA1";
        if(!opt.right.allow_rc4)
                    my_filter += " !RC4";
        if(!opt.right.allow_aes128)
                    my_filter += " !AES128";

        if(!opt.right.kex_dh)
                    my_filter += " !kEECDH !kEDH";

        if(!opt.right.kex_rsa)
                    my_filter += " !kRSA";

        _dia("right ciphers: %s",my_filter.c_str());
        SSL_set_cipher_list(sslcom_ssl,my_filter.c_str());
    }
    
    if(opt.right.no_tickets) {
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

#ifndef USE_OPENSSL300
    if(sslcom_ecdh) {
        EC_KEY_free(sslcom_ecdh);
        sslcom_ecdh = nullptr;
    }
#endif

    if(sslcom_ssl) {
        _deb("SSLCom::init_server: freeing old sslcom_ssl");
        SSL_free(sslcom_ssl);
        sslcom_ssl = nullptr;
    }

    
    _deb("baseSSLCom<L4Proto>::init_server: l4 proto = %d", l4_proto());

    if(l4_proto() == SOCK_STREAM) {

        if(sslcom_pref_ctx) {
            sslcom_ctx = sslcom_pref_ctx;
            _dia("SSLCom::init_server: using custom context 0x%x", sslcom_ctx);
        }
        else if(not sslcom_ctx) {

            if(not opt.cert.mitm_cert_searched_only) {
                sslcom_ctx = factory()->default_tls_server_cx();
            }
            else {
                _dia("using default tls context is prohibited");
                error(baseCom::ERROR_UNSPEC);
                return;
            }
        }


        if(sslcom_ctx)
            sslcom_ssl = SSL_new(sslcom_ctx);
    } else
    if(l4_proto() == SOCK_DGRAM) {

        if(sslcom_pref_ctx) {
            sslcom_ctx = sslcom_pref_ctx;
            _dia("SSLCom::init_server: using custom context 0x%x", sslcom_ctx);
        }
        else if(not sslcom_ctx) {
            sslcom_ctx = factory()->default_dtls_server_cx();
        }

        if(sslcom_ctx)
            sslcom_ssl = SSL_new(sslcom_ctx);
    }

    if(not sslcom_ssl) {
        _err("Server: Error creating SSL object!");
        log_if_error(iERR,"SSLCom::init_server");
        error(ERROR_UNSPEC);
        return;
    }
    if(l4_proto() == SOCK_DGRAM)
        SSL_set_options(sslcom_ssl, SSL_OP_COOKIE_EXCHANGE);

    if (!uses_default_cipher_filter(opt.left)) {
        std::string my_filter = ci_def_filter;

        if(!opt.left.allow_sha1)
                    my_filter += " !SHA1";
        if(!opt.left.allow_rc4)
                    my_filter += " !RC4";
        if(!opt.left.allow_aes128)
                    my_filter += " !AES128";

        if(!opt.left.kex_dh)
                    my_filter += " !kEECDH !kEDH";

        if(!opt.left.kex_rsa)
                    my_filter += " !kRSA";

        _dia("left ciphers: %s",my_filter.c_str());
        SSL_set_cipher_list(sslcom_ssl,my_filter.c_str());
    }

    if(opt.left.kex_dh) {
#ifdef USE_OPENSSL300
        SSL_set1_groups_list(sslcom_ssl, "X25519:P-521:P-384:P-256:ffdhe2048");
#else
                // ok, use DH, in that case select 
                if(sslcom_ecdh == nullptr) {
                    sslcom_ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
                }
                if(sslcom_ecdh != nullptr) {
                    // this actually disables ecdh callback
                    SSL_set_tmp_ecdh(sslcom_ssl,sslcom_ecdh);
                }
#endif
    }

    if (not sslcom_pref_ctx and (sslcom_pref_cert && sslcom_pref_key)) {

        _deb("SSLCom::init_server[%x]: loading preferred cert and key", this);

        if(SSL_use_certificate(sslcom_ssl, sslcom_pref_cert) != 1) {
            int err = static_cast<int>(ERR_get_error());
            _dia("    certificate error: %s",ERR_error_string(err, nullptr));
        }

        if(SSL_use_PrivateKey(sslcom_ssl, sslcom_pref_key) != 1) {
            int err = static_cast<int>(ERR_get_error());
            _dia("    private key error: %s",ERR_error_string(err, nullptr));
        }


        if(!sslcom_refcount_incremented_) {
#ifdef USE_OPENSSL11
            EVP_PKEY_up_ref(sslcom_pref_key);
            X509_up_ref(sslcom_pref_cert);
#else
            CRYPTO_add(&sslcom_pref_key->references,+1,CRYPTO_LOCK_EVP_PKEY);
            CRYPTO_add(&sslcom_pref_cert->references,+1,CRYPTO_LOCK_X509);
#endif
            sslcom_refcount_incremented_ = true;
        }
    } else {
        _deb("SSLCom::init_server[%x]: using custom context", this);
    }

    is_server(true);

    if(opt.left.no_tickets) {
        SSL_set_session(sslcom_ssl, nullptr);
        SSL_set_options(sslcom_ssl,SSL_OP_NO_TICKET);
    } else {
        // loading sessions for server are automatic done by openssl
        // loading from here is experimental and wip

        if(EXP_left_session_cache_enabled) {
            load_session_if_needed();
        }
    }

    SSL_set_mode(sslcom_ssl, SSL_MODE_ENABLE_PARTIAL_WRITE|SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER|SSL_MODE_RELEASE_BUFFERS);

    SSL_set_fd (sslcom_ssl, socket());


    init_ssl_callbacks();
    
}

template <class L4Proto>
bool baseSSLCom<L4Proto>::check_cert (const char* host) {
    if ( !is_server() && SSL_get_verify_result ( sslcom_ssl ) !=X509_V_OK ) {
        _dia( "check_cert: ssl client: target server's certificate cannot be verified!" );
    }

    /*Check the cert chain. The chain length
      is automatically checked by OpenSSL when
      we set the verify depth in the ctx */

    /* Check that the peer supplied a certificate. */
#ifdef USE_OPENSSL300
    X509* peer = const_cast<X509*>(SSL_get0_peer_certificate(sslcom_ssl));
#else
    X509* peer = SSL_get_peer_certificate(sslcom_ssl);
#endif

    if(! peer) {
        _err("check_cert: unable to retrieve peer certificate");

        // cannot proceed, next checks require peer X509 data
        return false;
    }

    if(host) {
    	_dia("peer host: %s",host);
        if (X509_check_host(peer, host, 0,
                            X509_CHECK_FLAG_ALWAYS_CHECK_SUBJECT, nullptr) != 1) {
            _dia( "Common name doesn't match host name" );
        }
    }

#ifndef USE_OPENSSL300
    X509_free(peer);
#endif
    sslcom_status(true);

    return true;
}


/* OK set  */
template <class L4Proto>
bool baseSSLCom<L4Proto>::readable(int s) {

    bool r = !sslcom_read_blocked_on_write;
    sslcom_read_blocked_on_write = false;

    _dum("SSLCom::readable[%d]: sslcom_read_blocked_on_write: %d", s, sslcom_read_blocked_on_write);
    _dum("SSLCom::readable[%d]: sslcom_write_blocked_on_read: %d", s, sslcom_write_blocked_on_read);

    if (r) {
        _dum("SSLCom::readable[%d]: %d",s,r);
    } else {
        _deb("SSLCom::readable[%d]: %d",s,r);
    }

    return r;
}

template <class L4Proto>
bool baseSSLCom<L4Proto>::writable(int s) {

    bool r = !sslcom_write_blocked_on_read;
    sslcom_write_blocked_on_read = false;

    _dum("SSLCom::writable[%d]: sslcom_read_blocked_on_write: %d", s, sslcom_read_blocked_on_write);
    _dum("SSLCom::writable[%d]: sslcom_write_blocked_on_read: %d", s, sslcom_write_blocked_on_read);

    if (r) {
        _dum("SSLCom::writable[%d]: %d",s,r);
    } else {
        _deb("SSLCom::writable[%d]: %d",s,r);
    }

    return r;
}

template <class L4Proto>
bool baseSSLCom<L4Proto>::bypass_me_and_peer() {
    if(peer()) {
        auto* speer = dynamic_cast<baseSSLCom*>(peer());
        
        if(speer) {
            opt.bypass = true;
            speer->opt.bypass = true;

            verify_reset(verify_status_t::VRF_OK);
            speer->verify_reset(verify_status_t::VRF_OK);
            return true;
        }
    }
    
    return false;
}


template<class L4Proto>
void baseSSLCom<L4Proto>::accept_socket (int sockfd) {

    _dia("SSLCom::accept_socket[%d]: attempt %d", sockfd, counters.prof_accept_cnt);

    L4Proto::on_new_socket(sockfd);
    L4Proto::accept_socket(sockfd);

    if (l4_proto() == SOCK_DGRAM && sockfd < 0) {
        auto const* l4com = dynamic_cast<UDPCom *>(this);
        if (l4com) {
            _inf("underlying com is UDPCom using virtual sockets");

            auto it_rec = l4com->datagram_com()->datagrams_received.find(sockfd);
            if (it_rec != l4com->datagram_com()->datagrams_received.end()) {
                _deb("datagram records found");

                auto record = it_rec->second;
                socket(::socket(record->dst_family(), SOCK_DGRAM, IPPROTO_UDP));

                if(socket() > 0) {

                    int ret_opt4 = 0;
                    int ret_opt6 = 0;

                    if(record->dst_family() == AF_INET or record->dst_family() == AF_INET6 or record->dst_family() == AF_UNSPEC) {
                        ret_opt4 = so_transparent_v4(sockfd);
                    }

                    if(record->dst_family() == AF_INET6) {
                        ret_opt6 = so_transparent_v6(sockfd);
                    }

                    int ret_con = ::connect(socket(), (sockaddr *) &record->src, sizeof(sockaddr_storage));
                    int ret_bind = ::bind(socket(), (sockaddr *) &record->dst, sizeof(sockaddr_storage));
                    _dia("Masked socket: connect=%d, bind=%d, transp4=%d, transp6=%d",
                         ret_con == 0, ret_bind == 0, ret_opt4 == 0, ret_opt6 == 0);
                }
                else {
                    _err("SSLCom<UDP>::accept_socket: cannot create real socket for %d", sockfd);
                    error(ERROR_SOCKET);
                }

            } else {
                _deb("datagram records not found");
            }
        } else {
            _inf("underlying com is UDPCom using real sockets");
        }
    }

    upgrade_server_socket(sockfd);
    if (opt.bypass) {
        counters.prof_accept_bypass_cnt++;
        return;
    }
    if(not sslcom_ssl) {
        return;
    }


    if (l4_proto() == SOCK_DGRAM) {

#ifdef USE_OPENSSL11
        BIO_ADDR *bia = BIO_ADDR_new();
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
    sslcom_ret = SSL_accept(sslcom_ssl);
    if (sslcom_ret > 0) {
        _dia("SSLCom::accept_socket[%d]: success at 1st attempt.", sockfd);
        sslcom_op_state = sslcom_op_state_t::READY;
        counters.prof_accept_ok++;
        sslcom_waiting = false;

        // reread socket
        forced_read(true);
        forced_write(true);

        if (SSL_session_reused(sslcom_ssl)) {
            flags_ |= HSK_REUSED;
        }

#ifndef USE_OPENSSL111
        if(sslkeylog) {
            dump_keys();
            sslkeylog = false;
        }
#endif

    } else {
        const int err = SSL_get_error(sslcom_ssl, sslcom_ret);
        if (err == SSL_ERROR_WANT_READ) {
            _dia("SSLCom::accept_socket[%d]: pending on want_read", sockfd);
            set_monitor(sockfd);
        } else if (err == SSL_ERROR_WANT_WRITE) {
            _dia("SSLCom::accept_socket[%d]: pending on want_write", sockfd);
            set_write_monitor_only(sockfd);
        } else {
            _err("SSLCom::accept_socket[%d]: initial SSL_accept failed: ret=%d err=%d",
                 sockfd, sslcom_ret, err);
            if (err == SSL_ERROR_SSL || err == SSL_ERROR_SYSCALL)
                sslcom_fatal = true;
            sslcom_waiting = false;
            error(ERROR_UNSPEC);
        }
    }
    counters.prof_accept_cnt++;
}

template <class L4Proto>
void baseSSLCom<L4Proto>::ssl_keylog_callback(const SSL* ssl, const char* line) {
    void* data = SSL_get_ex_data(ssl, extdata_index());
    auto* com = static_cast<baseSSLCom*>(data);

    if(com && com->sslkeylog) {
        com->log.log(loglevel(NON,flag_add(iNOT,CRT|KEYS),&log::level::LOG_EXEXACT,LOG_FLRAW),"com.ssl.callback.keys",line);
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

        log.log(loglevel(NON, flag_add(iNOT,CRT|KEYS), &log::level::LOG_EXEXACT, LOG_FLRAW),"com.ssl.keys",ret.c_str());
    }
}


template <class L4Proto>
void baseSSLCom<L4Proto>::delay_socket(int sockfd) {
    // we need to know even delayed socket
    socket(sockfd);
}


template <class L4Proto>
int baseSSLCom<L4Proto>::upgrade_server_socket(int sockfd) {

    socket(sockfd);

    sslcom_waiting = true;
    unblock();

    if(opt.bypass) {
        _inf("SSLCom::upgrade_server_socket[%d]: bypassed", socket());
        return sockfd;
    }

    if(not upgraded()) {
        init_server();
        if (not sslcom_ssl) {
            _err("SSLCom::upgrade_server_socket[%d]: failed to initialize SSL", socket());
            return -1;
        }
        upgraded(true);
    } else {
        _dia("already upgraded");
    }

    return socket();
}


template <class L4Proto>
int baseSSLCom<L4Proto>::handshake_server() {
    if(auto_upgrade() && !upgraded()) {
        _dia("SSLCom::handshake: server auto upgrade socket %d", socket());
        upgrade_server_socket(socket());
    }

    ERR_clear_error();
    if(not sslcom_ssl) {
        _dia("SSLCom::handshake: socket not upgraded, failing");
        error(ERROR_UNSPEC);
        return -1;
    }

    sslcom_ret = SSL_accept(sslcom_ssl);

    if(sslcom_ret == 1) {
        sslcom_op_state = sslcom_op_state_t::READY;
        store_session_if_needed();
    }

    counters.prof_accept_cnt++;
    baseSSLCom::counter_ssl_accept++;

    return sslcom_ret;
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
            _dia("SSLCom::waiting[%d]: executing client auto upgrade", socket());
            if(owner_cx() != nullptr && socket() == 0) {
                socket(owner_cx()->socket());
                _dia("SSLCom::waiting[%d]: socket 0 has been auto-upgraded to owner's socket", socket());
            }
            upgrade_client_socket(socket());
        }
    }

    // we have client hello
    if(sslcom_peer_hello_received()) {


        // Do we have sni_filter_to_bypass set? If so, check if we do have also SNI
        // and check all entries in the filter.

        if (sni_filter_to_bypass()) {
            _deb("SSLCom:waiting: check SNI filter for '%s'", sslcom_sni().c_str());

            if (!sslcom_sni().empty()) {

                for (std::string const& filter_element_raw: *sni_filter_to_bypass()) {

                    bool wildcard_planted = false;
                    auto filter_element = filter_element_raw;
                    if(filter_element_raw.size() > 1 and filter_element_raw.at(0) == '*' and filter_element_raw.at(1) == '.') {
                        filter_element.replace(0, 2, "");
                        wildcard_planted = true;
                    }

                    _deb("SSLCom:waiting: check SNI filter: %s %s", filter_element.c_str(), wildcard_planted ? "(*.)" : "");

                    std::size_t pos = sslcom_sni().rfind(filter_element);
                    if (pos != std::string::npos && pos + filter_element.size() >= sslcom_sni().size()) {

                        //ok, we know SNI ends with the filter entry. We need to check if the character BEFORE match pos in SNI is '.' to prevent
                        // match www.mycnn.com with cnn.com SNI entry.
                        bool cont = true;

                        if (pos > 0) {
                            if (sslcom_sni().at(pos - 1) != '.') {
                                _deb("%s NOT bypassed with sni filter %s", sslcom_sni().c_str(),
                                     filter_element.c_str());
                                cont = false;
                            }
                        }

                        if (cont) {
                            _dia("SSLCom:waiting: matched SNI filter: %s%s!", filter_element.c_str(), wildcard_planted ? " (*.)" : "");
                            sni_filter_to_bypass_matched = true;

                            if (bypass_me_and_peer()) {
                                _inf("%s bypassed with sni filter %s %s", sslcom_sni().c_str(),
                                     filter_element.c_str(), wildcard_planted ? " (*.)" : "");
                                return false;
                            } else {
                                _dia("SSLCom:waiting: SNI filter matched, but peer is not SSLCom");
                            }
                        }
                    }
                }
            } else {
                _deb("SSLCom:waiting: peer SNI empty");
            }
        } else {
            _dum("SSLCom::waiting[%d]: SNI bypass filter is empty", socket());
        }
    }

    return true;
}

// return values according to SSL_connect, except:
// return 2 when connection should be bypassed due to clienthello
template <class L4Proto>
int baseSSLCom<L4Proto>::handshake_client() {

    _deb("SSLCom::waiting: before SSL_connect");

    ERR_clear_error();
    sslcom_ret = SSL_connect(sslcom_ssl);
    if(sslcom_ret > 0) {
        sslcom_op_state = sslcom_op_state_t::READY;
    }

    counters.prof_connect_cnt++;
    baseSSLCom::counter_ssl_connect++;

    return sslcom_ret;
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

            _dia("SSLCom::handshake:  opcode: %d, error1: %d, error2: %d code2: %s", op_code, err, err2, err_desc);
            err2 = ERR_get_error();
        }

        if(maxiter-- <= 0) {
            _err("handshake_dia_error2: too many errors in the stack");
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

    auto fail_both_sides = [this](bool fatal) {
        sslcom_waiting = false;
        sslcom_fatal = sslcom_fatal || fatal;
        error(ERROR_UNSPEC);
        if (owner_cx())
            owner_cx()->error(true);
        if (socket() > 0)
            ::shutdown(socket(), SHUT_RDWR);
        if (auto* other = peer()) {
            other->error(ERROR_READ);
            if (other->owner_cx())
                other->owner_cx()->error(true);
            if (other->socket() > 0)
                ::shutdown(other->socket(), SHUT_RDWR);
        }
    };

    if (sslcom_ssl == nullptr and ! auto_upgrade()) {
        _war("SSLCom::handshake: sslcom_ssl is NULL and auto_upgrade is not set");
        return ret_handshake::ERROR;
    }

    int op_code = -1;


    ERR_clear_error();

    if (!is_server() ) {
        op_descr = op_connect;

        if(! handshake_peer_client() ) {
            _dia("SSLCom::handshake: %s on socket %d: waiting for the peer...", op_descr, socket());


            _dia("SSLCom::handshake: %s on socket %d: rescan IN", op_descr, socket());
            unset_monitor(socket());
            rescan_read(socket());


            return ret_handshake::AGAIN;
        }

        op_code = handshake_client();

    }
    else {
        op_descr = op_accept;
        op_code = handshake_server();
    }



    _dia("SSLCom::handshake: %s on socket %d: r=%d", op_descr, socket(), op_code);

    // general error handling code - both accept and connect yield the same errors
    if (op_code < 0) {

        if(error()) {
            fail_both_sides(true);
            return ret_handshake::FATAL;
        }

        int err = SSL_get_error(sslcom_ssl, op_code);
        unsigned long err2 = ERR_get_error();
        // potentially OK if non-blocking socket

        _dia("SSLCom::handshake: %s on socket %d: ret=%d, err=%d, err2=%d", op_descr, socket(), op_code, err, err2);

        if (err == SSL_ERROR_WANT_READ) {
            _dia("SSLCom::handshake: SSL_%s[%d]: pending on want_read", op_descr , socket());

            sslcom_waiting = true;
            counters.prof_want_read_cnt++;

            // OpenSSL made no progress and explicitly needs socket readability.
            // Retrying without a new readiness edge only burns a worker cycle.
            change_monitor(socket(), EPOLLIN);

            return ret_handshake::AGAIN;
        }
        else if (err == SSL_ERROR_WANT_WRITE) {
            _dia("SSLCom::handshake: SSL_%s[%d]: pending on want_write", op_descr, socket());

            sslcom_waiting = true;
            counters.prof_want_write_cnt++;

            // Monitor only the readiness OpenSSL requested.  The old cumulative
            // threshold permanently switched long-lived sessions to rescans.
            set_write_monitor_only(socket());
            return ret_handshake::AGAIN;
        }
        else if (err == SSL_ERROR_SYSCALL) {

            auto x_errno = errno;
            _dia("SSLCom::handshake: SSL_%s[%d]: error_syscall: %d %s", op_descr, socket(), x_errno, (x_errno == 0 ? "EOT from peer" : "" ));
            fail_both_sides(true);
            return ret_handshake::FATAL;
        }
        else {
            // any other error < 0 is considered as BAD thing.

            _dia("SSLCom::handshake: SSL_%s: ret=0, err=%d, err2=%d", op_descr, err, err2);
            handshake_dia_error2(op_code, err, err2);
            fail_both_sides(true);
            return ret_handshake::ERROR;
        }

    } else if (op_code == 0) {

        int err = SSL_get_error(sslcom_ssl, op_code);
        unsigned long err2 = ERR_get_error();

        // positively handshake error signalled by SSL_connect or SSL_accept
        _dia("SSLCom::handshake: SSL_%s: ret=0, err=%d, err2=%d", op_descr, err, err2);
        handshake_dia_error2(op_code, err, err2);

        // shutdown OK, but connection failed
        fail_both_sides(false);
        return ret_handshake::ERROR;
    }
    if(SSL_session_reused(sslcom_ssl)) {
        flags_ |= HSK_REUSED;
    }


    if(!is_server()) {
        if (not check_cert(ssl_waiting_host)) {
            _err("SSLCom::handshake: peer certificate/counterpart setup failed");
            fail_both_sides(false);
            return ret_handshake::ERROR;
        }
        store_session_if_needed();
    }

#ifndef USE_OPENSSL111
    if(( op_code > 0 ) && sslkeylog) {
        // dump only successfully established connections
        dump_keys();
        sslkeylog = false;
    }
#endif

    _dia("SSLCom::handshake: %s finished on socket %d", op_descr, socket());
    sslcom_waiting = false;

    return ret_handshake::SUCCESS;
}


template <class L4Proto>
bool baseSSLCom<L4Proto>::store_session_if_needed() {

    // add quick escape for server (left) side
    if(is_server() and not EXP_left_session_cache_enabled) {
        _deb("store_session_if_needed: left-side session cache not enabled");
        return false;
    }

    bool ret = false;
    bool proceed  = is_server() ? !opt.left.no_tickets : !opt.right.no_tickets;
    std::string pref = is_server() ? "l-" : "r-";

    if(proceed and factory() && owner_cx()) {
        std::string current_sni;

        if(is_server()) {
            auto peerscom = dynamic_cast<SSLCom*>(peer());
            if(peerscom) {
                // this is actually mine SNI :)
                current_sni = peerscom->get_sni();
            }

            auto sess = SSL_get0_session(sslcom_ssl);
            pref += owner_cx()->host() + "-";

            if(sess) {
                unsigned int sid_len = 0;
                auto sid = SSL_SESSION_get_id(sess, &sid_len);
                pref += hex_print(sid, sid_len) + "-";
            }


        } else {
            if (sslcom_sni().length() > 0) {
                current_sni = sslcom_sni();
            }
        }
        
        std::string key;
        if (current_sni.length() > 0) {
            key = pref + current_sni;
        } else {
            key = pref + string_format("%s:%s",owner_cx()->host().c_str(),owner_cx()->port().c_str());
        }

        if(!SSL_session_reused(sslcom_ssl)) {
            _dia("ticketing: key %s: full key exchange, connect attempt %d on socket %d", key.c_str(),
                                                                    counters.prof_connect_cnt, owner_cx()->socket());


            if(is_server()) {
                if(SSL_SESSION_is_resumable(SSL_get0_session(sslcom_ssl))
                   and
                   SSL_SESSION_has_ticket(SSL_get0_session(sslcom_ssl)) == 0) {
                    auto ns = new session_holder(SSL_get0_session(sslcom_ssl));
                    SSL_SESSION_up_ref(ns->ptr);

                    factory()->session_cache().set(key, ns);
                    _dia("left no ticket, saving sessionid: key %s: keying material stored, cache size = %d", key.c_str(),
                         factory()->session_cache().size());

                    ret = true;
                }
                return ret;
            }
            if(verify_bitcheck(verify_status_t::VRF_OK)) {

#if defined USE_OPENSSL111
                if(SSL_SESSION_is_resumable(SSL_get0_session(sslcom_ssl))) {
                    _dia("ticketing: obtained session can be used for resumption");

                    // only resumable, crystal OK sessions will be trusted for resumption
                    if(verify_get() == verify_status_t::VRF_OK) {
                        auto ns = new session_holder(SSL_get0_session(sslcom_ssl));
                        SSL_SESSION_up_ref(ns->ptr);

                        factory()->session_cache().set(key, ns);
                        _dia("right ticketing: key %s: keying material stored, cache size = %d", key.c_str(),
                             factory()->session_cache().size());
                    } else {

                        std::string ext_str;

                        if(! verify_extended_info().empty()) {
                            ext_str += ", extended ";
                            for (auto ei: verify_extended_info()) {
                                ext_str += string_format("%d, ", ei);
                            }
                        }

                        _dia("ticketing: session not stored due to verify result 0x%04x%s", verify_get(), ext_str.c_str());
                    }

                    ret = true;

                } else {
                    _dia("session CANNOT be resumed");
                }
#else
                certstore()->session_cache.set(key,new session_holder(SSL_get1_session(sslcom_ssl)));
                _dia("ticketing: key %s: keying material stored, cache size = %d",key.c_str(),certstore()->session_cache.cache().size());

                ret = true;

#endif // USE_OPENSSL11
            } else {
                if(verify_bitcheck(verify_status_t::VRF_NOTTESTED)) {
                    _dia("certificate verification not tested yet, session not stored in the cache.");
                } else {
                    _war("certificate verification failed, session not stored in the cache.");
                }
                ret = false;
            }
            
        } else {
            _dia("ticketing: key %s: abbreviated key exchange, connect attempt %d on socket %d",key.c_str(),
                                                            counters.prof_connect_cnt,owner_cx()->socket());
            flags_ |= HSK_REUSED;


            // we trust sites we have already connected to!
            _dia("verified by previous connection");
            verify_bitreset(verify_status_t::VRF_NOTTESTED);
            verify_bitset(verify_status_t::VRF_OK);
        }
    }
    
    return ret;
}


template <class L4Proto>
bool baseSSLCom<L4Proto>::load_session_if_needed() {

    // add quick escape for server (left) side
    if(is_server() and not EXP_left_session_cache_enabled) {
        _deb("store_session_if_needed: left-side session cache not enabled");
        return false;
    }

    bool ret = false;
    bool proceed  = is_server() ? !opt.left.no_tickets : !opt.right.no_tickets;
    std::string pref = is_server() ? "l-" : "r-";

    if(proceed and factory() && owner_cx()) {
        std::string current_sni;

        if(is_server()) {
            auto const* peerscom = dynamic_cast<SSLCom*>(peer());
            if(peerscom) {
                // this is actually mine SNI :)
                current_sni = peerscom->get_sni();
            }

            pref += owner_cx()->host() + "-";

            auto sid = peerscom->get_peer_id();
            if(sid.length() > 0) {
                pref += sid + "-";
            }

        } else {
            if (sslcom_sni().length() > 0) {
                current_sni = sslcom_sni();
            }
        }
        
        std::string key;
        if (current_sni.length() > 0) {
            key = pref + current_sni;
        } else {
            key = pref + string_format("%s:%s",owner_cx()->host().c_str(),owner_cx()->port().c_str());
        }

        auto h = factory()->session_cache().get(key);
        
        if(h != nullptr) {
            _dia("ticketing: key %s:target server TLS ticket found!",key.c_str());
            SSL_set_session(sslcom_ssl, h->ptr);
            h->cnt_loaded.fetch_add(1, std::memory_order_relaxed);
            
            ret = true;
        } else {
            _dia("ticketing: key %s:target server TLS ticket not found",key.c_str());
            SSL_set_session(sslcom_ssl, nullptr);
        }
    }
    
    return ret;
}

template <class L4Proto>
typename baseSSLCom<L4Proto>::client_hello_peek_t
baseSSLCom<L4Proto>::normalize_peer_hello_records() {
    constexpr std::size_t record_header_size = 5;
    constexpr std::size_t record_payload_max = 18432;
    constexpr std::size_t handshake_header_size = 4;

    auto& raw = sslcom_peer_hello_buffer;
    if (raw.size() < record_header_size)
        return client_hello_peek_t::WAIT;

    if (raw.get_at<unsigned char>(0) != SSL3_RT_HANDSHAKE)
        return client_hello_peek_t::NOT_TLS;
    if (raw.get_at<unsigned char>(1) != 3)
        return client_hello_peek_t::NOT_TLS;

    // The normal case is one complete ClientHello in one TLS record.  The
    // buffer already has exactly the layout parse_peer_hello() consumes, so
    // validate and reuse it instead of copying through a vector and a second
    // buffer.  The general path below still joins record-fragmented hellos.
    const std::size_t first_payload_size =
        ntohs(raw.get_at<unsigned short>(record_header_size - 2));
    if (first_payload_size == 0 || first_payload_size > record_payload_max)
        return client_hello_peek_t::INVALID;
    if (record_header_size + first_payload_size > SSLCOM_CLIENTHELLO_MAX_SIZE)
        return client_hello_peek_t::INVALID;
    if (raw.size() < record_header_size + first_payload_size)
        return client_hello_peek_t::WAIT;
    if (first_payload_size >= handshake_header_size) {
        const auto* first = raw.data() + record_header_size;
        if (first[0] != SSL3_MT_CLIENT_HELLO)
            return client_hello_peek_t::INVALID;
        const std::size_t expected = handshake_header_size +
            (static_cast<std::size_t>(first[1]) << 16U) +
            (static_cast<std::size_t>(first[2]) << 8U) +
            static_cast<std::size_t>(first[3]);
        if (expected > SSLCOM_CLIENTHELLO_MAX_SIZE - record_header_size)
            return client_hello_peek_t::INVALID;
        if (expected <= first_payload_size) {
            raw.set_at<unsigned short>(record_header_size - 2,
                                       htons(static_cast<unsigned short>(expected)));
            raw.size(record_header_size + expected);
            return client_hello_peek_t::READY;
        }
    }

    std::vector<unsigned char> handshake;
    std::size_t expected_handshake_size = 0;
    std::size_t offset = 0;
    unsigned char record_minor = raw.get_at<unsigned char>(2);

    while (true) {
        if (raw.size() - offset < record_header_size)
            return client_hello_peek_t::WAIT;
        if (raw.get_at<unsigned char>(offset) != SSL3_RT_HANDSHAKE ||
            raw.get_at<unsigned char>(offset + 1) != 3)
            return client_hello_peek_t::INVALID;

        const std::size_t payload_size = ntohs(raw.get_at<unsigned short>(offset + 3));
        if (payload_size == 0 || payload_size > record_payload_max)
            return client_hello_peek_t::INVALID;
        if (offset + record_header_size + payload_size > SSLCOM_CLIENTHELLO_MAX_SIZE)
            return client_hello_peek_t::INVALID;
        if (raw.size() - offset - record_header_size < payload_size)
            return client_hello_peek_t::WAIT;

        const auto* payload = raw.data() + offset + record_header_size;
        handshake.insert(handshake.end(), payload, payload + payload_size);

        if (expected_handshake_size == 0 && handshake.size() >= handshake_header_size) {
            if (handshake[0] != SSL3_MT_CLIENT_HELLO)
                return client_hello_peek_t::INVALID;
            expected_handshake_size = handshake_header_size +
                (static_cast<std::size_t>(handshake[1]) << 16U) +
                (static_cast<std::size_t>(handshake[2]) << 8U) +
                static_cast<std::size_t>(handshake[3]);
            if (expected_handshake_size > SSLCOM_CLIENTHELLO_MAX_SIZE - record_header_size)
                return client_hello_peek_t::INVALID;
        }

        if (expected_handshake_size != 0 && handshake.size() >= expected_handshake_size) {
            buffer normalized;
            normalized.capacity(record_header_size + expected_handshake_size);
            unsigned char header[record_header_size] {
                SSL3_RT_HANDSHAKE, 3, record_minor,
                static_cast<unsigned char>((expected_handshake_size >> 8U) & 0xffU),
                static_cast<unsigned char>(expected_handshake_size & 0xffU)
            };
            normalized.append(header, sizeof(header));
            normalized.append(handshake.data(), expected_handshake_size);
            raw = std::move(normalized);
            return client_hello_peek_t::READY;
        }

        offset += record_header_size + payload_size;
        if (offset >= raw.size())
            return client_hello_peek_t::WAIT;
    }
}

template <class L4Proto>
bool baseSSLCom<L4Proto>::waiting_peer_hello() {

    _dum("SSLCom::waiting_peer_hello: start");

    if(sslcom_peer_hello_received_) {
        _deb("SSLCom::waiting_peer_hello: already called, returning true");
        return true;
    }

    _dum("SSLCom::waiting_peer_hello: called");
    if(peer()) {
        auto* peer_scom = dynamic_cast<baseSSLCom*>(peer());
        if(peer_scom != nullptr) {
            if(peer_scom->socket() > 0) {
                _dum("SSLCom::waiting_peer_hello: peek max %d bytes from peer socket %d",sslcom_peer_hello_buffer.capacity(),peer_scom->socket());

                int red = ::recv(peer_scom->socket(),sslcom_peer_hello_buffer.data(),sslcom_peer_hello_buffer.capacity(), MSG_PEEK);
                if (red > 0) {
                    sslcom_peer_hello_buffer.size(red);

                    const auto peek_status = normalize_peer_hello_records();
                    if (peek_status == client_hello_peek_t::WAIT) {
                        if (sslcom_peer_hello_buffer.size() == sslcom_peer_hello_buffer.capacity() &&
                            sslcom_peer_hello_buffer.capacity() < SSLCOM_CLIENTHELLO_MAX_SIZE) {
                            sslcom_peer_hello_buffer.capacity(std::min(
                                SSLCOM_CLIENTHELLO_MAX_SIZE,
                                sslcom_peer_hello_buffer.capacity() * 2));
                        }
                        if (timeval_msdelta_now(&timer_start) > SSLCOM_CLIENTHELLO_TIMEOUT) {
                            _err("handshake timeout: waiting for complete ClientHello");
                            peer_scom->error(ERROR_READ);
                            error(ERROR_UNSPEC);
                        } else {
                            master()->poller.rescan_in(peer_scom->socket());
                        }
                        return false;
                    }
                    if (peek_status == client_hello_peek_t::INVALID) {
                        _err("SSLCom::waiting_peer_hello: invalid TLS ClientHello");
                        peer_scom->error(ERROR_READ);
                        error(ERROR_UNSPEC);
                        return false;
                    }

                    _dia("SSLCom::waiting_peer_hello: %d bytes in buffer for hello analysis",red);
                    _dum("SSLCom::waiting_peer_hello: ClientHello data:\r\n%s",
                                hex_dump(sslcom_peer_hello_buffer.data(),sslcom_peer_hello_buffer.size(), 4, 0, true).c_str());

                    int parse_hello_result = 0;
                    if (peek_status == client_hello_peek_t::READY) {
                        try {
                            parse_hello_result = parse_peer_hello();
                        }
                        catch(socle::ex::SSL_clienthello_malformed const& e) {
                            _dia("SSLCom::waiting_peer_hello: %d bytes of malformed ClientHello data",red);
                            peer_scom->error(ERROR_READ);
                            error(ERROR_UNSPEC);
                            return false;
                        }
                    }

                    if(parse_hello_result == 0) {
                        _dia("SSLCom::waiting_peer_hello: analysis failed");
                        _dia("SSLCom::waiting_peer_hello: failed ClientHello data:\r\n%s",
                                hex_dump(sslcom_peer_hello_buffer.data(),sslcom_peer_hello_buffer.size(), 4, 0, true).c_str());

                        if (peek_status == client_hello_peek_t::NOT_TLS && not opt.no_fallback_bypass) {

                            if (bypass_me_and_peer()) {
                                _inf("bypassing non-TLS connection");
                                log.event(INF, "[%s] cannot read ClientHello: bypassed",
                                          peer_scom->to_string(iINF).c_str());
                                return false;
                            }
                        }
                        else {
                            _inf("fallback bypass disabled!");
                            log.event(INF, "[%s] cannot read ClientHello: bypass disabled",
                                      peer_scom->to_string(iINF).c_str());
                        }
                        
                        error_flag_ = ERROR_UNSPEC; // peer nullptr or its com() is not SSLCom
                        return false;
                        
                    } else if(parse_hello_result < 0) {
                        // not enough of data
                        return false;
                    }

                    // Preserve the parsed ClientHello SNI on the client-facing
                    // peer, then optionally replace only this outbound value.
                    peer_scom->sslcom_sni() = sslcom_sni();
                    if(auto const* target = owner_cx(); target) {
                        sslcom_sni() = target->outbound_sni(sslcom_sni());
                    }
                    
                    sslcom_peer_hello_received(true);
                    change_monitor(socket(), EPOLLIN);

                } else {
                    _deb("SSLCom::waiting_peer_hello: peek returns %d, readbuf=%d", red, owner_cx() ? owner_cx()->readbuf()->size() : -1);
                    if(not owner_cx()) {
                        _deb("SSLCom::waiting_peer_hello: no owner_cx!");
                    }

                    // hopefully complete list of error codes allowing us to further peek peer's socket
                    if (red == 0) {
                        _err("SSLCom::waiting_peer_hello: EOF before ClientHello");
                        peer_scom->error(ERROR_READ);
                        error(ERROR_UNSPEC);
                    } else if (errno != EINPROGRESS && errno != EWOULDBLOCK &&
                               errno != EAGAIN && errno != EINTR) {
                        _err("SSLCom::waiting_peer_hello: unrecoverable peek errno: %s", string_error().c_str());
                        peer_scom->error(ERROR_READ);
                        error(ERROR_UNSPEC);
                    } else {
                        _deb("SSLCom::waiting_peer_hello: peek errno: %s",string_error().c_str());
                    }
                }

            } else {
                _dia("SSLCom::waiting_peer_hello: SSLCom peer doesn't have sslcom_fd set, socket %d",peer_scom->socket());
               
                // This is untested code for virtual sockets
                if(peer_scom->l4_proto() == SOCK_DGRAM) {
                    // atm don't wait for hello
                    sslcom_peer_hello_received(true);
                    change_monitor(socket(), EPOLLIN);
                }
            }
        } else {
            _dia("SSLCom::waiting_peer_hello: peer not SSLCom type");
        }
    } else {
        _dia("SSLCom::waiting_peer_hello: no peers, setting hello received.");
        sslcom_peer_hello_received(true);
        set_monitor(socket());
    }

    return sslcom_peer_hello_received_;
}

template <class L4Proto>
bool baseSSLCom<L4Proto>::enforce_peer_cert_from_cache(std::string & subj) {

    if(peer() and peer()->owner_cx()) {
        _dia("SSLCom::enforce_peer_cert_from_cache: about to force peer's side to use cached certificate");

        auto lc_ = std::scoped_lock(factory()->lock());

        auto parek = factory()->find_mitm(subj);
        if (parek.has_value()) {
            _dia("Found cached certificate %s based on fqdn search.",subj.c_str());
            auto* p = dynamic_cast<baseSSLCom*>(peer());
            if(p != nullptr) {

                if(p->sslcom_waiting) {
                    p->sslcom_pref_cert = parek.value().chain.cert;
                    p->sslcom_pref_key = parek.value().chain.key;

                    //p->init_server(); this will be done automatically, peer was waiting_for_peercom
                    p->owner_cx()->waiting_for_peercom(false);
                    _dia("SSLCom::enforce_peer_cert_from_cache: peer certs replaced by SNI lookup, peer was unpaused.");
                    sslcom_peer_sni_shortcut = true;

                    return true;
                } else {
                    _dia("SSLCom::enforce_peer_cert_from_cache: cannot modify non-waiting peer!");
                }
            } else {
                _dia("SSLCom::enforce_peer_cert_from_cache: failed to update peer:  it's not SSLCom* type!");
            }
        } else {
            _dia("SSLCom::enforce_peer_cert_from_cache: failed to update initiator with cached certificate: certificate was not found.!");
        }
    }

    return false;
}


template <class L4Proto>
int baseSSLCom<L4Proto>::parse_peer_hello() {

    int ret = -1;

    try {

        buffer& b = sslcom_peer_hello_buffer;
        if(b.size() >= 34) {

            buffer session_id;
            unsigned int curpos = 0;

            unsigned char message_type = b.get_at<unsigned char>(curpos);
            curpos+=sizeof(unsigned char);
            unsigned char version_maj = b.get_at<unsigned char>(curpos);
            curpos+=sizeof(unsigned char);
            unsigned char version_min = b.get_at<unsigned char>(curpos);
            curpos+=sizeof(unsigned char);

            unsigned short message_length = ntohs(b.get_at<unsigned short>(curpos));
            curpos+=sizeof(unsigned short);


            // version_maj should be always 3
            // version_min -
            //     0x03 - TLS 1.2
            //     0x02 - TLS 1.1
            //     0x01 - TLS 1.0

            if(version_maj != 3) {
                _dia("SSLCom::parse_peer_hello: version_maj should be always 3. not %d", version_maj);
                throw socle::ex::SSL_clienthello_malformed();
            }

            _dia("SSLCom::parse_peer_hello: buffer size %d, received message type %d, version %d.%d, length %d",b.size(), message_type, version_maj, version_min, message_length);
            if(b.size() != (unsigned int)message_length + 5) {
                _deb("SSLCom::parse_peer_hello: strange SSL payload received");
                if(message_type != 22 || version_maj > 5) {
                    _dia("SSLCom::parse_peer_hello: message is not ClientHello");
                    return 0;
                }
            }

            unsigned char handshake_type = b.get_at<unsigned char>(curpos);
            curpos += sizeof(unsigned char); //@6, followed by the 24-bit handshake length
            
            if(message_type == 22 && handshake_type == 1) {

                try {
                    const unsigned int handshake_length =
                        (static_cast<unsigned int>(b.get_at<unsigned char>(curpos)) << 16U) |
                        (static_cast<unsigned int>(b.get_at<unsigned char>(curpos + 1)) << 8U) |
                        static_cast<unsigned int>(b.get_at<unsigned char>(curpos + 2));
                    curpos += 3; //@9
                    if (handshake_length > b.size() - curpos)
                        throw socle::ex::SSL_clienthello_malformed();
                    unsigned char handshake_version_maj = b.get_at<unsigned char>(curpos);
                    curpos += sizeof(unsigned char); //@10
                    unsigned char handshake_version_min = b.get_at<unsigned char>(curpos);
                    curpos += sizeof(unsigned char); //@11
                    [[maybe_unused]]
                    unsigned int handshake_unixtime = ntohl(b.get_at<unsigned int>(curpos));
                    curpos += sizeof(unsigned int); //@15

                    curpos += 28; // skip random 24B bytes

                    unsigned char session_id_length = b.get_at<unsigned char>(curpos);
                    curpos += sizeof(unsigned char);

                    // we already know it's handshake, it's ok to return true
                    _dia("SSLCom::parse_peer_hello: handshake (type %u), version %u.%u, length %u", handshake_type,
                         handshake_version_maj, handshake_version_min, handshake_length);
                    if (handshake_type == 1) {
                        ret = 1;
                    }

                    if (session_id_length > 0) {
                        // here
                        session_id = b.view(curpos, session_id_length);
                        curpos += session_id_length;

                        sslcom_peer_hello_id_ = hex_print(session_id.data(), session_id.size());
                        _deb("SSLCom::parse_peer_hello: session_id (length %d)", session_id_length);
                        _dum("SSLCom::parse_peer_hello: session_id :\r\n%s",
                             hex_dump(session_id.data(), session_id.size()).c_str(), 4, 0, true);
                    } else {
                        _deb("SSLCom::parse_peer_hello: no session_id found.");
                    }

                    auto ciphers_length = tainted::var<unsigned short>(ntohs(b.get_at<unsigned short>(curpos)), tainted::any<unsigned short>);

                    curpos += sizeof(unsigned short);
                    if (curpos + ciphers_length > b.size())
                        throw socle::ex::SSL_clienthello_malformed();

                    curpos += ciphers_length; //skip ciphers
                    _deb("SSLCom::parse_peer_hello: ciphers length %d", ciphers_length);

                    auto compression_length = tainted::var<unsigned char>(b.get_at<unsigned char>(curpos), tainted::any<unsigned char>);

                    curpos += sizeof(unsigned char);
                    if (curpos + compression_length > b.size())
                        throw socle::ex::SSL_clienthello_malformed();

                    curpos += compression_length; // skip compression methods
                    _deb("SSLCom::parse_peer_hello: compression length %d", compression_length);

                } catch(std::out_of_range const& e) {
                    _dia("SSLCom::parse_peer_hello: too short to read position %d from data size %d", curpos, b.size());
                    throw socle::ex::SSL_clienthello_malformed();
                }

                /* extension section, optional in tls1.2, but mandatory in tls 1.3 */

                /*
                 * https://datatracker.ietf.org/doc/html/rfc8446#section-4.1.2

                All versions of TLS allow an extensions field to optionally follow
                the compression_methods field.  TLS 1.3 ClientHello messages always
                contain extensions (minimally "supported_versions", otherwise, they
                will be interpreted as TLS 1.2 ClientHello messages).  However,
                        TLS 1.3 servers might receive ClientHello messages without an
                extensions field from prior versions of TLS.
                 */

                unsigned short extensions_length = 0;
                if(curpos + sizeof(unsigned short) <= b.size()) {
                    extensions_length = ntohs(b.get_at<unsigned short>(curpos));
                    curpos += sizeof(unsigned short);
                }

                _deb("SSLCom::parse_peer_hello: extensions payload length %d", extensions_length);
                if (curpos + extensions_length > b.size()) {
                    _dia("SSLCom::parse_peer_hello: too short to read extensions position %d, extension len %d from data size %d", curpos, extensions_length, b.size());
                    throw socle::ex::SSL_clienthello_malformed();
                }

                if (extensions_length > 0) {
                    const unsigned int extensions_end = curpos + extensions_length;
                    while (curpos < extensions_end) {
                        if (extensions_end - curpos < 4)
                            throw socle::ex::SSL_clienthello_malformed();

                        _deb("SSLCom::parse_peer_hello: parsing extension at position %d", curpos);
                        const unsigned int parsed = parse_peer_hello_extensions(b, curpos);
                        if (parsed > extensions_end - curpos)
                            throw socle::ex::SSL_clienthello_malformed();
                        curpos += parsed;
                    }
                }
            }
            else if(message_type == 22 && handshake_type != 1) {
                _err("SSLCom::parse_peer_hello: handshake message, but not ClientHello; message_type %d, handshake_type %d", message_type, handshake_type);
                ret = 1; // we need to assume we are late, so let continue without SNI.
            }
            else if(message_type > 22) {
                _err("SSLCom::parse_peer_hello: post-handshake message; message_type %d, handshake_type %d", message_type, handshake_type);
                ret = 1; // we need to assume we are late, so let continue without SNI.
            } else {
                _err("SSLCom::parse_peer_hello: unknown message; message_type %d, handshake_type %d", message_type, handshake_type);
                ret = 1; // we need to assume we are late, so let continue without SNI.
            }
            
                
        } else {
            auto* p = dynamic_cast<baseSSLCom*>(peer());
            if(p != nullptr) 
                master()->poller.rescan_in(p->socket());
            
            _dia("SSLCom::parse_peer_hello: only %d bytes in peek:\n%s",b.size(),hex_dump(b.data(),b.size(), 4, 0, true).c_str());
            if(timeval_msdelta_now(&timer_start) > SSLCOM_CLIENTHELLO_TIMEOUT) {
                _err("handshake timeout: waiting for ClientHello");
                error(ERROR_UNSPEC);
            }
        }

        _dia("SSLCom::parse_peer_hello: return status %d",ret);
    }
    catch (std::out_of_range const& e) {
        _dia("SSLCom::parse_peer_hello: failed to parse hello: %s", e.what());
        error(ERROR_UNSPEC);
    }

    return ret;
}

template <class L4Proto>
unsigned short baseSSLCom<L4Proto>::parse_peer_hello_extensions(buffer& b, unsigned int curpos) {

    if (curpos > b.size() || b.size() - curpos < 4)
        throw socle::ex::SSL_clienthello_malformed();

    unsigned short ext_id = ntohs(b.get_at<unsigned short>(curpos));
    curpos+=sizeof(unsigned short);
    unsigned short ext_length = ntohs(b.get_at<unsigned short>(curpos));
    curpos+=sizeof(unsigned short);

    if (ext_length > b.size() - curpos)
        throw socle::ex::SSL_clienthello_malformed();

    const unsigned int ext_end = curpos + ext_length;

    _deb("SSLCom::parse_peer_hello_extensions: extension id 0x%x, length %d", ext_id, ext_length);

    if(ext_id == 0) {

        // SNI

        if (ext_length < 5)
            throw socle::ex::SSL_clienthello_malformed();

        [[maybe_unused]]
        unsigned short sn_list_length = ntohs(b.get_at<unsigned short>(curpos));
        curpos += sizeof(unsigned short);
        if (sn_list_length != ext_length - sizeof(unsigned short))
            throw socle::ex::SSL_clienthello_malformed();

        unsigned char sn_type = b.get_at<unsigned char>(curpos);
        curpos += sizeof(unsigned char);

        /* type is hostname*/
        if (sn_type == 0) {
            unsigned short sn_hostname_length = ntohs(b.get_at<unsigned short>(curpos));
            curpos += sizeof(unsigned short);
            if (sn_hostname_length > ext_end - curpos)
                throw socle::ex::SSL_clienthello_malformed();

            std::string s;
            s.append((const char *) b.data() + curpos, (size_t) sn_hostname_length);

            _dia("SSLCom::parse_peer_hello_extensions:    SNI hostname: %s", s.c_str());

            sslcom_sni_ = s;
        }
    }
    else if(ext_id == 16) {

        if (ext_length < sizeof(unsigned short))
            throw socle::ex::SSL_clienthello_malformed();

        unsigned short alpn_length = ntohs(b.get_at<unsigned short>(curpos));
        curpos += sizeof(unsigned short);
        if (alpn_length != ext_end - curpos)
            throw socle::ex::SSL_clienthello_malformed();

        std::string s;
        s.append((const char *) b.data() + curpos, (size_t) alpn_length);
        _dia("SSLCom::parse_peer_hello_extensions:    ALPN: %s",
             hex_print(reinterpret_cast<unsigned char *>(s.data()), s.size()).c_str());
        sslcom_peer_hello_alpn_ = s;
    }


    return ext_length + 4;  // +4 for ext_id and ext_length
}



#pragma GCC diagnostic ignored "-Wpointer-arith"
#pragma GCC diagnostic push

template <class L4Proto>
ssize_t baseSSLCom<L4Proto>::read (int _fd, void* _buf, size_t _n, int _flags )  {

    int total_r = 0;
    int rounds = 0;

    if(opt.bypass) {
        _deb("SSLCom::read[%d]: called: bypassed - to read max %d bytes", _fd, _n);
        return L4Proto::read(_fd, _buf, _n, _flags);
    }

    // non-blocking socket can be still opening
    if( sslcom_waiting ) {
        _dum("SSLCom::read[%d]: still waiting for handshake to complete.", _fd);
        ret_handshake c = handshake();

        if (c == ret_handshake::AGAIN) {

            if(opt.bypass) {
                _deb("SSLCom:: read[%d]: ssl_waiting() bypass from handshake ", _fd);
                return L4Proto::read(_fd, _buf, _n, _flags);
            }

            _dum("SSLCom:: read[%d]: ssl_waiting() returned %d: still waiting", _fd, c);
            return -1;

        }
        else if (c == ret_handshake::ERROR) {
            _dia("SSLCom:: read[%d]: ssl_waiting() returned %d: unrecoverable!", _fd, c);
            return 0;
        }
        else if (c == ret_handshake::FATAL) {
            _dia("SSLCom:: read[%d]: ssl_waiting() returned %d: unexpected termination!", _fd, c);
            sslcom_fatal = true;
            return 0;
        }

        _dia("SSLCom::read[%d]: handshake finished, continue with %s from socket", _fd, _flags & MSG_PEEK ? "peek" : "read");
        // if we were waiting, force next round of read
        forced_read(true);
        monitor_peer();
    }

    // if we are peeking, just do it and return, no magic done is here
    if ((_flags & MSG_PEEK) != 0) {
        _dum("SSLCom::read[%d]: about to peek  max %4d bytes", _fd, _n);
        sslcom_ret = SSL_peek(sslcom_ssl, _buf, _n);
        counters.prof_peek_cnt++;

        if(sslcom_ret > 0) {
            _dia("SSLCom::read[%d]: peek returned %d", _fd, sslcom_ret);
        } else {
            _dum("SSLCom::read[%d]: peek returned %d", _fd, sslcom_ret);

            auto errc = SSL_get_error(sslcom_ssl, sslcom_ret);
            if(errc == SSL_ERROR_SYSCALL or errc == SSL_ERROR_ZERO_RETURN or errc == SSL_ERROR_SSL) {
                sslcom_fatal = true;
                // this is bad
                _dia("SSLCom:: read[%d]: ssl_peek() returned %d: unexpected termination!", _fd, sslcom_ret);
                error(ERROR_READ);
                return 0;
            }
        }

        return sslcom_ret;
    }

    do {

        if(total_r >= (int)_n) {
            _deb("SSLCom::read[%d]: reached buffer capacity of %4d bytes, forcing new read", _fd, _n);

            // this is tricky one :)
            // I have spent quite couple of hours of troubleshooting this:
            // ...
            // We have to break here, since write buffer is full
            // BUT
            // openssl already has it internally
            // => select|poll won't return this socket as in read_set == no reads anymore !!!
            // => we have to have mechanism which will enforce read in the next round
            forced_read(true);
            master()->set_enforce(_fd);
            _deb("SSLCom::read[%d]:  forcing new read (this com 0x%x, master 0x%x)", _fd, this, master());
            _deb("SSLCom::read[%d]:  forcing new read (peer com 0x%x, peer master 0x%x)", _fd, peer(), peer()->master());
            break;
        }

        _ext("SSLCom::read[%d]: about to read  max %4d bytes", _fd, _n);

        ERR_clear_error();
        sslcom_ret = SSL_read (sslcom_ssl, static_cast<uint8_t*>(_buf) + total_r, _n - total_r);
        counters.prof_read_cnt++;

        if(sslcom_ret == 0) {
            _deb("SSLCom::read: SSL_read returned 0");
        }

        // A positive SSL_read result is unconditionally successful. Avoid
        // walking OpenSSL's error state on every TLS record in the data path.
        int err = sslcom_ret > 0 ? SSL_ERROR_NONE
                                 : SSL_get_error(sslcom_ssl, sslcom_ret);
        switch ( err ) {
            case SSL_ERROR_NONE:

                _deb("SSLCom::read [%d]: %4d bytes read:(round %d) %s, %X", _fd, sslcom_ret, rounds,
                     (sslcom_ret == (signed int)_n) ? "(max)" : "(no-max)",
                     debug_log_data_crc ? socle::tools::crc32::compute(0, _buf, sslcom_ret) : 0
                    );

                if(sslcom_ret > 0)
                    total_r += sslcom_ret;

                
                if(sslcom_read_blocked_on_write > 0) {
                    master()->poller.modify(_fd, EPOLLIN);
                    sslcom_read_blocked_on_write=0;
                }

                
                // reset IO timeouts
                set_timer_now(&timer_read_timeout);
                set_timer_now(&timer_write_timeout);

                // reset WANT counters
                counters.read_want_write_cur = 0;
                counters.read_want_read_cur = 0;


                break;

            case SSL_ERROR_ZERO_RETURN:
                _deb("SSLCom::read[%d]: zero returned", _fd);
                error(ERROR_READ);

                // we used to return sslcom_ret, but it may be -1 (we don't want that - it indicates "try later")
                return 0;

            case SSL_ERROR_WANT_READ:
                _deb("SSLCom::read[%d]: want read: err=%d, read_now=%4d, total=%4d", _fd, err, sslcom_ret, total_r);

                counters.read_want_read_cur++;
                counters.prof_want_read_cnt++;

                // Retry only after the readiness edge requested by OpenSSL.
                set_monitor(socket());

                // check timers and bail on timeout
                if(timeval_msdelta_now(&timer_read_timeout) > SSLCOM_READ_TIMEOUT) {
                    _err("SSLCom::read[%d]: wanted read timeout, closing.", _fd);
                    error(ERROR_READ);
                    return 0;
                }
                
                if(total_r > 0) return total_r;
                return sslcom_ret;

                /* We get a WANT_WRITE if we're
                trying to rehandshake and we block on
                a write during that rehandshake.

                We need to wait on the socket to be
                writeable but reinitiate the read
                when it is */

            case SSL_ERROR_WANT_CONNECT:
                _dia("SSLCom::read[%d]: want connect", _fd);

                if(total_r > 0) return total_r;
                return sslcom_ret;

            case SSL_ERROR_WANT_ACCEPT:
                _dia("SSLCom::read[%d]: want accept", _fd);

                if(total_r > 0) return total_r;
                return sslcom_ret;


            case SSL_ERROR_WANT_WRITE:
                _deb("SSLCom::read[%d]: want write, last read returned %d, total read %4d", _fd, sslcom_ret, total_r);

                forced_read_on_write(true);
                sslcom_read_blocked_on_write = 1;

                counters.read_want_write_cur++;
                counters.prof_want_write_cnt++;

                // Retry the read when the socket becomes writable.
                set_write_monitor(socket());


                // check timers and bail on timeout
                if(timeval_msdelta_now(&timer_read_timeout) > SSLCOM_READ_TIMEOUT) {
                    _err("SSLCom::read[%d]: wanted read timeout, closing.", _fd);
                    error(ERROR_READ);
                    return 0;
                }
                                
                
                if(total_r > 0) return total_r;
                return sslcom_ret;

            case SSL_ERROR_WANT_X509_LOOKUP:
                _dia("SSLCom::read[%d]: want x509 lookup", _fd);
                if(total_r > 0) return total_r;
                return sslcom_ret;

            case SSL_ERROR_SYSCALL:
                {
                auto x_errno = errno;
                _dia("SSLCom::read[%d]: syscall error: %d %s", _fd, x_errno, (x_errno == 0 ? "unexpected EOT from peer" : ""));
                }
                sslcom_fatal = true;

                if (total_r > 0) {
                    // syscall error when we have already bytes
                    _dia("SSLCom::read[%d]: syscall error: occurred after %d bytes read", _fd, total_r);
                    return total_r;
                }
                else {
                    // we used to return sslcom_ret (but it can be -1, we don't want that - it indicates "try later")
                    return 0;
                }

            default:
                if (sslcom_ret != -1 && err != 1) {
                    _dia("SSLCom::read[%d] problem: %d, read returned %4d", _fd, err, sslcom_ret);
                }

                if(total_r > 0) return total_r;
                return sslcom_ret;
        }

        /* We need a check for read_blocked here because
           SSL_pending() doesn't work properly during the
           handshake. This check prevents a busy-wait
           loop around SSL_read() */
        rounds++;

    } while ( SSL_pending (sslcom_ssl) );

    _deb("SSLCom::read: total %4d bytes read",total_r);

    if(total_r == 0) {
        _dia("SSLCom::read: logic error, total_r == 0");
    }

    return total_r;
}


template <class L4Proto>
ssize_t baseSSLCom<L4Proto>::write (int _fd, const void* _buf, size_t _n, int _flags )  {

    if(_n == 0) {
        _ext("SSLCom::write[%d]: called: about to write %d bytes", _fd, _n);
    } else {
        _deb("SSLCom::write[%d]: called: about to write %d bytes", _fd, _n);
    }


    if(opt.bypass) {
        _deb("SSLCom::write[%d]: called: bypassed - to write %d bytes", _fd, _n);
        return L4Proto::write(_fd, _buf, _n, _flags);
    }

    // non-blocking socket can be still opening
    if( sslcom_waiting ) {
        _dum("SSLCom::write[%d]: still waiting for handshake to complete.", _fd);

        ret_handshake c = handshake();
        if (c == ret_handshake::AGAIN) {

            if(opt.bypass) {
                _deb("SSLCom:: write[%d]: ssl_waiting() bypass from handshake", _fd);
                return L4Proto::write(_fd, _buf, _n, _flags);
            }

            _dum("SSLCom::write[%d]: ssl_waiting() returned %d: still waiting", _fd, c);
            return 0;

        }
        else if (c == ret_handshake::ERROR) {
            _dia("SSLCom::write[%d]: ssl_waiting() returned %d: unrecoverable!", _fd, c);
            return -1;
        }
        else if (c == ret_handshake::FATAL) {
            _dia("SSLCom::write[%d]: ssl_waiting() returned %d: unexpected termination!", _fd, c);
            sslcom_fatal = true;
            return -1;
        }

        _dia("SSLCom::write[%d]: handshake finished, continue with writing to socket", _fd);
        // if we were waiting, force next round of write
        forced_write(true);
        monitor_peer();
    }

    sslcom_write_blocked_on_read=0;
    int normalized__n = 20480;
    void *ptr = (void*)_buf;

    if(_n == 0) {
        _ext("SSLCom::write[%d]: attempt to send %d bytes", _fd, _n);
    } else {
        _deb("SSLCom::write[%d]: attempt to send %d bytes", _fd, _n);
    }
    if (_n < 20480) {
        normalized__n = _n;
    }

    if (_n <= 0 ) {
        return 0;
    }

    /* Try to write */
    ERR_clear_error();
    sslcom_ret = SSL_write (sslcom_ssl, ptr, normalized__n);

    if(sslcom_ret >= normalized__n) {
        forced_write(true);
    }

    counters.prof_write_cnt++;

    // A positive SSL_write result is unconditionally successful. Error state
    // inspection belongs only on the non-success path.
    int err = sslcom_ret > 0 ? SSL_ERROR_NONE
                             : SSL_get_error(sslcom_ssl, sslcom_ret);
    bool is_problem = true;
    bool apply_error_timer = false;

    switch ( err ) {

            /* We wrote something*/
        case SSL_ERROR_NONE:
            _deb("SSLCom::write[%d]: %4d bytes written to the ssl socket %s, %X", _fd, sslcom_ret, sslcom_ret != (signed int)_n ? "(incomplete)" : "",
                 debug_log_data_crc ? socle::tools::crc32::compute(0, _buf, sslcom_ret) : 0
                );
            is_problem = false;

            if(sslcom_write_blocked_on_read > 0) {
                sslcom_write_blocked_on_read = 0;
                forced_write_on_read(false);
                _dia("SSLCom::write[%d]: want read: cleared", _fd);
            }
            if(sslcom_write_blocked_on_write > 0) {
                sslcom_write_blocked_on_write = 0;
                master()->poller.modify(_fd, EPOLLIN);
                _dia("SSLCom::write[%d]: want write: cleared", _fd);
            }
            
            // reset IO timeouts
            set_timer_now(&timer_read_timeout);
            set_timer_now(&timer_write_timeout);


            // reset rescan counters
            counters.write_want_read_cur = 0;
            counters.write_want_write_cur = 0;

            break;

            /* We would have blocked */
        case SSL_ERROR_WANT_WRITE:
            _dia("SSLCom::write[%d]: want write: %d (written %4d)", _fd, err, sslcom_ret);

            // trigger write again
            master()->poller.modify(_fd, EPOLLIN | EPOLLOUT);
            sslcom_write_blocked_on_write=1;

            if (sslcom_ret > 0) {
                normalized__n = normalized__n - sslcom_ret;
                ptr = static_cast<uint8_t*>(ptr) + sslcom_ret;
            } else {
                _dum("SSLCom::write[%d]: want write: repeating last operation", _fd);
            }

            counters.write_want_write_cur++;
            counters.prof_want_write_cnt++;

            // Retry only after the socket becomes writable.
            set_write_monitor(socket());

            apply_error_timer = true;
            break;

            /* We get a WANT_READ if we're
                    trying to rehandshake and we block on
                    write during the current connection.

                    We need to wait on the socket to be readable
                    but reinitiate our write when it is */
        case SSL_ERROR_WANT_READ:
            _dia("SSLCom::write[%d]: want read: %d (written %4d)", _fd, err, sslcom_ret);

            sslcom_write_blocked_on_read=1;
            forced_write_on_read(true);

            counters.write_want_read_cur++;
            counters.prof_want_read_cnt++;

            // Retry the write when the socket becomes readable.
            set_monitor(socket());


            apply_error_timer = true;
            break;

        case SSL_ERROR_ZERO_RETURN:
            _dia("SSLCom::write[%d]: TLS close_notify while writing", _fd);
            error(ERROR_WRITE);
            return -1;

        case SSL_ERROR_SYSCALL:
        case SSL_ERROR_SSL:
            _dia("SSLCom::write[%d]: fatal TLS write error: %d", _fd, err);
            sslcom_fatal = true;
            error(ERROR_WRITE);
            return -1;

        /* Some other error */
        default:
            _deb("SSLCom::write[%d]: problem: %d", _fd, err);
            apply_error_timer = true;


    }
    
    if(apply_error_timer && timeval_msdelta_now(&timer_write_timeout) > SSLCOM_WRITE_TIMEOUT) {
        _err("SSLCom::write[%d]: write timeout, closing.", _fd);
        error(ERROR_WRITE);
        is_problem = true;
    }    

    if (is_problem) {
        return 0;
    }

    _deb("SSLCom::write[%d]: %4d bytes written", _fd, sslcom_ret);
    return sslcom_ret;
}

#pragma GCC diagnostic pop

template <class L4Proto>
void baseSSLCom<L4Proto>::cleanup()  {

    _dia("  prof_accept %d, prof_connect %d, prof_peek %d, prof_read %d, prof_want_read %d, prof_want_write %d, prof_write %d",
         counters.prof_accept_cnt   , counters.prof_connect_cnt   , counters.prof_peek_cnt   , counters.prof_read_cnt   ,
         counters.prof_want_read_cnt   , counters.prof_want_write_cnt   , counters.prof_write_cnt);
    _dia("   prof_accept_ok %d, prof_connect_ok %d", counters.prof_accept_ok, counters.prof_connect_ok);

    if(sslcom_ssl) {

        if (not sslcom_waiting and not sslcom_fatal) {

            bool const sent_already = SSL_get_shutdown(sslcom_ssl) & SSL_SENT_SHUTDOWN;

            if (not sent_already) {

                int last_status = SSL_get_error(sslcom_ssl, sslcom_ret);

                if(last_status != SSL_ERROR_SSL and last_status != SSL_ERROR_SYSCALL) {
                    int shit = SSL_shutdown(sslcom_ssl);  //_sh_utdown _it_
                    if (shit == 0) {
                        _deb("  shutdown success");
                    } else if (shit < 0) {
                        _err("  shutdown failed: %d", SSL_get_error(sslcom_ssl, shit));
                    }
                } else {
                    _not("  shutdown not called on this error");
                }
            } else {
                _not("  shutdown already sent");
            }
        }

        if (sslcom_ssl) {
            SSL_free(sslcom_ssl);
            sslcom_ssl = nullptr;
        }
    }

    L4Proto::cleanup();
}

template <class L4Proto>
int baseSSLCom<L4Proto>::upgrade_client_socket(int sock) {

    socket(sock);

    bool ch = waiting_peer_hello();

    if(ch) {

        if(opt.bypass) {
            _dia("SSLCom::upgrade_client_socket[%d]: bypassed",sock);
            return sock;
        }


        init_client();

        if(sslcom_ssl == nullptr) {
            _err("SSLCom::upgrade_client_socket[%d]: failed to create SSL structure!",sock);
            return -1;
        }

        if(not sslcom_sni_.empty()) {
            _dia("SSLCom::upgrade_client_socket[%d]: set sni extension to: %s", sock, sslcom_sni_.c_str());
            SSL_set_tlsext_host_name(sslcom_ssl, sslcom_sni_.c_str());
        }

        if(not opt.alpn_block and not sslcom_peer_hello_alpn_.empty()) {
            _dia("SSLCom::upgrade_client_socket[%d]: set alpn extension to: %s",sock,
                 hex_print(sslcom_peer_hello_alpn_.data(), sslcom_peer_hello_alpn_.size()).c_str());

            SSL_set_alpn_protos(sslcom_ssl, reinterpret_cast<unsigned char*>(sslcom_peer_hello_alpn_.data()), sslcom_peer_hello_alpn_.size());
        }

        sslcom_sbio = BIO_new_socket(sock,BIO_NOCLOSE);
        if (sslcom_sbio == nullptr) {
            _err("SSLCom::upgrade_client_socket[%d]: BIO allocation failed! ",sock);
        }

        SSL_set_bio(sslcom_ssl,sslcom_sbio,sslcom_sbio);

        ERR_clear_error();
        sslcom_ret = SSL_connect(sslcom_ssl);
        counters.prof_connect_cnt++;

        if (sslcom_ret > 0) {
            sslcom_op_state = sslcom_op_state_t::READY;
        }
        else {
            if(is_blocking(sock)) {
                _err("SSL connect error on blocking socket %d",sock);
                close(sock);
                return -1;
            }
            /* non-blocking may return -1 */

            if (sslcom_ret == -1) {
                int err = SSL_get_error(sslcom_ssl, sslcom_ret);
                if (err == SSL_ERROR_WANT_WRITE) {
                    _dia("upgrade_client_socket[%d]: SSL_connect: pending on want_write",sock);
                    
                    // interested in WRITE, so ignore read events
                    set_write_monitor_only(socket());
                    
                    // since connect is not immediate, ignore all read events of the peer causing busy loop
                    unmonitor_peer();
                   
                }
                else if(err == SSL_ERROR_WANT_READ) {
                    _dia("upgrade_client_socket[%d]: SSL_connect: pending on want_read",sock);

                    // connect() completion may have left this socket monitored
                    // only for writes.  Without restoring read interest here,
                    // a ServerHello, alert or EOF can arrive without another
                    // event and leave the client-facing handshake suspended.
                    change_monitor(socket(), EPOLLIN);
                    // EPOLLET may already have delivered the EOF/data edge
                    // before the mask change. Queue exactly one retry to
                    // observe the current socket state.
                    rescan_read(socket());

                    // since connect is not immediate, ignore all read events of the peer causing busy loop
                    unmonitor_peer();
                }
                else {
                    _err("upgrade_client_socket[%d]: initial SSL_connect failed: %d", sock, err);
                    if (err == SSL_ERROR_SSL || err == SSL_ERROR_SYSCALL)
                        sslcom_fatal = true;
                    error(ERROR_UNSPEC);
                    sslcom_waiting = false;
                    return -1;
                }
                sslcom_waiting = true;
                return sock;
            }
            _err("upgrade_client_socket[%d]: initial SSL_connect returned %d", sock, sslcom_ret);
            error(ERROR_UNSPEC);
            sslcom_waiting = false;
            return -1;
        }

        counters.prof_connect_ok++;

        _deb("SSLCom::upgrade_client_socket[%d]: connection succeeded",sock);
        sslcom_waiting = false;
        
        // restore peer monitoring
        monitor_peer();
        store_session_if_needed();

        if (not check_cert(nullptr)) {
            _err("SSLCom::upgrade_client_socket[%d]: peer certificate/counterpart setup failed", sock);
            error(ERROR_UNSPEC);
            sslcom_waiting = false;
            return -1;
        }

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

    _dia("SSLCom::connect[%d]: %s connected",sock,L4Proto::c_type());
    sock = upgrade_client_socket(sock);

    if(upgraded()) {
        _dia("SSLCom::connect[%d]: socket upgraded at 1st attempt!",sock);
    }

    return sock;
}


template <class L4Proto>
bool baseSSLCom<L4Proto>::com_status() {
    if(L4Proto::com_status()) {
        if(opt.bypass) {
            _dia("SSLCom::com_status: L4 OK, bypassed");
            return true;
        }

        bool l5_status = sslcom_status();

        if(l5_status) {
            if(! is_server()) {
                _war("SSLCom::com_status: L4 and SSL layers OK - client: target cert: %d, issuer: %d", (target_cert() != nullptr), (target_issuer() != nullptr));
                if( target_cert() || target_issuer() ) {
                    _war("SSLCom::com_status: L4 and SSL layers OK - verify status: 0x%04x", verify_get());
                }

                if(verify_bitcheck(verify_status_t::VRF_NOTTESTED)) {
                    _war("SSLCom::com_status: not yet verified");

                    return false;
                }
            }
            else {
                _war("SSLCom::com_status: L4 and SSL layers OK - server", (target_cert() != nullptr), (target_issuer() != nullptr));
            }
        } else {
            _deb("SSLCom::com_status: L4 OK, but SSL layer not ready.");
        }

        _deb("SSLCom::com_status: returning %d", l5_status);
        return l5_status;
    }

    _deb("SSLCom::com_status: L4 layer not ready, returning 0");
    return false;
}

template <class L4Proto>
void baseSSLCom<L4Proto>::shutdown(int _fd) {
    
    if(sslcom_ssl != nullptr and not sslcom_fatal) {
        SSL_shutdown(sslcom_ssl);
    }
    L4Proto::shutdown(_fd);
}


#endif // SSLCOM_INCL
