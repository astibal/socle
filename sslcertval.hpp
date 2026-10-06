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

#ifndef SSLCERTVAL_HTTP
#define SSLCERTVAL_HTTP

#include <sys/time.h>
#include <openssl/conf.h>
#include <openssl/ocsp.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/crypto.h>
#include <openssl/ocsp.h>
#include <openssl/pem.h>

#include <string>
#include <vector>
#include <buffer.hpp>
#include <epoll.hpp>

namespace inet {

    namespace cert {


        // yet another smart pointer

        template <class T, class Deleter = std::default_delete<T>>
        struct finger {
            explicit finger(T* x, Deleter d) : p_(x), deletor(d) {};
//            finger(finger &&rr) {
//                this->p_ = rr.p_;
//                rr.p_ = nullptr;
//            }


            finger(finger const& r) = delete;
            finger& operator=(finger const&) = delete;

//            finger& operator=(finger&& rr) noexcept {
//                this->p_ = rr.p_;
//                rr.p_ = nullptr;
//            }

            operator T*() const { return p_; };
            T* operator->() const { return p_; };

            explicit operator bool() const { return p_ != nullptr; };

            T* get() const { return p_; }
            T* release() { T* r = p_; p_ = nullptr; return r; }
            void assign(T* p) { if(p_) deletor(p_); p_ = p; };

            virtual ~finger() { if(p_) deletor(p_); }

        private:
            T* p_ = nullptr;
            Deleter deletor;
        };

        typedef finger<X509, decltype(&X509_free)> px509;

        struct VerifyStatus {

            enum class status_origin { OCSP, CRL } ;

            VerifyStatus() : revoked(-1), ttl(600), origin(status_origin::OCSP) {};
            VerifyStatus(int revoked, int ttl, status_origin orig): revoked(revoked), ttl(ttl), origin(orig) {};

            int revoked = -1;
            int ttl = 600;

            status_origin origin = status_origin::OCSP;
        };

    }

    namespace ocsp {

        struct OcspFactory {
            static logan_lite& log() {
                static logan_lite l = logan_lite("com.ssl.ocsp");
                return l;
            }
        };


        std::vector<std::string> ocsp_urls (X509 *x509);

        int ocsp_prepare_request (OCSP_REQUEST **req, X509 *cert, const EVP_MD *cert_id_md, X509 *issuer,
                                  STACK_OF(OCSP_CERTID) *ids);

        OCSP_RESPONSE *
        ocsp_query_responder (BIO *err, BIO *cbio, char *path, char *host, OCSP_REQUEST *req, int req_timeout);

        OCSP_RESPONSE *
        ocsp_send_request (BIO *err, OCSP_REQUEST *req, char *host, char *path, char *port, int use_ssl,
                           int req_timeout);

        inet::cert::VerifyStatus ocsp_verify_response(OCSP_RESPONSE *resp, X509* cert, X509* issuer,
                                                      X509_STORE* trust_store = nullptr);

        inet::cert::VerifyStatus ocsp_check_cert (X509 *x509, X509 *issuer, int req_timeout = 2);

        int ocsp_check_bytes (const char cert_bytes[], const char issuer_bytes[]);



    }

    namespace crl {

        struct CrlFactory {
            static logan_lite& log() {
                static logan_lite l = logan_lite("com.ssl.crl");
                return l;
            }
        };

        std::vector<std::string> crl_urls (X509 *x509);
        X509_CRL *crl_from_bytes (const char *cert_bytes);
        X509_CRL *crl_from_bytes (buffer &b);
        X509_CRL *crl_from_file(const char *crl_filename);

        int crl_verify_trust (X509 *x509, X509 *issuer, X509_CRL *crl_file, const std::string &cacerts_pem_path);
        int crl_is_revoked_by (X509 *x509, X509 *issuer, X509_CRL *crl_file);
    }
}

#endif
