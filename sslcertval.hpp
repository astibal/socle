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

        inet::cert::VerifyStatus ocsp_verify_response(OCSP_RESPONSE *resp, X509* cert, X509* issuer);

        inet::cert::VerifyStatus ocsp_check_cert (X509 *x509, X509 *issuer, int req_timeout = 2);

        int ocsp_check_bytes (const char cert_bytes[], const char issuer_bytes[]);


/*
 * Non-blocking, stateful OCSP responder
 *
 * */

        class OcspQuery {

            using x509ptr = inet::cert::finger<X509, decltype(&X509_free)>;

            // socket state structure used together with event_handlers
            socket_state socket;

            // OCSP connection BIO
            BIO *conn_bio = nullptr;

            // certificate and issuer to check
            x509ptr cert_check;
            x509ptr cert_issuer;

            // reference ID (time being it's a OID of owning object)
            uint64_t ref_id;


            // OCSP request structures
            OCSP_REQUEST *ocsp_req = nullptr;
            STACK_OF(OCSP_CERTID) *ocsp_req_ids = nullptr;

            // OCSP response structures
            OCSP_REQ_CTX *ocsp_req_ctx = nullptr;
            OCSP_RESPONSE *ocsp_resp = nullptr;


            // list of OCSP servers destilled from certificate - tuples<host, port, path, ssl>
            std::vector<std::tuple<std::string, std::string, std::string, bool>> ocsp_targets;

            // currently used ocsp_target index
            int ocsp_target_index = -1;

            // currently used OCSP server (full list in tuple vector 'ocsp_targes').
            std::string ocsp_host;
            std::string ocsp_port;
            std::string ocsp_path;
            bool ocsp_ssl = false;

        public:

            // state machine ... states
            enum state_t{
                ST_INIT = 1000, ST_CONNECTING, ST_CONNECTED, ST_REQ_INPROGRESS, ST_REQ_SENT, ST_RESP_RECEIVED, ST_FINISHED, ST_CLOSED
            };

            [[nodiscard]] static const char* state_str(int s) {
                switch(s) {
                    case ST_INIT:
                        return "ST_INIT";
                    case ST_CONNECTING:
                        return "ST_CONNECTING";
                    case ST_CONNECTED:
                        return "ST_CONNECTED";
                    case ST_REQ_INPROGRESS:
                        return "ST_REQ_INPROGRESS";
                    case ST_REQ_SENT:
                        return "ST_REQ_SENT";
                    case ST_RESP_RECEIVED:
                        return  "ST_RESP_RECEIVED";
                    case ST_FINISHED:
                        return "ST_FINISHED";
                    case ST_CLOSED:
                        return "ST_CLOSED";
                    default:
                        return "<?>";
                }
            }

            //
            enum yield_t {
                RET_CONNFAIL = -127,
                RET_UNKNOWN = -1,
                RET_REVOKED = 0,
                RET_VALID = 1,
                RET_UNKNOWNSTATUS = 2,
                RET_NOOCSP_TARGETS
            };

            [[nodiscard]] static const char* yield_str(int y)  {
                switch(y) {
                    case RET_CONNFAIL:
                        return "RET_CONNFAIL";
                    case RET_UNKNOWN:
                        return "RET_UNKNOWN";
                    case RET_REVOKED:
                        return "RET_REVOKED";
                    case RET_VALID:
                        return "RET_VALID";
                    case RET_UNKNOWNSTATUS:
                        return "RET_UNKNOWNSTATUS";
                    case RET_NOOCSP_TARGETS:
                        return "RET_NOOCSP_TARGETS";
                    default:
                        return "<?>";
                }
            }

            [[nodiscard]] inline const socket_state &io () const { return socket; }
            inline socket_state &io () { return socket; }

            OcspQuery(X509 *cert, X509 *issuer, uint64_t ref_id):
              cert_check(X509_dup(cert), &X509_free),
              cert_issuer(X509_dup(issuer), &X509_free),
              ref_id(ref_id) {
                timer_ = time(nullptr);
            };


            // parse cert and find useful fields -> copy to internal structures
            void parse_cert ();

            // non-blocking run, until returns false
            bool run ();

            virtual ~OcspQuery ();


            // functions called in run() state machine
            // return status if successful. False means usually you should check yield_ and state_ and re-run if needed.

            // initialize
            bool do_init ();


            time_t timer_;


            bool do_prepare_target();

            int timeout_connect = 2;
            // connect to responder -- Might be called multiple times if needed or if the operation would block.
            bool do_connect ();

            // send request -- Might be called multiple times if needed or if the operation would block.
            bool do_send_request ();

            int timeout_request = 5;
            // process received response
            bool do_process_response ();

            [[nodiscard]] int state() const { return state_; }
            [[nodiscard]] const char* state_str() const { return state_str(state_); };

            [[nodiscard]] int yield() const { return yield_; };
            [[nodiscard]] const char*yield_str() const { return yield_str(yield_); }

        private:
            int state_ = OcspQuery::ST_INIT;
            int yield_ = RET_UNKNOWN;
        };

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