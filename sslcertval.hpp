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

        struct OcspResult {
            // -1 for unknown
            //  0 valid
            //  1 revoked
            int is_revoked = -1;
            int ttl = 0;
        };
        OcspResult ocsp_verify_response(OCSP_RESPONSE *resp, X509* issuer);

        int ocsp_check_cert (X509 *x509, X509 *issuer, int req_timeout = 2);

        int ocsp_check_bytes (const char cert_bytes[], const char issuer_bytes[]);


/*
 * Non-blocking, stateful OCSP responder
 *
 * */
        class OcspQuery {

            // socket state structure used together with event_handlers
            socket_state socket;

            // OCSP connection BIO
            BIO *conn_bio = nullptr;

            // certificate and issuer to check
            X509 *cert_check = nullptr;
            X509 *cert_issuer = nullptr;


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

            // if retry flag is set, already created connection bio will be used to establish connection
            bool ocsp_target_retry = false;

            // currently used OCSP server (full list in tuple vector 'ocsp_targes').
            std::string ocsp_host;
            std::string ocsp_port;
            std::string ocsp_path;
            bool ocsp_ssl = false;

        public:

            // state machine ... states
            enum state_t{
                ST_INIT = 1000, ST_CONNECTING, ST_CONNECTED, ST_REQ_INPROGRESS, ST_RESP_RECEIVED, ST_FINISHED, ST_CLOSED
            } ;

            //
            enum yield_t {
                RET_CONNFAIL = -127,
                RET_UNKNOWN = -1,
                RET_REVOKED = 0,
                RET_VALID = 1,
                RET_UNKNOWNSTATUS = 2,
                RET_NOOCSP_TARGETS
            } ;

            inline const socket_state &io () const { return socket; }

            OcspQuery (X509 *cert, X509 *issuer) : cert_check(cert), cert_issuer(issuer) {};

            // parse cert and find useful fields -> copy to internal structures
            void parse_cert ();

            // non-blocking run, until returns false
            bool run ();

            virtual ~OcspQuery ();


            // functions called in run() state machine
            // return status if successful. False means usually you should check yield_ and state_ and re-run if needed.

            // initialize
            bool do_init ();


            // connect to responder -- Might be called multiple times if needed or if the operation would block.
            bool do_connect ();

            // send request -- Might be called multiple times if needed or if the operation would block.
            bool do_send_request ();

            // proces received response
            bool do_process_response ();

        private:
            int state_ = OcspQuery::ST_INIT;
            int yield_ = RET_UNKNOWN;
        };

    }

    namespace crl {
        std::vector<std::string> crl_urls (X509 *x509);
        X509_CRL *crl_from_bytes (const char *cert_bytes);
        X509_CRL *crl_from_bytes (buffer &b);
        X509_CRL *crl_from_file(const char *crl_filename);

        int crl_verify_trust (X509 *x509, X509 *issuer, X509_CRL *crl_file, const std::string &cacerts_pem_path);
        int crl_is_revoked_by (X509 *x509, X509 *issuer, X509_CRL *crl_file);
    }
}

#endif