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

#include <sslcertval.hpp>
#include <display.hpp>

#include <sslcertstore.hpp>
#include <log/logger.hpp>
#include <buffer.hpp>
#include <biostring.hpp>
#include <socle.hpp>

namespace inet {

    namespace crl {

        int crl_is_revoked_by (X509 *x509, X509 *issuer, X509_CRL *crl_file) {

            auto log = CrlFactory::log();

            int is_revoked = -1;
            if (issuer) {
                EVP_PKEY *ikey = X509_get_pubkey(issuer); // must be freed
                [[maybe_unused]] ASN1_INTEGER *serial = X509_get_serialNumber(x509); // must not be freed

                if (crl_file && ikey) {
                    if (X509_CRL_verify(crl_file, ikey)) {

                        _deb("X509_CRL_verify ok");
                        is_revoked = 0;

#ifdef USE_OPENSSL11
                        //const STACK_OF(X509_REVOKED) *revoked_list = X509_CRL_get_REVOKED(crl_file);

                        const ASN1_INTEGER *mycertser = X509_get0_serialNumber(x509);
                        X509_REVOKED *myentry = nullptr;

                        //retype mycertser to non-const (not modified by function call - based on API doc promise ... :/ )

                        if (X509_CRL_get0_by_serial(crl_file, &myentry, const_cast<ASN1_INTEGER*> (mycertser)) > 0 && myentry) {
                            const ASN1_TIME *tm = X509_REVOKED_get0_revocationDate(myentry);

                            std::string revocation_date;
                            BIO *myb = BIO_new_string(&revocation_date);

                            _dia("certificate revoked: %s", revocation_date.c_str());

                            ASN1_TIME_print(myb, tm);
                            BIO_free(myb);
                        }


#else
                        STACK_OF(X509_REVOKED) *revoked_list = crl_file->crl->revoked;

                        for (int j = 0; j < sk_X509_REVOKED_num(revoked_list) && !is_revoked; j++)
                        {
                            X509_REVOKED *entry = sk_X509_REVOKED_value(revoked_list, j);
                            if (entry->serialNumber->length==serial->length)
                            {
                                if (memcmp(entry->serialNumber->data, serial->data, serial->length)==0)
                                {
                                    is_revoked=1;
                                }
                            }
                        }
#endif
                    }
                }

                if (ikey) EVP_PKEY_free(ikey);
            }
            return is_revoked;
        }


        int crl_verify_trust (X509 *x509, X509 *issuer, X509_CRL *crl_file, const std::string &cacerts_pem_path) {

            auto log = CrlFactory::log();

            STACK_OF (X509) *chain = sk_X509_new_null();
            sk_X509_push(chain, issuer);

            X509_STORE *store = X509_STORE_new();
            if (! store) {
                _err("crl_verify_trust: X509_STORE_new failed");

                sk_X509_free(chain);
                return 0;
            }
            X509_STORE_set_default_paths(store);


            // single-use lookup store
            X509_STORE_CTX *csc = X509_STORE_CTX_new();

            int verify_result = 0;
            if (csc) {
                X509_STORE_CTX_init(csc, store, x509, chain);
                X509_STORE_CTX_set_purpose(csc, X509_PURPOSE_SSL_SERVER);

                X509_STORE_add_crl(store, crl_file);
                X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK);

                verify_result = X509_verify_cert(csc);
                if (verify_result != 1) {
                    _dia("crl_verify_trust: %s", X509_verify_cert_error_string(X509_STORE_CTX_get_error(csc)));
                }

                X509_STORE_CTX_cleanup(csc);
                X509_STORE_CTX_free(csc);
            }

            if (store) X509_STORE_free(store);
            if (chain) sk_X509_free(chain);

            return verify_result;
        }


        std::vector<std::string> crl_urls (X509 *x509) {
            std::vector<std::string> list;
            int nid = NID_crl_distribution_points;
            STACK_OF(DIST_POINT) *dist_points = (STACK_OF(DIST_POINT) *) X509_get_ext_d2i(x509, nid, nullptr, nullptr);
            for (int j = 0; j < sk_DIST_POINT_num(dist_points); j++) {
                DIST_POINT *dp = sk_DIST_POINT_value(dist_points, j);
                DIST_POINT_NAME *distpoint = dp->distpoint;
                if (distpoint->type == 0)//fullname GENERALIZEDNAME
                {
                    for (int k = 0; k < sk_GENERAL_NAME_num(distpoint->name.fullname); k++) {
                        GENERAL_NAME *gen = sk_GENERAL_NAME_value(distpoint->name.fullname, k);
                        ASN1_IA5STRING *asn1_str = gen->d.uniformResourceIdentifier;
#ifdef USE_OPENSSL11
                        list.emplace_back(
                                std::string((char *) ASN1_STRING_get0_data(asn1_str), ASN1_STRING_length(asn1_str)));
#else
                        list.push_back( std::string( (char*)ASN1_STRING_data(asn1_str), ASN1_STRING_length(asn1_str) ) );
#endif
                    }
                } else if (distpoint->type == 1)//relativename X509NAME
                {
                    STACK_OF(X509_NAME_ENTRY) *sk_relname = distpoint->name.relativename;
                    for (int k = 0; k < sk_X509_NAME_ENTRY_num(sk_relname); k++) {
                        X509_NAME_ENTRY *e = sk_X509_NAME_ENTRY_value(sk_relname, k);
                        ASN1_STRING *d = X509_NAME_ENTRY_get_data(e);
#ifdef USE_OPENSSL11
                        list.emplace_back(std::string((char *) ASN1_STRING_get0_data(d), ASN1_STRING_length(d)));
#else
                        list.push_back( std::string( (char*)ASN1_STRING_data(d), ASN1_STRING_length(d) ) );
#endif
                    }
                }
            }

            CRL_DIST_POINTS_free(dist_points);

            return list;
        }


        X509* cert_from_bytes(const char *cert_bytes) {
            BIO *bio_mem = BIO_new(BIO_s_mem());
            BIO_puts(bio_mem, cert_bytes);
            X509 *x509 = PEM_read_bio_X509(bio_mem, nullptr, nullptr, nullptr);
            BIO_free(bio_mem);
            return x509;
        }

        X509_CRL* crl_from_bytes(const char *cert_bytes) {


            BIO *bio_mem = BIO_new(BIO_s_mem());
            BIO_puts(bio_mem, cert_bytes);
            X509_CRL *crl = d2i_X509_CRL_bio(bio_mem, nullptr);
            BIO_free(bio_mem);
            return crl;
        }

        X509_CRL *crl_from_bytes(buffer &b) {

            auto log = CrlFactory::log();
            _dum("crl_from_bytes: \n%s", hex_dump(b).c_str());

            BIO *bio_mem = BIO_new(BIO_s_mem());
            BIO_write(bio_mem, b.data(), b.size());

            X509_CRL *crl = d2i_X509_CRL_bio(bio_mem, nullptr);

            BIO_free(bio_mem);
            return crl;
        }

        X509_CRL *crl_from_file(const char *crl_filename) {
            BIO *bio = BIO_new_file(crl_filename, "r");
            X509_CRL *crl = d2i_X509_CRL_bio(bio,
                                             nullptr); //if (format == FORMAT_PEM) crl=PEM_read_bio_X509_CRL(in,nullptr,nullptr,nullptr);
            BIO_free(bio);
            return crl;
        }
    }

    namespace ocsp {

        std::vector<std::string> ocsp_urls (X509 *x509) {
            STACK_OF(OPENSSL_STRING) *ocsp_list = X509_get1_ocsp(x509);
            std::size_t ocsp_list_len = sk_OPENSSL_STRING_num(ocsp_list);

            std::vector<std::string> list(ocsp_list_len);
            for (int j = 0; j < sk_OPENSSL_STRING_num(ocsp_list); j++) {

                list.emplace_back(std::string(sk_OPENSSL_STRING_value(ocsp_list, j)));
            }
            X509_email_free(ocsp_list);
            return list;
        }


        int ocsp_prepare_request (OCSP_REQUEST **req, X509 *cert, const EVP_MD *cert_id_md, X509 *issuer,
                                  STACK_OF(OCSP_CERTID) *ids) {

            auto log = OcspFactory::log();

            OCSP_CERTID *id;
            if (!issuer) {

                _err("ocsp_prepare_request: No issuer certificate specified");
                return 0;
            }

            if (!*req)
                *req = OCSP_REQUEST_new();

            if (!*req)
                goto err;

            id = OCSP_cert_to_id(cert_id_md, cert, issuer);

            if (!id || !sk_OCSP_CERTID_push(ids, id))
                goto err;

            if (!OCSP_request_add0_id(*req, id))
                goto err;

            return 1;

            err:
            _err("ocsp_prepare_request: Error Creating OCSP request");

            return 0;
        }


        OCSP_RESPONSE *ocsp_query_responder (BIO *err, BIO *cbio, char *path,
                                             char *host, OCSP_REQUEST *req, int req_timeout) {
            int fd;
            int rv;
            OCSP_REQ_CTX *ctx = nullptr;
            OCSP_RESPONSE *rsp = nullptr;

            auto log = OcspFactory::log();

            if (req_timeout != -1)
                BIO_set_nbio(cbio, 1);

            rv = BIO_do_connect(cbio);

            if ((rv <= 0) && ((req_timeout == -1) || !BIO_should_retry(cbio))) {

                _err("ocsp_query_responder: Error connecting BIO");
                return nullptr;
            }

            epoll epoller;
            if ( epoller.init() <= 0) {
                _err("ocsp_query_responder: Can't initialize epoll");
                goto err;
            }

            if (BIO_get_fd(cbio, &fd) <= 0) {
                _err("ocsp_query_responder: Can't get connection fd");
                goto err;
            }

            epoller.add(fd, EPOLLOUT);

            if (req_timeout != -1 && rv <= 0) {


                int nfds = epoller.wait(req_timeout*1000);

                if (nfds == 0) {

                    _err("ocsp_query_responder: Timeout on connect");

                    //BIO_puts(err, "Timeout on connect\n");
                    return nullptr;
                }
            }

            ctx = OCSP_sendreq_new(cbio, path, nullptr, -1);
            if (!ctx)
                return nullptr;

            if (!OCSP_REQ_CTX_add1_header(ctx, "Host", host))
                goto err;

            if (!OCSP_REQ_CTX_set1_req(ctx, req))
                goto err;

            for (;;) {

                rv = OCSP_sendreq_nbio(&rsp, ctx);
                if (rv != -1)
                    break;
                if (req_timeout == -1)
                    continue;

                if (BIO_should_read(cbio)) {

                    epoller.modify(fd, EPOLLIN);

                    _deb("ocsp_query_responder: epoll - wait for reading");
                    rv = epoller.wait(req_timeout*1000);
                } else if (BIO_should_write(cbio)) {

                    epoller.modify(fd, EPOLLOUT);
                    _deb("ocsp_query_responder: epoll - wait for writing");
                    rv = epoller.wait(req_timeout*1000);
                } else {
                    _war("ocsp_query_responder: unexpected retry condition");
                    goto err;
                }


                if (rv == 0) {
                    _err("ocsp_query_responder: timeout on request");
                    break;
                } else if (rv == -1) {
                    _err("ocsp_query_responder: epoll error: %s", string_error().c_str());
                    break;
                } else {
                    _deb("ocsp_query_responder: epoll ok - returned %d", rv);
                }
            }

            err:

            if (ctx)
                OCSP_REQ_CTX_free(ctx);

            return rsp;
        }

        OCSP_RESPONSE *ocsp_send_request (BIO *err, OCSP_REQUEST *req,
                                          char *host, char *path, char *port, int use_ssl,
                                          int req_timeout) {
            BIO *cbio = nullptr;
            OCSP_RESPONSE *resp = nullptr;
            cbio = BIO_new_connect(host);

            auto log = OcspFactory::log();

            if (cbio && use_ssl == 0) {
                if(port) {
                    BIO_set_conn_port(cbio, port);
                }

                resp = ocsp_query_responder(err, cbio, path, host, req, req_timeout);
                if (!resp) {
                    auto xhost = host ? host : "?";
                    auto xport = port ? port : "?";
                    auto xpath = path ? path : "?";

                    _dia("ocsp_send_request: Error querying OCSP responder: %s:%s/%s", xhost, xport, xpath);
                }
            }
            if (cbio)
                BIO_free_all(cbio);
            return resp;
        }

        inet::cert::VerifyStatus ocsp_verify_response(OCSP_RESPONSE *resp, X509* cert, X509* issuer) {

            using namespace inet::cert;

            int is_revoked = -1;
            int ttl = 60;

            auto log = OcspFactory::log();

#ifdef USE_OPENSSL11

            OCSP_BASICRESP *br = OCSP_response_get1_basic(resp);

            if(br) {

                X509_STORE *st = X509_STORE_new();
                X509_STORE_set_default_paths(st);

                STACK_OF(X509*) signers = sk_X509_new_null();
                sk_X509_push(signers, issuer);

                // @certs - untrusted intermediates
                // @st - truststore
                // 1 .. looking for _signer_ in certs and (if !OCSP_NOINTERN) in OCSP response (therefore untrusted sources)
                //   .. fails if cannot be found!
                // 2 ..
                int ocsp_verify_result = OCSP_basic_verify(br, signers, st, 0);

                _dia("ocsp_verify_response: OCSP_basic_verify returned %d", ocsp_verify_result);

                if (ocsp_verify_result <= 0) {
                    is_revoked = -1;

                    int err = static_cast<int>(ERR_get_error());
                    _dia("    error: %s",ERR_error_string(err,nullptr));

                } else {

                    bool matching_ids = false;

                    int resp_count = OCSP_resp_count(br);
                    _deb("ocsp_verify_response: got %d entries in response", resp_count);
                    for (int i = 0; i < resp_count; i++) {
                        OCSP_SINGLERESP *single = OCSP_resp_get0(br, i);
                        int reason;
                        ASN1_GENERALIZEDTIME *revtime;
                        ASN1_GENERALIZEDTIME *thisupd;
                        ASN1_GENERALIZEDTIME *nextupd;

                        int status = OCSP_single_get0_status(single, &reason, &revtime, &thisupd, &nextupd);

                        const OCSP_CERTID* id = OCSP_SINGLERESP_get0_id(single);
                        ASN1_OCTET_STRING* name_hash;
                        ASN1_OCTET_STRING* key_hash;
                        ASN1_OBJECT* pmd;
                        ASN1_INTEGER* serial;

                        // get shallow details from CERTID
                        OCSP_id_get0_info(&name_hash, &pmd, &key_hash, &serial, const_cast<OCSP_CERTID*>(id));

                        // now we can create cert ID and compare it to one from OCSP response

                        const EVP_MD* md = EVP_get_digestbyobj(const_cast<const ASN1_OBJECT*>(pmd));
                        OCSP_CERTID* my_id = OCSP_cert_to_id(md , cert , issuer);

                        // match certificate ID in response with checked cert (to prevent replays of correct OCSP responses
                        // but for different cert
                        if (OCSP_id_cmp(const_cast<OCSP_CERTID*>(id), my_id) == 0) {
                            _dia("ocsp_verify_response [%d]: certificate ID matching this single", i);
                            matching_ids = true;
                        } else {
                            _dia("ocsp_verify_response [%d]: certificate ID NOT MATCHING this single", i);
                        }
                        // don't forget to free mycert CERTID
                        OCSP_CERTID_free(my_id);
                        my_id = nullptr;

                        if(! matching_ids) {
                            continue;
                        }

                        std::string s_name_hash = SSLFactory::print_ASN1_OCTET_STRING(name_hash);

                        _dia("ocsp_verify_response [%d]: response for name hash: %s", i, s_name_hash.c_str());

                        if (status == V_OCSP_CERTSTATUS_REVOKED) {
                            _dia("ocsp_verify_response [%d]: OCSP_single_get0_status returned REVOKED(%d)", i, status);
                            is_revoked = 1;
                            //break;
                        } else if (status == V_OCSP_CERTSTATUS_GOOD) {
                            _dia("ocsp_verify_response [%d]: OCSP_single_get0_status returned GOOD(%d)", i, status);
                            is_revoked = 0;
                            //break;
                        } else if (status == V_OCSP_CERTSTATUS_UNKNOWN) {
                            _dia("ocsp_verify_response [%d]: OCSP_single_get0_status returned UNKNOWN(%d)", i, status);
                        } else {
                            _dia("ocsp_verify_response [%d]: OCSP_single_get0_status returned ?(%d)", i, status);
                        }

                        int days = 0;
                        int secs = 0;
                        if (ASN1_TIME_diff( &days, &secs, nullptr, nextupd) > 0) {
                            _dia("ocsp_verify_response [%d]: TTL: %d days, %d seconds", i, days, secs);

                            ttl = days*24*60*60 + secs;

                        } else {
                            _war("ocsp_verify_response [%d]: negative TTL: %d days, %d seconds", i, days, secs);
                            _err("this is possible OCSP replay attack, marked as revoked!");
                            is_revoked = 1;
                        }
                    }

                    if(! matching_ids) {
                        _err("no matching cert IDs were found in OCSP response, returning -1");
                        is_revoked = -1;
                    }
                }

                OCSP_BASICRESP_free(br);
                X509_STORE_free(st);
                sk_X509_free(signers);
            } else {
                _err("received data doesn't contain OCSP response");
            }

#else
            OCSP_RESPBYTES *rb = resp->responseBytes;
            if (rb && OBJ_obj2nid(rb->responseType) == NID_id_pkix_OCSP_basic)
            {
                OCSP_BASICRESP *br = OCSP_response_get1_basic(resp);
                if(br) {
                    OCSP_RESPDATA  *rd = br->tbsResponseData;

                    for (int i = 0; i < sk_OCSP_SINGLERESP_num(rd->responses); i++)
                    {
                        OCSP_SINGLERESP *single = sk_OCSP_SINGLERESP_value(rd->responses, i);
                        //OCSP_CERTID *cid = single->certId;
                        OCSP_CERTSTATUS *cst = single->certStatus;
                        if (cst->type == V_OCSP_CERTSTATUS_REVOKED)
                        {
                            is_revoked = 1;
                        }
                        else if (cst->type == V_OCSP_CERTSTATUS_GOOD)
                        {
                            is_revoked = 0;
                        }
                    }
                    OCSP_BASICRESP_free(br);
                }
            }
#endif // USE_OPENSSL11

            _dia("ocsp_verify_response:  returning %d", is_revoked);
            return VerifyStatus(is_revoked, ttl, VerifyStatus::status_origin::OCSP);
        }

        inet::cert::VerifyStatus ocsp_check_cert (X509 *x509, X509 *issuer, int req_timeout) {

            using namespace inet::cert;

            int is_revoked = -1;
            VerifyStatus ret(-1, 60, VerifyStatus::status_origin::OCSP);

            BIO *bio_out = BIO_new_fp(stdout, BIO_NOCLOSE | BIO_FP_TEXT);
            BIO *bio_err = BIO_new_fp(stderr, BIO_NOCLOSE | BIO_FP_TEXT);

            if (issuer) {
                //build ocsp request
                OCSP_REQUEST *req = nullptr;
                //STACK_OF(CONF_VALUE) *headers = nullptr;
                STACK_OF(OCSP_CERTID) *ids = sk_OCSP_CERTID_new_null();
                const EVP_MD *cert_id_md = EVP_sha1();
                ocsp_prepare_request(&req, x509, cert_id_md, issuer, ids);

                //loop through OCSP urls
                STACK_OF(OPENSSL_STRING) *ocsp_list = X509_get1_ocsp(x509);
                for (int j = 0; j < sk_OPENSSL_STRING_num(ocsp_list) && is_revoked == -1; j++) {
                    char *host = nullptr, *port = nullptr, *path = nullptr;
                    int use_ssl;
                    //std::string ocsp_url0 = std::string( sk_OPENSSL_STRING_value(ocsp_list, j) );

                    char *ocsp_url = sk_OPENSSL_STRING_value(ocsp_list, j);
                    if (OCSP_parse_url(ocsp_url, &host, &port, &path, &use_ssl) && !use_ssl) {
                        //send ocsp request
                        OCSP_RESPONSE *resp = ocsp_send_request(bio_err, req, host, path, port, use_ssl, req_timeout);
                        if (resp) {
                            //see crypto/ocsp/ocsp_prn.c for examples parsing OCSP responses
                            int responder_status = OCSP_response_status(resp);

                            //parse response
                            if (resp && responder_status == OCSP_RESPONSE_STATUS_SUCCESSFUL) {
                                ret = ocsp_verify_response(resp, x509, issuer);
                            }
                            OCSP_RESPONSE_free(resp);
                        }
                    }
                    OPENSSL_free(host);
                    OPENSSL_free(path);
                    OPENSSL_free(port);
                }
                sk_OCSP_CERTID_free(ids);
                X509_email_free(ocsp_list);
                OCSP_REQUEST_free(req);
            }

            BIO_free(bio_out);
            BIO_free(bio_err);
            return ret;
        }


        int ocsp_check_bytes (const char cert_bytes[], const char issuer_bytes[]) {
            BIO *bio_mem1 = BIO_new(BIO_s_mem());
            BIO *bio_mem2 = BIO_new(BIO_s_mem());
            BIO_puts(bio_mem1, cert_bytes);
            BIO_puts(bio_mem2, issuer_bytes);
            X509 *x509 = PEM_read_bio_X509(bio_mem1, nullptr, nullptr, nullptr);
            X509 *issuer = PEM_read_bio_X509(bio_mem2, nullptr, nullptr, nullptr);
            int ret = inet::ocsp::ocsp_check_cert(x509, issuer).revoked;
            BIO_free(bio_mem1);
            BIO_free(bio_mem2);
            X509_free(x509);
            X509_free(issuer);

            return ret;
        }



        OcspQuery::~OcspQuery () {
            if (conn_bio)
                BIO_free_all(conn_bio);

            if (ocsp_req)
                OCSP_REQUEST_free(ocsp_req);

            if (ocsp_req_ids)
                sk_OCSP_CERTID_free(ocsp_req_ids);

            if (ocsp_req_ctx)
                OCSP_REQ_CTX_free(ocsp_req_ctx);

        }

        void OcspQuery::parse_cert () {
            auto& log = OcspFactory::log();

            STACK_OF(OPENSSL_STRING) *ocsp_list = X509_get1_ocsp(cert_check);
            for (int j = 0; j < sk_OPENSSL_STRING_num(ocsp_list); j++) {

                char *host = nullptr;
                char *port = nullptr;
                char *path = nullptr;
                int use_ssl;

                char *ocsp_url = sk_OPENSSL_STRING_value(ocsp_list, j);
                if (OCSP_parse_url(ocsp_url, &host, &port, &path, &use_ssl)) {
                    ocsp_targets.emplace_back(
                            std::tuple<std::string, std::string, std::string, bool>(std::string(host),
                                                                                    std::string(port),
                                                                                    std::string(path),
                                                                                    (use_ssl > 0)));
                    _dia("OcspQuery::parse_cert[0x%lx]: OCSP URL: %s", ref_id, ESC_(ocsp_url).c_str());
                } else {
                    _err("OcspQuery::parse_cert[0x%lx]: failed to parse OCSP URL: %s", ref_id, ESC_(ocsp_url).c_str());
                }
            }

            X509_email_free(ocsp_list);
        }


        bool OcspQuery::do_init () {
            auto& log = OcspFactory::log();

            parse_cert();


            if (ocsp_targets.empty()) {
                _war("OcspQuery::do_init[0x%lx]: no OCSP targets", ref_id);

                state_ = OcspQuery::ST_FINISHED;
                yield_ = OcspQuery::RET_NOOCSP_TARGETS;

                _dia("OcspQuery::do_init[0x%lx]: state ST_FINISHED", ref_id);

                return false;
            }

            //build ocsp request
            ocsp_req_ids = sk_OCSP_CERTID_new_null();
            const EVP_MD *cert_id_md = EVP_sha1();
            ocsp_prepare_request(&ocsp_req, cert_check, cert_id_md, cert_issuer, ocsp_req_ids);

            return true;
        }


        bool OcspQuery::do_prepare_target() {

            auto& log = OcspFactory::log();
            int skip = 0;

            // prepare skipping
            if (ocsp_target_index >= 0) {
                skip = ocsp_target_index;
            }
            //reset index (so it starts at 0 once incremented)
            ocsp_target_index = -1;

            for (const auto &tup: ocsp_targets) {

                // count again the index
                ocsp_target_index++;

                // skip to previous position
                if (skip > 0) {
                    skip--;
                    continue;
                }
                _err("OcspQuery::do_prepare_target[0x%lx]: processing target index %d", ref_id, ocsp_target_index);

                // reset timer for this target
                timer_ = ::time(nullptr);


                // cound be init in previous iteration
                if(conn_bio) {
                    _err("OcspQuery::do_prepare_target[0x%lx]: removing old connection", ref_id);
                    BIO_free(conn_bio);
                }

                // run this only if we are not retrying (initiate conn_bio)

                ocsp_host = std::get<0>(tup);
                ocsp_port = std::get<1>(tup);
                ocsp_path = std::get<2>(tup);
                ocsp_ssl = std::get<3>(tup);

                if(ocsp_ssl) {
                    _err("OcspQuery::do_prepare_target[0x%lx]: OCSP over https is not supported", ref_id);
                    continue;
                }

                std::string host_port = ocsp_host;
                if (!ocsp_port.empty()) {
                    //BIO_set_conn_port(conn_bio, ocsp_port.c_str());
                    host_port += ":" + ocsp_port;
                }
                _dia("OcspQuery::do_prepare_target[0x%lx]: connecting to: %s%s", ref_id, ocsp_host.c_str(), ocsp_path.c_str());
                conn_bio = BIO_new_connect(host_port.c_str());

                if (conn_bio && !ocsp_ssl) {
                    state_ = OcspQuery::ST_CONNECTING;
                    _dia("OcspQuery::do_prepare_target[0x%lx]: state CONNECTING", ref_id);
                    BIO_set_nbio(conn_bio, 1);
                } else {
                    continue;
                }


                break;
            }

            return conn_bio != nullptr;
        }

        bool OcspQuery::do_connect () {

            auto& log = OcspFactory::log();

            if(! conn_bio) {
                if (! do_prepare_target()) {
                    _err("OcspQuery::do_connect[0x%lx]: no ocsp targets %s", ref_id, ocsp_targets.empty() ? "" : "left");
                    state_ = ST_FINISHED;
                    yield_ = RET_NOOCSP_TARGETS;
                    return true; // report finished task
                }
            }

            if (conn_bio) {
                // attempt to connect to this OCSP service
                if (BIO_do_connect(conn_bio) <= 0) {
                    socket.socket_ = BIO_get_fd(conn_bio, nullptr);
                    if(BIO_should_read(conn_bio))
                        socket.mon_read();

                    if(BIO_should_write(conn_bio))
                        socket.mon_write();

                    if (BIO_should_retry(conn_bio)) {

                        if(time(nullptr) - timer_ > timeout_connect) {
                            _dia("OcspQuery::do_connect[0x%lx]: connection timeout: %s/%s", ref_id , ocsp_host.c_str(), ocsp_path.c_str());
                            if(conn_bio) {
                                BIO_free(conn_bio);
                            }

                            // try next target
                            ocsp_target_index++;

                            // reset current connection info
                            conn_bio = nullptr;

                            state_ = ST_CLOSED;
                            yield_ = RET_CONNFAIL;

                        } else {
                            _dia("OcspQuery::do_connect[0x%lx]: retry on socket %d", ref_id, socket.socket_);
                            return false;
                        }
                    }

                } else {

                    // reset timer for response timeout
                    timer_ = time(nullptr);

                    socket.socket_ = BIO_get_fd(conn_bio, nullptr);
                    socket.mon_read();

                    state_ = OcspQuery::ST_CONNECTED;
                    _dia("OcspQuery::do_connect[0x%lx]: state CONNECTED", ref_id);
                }
            }

            return (state_ == OcspQuery::ST_CONNECTED);
        }


        bool OcspQuery::do_send_request () {
            auto log = OcspFactory::log();
            int rv;

            switch (state_) {

                case OcspQuery::ST_CONNECTED:


                    ocsp_req_ctx = OCSP_sendreq_new(conn_bio, ocsp_path.c_str(), nullptr, -1);
                    if (!ocsp_req_ctx) {
                        _err("OcspQuery::do_send_request[0x%lx]: OCSP_sendreq_new failed", ref_id);
                        goto err;
                    }

                    if (!OCSP_REQ_CTX_add1_header(ocsp_req_ctx, "Host", ocsp_host.c_str())) {
                        _err("OcspQuery::do_send_request[0x%lx]: OCSP_REQ_CTX_add1_header 'Host' failed", ref_id);
                        goto err;
                    }

                    if (!OCSP_REQ_CTX_add1_header(ocsp_req_ctx, "User-Agent",
                                                  string_format("socle/%s", SOCLE_VERSION).c_str())) {
                        _err("OcspQuery::do_send_request[0x%lx]: OCSP_REQ_CTX_add1_header 'User-Agent' failed", ref_id);
                        goto err;
                    }

                    if (!OCSP_REQ_CTX_set1_req(ocsp_req_ctx, ocsp_req)) {
                        _err("OcspQuery::do_send_request[0x%lx]: OCSP_REQ_CTX_set1_req failed", ref_id);
                        goto err;
                    }
                    // transit to next state
                    state_ = OcspQuery::ST_REQ_INPROGRESS;
                    _dia("OcspQuery::do_send_request[0x%lx]: state REQ_INPROGRESS", ref_id);

                    [[ fallthrough ]];

                case OcspQuery::ST_REQ_INPROGRESS:

                    rv = OCSP_sendreq_nbio(&ocsp_resp, ocsp_req_ctx);

                    // operation should be retried
                    if (rv == -1) {

                        if(time(nullptr) - timer_ > timeout_request) {
                            _err("OcspQuery::do_send_request[0x%lx]: operation timed out.", ref_id);
                            goto err;
                        }

                        if (BIO_should_read(conn_bio))
                            socket.mon_read();
                        else if (BIO_should_write(conn_bio))
                            socket.mon_write();
                        else {
                            _err("OcspQuery::do_send_request[0x%lx]: Unexpected retry condition", ref_id);
                            goto err;
                        }

                        // operation successful
                    } else if (rv == 1) {
                        state_ = OcspQuery::ST_RESP_RECEIVED; // waiting for response now
                        _dia("OcspQuery::do_send_request[0x%lx]: state RESP_RECEIVED", ref_id);
                        return true;
                    }
                        // rv == 0, or undefined returned value
                    else {
                        _err("OcspQuery::do_send_request[0x%lx]: Timeout or error while sending request", ref_id);
                    }
            }

            return false;

            err:

            if(conn_bio) {
                BIO_free(conn_bio);
                conn_bio = nullptr;
            }

            // set state to connecting - try other ocsp host if available.
            // connect to next ocsp host
            state_ = OcspQuery::ST_CONNECTING;
            _dia("OcspQuery::do_send_request[0x%lx]: state CONNECTING", ref_id);
            ocsp_target_index++;

            return false;
        }

        bool OcspQuery::do_process_response() {

            auto& log = OcspFactory::log();

            state_ = OcspQuery::ST_FINISHED;

            if (ocsp_resp) {
                switch(ocsp_verify_response(ocsp_resp, cert_check, cert_issuer).revoked) {
                    case -1:
                        yield_ = RET_UNKNOWN;
                        break;

                    case 0:
                        yield_ = RET_VALID;
                        break;

                    case 1:
                        yield_ = RET_REVOKED;
                        break;

                    default:
                        yield_ = RET_UNKNOWNSTATUS;

                }
                _dia("OcspQuery::do_process_response[0x%lx]: state FINISHED", ref_id);

                return true;
            } else {
                yield_ = RET_UNKNOWN;

                _err("OcspQuery::do_process_response[0x%lx]: no OCSP response", ref_id);
            }


            return false;
        }

        bool OcspQuery::run () {

            switch (state_) {
                case OcspQuery::ST_INIT:

                    do_init();

                    [[ fallthrough ]];

                case OcspQuery::ST_CONNECTING:

                    // return only on IO blocking (can connect immediately)
                    if (!do_connect()) {
                        if (state_ == OcspQuery::ST_CONNECTING) {
                            return false;
                        } else {
                            break;
                        }
                    }
                    state_ = ST_CONNECTED;

                    [[ fallthrough ]];

                case OcspQuery::ST_CONNECTED:

                    [[ fallthrough ]];

                case OcspQuery::ST_REQ_INPROGRESS:

                    // break on IO retry
                    if (!do_send_request()) {
                        break;
                    } else {
                        state_ = ST_REQ_SENT;
                    }

                    [[ fallthrough ]];

                case OcspQuery::ST_RESP_RECEIVED:
                    do_process_response();
                    // processing response is not blocking operation - transit to next

                    [[ fallthrough ]];

                case OcspQuery::ST_FINISHED:
                    return false;
            }

            return true;
        }
    }
}