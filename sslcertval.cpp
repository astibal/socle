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
#include <cctype>
#include <chrono>
#include <filesystem>
#include <limits>

namespace inet {

    namespace {
        class openssl_error_scope {
        public:
            openssl_error_scope() : marked_(ERR_set_mark() == 1) {}
            openssl_error_scope(const openssl_error_scope&) = delete;
            openssl_error_scope& operator=(const openssl_error_scope&) = delete;
            ~openssl_error_scope() {
                if(marked_)
                    ERR_pop_to_mark();
                else
                    ERR_clear_error();
            }

        private:
            bool marked_;
        };

        bool valid_revocation_uri(const unsigned char* data, int length) {
            if(!data || length <= 0)
                return false;
            for(int i = 0; i < length; ++i) {
                if(data[i] <= 0x20 || data[i] == 0x7f)
                    return false;
            }
            return true;
        }
    }

    namespace crl {

        static bool bio_has_only_trailing_whitespace(BIO* bio) {
            unsigned char remainder[256];
            int count = 0;
            while((count = BIO_read(bio, remainder, sizeof(remainder))) > 0) {
                for(int i = 0; i < count; ++i) {
                    if(!std::isspace(remainder[i]))
                        return false;
                }
            }
            return true;
        }

        static X509_CRL* parse_crl_bytes(
                const unsigned char* data, std::size_t size) {
            if(!data || size == 0 ||
               size > static_cast<std::size_t>(std::numeric_limits<long>::max()))
                return nullptr;

            const unsigned char* cursor = data;
            X509_CRL* crl = d2i_X509_CRL(
                nullptr, &cursor, static_cast<long>(size));
            if(crl) {
                if(cursor == data + size)
                    return crl;
                X509_CRL_free(crl);
                crl = nullptr;
            }

            ERR_clear_error();
            if(size > static_cast<std::size_t>(std::numeric_limits<int>::max()))
                return nullptr;
            BIO* bio = BIO_new_mem_buf(data, static_cast<int>(size));
            if(!bio)
                return nullptr;
            crl = PEM_read_bio_X509_CRL(bio, nullptr, nullptr, nullptr);
            if(crl && !bio_has_only_trailing_whitespace(bio)) {
                X509_CRL_free(crl);
                crl = nullptr;
            }
            BIO_free(bio);
            if(!crl)
                ERR_clear_error();
            return crl;
        }

        int crl_is_revoked_by (X509 *x509, X509 *issuer, X509_CRL *crl_file) {

            auto const& log = CrlFactory::log();
            openssl_error_scope error_scope;

            int is_revoked = -1;
            if (!x509 || !issuer || !crl_file)
                return is_revoked;

            if (issuer) {
                EVP_PKEY *ikey = X509_get_pubkey(issuer); // must be freed
                [[maybe_unused]] ASN1_INTEGER *serial = X509_get_serialNumber(x509); // must not be freed

                if (crl_file && ikey) {
                    if (X509_CRL_verify(crl_file, ikey) == 1) {

                        _deb("X509_CRL_verify ok");
                        is_revoked = 0;

#ifdef USE_OPENSSL11
                        //const STACK_OF(X509_REVOKED) *revoked_list = X509_CRL_get_REVOKED(crl_file);

                        const ASN1_INTEGER *mycertser = X509_get0_serialNumber(x509);
                        X509_REVOKED *myentry = nullptr;

                        //retype mycertser to non-const (not modified by function call - based on API doc promise ... :/ )

                        if (X509_CRL_get0_by_serial(crl_file, &myentry, const_cast<ASN1_INTEGER*> (mycertser)) > 0 && myentry) {
                            is_revoked = 1;
                            const ASN1_TIME *tm = X509_REVOKED_get0_revocationDate(myentry);

                            std::string revocation_date;
                            BIO *time_bio = BIO_new(BIO_s_mem());
                            if (time_bio) {
                                if (ASN1_TIME_print(time_bio, tm) == 1) {
                                    char* text = nullptr;
                                    const long length = BIO_get_mem_data(time_bio, &text);
                                    if (length > 0 && text)
                                        revocation_date.assign(text, static_cast<std::size_t>(length));
                                }
                                BIO_free(time_bio);
                            }
                            _dia("certificate revoked: %s", revocation_date.c_str());
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

            auto const& log = CrlFactory::log();
            openssl_error_scope error_scope;

            if (!x509 || !issuer || !crl_file)
                return 0;

            // A delta CRL contains only changes relative to a numbered base
            // CRL. This validator has no base+delta composition state, so
            // treating the delta alone as a complete list could turn an
            // omitted, still-revoked serial into GOOD.
            ASN1_INTEGER* delta_base = static_cast<ASN1_INTEGER*>(
                X509_CRL_get_ext_d2i(crl_file, NID_delta_crl, nullptr, nullptr));
            if(delta_base) {
                ASN1_INTEGER_free(delta_base);
                _war("crl_verify_trust: delta CRL requires an unavailable base CRL");
                return 0;
            }

            // RFC 5280 permits nextUpdate to be omitted, but OpenSSL then has
            // no upper age bound for an otherwise valid CRL.  Tie such CRLs
            // to the same interval after which we expect to redownload them.
            if(!X509_CRL_get0_nextUpdate(crl_file)) {
                const ASN1_TIME* last_update = X509_CRL_get0_lastUpdate(crl_file);
                const int max_age = SSLFactory::options::crl_status_ttl > 0
                    ? SSLFactory::options::crl_status_ttl : 86400;
                int age_days = 0;
                int age_seconds = 0;
                if(!last_update || ASN1_TIME_diff(
                        &age_days, &age_seconds, last_update, nullptr) != 1 ||
                   age_days > max_age / 86400 ||
                   (age_days == max_age / 86400 &&
                    age_seconds > max_age % 86400)) {
                    _dia("crl_verify_trust: CRL without nextUpdate is too old");
                    return 0;
                }
            }

            STACK_OF (X509) *chain = sk_X509_new_null();
            if (!chain)
                return 0;
            if (sk_X509_push(chain, issuer) != 1) {
                sk_X509_free(chain);
                return 0;
            }

            X509_STORE *store = X509_STORE_new();
            if (! store) {
                _err("crl_verify_trust: X509_STORE_new failed");

                sk_X509_free(chain);
                return 0;
            }
            std::string trust_location = cacerts_pem_path;
            if(trust_location.empty()) {
                auto& factory = SSLFactory::factory();
                trust_location = !factory.ca_file().empty()
                    ? factory.ca_file() : factory.ca_path();
            }

            int locations_loaded = 0;
            if(trust_location.empty()) {
                locations_loaded = X509_STORE_set_default_paths(store);
            }
            else {
                std::error_code path_error;
                const bool is_directory = std::filesystem::is_directory(
                    trust_location, path_error);
                if(path_error) {
                    _err("crl_verify_trust: cannot inspect trust location: %s",
                         path_error.message().c_str());
                }
                else if(is_directory) {
                    locations_loaded = X509_STORE_load_locations(
                        store, nullptr, trust_location.c_str());
                }
                else {
                    locations_loaded = X509_STORE_load_locations(
                        store, trust_location.c_str(), nullptr);
                }
            }
            if (locations_loaded != 1) {
                X509_STORE_free(store);
                sk_X509_free(chain);
                return 0;
            }

            // X509_STORE_CTX_init copies the store verification parameters.
            // Configure revocation before initializing the context, otherwise
            // CRL_CHECK may never reach this verification operation.
            if (X509_STORE_add_crl(store, crl_file) != 1 ||
                X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK) != 1) {
                X509_STORE_free(store);
                sk_X509_free(chain);
                return 0;
            }


            // single-use lookup store
            X509_STORE_CTX *csc = X509_STORE_CTX_new();

            int verify_result = 0;
            if (csc) {
                if (X509_STORE_CTX_init(csc, store, x509, chain) == 1 &&
                    X509_STORE_CTX_set_purpose(csc, X509_PURPOSE_SSL_SERVER) == 1) {
                    verify_result = X509_verify_cert(csc);
                    if (verify_result != 1) {
                        const int verify_error = X509_STORE_CTX_get_error(csc);
                        // This function establishes that the chain and CRL
                        // are trustworthy. A positive revocation result means
                        // exactly that OpenSSL accepted the CRL and found the
                        // leaf serial in it; classification is performed by
                        // crl_is_revoked_by() immediately afterwards.
                        if(verify_error == X509_V_ERR_CERT_REVOKED) {
                            verify_result = 1;
                        }
                        else {
                            _dia("crl_verify_trust: %s",
                                 X509_verify_cert_error_string(verify_error));
                        }
                    }
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
            if (!x509)
                return list;

            int nid = NID_crl_distribution_points;
            STACK_OF(DIST_POINT) *dist_points = (STACK_OF(DIST_POINT) *) X509_get_ext_d2i(x509, nid, nullptr, nullptr);
            if (!dist_points)
                return list;

            for (int j = 0; j < sk_DIST_POINT_num(dist_points); j++) {
                DIST_POINT *dp = sk_DIST_POINT_value(dist_points, j);
                if (!dp || !dp->distpoint)
                    continue;
                DIST_POINT_NAME *distpoint = dp->distpoint;
                if (distpoint->type == 0)//fullname GENERALIZEDNAME
                {
                    for (int k = 0; k < sk_GENERAL_NAME_num(distpoint->name.fullname); k++) {
                        GENERAL_NAME *gen = sk_GENERAL_NAME_value(distpoint->name.fullname, k);
                        if (!gen || gen->type != GEN_URI)
                            continue;
                        ASN1_IA5STRING *asn1_str = gen->d.uniformResourceIdentifier;
                        if (!asn1_str)
                            continue;
#ifdef USE_OPENSSL11
                        const auto* data = ASN1_STRING_get0_data(asn1_str);
#else
                        const auto* data = ASN1_STRING_data(asn1_str);
#endif
                        const int length = ASN1_STRING_length(asn1_str);
                        if(valid_revocation_uri(data, length)) {
                            list.emplace_back(
                                reinterpret_cast<const char*>(data),
                                static_cast<std::size_t>(length));
                        }
                    }
                }
                // nameRelativeToCRLIssuer is an X.500 relative distinguished
                // name, not a network location. Only fullName entries of type
                // uniformResourceIdentifier are valid download endpoints.
            }

            CRL_DIST_POINTS_free(dist_points);

            return list;
        }


        X509* cert_from_bytes(const char *cert_bytes) {
            openssl_error_scope error_scope;
            if (!cert_bytes)
                return nullptr;
            BIO *bio_mem = BIO_new(BIO_s_mem());
            if (!bio_mem)
                return nullptr;
            BIO_puts(bio_mem, cert_bytes);
            X509 *x509 = PEM_read_bio_X509(bio_mem, nullptr, nullptr, nullptr);
            BIO_free(bio_mem);
            return x509;
        }

        X509_CRL* crl_from_bytes(const char *cert_bytes) {
            if (!cert_bytes)
                return nullptr;
            return parse_crl_bytes(
                reinterpret_cast<const unsigned char*>(cert_bytes),
                std::strlen(cert_bytes));
        }

        X509_CRL *crl_from_bytes(buffer &b) {

            auto const& log = CrlFactory::log();
            _dum("crl_from_bytes: \n%s", hex_dump(b).c_str());

            return parse_crl_bytes(
                reinterpret_cast<const unsigned char*>(b.data()), b.size());
        }

        X509_CRL *crl_from_file(const char *crl_filename) {
            if (!crl_filename)
                return nullptr;
            BIO *bio = BIO_new_file(crl_filename, "r");
            if (!bio)
                return nullptr;
            X509_CRL *crl = d2i_X509_CRL_bio(bio, nullptr);
            if(crl) {
                unsigned char trailing = 0;
                if(BIO_read(bio, &trailing, 1) > 0) {
                    X509_CRL_free(crl);
                    crl = nullptr;
                }
            }
            if(!crl) {
                ERR_clear_error();
                if(BIO_seek(bio, 0) >= 0)
                    crl = PEM_read_bio_X509_CRL(bio, nullptr, nullptr, nullptr);
                if(crl && !bio_has_only_trailing_whitespace(bio)) {
                    X509_CRL_free(crl);
                    crl = nullptr;
                }
            }
            BIO_free(bio);
            if(!crl)
                ERR_clear_error();
            return crl;
        }
    }

    namespace ocsp {

        std::vector<std::string> ocsp_urls (X509 *x509) {
            if (!x509)
                return {};

            AUTHORITY_INFO_ACCESS* access = static_cast<AUTHORITY_INFO_ACCESS*>(
                X509_get_ext_d2i(x509, NID_info_access, nullptr, nullptr));
            if (!access)
                return {};

            std::vector<std::string> list;
            list.reserve(static_cast<std::size_t>(sk_ACCESS_DESCRIPTION_num(access)));
            for(int i = 0; i < sk_ACCESS_DESCRIPTION_num(access); ++i) {
                const ACCESS_DESCRIPTION* description =
                    sk_ACCESS_DESCRIPTION_value(access, i);
                if(!description ||
                   OBJ_obj2nid(description->method) != NID_ad_OCSP ||
                   !description->location ||
                   description->location->type != GEN_URI)
                    continue;
                const ASN1_IA5STRING* uri =
                    description->location->d.uniformResourceIdentifier;
                const auto* data = uri ? ASN1_STRING_get0_data(uri) : nullptr;
                const int length = uri ? ASN1_STRING_length(uri) : 0;
                if(valid_revocation_uri(data, length)) {
                    list.emplace_back(
                        reinterpret_cast<const char*>(data),
                        static_cast<std::size_t>(length));
                }
            }
            AUTHORITY_INFO_ACCESS_free(access);
            return list;
        }


        int ocsp_prepare_request (OCSP_REQUEST **req, X509 *cert, const EVP_MD *cert_id_md, X509 *issuer,
                                  STACK_OF(OCSP_CERTID) *ids) {

            auto const& log = OcspFactory::log();

            OCSP_CERTID *id;
            if (!req || !cert || !cert_id_md || !issuer || !ids) {

                _err("ocsp_prepare_request: Invalid request inputs");
                return 0;
            }

            if (!*req)
                *req = OCSP_REQUEST_new();

            if (!*req)
                goto err;

            id = OCSP_cert_to_id(cert_id_md, cert, issuer);

            if (!id)
                goto err;

            if (!sk_OCSP_CERTID_push(ids, id)) {
                OCSP_CERTID_free(id);
                goto err;
            }

            if (!OCSP_request_add0_id(*req, id)) {
                sk_OCSP_CERTID_pop(ids);
                OCSP_CERTID_free(id);
                goto err;
            }

            return 1;

            err:
            _err("ocsp_prepare_request: Error Creating OCSP request");

            return 0;
        }


        using ocsp_clock = std::chrono::steady_clock;

        static OCSP_RESPONSE *ocsp_query_responder_until(
                BIO *err, BIO *cbio, char *path, char *host,
                OCSP_REQUEST *req, bool timed,
                ocsp_clock::time_point deadline) {
            int fd;
            int rv;
            OCSP_REQ_CTX *ctx = nullptr;
            OCSP_RESPONSE *rsp = nullptr;

            auto const& log = OcspFactory::log();

            if (!cbio || !path || !host || !req)
                return nullptr;

            const auto remaining_timeout_ms = [&]() {
                const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
                    deadline - ocsp_clock::now()).count();
                if(remaining <= 0)
                    return 0;
                return static_cast<int>(std::min<long long>(
                    remaining, std::numeric_limits<int>::max()));
            };

            if (timed)
                BIO_set_nbio(cbio, 1);

            rv = BIO_do_connect(cbio);

            if ((rv <= 0) && (!timed || !BIO_should_retry(cbio))) {

                _err("ocsp_query_responder: Error connecting BIO");
                return nullptr;
            }

            epoll epoller;
            if ( epoller.init() <= 0) {
                _err("ocsp_query_responder: Can't initialize epoll");
                goto err;
            }

            // Descriptor zero is valid when the daemon inherited a closed
            // stdin and the connect socket reused that slot.
            if (BIO_get_fd(cbio, &fd) < 0) {
                _err("ocsp_query_responder: Can't get connection fd");
                goto err;
            }

            epoller.add(fd, EPOLLOUT);

            if (timed && rv <= 0) {


                int nfds = epoller.wait(remaining_timeout_ms());

                if (nfds <= 0) {
                    _err("ocsp_query_responder: %s", nfds < 0 ?
                            string_format("error %d: %s", errno, string_error().c_str()).c_str() : "timeout" );
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
                if (!timed)
                    continue;

                if (BIO_should_read(cbio)) {

                    epoller.modify(fd, EPOLLIN);

                    _deb("ocsp_query_responder: epoll - wait for reading");
                    rv = epoller.wait(remaining_timeout_ms());
                } else if (BIO_should_write(cbio)) {

                    epoller.modify(fd, EPOLLOUT);
                    _deb("ocsp_query_responder: epoll - wait for writing");
                    rv = epoller.wait(remaining_timeout_ms());
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

        OCSP_RESPONSE *ocsp_query_responder (BIO *err, BIO *cbio, char *path,
                                             char *host, OCSP_REQUEST *req, int req_timeout) {
            const bool timed = req_timeout != -1;
            const auto deadline = ocsp_clock::now() +
                std::chrono::seconds(req_timeout > 0 ? req_timeout : 0);
            return ocsp_query_responder_until(
                err, cbio, path, host, req, timed, deadline);
        }

        static OCSP_RESPONSE *ocsp_send_request_until(
                BIO *err, OCSP_REQUEST *req, char *host, char *path,
                char *port, int use_ssl, bool timed,
                ocsp_clock::time_point deadline) {
            if (!req || !host || !path || use_ssl != 0)
                return nullptr;
            BIO *cbio = nullptr;
            OCSP_RESPONSE *resp = nullptr;
            cbio = BIO_new_connect(host);

            auto const& log = OcspFactory::log();

            if (cbio && use_ssl == 0) {
                if(port) {
                    BIO_set_conn_port(cbio, port);
                }

                // RFC 7230 requires the non-default authority port in Host.
                // OCSP_parse_url() returns host and port separately, while the
                // old request path passed only host and broke responders behind
                // name-based HTTP routing on a custom port.
                std::string host_header(host);
                if(std::strchr(host, ':') && host_header.front() != '[')
                    host_header = "[" + host_header + "]";
                if(port && std::strcmp(port, "80") != 0) {
                    host_header += ':';
                    host_header += port;
                }
                resp = ocsp_query_responder_until(
                    err, cbio, path, host_header.data(), req, timed, deadline);
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

        OCSP_RESPONSE *ocsp_send_request (BIO *err, OCSP_REQUEST *req,
                                          char *host, char *path, char *port, int use_ssl,
                                          int req_timeout) {
            const bool timed = req_timeout != -1;
            const auto deadline = ocsp_clock::now() +
                std::chrono::seconds(req_timeout > 0 ? req_timeout : 0);
            return ocsp_send_request_until(
                err, req, host, path, port, use_ssl, timed, deadline);
        }

        inet::cert::VerifyStatus ocsp_verify_response(OCSP_RESPONSE *resp, X509* cert, X509* issuer,
                                                      X509_STORE* trust_store) {

            using namespace inet::cert;
            openssl_error_scope error_scope;

            int is_revoked = -1;
            int ttl = 60;

            auto const& log = OcspFactory::log();

            if (!resp || !cert || !issuer)
                return VerifyStatus(is_revoked, ttl, VerifyStatus::status_origin::OCSP);

            if(OCSP_response_status(resp) != OCSP_RESPONSE_STATUS_SUCCESSFUL)
                return VerifyStatus(is_revoked, ttl, VerifyStatus::status_origin::OCSP);

#ifdef USE_OPENSSL11

            OCSP_BASICRESP *br = OCSP_response_get1_basic(resp);

            if(br) {

                X509_STORE* configured_store = trust_store
                    ? trust_store : SSLFactory::factory().trust_store();
                const bool owns_store = configured_store == nullptr;
                X509_STORE *st = owns_store ? X509_STORE_new() : configured_store;
                if (!st) {
                    OCSP_BASICRESP_free(br);
                    return VerifyStatus(-1, ttl, VerifyStatus::status_origin::OCSP);
                }
                if (owns_store && X509_STORE_set_default_paths(st) != 1) {
                    OCSP_BASICRESP_free(br);
                    X509_STORE_free(st);
                    return VerifyStatus(-1, ttl, VerifyStatus::status_origin::OCSP);
                }

                STACK_OF(X509*) signers = sk_X509_new_null();
                if (!signers || sk_X509_push(signers, issuer) != 1) {
                    sk_X509_free(signers);
                    OCSP_BASICRESP_free(br);
                    if (owns_store)
                        X509_STORE_free(st);
                    return VerifyStatus(-1, ttl, VerifyStatus::status_origin::OCSP);
                }

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
                    ERR_clear_error();

                } else {

                    bool matching_ids = false;

                    int resp_count = OCSP_resp_count(br);
                    _deb("ocsp_verify_response: got %d entries in response", resp_count);
                    for (int i = 0; i < resp_count; i++) {
                        OCSP_SINGLERESP *single = OCSP_resp_get0(br, i);
                        if (!single)
                            continue;
                        int reason;
                        ASN1_GENERALIZEDTIME *revtime;
                        ASN1_GENERALIZEDTIME *thisupd;
                        ASN1_GENERALIZEDTIME *nextupd;

                        int status = OCSP_single_get0_status(single, &reason, &revtime, &thisupd, &nextupd);

                        const OCSP_CERTID* id = OCSP_SINGLERESP_get0_id(single);
                        ASN1_OCTET_STRING* name_hash = nullptr;
                        ASN1_OCTET_STRING* key_hash = nullptr;
                        ASN1_OBJECT* pmd = nullptr;
                        ASN1_INTEGER* serial = nullptr;

                        // get shallow details from CERTID
                        if (!id || OCSP_id_get0_info(
                                &name_hash, &pmd, &key_hash, &serial,
                                const_cast<OCSP_CERTID*>(id)) != 1 || !pmd) {
                            continue;
                        }

                        // now we can create cert ID and compare it to one from OCSP response

                        const EVP_MD* md = EVP_get_digestbyobj(const_cast<const ASN1_OBJECT*>(pmd));
                        if (!md)
                            continue;
                        OCSP_CERTID* my_id = OCSP_cert_to_id(md , cert , issuer);

                        // match certificate ID in response with checked cert (to prevent replays of correct OCSP responses
                        // but for different cert
                        const bool id_matches = my_id &&
                            OCSP_id_cmp(const_cast<OCSP_CERTID*>(id), my_id) == 0;
                        if (id_matches) {
                            if(matching_ids) {
                                _err("ocsp_verify_response [%d]: duplicate CertID in response", i);
                                OCSP_CERTID_free(my_id);
                                is_revoked = -1;
                                break;
                            }
                            _dia("ocsp_verify_response [%d]: certificate ID matching this single", i);
                            matching_ids = true;
                        } else {
                            _dia("ocsp_verify_response [%d]: certificate ID NOT MATCHING this single", i);
                        }
                        // don't forget to free mycert CERTID
                        OCSP_CERTID_free(my_id);
                        my_id = nullptr;

                        if(! id_matches) {
                            continue;
                        }

                        const long ocsp_max_age = SSLFactory::options::ocsp_status_ttl > 0
                            ? SSLFactory::options::ocsp_status_ttl : 1800;
                        if (OCSP_check_validity(
                                thisupd, nextupd, 5 * 60, ocsp_max_age) != 1) {
                            _err("ocsp_verify_response [%d]: response validity interval is not current", i);
                            is_revoked = -1;
                            break;
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
                        if (nextupd) {
                            if (ASN1_TIME_diff( &days, &secs, nullptr, nextupd) > 0) {
                                _dia("ocsp_verify_response [%d]: TTL: %d days, %d seconds", i, days, secs);
                                const long long responder_ttl =
                                    static_cast<long long>(days) * 24 * 60 * 60 + secs;
                                const int configured_ttl =
                                    SSLFactory::options::ocsp_status_ttl > 0
                                        ? SSLFactory::options::ocsp_status_ttl
                                        : 1800;
                                ttl = responder_ttl < configured_ttl
                                    ? static_cast<int>(responder_ttl)
                                    : configured_ttl;
                            } else {
                                _war("ocsp_verify_response [%d]: negative TTL: %d days, %d seconds", i, days, secs);
                                _err("this is possible OCSP replay attack, marked as revoked!");
                                is_revoked = 1;
                            }
                        }

                        // Continue over unrelated entries and reject a second
                        // status for this same CertID instead of letting wire
                        // order choose between contradictory evidence.
                    }

                    if(! matching_ids) {
                        _err("no matching cert IDs were found in OCSP response, returning -1");
                        is_revoked = -1;
                    }
                }

                OCSP_BASICRESP_free(br);
                if (owns_store)
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
            openssl_error_scope error_scope;

            VerifyStatus ret(-1, 60, VerifyStatus::status_origin::OCSP);

            if (!x509 || !issuer)
                return ret;

            BIO *bio_out = BIO_new_fp(stdout, BIO_NOCLOSE | BIO_FP_TEXT);
            BIO *bio_err = BIO_new_fp(stderr, BIO_NOCLOSE | BIO_FP_TEXT);

            if (issuer) {
                //build ocsp request
                OCSP_REQUEST *req = nullptr;
                //STACK_OF(CONF_VALUE) *headers = nullptr;
                STACK_OF(OCSP_CERTID) *ids = sk_OCSP_CERTID_new_null();
                const EVP_MD *cert_id_md = EVP_sha1();
                if (!ids || !ocsp_prepare_request(&req, x509, cert_id_md, issuer, ids)) {
                    sk_OCSP_CERTID_free(ids);
                    OCSP_REQUEST_free(req);
                    BIO_free(bio_out);
                    BIO_free(bio_err);
                    return ret;
                }

                //loop through OCSP urls
                const auto endpoints = ocsp_urls(x509);
                const bool timed = req_timeout != -1;
                const auto deadline = ocsp_clock::now() +
                    std::chrono::seconds(req_timeout > 0 ? req_timeout : 0);
                for (const auto& endpoint : endpoints) {
                    if(ret.revoked != -1)
                        break;
                    if(timed && ocsp_clock::now() >= deadline)
                        break;
                    char *host = nullptr, *port = nullptr, *path = nullptr;
                    int use_ssl;
                    std::vector<char> mutable_url(endpoint.begin(), endpoint.end());
                    mutable_url.push_back('\0');
                    char *ocsp_url = mutable_url.data();
                    if (OCSP_parse_url(ocsp_url, &host, &port, &path, &use_ssl) && !use_ssl) {
                        //send ocsp request
                        OCSP_RESPONSE *resp = ocsp_send_request_until(
                            bio_err, req, host, path, port, use_ssl,
                            timed, deadline);
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
                OCSP_REQUEST_free(req);
            }

            BIO_free(bio_out);
            BIO_free(bio_err);
            return ret;
        }


        int ocsp_check_bytes (const char cert_bytes[], const char issuer_bytes[]) {
            openssl_error_scope error_scope;
            if (!cert_bytes || !issuer_bytes)
                return -1;
            BIO *bio_mem1 = BIO_new(BIO_s_mem());
            BIO *bio_mem2 = BIO_new(BIO_s_mem());
            if (!bio_mem1 || !bio_mem2) {
                BIO_free(bio_mem1);
                BIO_free(bio_mem2);
                return -1;
            }
            if (BIO_puts(bio_mem1, cert_bytes) <= 0 || BIO_puts(bio_mem2, issuer_bytes) <= 0) {
                BIO_free(bio_mem1);
                BIO_free(bio_mem2);
                return -1;
            }
            X509 *x509 = PEM_read_bio_X509(bio_mem1, nullptr, nullptr, nullptr);
            X509 *issuer = PEM_read_bio_X509(bio_mem2, nullptr, nullptr, nullptr);
            int ret = inet::ocsp::ocsp_check_cert(x509, issuer).revoked;
            BIO_free(bio_mem1);
            BIO_free(bio_mem2);
            X509_free(x509);
            X509_free(issuer);

            return ret;
        }



    }
}
