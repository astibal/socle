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
#include <logger.hpp>
#include <buffer.hpp>
#include <socle.hpp>

std::vector<std::string> ocsp_urls(X509 *x509)
{
    std::vector<std::string> list;
    STACK_OF(OPENSSL_STRING) *ocsp_list = X509_get1_ocsp(x509);
    for (int j = 0; j < sk_OPENSSL_STRING_num(ocsp_list); j++)
    {
        list.push_back( std::string( sk_OPENSSL_STRING_value(ocsp_list, j) ) ); 
    }
    X509_email_free(ocsp_list);
    return list;
}


int ocsp_prepare_request(OCSP_REQUEST **req, X509 *cert, const EVP_MD *cert_id_md,X509 *issuer,
                STACK_OF(OCSP_CERTID) *ids)
{
    OCSP_CERTID *id;
    if(!issuer)
        {
        DIAS_("prepareRequest: No issuer certificate specified");
        return 0;
        }
    if(!*req) *req = OCSP_REQUEST_new();
    if(!*req) goto err;
    id = OCSP_cert_to_id(cert_id_md, cert, issuer);
    if(!id || !sk_OCSP_CERTID_push(ids, id)) goto err;
    if(!OCSP_request_add0_id(*req, id)) goto err;
    return 1;
 
    err:
        DIAS_("prepareRequest: Error Creating OCSP request");
    return 0;
}


OCSP_RESPONSE * ocsp_query_responder(BIO *err, BIO *cbio, char *path,
                char *host, OCSP_REQUEST *req, int req_timeout)
{
    int fd;
    int rv;
    OCSP_REQ_CTX *ctx = NULL;
    OCSP_RESPONSE *rsp = NULL;
    fd_set confds;
    struct timeval tv;
 
    if (req_timeout != -1)
        BIO_set_nbio(cbio, 1);
 
    rv = BIO_do_connect(cbio);
 
    if ((rv <= 0) && ((req_timeout == -1) || !BIO_should_retry(cbio)))
        {
        DIAS_("queryResponder: Error connecting BIO");
        return NULL;
        }
 
    if (BIO_get_fd(cbio, &fd) <= 0)
        {
        DIAS_("queryResponder: Can't get connection fd");
        goto err;
        }
 
    if (req_timeout != -1 && rv <= 0)
        {
        FD_ZERO(&confds);
        FD_SET(fd, &confds);
        tv.tv_usec = 0;
        tv.tv_sec = req_timeout;
        rv = select(fd + 1, NULL, &confds, NULL, &tv);
        if (rv == 0)
            {
            DIAS_("queryResponder: Timeout on connect");
        
            //BIO_puts(err, "Timeout on connect\n");
            return NULL;
            }
        }
 
    ctx = OCSP_sendreq_new(cbio, path, NULL, -1);
    if (!ctx)
        return NULL;
 
    if (!OCSP_REQ_CTX_add1_header(ctx, "Host", host))
        goto err;
 
    if (!OCSP_REQ_CTX_set1_req(ctx, req))
        goto err;
 
    for (;;)
        {
        rv = OCSP_sendreq_nbio(&rsp, ctx);
        if (rv != -1)
            break;
        if (req_timeout == -1)
            continue;
        FD_ZERO(&confds);
        FD_SET(fd, &confds);
        tv.tv_usec = 0;
        tv.tv_sec = req_timeout;
        if (BIO_should_read(cbio))
            rv = select(fd + 1, &confds, NULL, NULL, &tv);
        else if (BIO_should_write(cbio))
            rv = select(fd + 1, NULL, &confds, NULL, &tv);
        else
            {
            DIAS_("queryResponder: Unexpected retry condition");
            goto err;
            }
        if (rv == 0)
            {
            DIAS_("queryResponder: Timeout on request");
            break;
            }
        if (rv == -1)
            {
            DIAS_("queryResponder: Select error");
            break;
            }
 
        }
    err:
    if (ctx)
        OCSP_REQ_CTX_free(ctx);
 
    return rsp;
}

OCSP_RESPONSE * ocsp_send_request(BIO *err, OCSP_REQUEST *req,
            char *host, char *path, char *port, int use_ssl,
            int req_timeout)
{
    BIO *cbio = NULL;
    OCSP_RESPONSE *resp = NULL;
    cbio = BIO_new_connect(host);
    if (cbio && port && use_ssl==0)
    {
        BIO_set_conn_port(cbio, port);
        resp = ocsp_query_responder(err, cbio, path, host, req, req_timeout);
        if (!resp)
            DIAS_("sendRequest: Error querying OCSP responder");
    }
    if (cbio)
        BIO_free_all(cbio);
    return resp;
}

int ocsp_parse_response(OCSP_RESPONSE *resp)
{
    int is_revoked = -1;

#ifdef USE_OPENSSL11

    OCSP_BASICRESP *br = OCSP_response_get1_basic(resp);

    X509_STORE* st = X509_STORE_new();
    X509_STORE_set_default_paths(st);

    int ocsp_verify_result = OCSP_basic_verify(br, nullptr, st, 0);

    if(ocsp_verify_result <= 0) {
        is_revoked = -1;
    } else {
        for (int i = 0; i < OCSP_resp_count(br); i++) {
            OCSP_SINGLERESP *single = OCSP_resp_get0(br, i);
            int reason;
            ASN1_GENERALIZEDTIME* revtime;
            ASN1_GENERALIZEDTIME* thisupd;
            ASN1_GENERALIZEDTIME* nextupd;

            int status = OCSP_single_get0_status(single, &reason, &revtime, &thisupd, &nextupd);
            if (status == V_OCSP_CERTSTATUS_REVOKED) {
                is_revoked = 1;
            } else if (status == V_OCSP_CERTSTATUS_GOOD) {
                is_revoked = 0;
            }
        }
    }

    OCSP_BASICRESP_free(br);
    X509_STORE_free(st);

#else
    OCSP_RESPBYTES *rb = resp->responseBytes;
    if (rb && OBJ_obj2nid(rb->responseType) == NID_id_pkix_OCSP_basic)
    {
        OCSP_BASICRESP *br = OCSP_response_get1_basic(resp);
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
#endif // USE_OPENSSL11
    return is_revoked;
}

int ocsp_check_cert(X509 *x509, X509 *issuer, int req_timeout)
{
    int is_revoked=-1;
 
    BIO *bio_out = BIO_new_fp(stdout, BIO_NOCLOSE|BIO_FP_TEXT);
    BIO *bio_err = BIO_new_fp(stderr, BIO_NOCLOSE|BIO_FP_TEXT);
 
    if (issuer)
    {
        //build ocsp request
        OCSP_REQUEST *req = NULL;
        //STACK_OF(CONF_VALUE) *headers = NULL;
        STACK_OF(OCSP_CERTID) *ids = sk_OCSP_CERTID_new_null();
        const EVP_MD *cert_id_md = EVP_sha1();
        ocsp_prepare_request(&req, x509, cert_id_md, issuer, ids);
 
        //loop through OCSP urls
        STACK_OF(OPENSSL_STRING) *ocsp_list = X509_get1_ocsp(x509);
        for (int j = 0; j < sk_OPENSSL_STRING_num(ocsp_list) && is_revoked==-1; j++)
        {
            char *host = NULL, *port = NULL, *path = NULL; 
            int use_ssl;
            //std::string ocsp_url0 = std::string( sk_OPENSSL_STRING_value(ocsp_list, j) );

            char *ocsp_url = sk_OPENSSL_STRING_value(ocsp_list, j);
            if (OCSP_parse_url(ocsp_url, &host, &port, &path, &use_ssl) && !use_ssl)
            {
                //send ocsp request
                OCSP_RESPONSE *resp = ocsp_send_request(bio_err, req, host, path, port, use_ssl, req_timeout);
                if (resp)
                {
                                        //see crypto/ocsp/ocsp_prn.c for examples parsing OCSP responses
                    int responder_status = OCSP_response_status(resp);
 
                    //parse response
                    if (resp && responder_status == OCSP_RESPONSE_STATUS_SUCCESSFUL)
                    {
                        is_revoked = ocsp_parse_response(resp);
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
    return is_revoked;
}


int ocsp_check_bytes(const char cert_bytes[], const char issuer_bytes[])
{
    BIO *bio_mem1 = BIO_new(BIO_s_mem());
    BIO *bio_mem2 = BIO_new(BIO_s_mem());
    BIO_puts(bio_mem1, cert_bytes);
    BIO_puts(bio_mem2, issuer_bytes);
    X509 * x509 = PEM_read_bio_X509(bio_mem1, NULL, NULL, NULL);
    X509 * issuer = PEM_read_bio_X509(bio_mem2, NULL, NULL, NULL);
    int ret =  ocsp_check_cert(x509, issuer);
    BIO_free(bio_mem1);
    BIO_free(bio_mem2);
    X509_free(x509);
    X509_free(issuer);
    
    return ret;
}



int crl_is_revoked_by(X509 *x509, X509 *issuer, X509_CRL *crl_file)
{
    int is_revoked = -1;
    if (issuer)
    {
        EVP_PKEY *ikey=X509_get_pubkey(issuer); // must be freed
        ASN1_INTEGER *serial = X509_get_serialNumber(x509); // must not be freed
 
        if (crl_file && ikey) {
            if(X509_CRL_verify(crl_file, ikey)) {

                DEBS_("X509_CRL_verify ok");
                is_revoked = 0;
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
            }
        }
        
        if(ikey) EVP_PKEY_free(ikey);
    }
    return is_revoked;
}


int crl_verify_trust(X509 *x509, X509* issuer, X509_CRL *crl_file, const std::string& cacerts_pem_path)
{
    STACK_OF (X509)* chain = sk_X509_new_null();
    sk_X509_push(chain, issuer);
 
    X509_STORE *store=X509_STORE_new();
    if (store==NULL) { 
        INFS_("crl_verify_trust: X509_STORE_new failed"); 
        return 0; 
    }
 
    X509_LOOKUP *lookup=X509_STORE_add_lookup(store,X509_LOOKUP_file());
    if (lookup==NULL) { 
        INFS_("crl_verify_trust: X509_STORE_add_lookup failed"); 
        X509_STORE_free(store);
        return 0; 
    }
 
    // FIXME
    //INF_("crl_verify_trust: Loading CA path %s",cacerts_pem_path.c_str());
    //int q1 = X509_LOOKUP_load_file(lookup, cacerts_pem_path.c_str(), X509_FILETYPE_PEM);
    //if (!q1) { INFS_("crl_verify_trust: X509_LOOKUP_load_file failed"); return 0; }
 
    X509_STORE_CTX *csc = X509_STORE_CTX_new();
    
    int verify_result = 0;
    if(csc) {
        X509_STORE_CTX_init(csc, store, x509, chain);
        X509_STORE_CTX_set_purpose(csc, X509_PURPOSE_SSL_SERVER);
    
        X509_STORE_add_crl(store, crl_file);
        X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK);
    
        verify_result=X509_verify_cert(csc);
        if (verify_result != 1) {
            DIA_("crl_verify_trust: %s",X509_verify_cert_error_string(csc->error));
        }

        X509_STORE_CTX_cleanup(csc);
        X509_STORE_CTX_free(csc);
    }
    
    if(store) X509_STORE_free(store);
    if(chain) sk_X509_free(chain);
 
    return verify_result;
}


std::vector<std::string> crl_urls(X509 *x509)
{
    std::vector<std::string> list;
    int nid = NID_crl_distribution_points;
    STACK_OF(DIST_POINT) * dist_points =(STACK_OF(DIST_POINT) *)X509_get_ext_d2i(x509, nid, NULL, NULL);
    for (int j = 0; j < sk_DIST_POINT_num(dist_points); j++)
    {
        DIST_POINT *dp = sk_DIST_POINT_value(dist_points, j);
        DIST_POINT_NAME    *distpoint = dp->distpoint;
        if (distpoint->type==0)//fullname GENERALIZEDNAME
        {
            for (int k = 0; k < sk_GENERAL_NAME_num(distpoint->name.fullname); k++) 
            {
                GENERAL_NAME *gen = sk_GENERAL_NAME_value(distpoint->name.fullname, k);
                ASN1_IA5STRING *asn1_str = gen->d.uniformResourceIdentifier;
                list.push_back( std::string( (char*)ASN1_STRING_data(asn1_str), ASN1_STRING_length(asn1_str) ) );
            }
        }
        else if (distpoint->type==1)//relativename X509NAME
        {
            STACK_OF(X509_NAME_ENTRY) *sk_relname = distpoint->name.relativename;
            for (int k = 0; k < sk_X509_NAME_ENTRY_num(sk_relname); k++) 
            {
                X509_NAME_ENTRY *e = sk_X509_NAME_ENTRY_value(sk_relname, k);
                ASN1_STRING *d = X509_NAME_ENTRY_get_data(e);
                list.push_back( std::string( (char*)ASN1_STRING_data(d), ASN1_STRING_length(d) ) );
            }
        }
    }
    
    CRL_DIST_POINTS_free(dist_points);
    
    return list;
}


std::string fingerprint(X509* cert) {

  const EVP_MD *fprint_type = NULL;
  unsigned fprint_size;
  unsigned char fprint[EVP_MAX_MD_SIZE];

  fprint_type = EVP_sha1();

  if (!X509_digest(cert, fprint_type, fprint, &fprint_size)) {
    ERRS_("error creating the certificate fingerprint");
  }

  std::string ret;
  for (unsigned int j = 0; j < fprint_size; ++j)  {
      ret += string_format("%02x", fprint[j]);
  }
  
  
  return ret;
}

X509 *new_x509(const char* cert_bytes)
{
    BIO *bio_mem = BIO_new(BIO_s_mem());
    BIO_puts(bio_mem, cert_bytes);
    X509 * x509 = PEM_read_bio_X509(bio_mem, NULL, NULL, NULL);
    BIO_free(bio_mem);
    return x509;
}

X509_CRL *new_CRL(const char* cert_bytes)
{
    BIO *bio_mem = BIO_new(BIO_s_mem());
    BIO_puts(bio_mem, cert_bytes);
    X509_CRL * crl = d2i_X509_CRL_bio(bio_mem, NULL);
    BIO_free(bio_mem);
    return crl;
}

X509_CRL *new_CRL(buffer& b)
{
    BIO *bio_mem = BIO_new(BIO_s_mem());
    BIO_write(bio_mem,b.data(),b.size());
    EXT_("new_CRL: \n%s",hex_dump(b).c_str())
    
    X509_CRL * crl = d2i_X509_CRL_bio(bio_mem, NULL);
    
    BIO_free(bio_mem);
    return crl;
}



X509_CRL *new_CRL_from_file(const char* crl_filename)
{
    BIO *bio = BIO_new_file(crl_filename, "r");
    X509_CRL *crl=d2i_X509_CRL_bio(bio,NULL); //if (format == FORMAT_PEM) crl=PEM_read_bio_X509_CRL(in,NULL,NULL,NULL);
    BIO_free(bio);
    return crl;
}


OcspQuery::~OcspQuery() {
    if(conn_bio)
        BIO_free_all(conn_bio);

    if(ocsp_req)
        OCSP_REQUEST_free(ocsp_req);

    if(ocsp_req_ids)
        sk_OCSP_CERTID_free(ocsp_req_ids);

    if (ocsp_req_ctx)
        OCSP_REQ_CTX_free(ocsp_req_ctx);

}

void OcspQuery::parse_cert() {

    STACK_OF(OPENSSL_STRING) *ocsp_list = X509_get1_ocsp(cert_check);
    for (int j = 0; j < sk_OPENSSL_STRING_num(ocsp_list); j++) {

        char *host = nullptr;
        char *port = nullptr;
        char *path = nullptr;
        int use_ssl;

        char *ocsp_url = sk_OPENSSL_STRING_value(ocsp_list, j);
        if (OCSP_parse_url(ocsp_url, &host, &port, &path, &use_ssl)) {
            ocsp_targets.push_back( { std::string(host), std::string(port), std::string(path), (use_ssl > 0) } );
        }
    }

    X509_email_free(ocsp_list);
}


bool OcspQuery::do_init() {
    parse_cert();



    if(ocsp_targets.empty()) {
        state_ = OcspQuery::ST_FINISHED;
        yield_ = OcspQuery::RET_NOOCSP_TARGETS;
        return false;
    }

    //build ocsp request
    ocsp_req_ids = sk_OCSP_CERTID_new_null();
    const EVP_MD *cert_id_md = EVP_sha1();
    ocsp_prepare_request(&ocsp_req, cert_check, cert_id_md, cert_issuer, ocsp_req_ids);

    return true;
}

bool OcspQuery::do_connect() {

    bool to_continue = false;
    int skip = 0;

    // prepare skipping
    if(ocsp_target_index >= 0) {
        skip = ocsp_target_index;
    }
    //reset index (so it starts at 0 once incremented)
    ocsp_target_index = -1;

    for(const auto& tup: ocsp_targets) {
        // count again the index
        ocsp_target_index++;

        // skip to previous position
        if(skip > 0) {
            skip--;
            continue;
        }

        // run this only if we are not retrying (initiate conn_bio)
        if(!ocsp_target_retry) {
            ocsp_host = std::get<0>(tup);
            ocsp_port = std::get<1>(tup);
            ocsp_path = std::get<2>(tup);
            ocsp_ssl = std::get<3>(tup);

            // free old structure
            if(conn_bio) { BIO_free_all(conn_bio); }

            conn_bio = BIO_new_connect(ocsp_host.c_str());

            if (conn_bio && !ocsp_ssl) {
                state_ = OcspQuery::ST_CONNECTING;
                BIO_set_nbio(conn_bio, 1);

                socket.socket_ = BIO_get_fd(conn_bio, nullptr);

                if (!ocsp_port.empty()) {
                    BIO_set_conn_port(conn_bio, ocsp_port.c_str());
                }
            }
        }
        if(conn_bio) {
            // attempt to connect to this OCSP service
            if(BIO_do_connect(conn_bio) <= 0) {
                if(BIO_should_retry(conn_bio)) {

                    ocsp_target_retry = true;
                    return false;

                } else {
                    to_continue = true;
                }
            } else {
                // reset retry
                ocsp_target_retry = false;
                state_ = OcspQuery::ST_CONNECTED;
            }


        } else {
           to_continue = true;
        }


        if(!to_continue) {
            break;
        }
    }

    return (state_ == OcspQuery::ST_CONNECTED);
}


bool OcspQuery::do_send_request() {
    int rv;

    switch(state_) {

        case OcspQuery::ST_CONNECTED:


                ocsp_req_ctx = OCSP_sendreq_new(conn_bio, ocsp_path.c_str(), nullptr, -1);
            if (!ocsp_req_ctx) {
                goto err;
            }

            if (!OCSP_REQ_CTX_add1_header(ocsp_req_ctx, "Host", ocsp_host.c_str())) {
                goto err;
            }

            if (!OCSP_REQ_CTX_add1_header(ocsp_req_ctx, "User-Agent", string_format("socle/%s", SOCLE_VERSION).c_str())){
                goto err;
            }

            if (!OCSP_REQ_CTX_set1_req(ocsp_req_ctx, ocsp_req)){
                goto err;
            }
            // transit to next state
            state_ = OcspQuery::ST_REQ_INPROGRESS;

        case OcspQuery::ST_REQ_INPROGRESS:

            rv = OCSP_sendreq_nbio(&ocsp_resp, ocsp_req_ctx);

            // operation should be retried
            if (rv == -1) {
                if (BIO_should_read(conn_bio))
                    socket.mon_read();
                else if (BIO_should_write(conn_bio))
                    socket.mon_write();

                else {
                    DIAS_("queryResponder: Unexpected retry condition");
                    goto err;
                }

            // operation successful
            } else if (rv == 1) {
                state_ = OcspQuery::ST_RESP_RECEIVED; // waiting for response now
                return true;
            }
            // rv == 0, or undefined returned value
            else {
                DIAS_("queryResponder: Timeout or error while sending request");
            }
    }

    return false;

    err:

    // set state to connecting - try other ocsp host if available.
    // connect to next ocsp host
    state_ = OcspQuery::ST_CONNECTING;
    ocsp_target_index++;

    return false;
}

bool OcspQuery::do_process_response() {

    if(ocsp_resp) {
        yield_ = ocsp_parse_response(ocsp_resp);
        state_ = OcspQuery::ST_FINISHED;
        return true;
    }

    return false;
}

bool OcspQuery::run() {
    switch(state_) {
        case OcspQuery::ST_INIT:

            do_init();

        case OcspQuery::ST_CONNECTING:

            // return only on IO blocking (can connect immediately)
            if (! do_connect()) break;


        case OcspQuery::ST_CONNECTED:
        case OcspQuery::ST_REQ_INPROGRESS:

            // break on IO retry
            if (!do_send_request())
                break;

        case OcspQuery::ST_RESP_RECEIVED:
            do_process_response();
            // processing response is not blocking operation - transit to next

        case OcspQuery::ST_FINISHED:
            return false;
    }

    return true;
}