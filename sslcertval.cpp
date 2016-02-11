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

#include <sslcertstore.hpp>
#include <logger.hpp>

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
    int i;
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
    OCSP_RESPBYTES *rb = resp->responseBytes;
    if (rb && OBJ_obj2nid(rb->responseType) == NID_id_pkix_OCSP_basic)
    {
        OCSP_BASICRESP *br = OCSP_response_get1_basic(resp);
        OCSP_RESPDATA  *rd = br->tbsResponseData;
 
        for (int i = 0; i < sk_OCSP_SINGLERESP_num(rd->responses); i++)
        {
            OCSP_SINGLERESP *single = sk_OCSP_SINGLERESP_value(rd->responses, i);
            OCSP_CERTID *cid = single->certId;
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
    return is_revoked;
}

int ocsp_check_cert(X509 *x509, X509 *issuer)
{
    int is_revoked=-1;
 
    BIO *bio_out = BIO_new_fp(stdout, BIO_NOCLOSE|BIO_FP_TEXT);
    BIO *bio_err = BIO_new_fp(stderr, BIO_NOCLOSE|BIO_FP_TEXT);
 
    if (issuer)
    {
        //build ocsp request
        OCSP_REQUEST *req = NULL;
        STACK_OF(CONF_VALUE) *headers = NULL;
        STACK_OF(OCSP_CERTID) *ids = sk_OCSP_CERTID_new_null();
        const EVP_MD *cert_id_md = EVP_sha1();
        ocsp_prepare_request(&req, x509, cert_id_md, issuer, ids);
 
        //loop through OCSP urls
        STACK_OF(OPENSSL_STRING) *ocsp_list = X509_get1_ocsp(x509);
        for (int j = 0; j < sk_OPENSSL_STRING_num(ocsp_list) && is_revoked==-1; j++)
        {
            char *host = NULL, *port = NULL, *path = NULL; 
            int use_ssl, req_timeout = 30;
            std::string ocsp_url0 = std::string( sk_OPENSSL_STRING_value(ocsp_list, j) );
 
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
