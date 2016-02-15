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


std::string fingerprint(X509* cert);

std::vector<std::string> ocsp_urls(X509 *x509);
int ocsp_prepare_request(OCSP_REQUEST **req, X509 *cert, const EVP_MD *cert_id_md,X509 *issuer,STACK_OF(OCSP_CERTID) *ids);
OCSP_RESPONSE * ocsp_query_responder(BIO *err, BIO *cbio, char *path, char *host, OCSP_REQUEST *req, int req_timeout);
OCSP_RESPONSE * ocsp_send_request(BIO *err, OCSP_REQUEST *req, char *host, char *path, char *port, int use_ssl,int req_timeout);
int ocsp_parse_response(OCSP_RESPONSE *resp);
int ocsp_check_cert(X509 *x509, X509 *issuer,int req_timeout=2);
int ocsp_check_bytes(const char cert_bytes[], const char issuer_bytes[]);


std::vector<std::string> crl_urls(X509 *x509);
X509_CRL *new_CRL(const char* cert_bytes);
X509_CRL *new_CRL(buffer& b);
int crl_verify_trust(X509 *x509, X509* issuer, X509_CRL *crl_file, const std::string& cacerts_pem_path);
int crl_is_revoked_by(X509 *x509, X509 *issuer, X509_CRL *crl_file);

#endif