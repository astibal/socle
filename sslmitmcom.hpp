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

#ifndef __SSLMITMCOM_HPP__
#define __SSLMITMCOM_HPP__


#include <sslcom.hpp>

#define EXT_COUNT 4

struct entry    {
    char *key;
    char *value;
};


#pragma GCC diagnostic ignored "-Wwrite-strings"
#pragma GCC diagnostic push

static struct entry ext_ent[EXT_COUNT] = {
    { "basicConstraints",      "CA:FALSE" },
    { "nsComment",           "\"Mitm generated certificate\"" },
    { "subjectKeyIdentifier",  "hash" },
    { "authorityKeyIdentifier","keyid,issuer:always" } //, 
    //{ "keyUsage",              "nonrepudiation,digitalSig nature,keyEncipherment" }
};

#pragma GCC diagnostic pop

struct SpoofOptions {
  bool self_signed = false; // set to true if we should deliberately make a mistake
  std::vector<std::string> sans;
};


template <class SSLProto>
class baseSSLMitmCom : public SSLProto {
public:
   static std::string sslmitmcom_name_;
   static std::string sslmitmcom_insp_name_;
    
   virtual bool check_cert(const char*);
   virtual bool spoof_cert(X509* cert_orig, SpoofOptions& spo);
   virtual baseCom* replicate() { return new baseSSLMitmCom(); };

    virtual ~baseSSLMitmCom() {};

    DECLARE_C_NAME("baseSSLMitmCom")
    DECLARE_DEF_TO_STRING
    DECLARE_LOGGING(to_string)
    
    virtual const std::string shortname() const { return std::string("ssli"); }
};

#include <sslmitmcom.tpp>

typedef baseSSLMitmCom<SSLCom> SSLMitmCom;
typedef baseSSLMitmCom<DTLSCom> DTLSMitmCom;

#endif // __SSLMITMCOM_HPP__