#ifndef __SSLMITMCOM_HPP__
#define __SSLMITMCOM_HPP__


#include <sslcom.hpp>

#define EXT_COUNT 4

struct entry    {
    char *key;
    char *value;
};

static struct entry ext_ent[EXT_COUNT] = {
    { "basicConstraints",      "CA:FALSE" },
    { "nsComment",           "\"Mitm generated certificate\"" },
    { "subjectKeyIdentifier",  "hash" },
    { "authorityKeyIdentifier","keyid,issuer:always" } //, 
    //{ "keyUsage",              "nonrepudiation,digitalSig nature,keyEncipherment" }
};


class SSLMitmCom : public SSLCom {
public:
   virtual bool check_cert(const char*);
   virtual bool spoof_cert(X509*);
};

#endif // __SSLMITMCOM_HPP__