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


struct SpoofOptions {
    std::string sni;
    bool self_signed = false; // set to true if we should deliberately make a mistake
    std::vector<std::string> sans;
};


template <class SSLProto>
class baseSSLMitmCom : public SSLProto {
public:
    using verify_status_t = SSLCom::verify_status_t;

    virtual ~baseSSLMitmCom() = default;

    bool check_cert(const char*) override;
    virtual bool spoof_cert(X509* cert_orig, SpoofOptions& spo);
    virtual bool use_cert_sni(SpoofOptions &spo);
    virtual bool use_cert_ip(SpoofOptions &spo);
    virtual bool use_cert_mitm(X509* cert_orig, SpoofOptions& spo);

    baseCom* replicate() override { return new baseSSLMitmCom(); };

    std::string shortname() const override { static std::string s("ssli"); return s; }
    std::string to_string(int verbosity) const override { return SSLProto::to_string(verbosity); };

    TYPENAME_OVERRIDE("baseSSLMitmCom")
    DECLARE_LOGGING(to_string)

    struct log {
        static logan_lite &ca() {
            static logan_lite l("com.tls.ca");
            return l;
        }
        static logan_lite &mitm () {
            static logan_lite l("com.tls.mitm");
            return l;
        }

    };
};

using SSLMitmCom = baseSSLMitmCom<SSLCom> ;
using DTLSMitmCom = baseSSLMitmCom<DTLSCom>;

#endif // __SSLMITMCOM_HPP__

#include <sslmitmcom.tpp>


