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

#ifndef THREADEDWORKER_HPP
#define THREADEDWORKER_HPP

struct proxyType {
    enum class proxy_type_t { NONE, TRANSPARENT, PROXY, REDIRECT } type_;
    std::string to_string();

    bool is_none() const { return type_ == proxy_type_t::NONE; };
    bool is_transparent() const { return type_ == proxy_type_t::TRANSPARENT; };
    bool is_proxy() const { return type_ == proxy_type_t::PROXY; };
    bool is_redirect() const { return type_ == proxy_type_t::REDIRECT; };

    static proxyType none() { return { .type_ = proxy_type_t::NONE }; };
    static proxyType transparent() { return { .type_ = proxy_type_t::TRANSPARENT }; };
    static proxyType proxy() { return { .type_ = proxy_type_t::PROXY }; };
    static proxyType redirect() { return { .type_ = proxy_type_t::REDIRECT }; };
};

class threadedProxyWorker  {

public:
    threadedProxyWorker(uint32_t worker_id, proxyType t): type_(t), worker_id_(worker_id) {}

    proxyType type_;

    [[nodiscard]]
    inline proxyType proxy_type() const { return type_; }
    uint32_t worker_id_ = 0;

};


inline std::string proxyType::to_string() {
    switch(type_) {
        case proxy_type_t::NONE:
            return "none";

        case proxy_type_t::TRANSPARENT:
            return "transparent";

        case proxy_type_t::PROXY:
            return "proxy";

        case proxy_type_t::REDIRECT:
            return "redirected";
    }

    return "unknown";
}
#endif //THREADEDWORKER_HPP
