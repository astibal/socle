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

#include <string>

class baseCom;

#ifndef SMITHPROXY_IPROXY_HPP
class Proxy {
public:
    virtual int prepare_sockets(baseCom*) = 0;   // which Com should be set: typically it should be the parent's proxy's Com
    virtual int handle_sockets_once(baseCom*) = 0;
    virtual int run() = 0;
    virtual void shutdown() = 0;
    [[nodiscard]] virtual std::string to_string(int verbosity) const = 0; //string name representing the proxy
    [[nodiscard]] inline std::string str() const { return to_string(iINF); }
    virtual ~Proxy() = default;
};

#define SMITHPROXY_IPROXY_HPP

#endif //SMITHPROXY_IPROXY_HPP
