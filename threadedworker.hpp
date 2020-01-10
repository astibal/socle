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

class threadedProxyWorker  {

public:
    using proxy_type = enum class proxy_type { NONE, TRANSPARENT, PROXY, REDIRECT };

    threadedProxyWorker(int worker_id, proxy_type t):  type_(t), worker_id_(worker_id) {}

    proxy_type type_;
    int worker_id_ = 0;

};
#endif //THREADEDWORKER_HPP
