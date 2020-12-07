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

#ifndef SMITHPROXY_BIOMEM_HPP
#define SMITHPROXY_BIOMEM_HPP

#include <openssl/bio.h>

#include <mpstd.hpp>

class BioMemory {
public:
    BioMemory() {
        mem_ = BIO_new(BIO_s_mem());
        BIO_get_mem_ptr(mem_, &bptr_);
        BIO_set_close(mem_, BIO_NOCLOSE);
    }

    virtual ~BioMemory() {
        BIO_free(mem_);
    }

    std::string str() const { return std::string(bptr_->data, bptr_->length); }
    mp::string mp_str() const { return mp::string(bptr_->data, bptr_->length); }

    operator BIO*() { return mem_; };
private:
    BIO* mem_ {nullptr};
    BUF_MEM* bptr_{nullptr};
};


#endif //SMITHPROXY_BIOMEM_HPP
