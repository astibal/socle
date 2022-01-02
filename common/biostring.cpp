// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <openssl/bio.h>
#include <string>
#include <cstring>

#include <socle_common.hpp>
#include <openssl/buffer.h>

namespace {
    int bio_string_write(BIO* bio, const char* data, int len) {

#ifdef USE_OPENSSL11
        BUF_MEM* ptr;
        BIO_get_mem_ptr(bio,&ptr);

        reinterpret_cast<std::string*>((void*)ptr)->append(data, len);
#else
        reinterpret_cast<std::string*>(bio->ptr)->append(data, len);
#endif // USE_OPENSSL11
        return len;
    }

    int bio_string_puts(BIO* bio, const char* data) {
        // Note: unlike puts(), BIO_puts does not add a newline.
        return bio_string_write(bio, data, strlen(data));
    }

    long bio_string_ctrl(BIO* bio, int cmd, long num, void* ptr) {

#ifdef USE_OPENSSL11
        BUF_MEM* mem_ptr;
        BIO_get_mem_ptr(bio,&mem_ptr);
        auto str = reinterpret_cast<std::string*>((void*)mem_ptr);
#else

        std::string* str = reinterpret_cast<std::string*>(bio->ptr);
#endif //USE_OPENSSL11

        switch (cmd) {
            case BIO_CTRL_RESET:
            str->clear();
            return 1;
            case BIO_C_FILE_SEEK:
            return -1;
            case BIO_C_FILE_TELL:
            return str->size();
            case BIO_CTRL_FLUSH:
            return 1;
            default:
            return 0;
        }
    }

    int bio_string_new(BIO* bio) {
#ifdef USE_OPENSSL11
        BIO_reset(bio);
        return 1;
#else
        bio->ptr = nullptr;
        bio->init = 0;
        return 1;
#endif //USE_OPENSSL11
    }

    int bio_string_free(BIO* bio) {
        // The string is owned by the caller, so there's nothing to do here.
        return bio != nullptr;
    }

#ifdef USE_OPENSSL11

    static BIO_METHOD* my_init_meth() {
        BIO_METHOD* new_meth = BIO_meth_new( BIO_TYPE_SOURCE_SINK, "bio_string");

        BIO_meth_set_write(new_meth, bio_string_write);
        BIO_meth_set_puts(new_meth, bio_string_puts);
        BIO_meth_set_ctrl(new_meth, bio_string_ctrl);
        BIO_meth_set_create(new_meth, bio_string_new);
        BIO_meth_set_destroy(new_meth, bio_string_free);

        return new_meth;
    }

    static BIO_METHOD* bio_string_methods() {
        static BIO_METHOD* meth =  my_init_meth();
        return meth;
    }

#else
    BIO_METHOD bio_string_methods = {
        // TODO(mattm): Should add some type number too? (bio.h uses 1-24)
        BIO_TYPE_SOURCE_SINK,
        "bio_string",
        bio_string_write,
        nullptr, /* read */
        bio_string_puts,
        nullptr, /* gets */
        bio_string_ctrl,
        bio_string_new,
        bio_string_free,
        nullptr, /* callback_ctrl */
    };

#endif //USE_OPENSSL11

}  // namespace


BIO* BIO_new_string(std::string* out) {

#ifdef USE_OPENSSL11
    BIO* bio = BIO_new(bio_string_methods());
    BUF_MEM* mem_ptr = BUF_MEM_new();

    mem_ptr->data = (char*) out->data();
    mem_ptr->length = out->length();

    // set NOCLOSE, because string takes responsibility to free the memory
    BIO_set_mem_buf( bio, mem_ptr, BIO_NOCLOSE);
    BIO_set_init(bio, 1);
#else
    BIO* bio = BIO_new(&bio_string_methods);
    if (!bio)
        return bio;
    bio->ptr = out;
    bio->init = 1;

#endif
  return bio;
}
