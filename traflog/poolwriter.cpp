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


#include <sys/stat.h>
#include <traflog/poolwriter.hpp>
#include <buffer.hpp>

namespace socle {

    bool poolFileWriter::recreate(std::string const& fnm) {
        struct stat st{};
        int result = stat(fnm.c_str(), &st);
        auto file_exists = result == 0;

        if(not file_exists) {
            _err("recreate: file %s doesn't exist: %s", fnm.c_str(), string_error().c_str());
            if (not close(fnm)) {
                _not("recreate: file %s not in cache", fnm.c_str());
            }
            return true;
        }

        return false;
    }

    std::size_t poolFileWriter::write(std::string const& fnm, std::string const& str) {

        std::scoped_lock<std::recursive_mutex> l_(ofstream_pool.getlock());

        auto resource = get_ofstream(fnm);

        if(!resource) return 0;

        auto sz = str.size();
        try {
            resource->first->flush();

            auto lock = std::lock_guard(*resource->second);
            (*resource->first) << str;

        } catch(std::ios_base::failure const& e) {
            sz = 0;
            _err("file: %s: write string failed: %s", fnm.c_str(), e.what());
        }



        _dia("file: %s: written string of %dB", fnm.c_str(), sz);
        return sz;
    };


    std::size_t poolFileWriter::write(std::string const& fnm, buffer const& buf) {

        std::scoped_lock<std::recursive_mutex> l_(ofstream_pool.getlock());

        auto resource = get_ofstream(fnm);

        if(!resource) return 0;

        if(not buf.data() or buf.empty()) return 0;

        auto sz = buf.size();
        try {
            resource->first->flush();

            auto lock = std::lock_guard(*resource->second);
            (*resource->first) << buf;
        } catch(std::ios_base::failure const& e) {
            sz = 0;
            _err("file: %s: write buffer failed: %s", fnm.c_str(), e.what());
        }

        _dia("file: %s: written buffer of %dB", fnm.c_str(), sz);
        return sz;
    };


    std::shared_ptr<poolFileWriter::resource_t> poolFileWriter::get_ofstream(std::string const& fnm, bool create) {

        std::scoped_lock<std::recursive_mutex> l_(ofstream_pool.getlock());

        auto optr = ofstream_pool.get(fnm);
        if (! optr) {

            if(! create) {
                _dia("file: %s: stream not found.", fnm.c_str());
                return nullptr;
            }

            _dia("file: %s: creating a new stream", fnm.c_str());

            for(auto const& s: ofstream_pool.items()) {
                _deb("pool item: %s", s.c_str());
            }

            auto* stream = new std::ofstream(fnm , std::ofstream::out | std::ofstream::app);

            if(chmod(fnm.c_str(), 0600) != 0) {
                _err("chmod failed: %s", string_error().c_str());
            }

            bool replaced = ofstream_pool.set(fnm, std::make_shared<resource_t>(stream, new std::mutex));
            _deb("new ostream %s -> 0x%x (replaced=%d)", fnm.c_str(), stream, replaced);

            auto entry = ofstream_pool.cache().find(fnm);
            if(entry != ofstream_pool.cache().end()) {

                auto exo = entry->second->ptr();
                _deb("new ofstream entry: 0x%x", exo.get());

            } else {

                _deb("cannot find inserted entry!!!");
            }


            return ofstream_pool.get(fnm);
        } else {
            _deb("file: %s: existing stream", fnm.c_str());
            return optr;
        }
    }

    bool poolFileWriter::flush(std::string const& fnm) {

        std::scoped_lock<std::recursive_mutex> l_(ofstream_pool.getlock());

        auto resource = get_ofstream(fnm, false);
        if(not resource) return false;

        auto lock = std::lock_guard(*resource->second);

        if(resource->first) {
            resource->first->flush();
            _dia("file: %s: flushed", fnm.c_str());
            return true;
        }

        return false;
    }

    bool poolFileWriter::close(std::string const& fnm) {

        std::scoped_lock<std::recursive_mutex> l_(ofstream_pool.getlock());

        auto o = get_ofstream(fnm, false);
        if(o) {
            ofstream_pool.erase(fnm);

            _dia("file: %s: erased", fnm.c_str());
            return true;
        }

        return false;
    }

    // trafLog compatible API
    bool poolFileWriter::open(std::string const& fnm) {

        auto o = get_ofstream(fnm);

        return o != nullptr;
    }

}
