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


#include <traflog/poolwriter.hpp>
#include <buffer.hpp>

namespace socle {
    std::size_t poolFileWriter::write(std::string const& fnm, std::string const& str) {

        std::scoped_lock<std::recursive_mutex> l_(ofstream_pool.getlock());

        auto o = get_ofstream(fnm);

        if(!o) return 0;

        o->flush();
        (*o) << str;


        auto sz = str.size();

        _dia("file: %s: written string of %dB", fnm.c_str(), sz);
        return sz;
    };


    std::size_t poolFileWriter::write(std::string const& fnm, buffer const& buf) {

        std::scoped_lock<std::recursive_mutex> l_(ofstream_pool.getlock());

        auto o = get_ofstream(fnm);

        if(!o) return 0;

        if(not buf.data() or buf.empty() > 0) return 0;

        o->flush();
        (*o) << buf;


        auto sz = buf.size();

        _dia("file: %s: written buffer of %dB", fnm.c_str(), sz);
        return sz;
    };


    std::shared_ptr<std::ofstream> poolFileWriter::get_ofstream(std::string const& fnm, bool create) {

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

            bool replaced = ofstream_pool.set(fnm, stream);
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

        auto o = get_ofstream(fnm, false);
        if(o) {
            o->flush();
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
