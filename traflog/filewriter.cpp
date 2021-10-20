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
#include <traflog/filewriter.hpp>

namespace socle {

    std::size_t fileWriter::write(std::string const&fnm, std::string const& str) {

        if(! writer_) return 0;

        *writer_ << str;
        return str.size();
    }

    std::size_t fileWriter::write(std::string const&fnm, buffer const& buf) {

        if(! writer_) return 0;
        if(not buf.data() or buf.empty()) return 0;

        *writer_ << buf;
        return buf.size();
    }


    bool fileWriter::open(std::string const& fnm) {

        if(writer_) return true;

        if(fnm.empty()) {
            return false;
        }

        writer_ = std::make_unique<std::ofstream>(fnm , std::ofstream::out | std::ofstream::app);
        chmod(fnm.c_str(), 0600);

        if(writer_->is_open()) {
            filename_ = fnm;
            opened(true);
            return true;
        }

        close();
        return false;
    }

    bool fileWriter::close(std::string const& fnm) {
        close();

        return !opened();
    }

    void fileWriter::close() {
        opened(false);

        if(writer_) {
            if(writer_->is_open()) {
                writer_->close();
            }

            filename_.clear();
        }
    }

    bool fileWriter::flush(std::string const& fnm) {
        if(writer_) {
            writer_->flush();

            return true;
        }

        return false;

    }
}