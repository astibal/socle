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

#ifndef SMCAPLOG_HPP
#define SMCAPLOG_HPP

#include <traflog/basetraflog.hpp>
#include <traflog/filewriter.hpp>
#include <traflog/threadedpoolwriter.hpp>

namespace socle::traflog {
    class SmcapLog : public baseTrafficLogger, public sobject {

        static const bool use_pool_writer = true;

    public:
        SmcapLog(baseProxy *p, const char* d_dir, const char* f_prefix, const char* f_suffix);
        ~SmcapLog() override;

        bool ask_destroy() override {
            delete this;

            return true;
        };

    private:
        baseProxy *proxy_;

        baseFileWriter* writer_ = nullptr;

        std::string data_dir;
        std::string file_prefix;
        std::string file_suffix;

        std::string writer_key_l_;
        std::string writer_key_r_;
        std::string host_l_;


        std::string writer_key_;
        std::string create_writer_key();

    public:
        void write(side_t side, std::string const& s) override;
        void write(side_t side, const buffer &b) override {
            switch (side) {
                case side_t::LEFT:
                    write(side, hex_dump(b,0,'>'));
                    return;
                case side_t::RIGHT:
                    write(side, hex_dump(b,2,'<'));
                    return;
            }
        }

        std::string to_string(int verbosity) const override;

        TYPENAME_OVERRIDE("trafLog")
        DECLARE_LOGGING(to_string)
    };
}

#endif //SMCAPLOG_HPP
