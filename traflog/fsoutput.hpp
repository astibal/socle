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

#ifndef FSOUTPUT_HPP
#define FSOUTPUT_HPP

#include <string>
#include <baseproxy.hpp>

namespace socle::traflog {

    struct FsOutput {
        std::string filename_full;
        std::string writer_key_l_{"???:???"};
        std::string writer_key_r_{"???:???"};

        FsOutput () = default;

        FsOutput (baseProxy *proxy_, const char *d_dir, const char *f_prefix, const char *f_suffix, bool create_dirs) :
                data_dir(d_dir),
                file_prefix(f_prefix),
                file_suffix(f_suffix) {

            if(proxy_) {
                generate_filename(proxy_, create_dirs);
            }
            else{
                generate_filename_single("capture", create_dirs);
            }
        }

        std::string generate_filename(baseProxy *proxy_, bool create_dirs);
        std::string generate_filename_single(const char* filename, bool create_dirs);
    private:
        std::string data_dir;
        std::string file_prefix;

        std::string file_suffix;
        std::string host_l_;
    };

}

#endif //FSOUTPUT_HPP
